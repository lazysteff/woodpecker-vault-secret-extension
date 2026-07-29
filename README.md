# woodpecker-vault-secret-extension

`woodpecker-vault-secret-extension` is a standalone Go service that implements the Woodpecker CI secret extension protocol and returns Woodpecker-compatible `from_secret` values from HashiCorp Vault or OpenBao KV v2.

It is not a generic Vault proxy. A request can receive a secret only when the Woodpecker HTTP signature is valid, the repository and pipeline context match a static allowlist rule, PR/fork policy allows the request, the Vault path is statically configured, and every configured field resolves to a string.

## Features

- `POST /secrets` Woodpecker secret extension endpoint
- `GET /healthz` liveness endpoint that does not contact Vault
- `GET /readyz` readiness endpoint that checks Vault/OpenBao health and token usability
- Ed25519 HTTP Message Signature verification using Woodpecker's extension public key
- Static repository/event/branch/ref/tag allowlist rules
- Default-deny pull request and fork handling
- HashiCorp Vault and OpenBao compatible KV v2 reads
- Token and AppRole authentication, including non-default AppRole mount paths
- Per-request Vault path read grouping
- Structured logs without secret values

## Woodpecker Setup

Configure the Woodpecker server to call this service:

```yaml
WOODPECKER_SECRET_EXTENSION_ENDPOINT: "http://woodpecker-vault-secret-extension:8080/secrets"
WOODPECKER_SECRET_EXTENSION_NETRC: "false"
WOODPECKER_EXTENSIONS_ALLOWED_HOSTS: "private"
```

Woodpecker signs extension requests with an Ed25519 key pair. Get the public key from:

```text
https://your-woodpecker.example/api/signature/public-key
```

Use that key as `woodpecker.public_key_file` or `woodpecker.public_key`. The inline value may be PEM or base64-encoded raw Ed25519 public key material.

Pipeline usage:

```yaml
steps:
  - name: deploy
    image: alpine
    environment:
      VAULT_ADDR:
        from_secret: VAULT_ADDR
      VAULT_ROLE_ID:
        from_secret: VAULT_APP_ROLE
      VAULT_SECRET_ID:
        from_secret: VAULT_SECRET_ID
    commands:
      - echo "Deploying"
```

## Config

Config is one YAML document. `${VAR}` expressions are expanded after YAML parsing. Missing environment variables, additional YAML documents, non-positive timeouts, invalid Vault endpoint or mount values, and inline Vault credentials with surrounding whitespace fail startup. File-backed Vault credentials are trimmed when read. Expansion is not applied to values returned from Vault/OpenBao.

```yaml
server:
  listen_addr: ":8080"
  read_timeout: "5s"
  write_timeout: "10s"
  idle_timeout: "60s"
  max_body_bytes: 1048576

logging:
  level: "info"
  format: "json"

woodpecker:
  public_key_file: "/run/secrets/woodpecker_extension_public_key"
  netrc:
    enabled: false

vault:
  address: "https://vault.example.com"
  namespace: ""
  auth:
    method: "approle"
    mount_path: "approle"
    role_id_file: "/run/secrets/vault_role_id"
    secret_id_file: "/run/secrets/vault_secret_id"
  kv:
    version: 2
    mount: "kv"
  request_timeout: "5s"
  token_renewal: true

rules:
  - id: "main-deploy"
    repo: "example/repo"
    events: ["push"]
    branches: ["main"]
    allow_pull_requests: false
    allow_forks: false
    partial: false
    secrets:
      - name: "VAULT_ADDR"
        path: "cicd/woodpecker/deploy"
        field: "vault_addr"
        events: ["push"]
```

See [examples/config.yml](examples/config.yml).

## Rule Semantics

Repository identity is resolved from every populated representation supported by current and older Woodpecker v3 payloads:

1. `repo.full_name`
2. `repo.slug`
3. `repo.owner + "/" + repo.name`
4. `repo.namespace + "/" + repo.name`

All populated repository representations must resolve to the same lower-case identity; conflicting identities are denied. Every request must carry a non-empty event without surrounding whitespace, and configured event entries must follow the same rule. Events are exact matches. Branches match `pipeline.branch` for branch-based events. Refs match `pipeline.ref` using glob-style `*` and `?`. Configured ref and tag patterns must be non-empty and free of surrounding whitespace. Tags are shorthand for `refs/tags/...`. A tag ref must contain a non-empty tag name, and a tag event must carry such a ref. A push must carry a non-empty branch and the corresponding `refs/heads/<branch>` ref. Pull-request events must carry a non-empty, non-tag ref. Inconsistent metadata is denied before rule matching. Other event types can legitimately target a tag and remain governed by their configured event and ref rules.

Pull request secrets are denied by default. The `pull_request` event and every event whose name starts with `pull_request_` are treated as pull-request events. Forked requests are denied by default. Fork signals are evaluated together: any true signal means forked, while an invalid or contradictory set cannot establish non-fork status. If fork status cannot be determined on a pull request, the request is treated as forked. Such a request matches only when both `allow_pull_requests: true` and `allow_forks: true` are configured.

Multiple rules may match. Rules are evaluated in YAML order. Duplicate names inside one rule fail configuration validation. Duplicate Woodpecker secret names across matching rules fail the request with `500` unless `allow_override: true` is explicitly set on the later rule producing the replacement. An earlier rule cannot authorize a later replacement.

## Vault / OpenBao

Supported auth methods:

```yaml
vault:
  token_renewal: false
  auth:
    method: "token"
    token: "${VAULT_TOKEN}"
```

```yaml
vault:
  token_renewal: false
  auth:
    method: "token"
    token_file: "/run/secrets/vault_token"
```

```yaml
vault:
  token_renewal: true
  auth:
    method: "approle"
    mount_path: "approle"
    role_id_file: "/run/secrets/vault_role_id"
    secret_id_file: "/run/secrets/vault_secret_id"
```

`token_renewal` is supported only for AppRole authentication. Token authentication deliberately treats inline and file-backed tokens as static credentials. After rotating a configured token or replacing `token_file`, restart the extension so the new value is loaded.

KV paths in rules are canonical logical paths under the configured mount. Do not prefix a path with the KV v2 API segment `data/`; the service inserts that segment itself. A segment named `data` elsewhere in the logical path is valid. Empty path segments, dot segments, and trailing slashes are rejected. Configured path characters are encoded as literal URL path data and are never reinterpreted as API query parameters.

For this rule path:

```yaml
path: "cicd/woodpecker/deploy"
```

Use a minimal KV v2 policy:

```hcl
path "kv/data/cicd/woodpecker/deploy" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Required when token_renewal is enabled.
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

Do not rely implicitly on Vault's built-in `default` policy for these self-management capabilities: it can be modified or excluded from issued tokens. Static and AppRole-issued tokens must report `num_uses: 0` (unlimited) through `lookup-self`; limited-use tokens are incompatible with a long-running secret service and are rejected. Every newly issued AppRole token must pass this lookup before it is installed. After Vault accepts an AppRole login, any malformed login response, self-lookup denial, limited-use token, or other token-admission failure blocks further AppRole logins until the extension restarts. A transport failure after the complete login request was written is treated as potentially accepted and blocks further logins as well; failures before the request is written remain retryable. A blocked client reports not ready without making further Vault calls, and renewal maintenance emits the safe `vault_auth_blocked` error code to make the required restart visible. This prevents readiness probes and requests from repeatedly consuming AppRole credentials when an issued token cannot be safely installed.

Avoid broad policies such as this in production:

```hcl
path "kv/data/*" {
  capabilities = ["read"]
}
```

Minimal AppRole setup:

```bash
vault auth enable approle

vault policy write woodpecker-secret-extension woodpecker-secret-extension.hcl

vault write auth/approle/role/woodpecker-secret-extension \
  token_policies="woodpecker-secret-extension" \
  token_num_uses=0 \
  token_ttl="1h" \
  token_max_ttl="4h"

vault read auth/approle/role/woodpecker-secret-extension/role-id
vault write -f auth/approle/role/woodpecker-secret-extension/secret-id
```

OpenBao is supported through its Vault-compatible HTTP API behavior for auth and KV v2.

Vault redirects are rejected. Tokens, namespaces, Role IDs, and Secret IDs are never forwarded to a redirected location. The `/sys/health` readiness check is sent to Vault's root namespace as required by Vault; authentication, token management, and KV requests remain scoped to the configured namespace. AppRole login, reauthentication, renewal, and renewal fallback are serialized so concurrent operations cannot overwrite a newer shared token or trigger duplicate logins for the same rejected token. Installing a replacement token reschedules renewal from its lease. If renewal and fallback login both fail, maintenance is retried within the remaining lease window, and shutdown waits for the renewal worker to stop. A KV `403` is checked against `auth/token/lookup-self`: a usable unlimited-use token means the response is a policy denial and does not trigger another AppRole login. Newly issued AppRole tokens must also pass that check before installation. Vault JSON responses are size-bounded, must contain exactly one complete JSON document, and authentication responses must contain a non-empty token with a positive, representable lease duration.

## Security Model

This service does not keep secrets inside Vault at runtime. Any returned secret becomes a Woodpecker pipeline secret.

Woodpecker merges extension secrets with locally configured Woodpecker secrets. Extension secrets take priority by name. If the extension is unavailable, Woodpecker may fall back to locally configured secrets. For strict Vault-only behavior, do not define local fallback secrets with the same names.

Warnings:

- Do not enable pull request secrets for public repositories unless you fully understand the risk.
- Do not enable netrc forwarding in v1.
- Do not expose this service publicly without network-level access control.
- Do not reuse broad Vault tokens.
- Use minimal Vault policies scoped to the exact configured paths.

## Failure Semantics

- `200 OK`: valid signed request, at least one secret matched, all values resolved
- `204 No Content`: valid signed request, no rule matched
- `400 Bad Request`: invalid JSON, too large body, or structurally unusable body
- `401 Unauthorized`: missing or invalid Woodpecker signature, tampered body, wrong key, digest failure
- `405 Method Not Allowed`: wrong method
- `500 Internal Server Error`: config invariant violation, duplicate secret name, missing or non-string Vault field
- `503 Service Unavailable`: Vault/OpenBao unavailable, auth failure, token unusable, timeout, upstream transport error

Error bodies are non-sensitive and do not include secret values, Vault paths, tokens, AppRole identifiers, netrc data, request bodies, or raw Vault response bodies.

## Docker

```bash
docker build -t woodpecker-vault-secret-extension .

docker run --rm -p 8080:8080 \
  -e CONFIG_FILE=/config/config.yml \
  -v "$PWD/examples/config.yml:/config/config.yml:ro" \
  -v "$PWD/secrets:/run/secrets:ro" \
  woodpecker-vault-secret-extension
```

The image runs as non-root, uses the latest minimal distroless runtime image, exposes port `8080`, and does not bake secrets into the image. The build copies only Go source and module metadata, while local root `config.yml`, `.env`, and `secrets/` inputs are excluded from both Git and the Docker build context. Container bases and deployment images intentionally track their moving latest references; deployments must always pull before starting a container.

## Development

```bash
go test ./...
go vet ./...
govulncheck ./...
docker build -t woodpecker-vault-secret-extension .
```

## References

- [Woodpecker secret extension](https://woodpecker-ci.org/docs/usage/extensions/secret-extension)
- [Woodpecker extension security and allowed hosts](https://woodpecker-ci.org/docs/usage/extensions)
- [Woodpecker secrets and pull request warning](https://woodpecker-ci.org/docs/usage/secrets)
- [Vault AppRole API](https://developer.hashicorp.com/vault/api-docs/auth/approle)
- [Vault KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
- [OpenBao API compatibility](https://openbao.org/api-docs/libraries/)
