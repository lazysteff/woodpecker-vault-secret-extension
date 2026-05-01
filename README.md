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

Config is YAML. `${VAR}` expressions are expanded after YAML parsing. Missing environment variables fail startup. Expansion is not applied to values returned from Vault/OpenBao.

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
    repo: "sendico/sendico"
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

Repository identity is resolved in this order:

1. `repo.full_name`
2. `repo.slug`
3. `repo.namespace + "/" + repo.name`

Repository matching is lower-case. Events are exact matches. Branches match `pipeline.branch` for branch-based events. Refs match `pipeline.ref` using glob-style `*` and `?`. Tags are shorthand for `refs/tags/...`.

Pull request secrets are denied by default. Forked requests are denied by default. If fork status cannot be determined on a pull request, the request is treated as forked.

Multiple rules may match. Rules are evaluated in YAML order. Duplicate Woodpecker secret names fail the request with `500` unless `allow_override: true` is explicitly set on the overriding rule.

## Vault / OpenBao

Supported auth methods:

```yaml
vault:
  auth:
    method: "token"
    token: "${VAULT_TOKEN}"
```

```yaml
vault:
  auth:
    method: "token"
    token_file: "/run/secrets/vault_token"
```

```yaml
vault:
  auth:
    method: "approle"
    mount_path: "approle"
    role_id_file: "/run/secrets/vault_role_id"
    secret_id_file: "/run/secrets/vault_secret_id"
```

KV paths in rules are logical paths under the configured mount. Do not include `data/`; the service constructs the KV v2 API path internally.

For this rule path:

```yaml
path: "cicd/woodpecker/deploy"
```

Use a minimal KV v2 policy:

```hcl
path "kv/data/cicd/woodpecker/deploy" {
  capabilities = ["read"]
}
```

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
  token_ttl="1h" \
  token_max_ttl="4h"

vault read auth/approle/role/woodpecker-secret-extension/role-id
vault write -f auth/approle/role/woodpecker-secret-extension/secret-id
```

OpenBao is supported through its Vault-compatible HTTP API behavior for auth and KV v2.

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

The image runs as non-root, uses a minimal distroless runtime image, exposes port `8080`, and does not bake secrets into the image.

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
