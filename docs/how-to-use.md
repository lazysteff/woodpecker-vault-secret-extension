# How to use the Woodpecker Vault secret extension

This guide deploys the extension with Docker Compose, AppRole authentication,
and a least-privilege Vault or OpenBao KV v2 policy. The same configuration
model applies to Kubernetes; deployment-specific notes are included below.

## 1. Prerequisites

You need:

- Woodpecker 3.x with administrator access;
- Vault or OpenBao with a KV v2 mount;
- Docker Engine with Docker Compose; and
- network connectivity from Woodpecker to the extension and from the extension
  to Vault or OpenBao.

Use TLS for the Vault/OpenBao endpoint. Keep the extension on a private network;
Woodpecker is its only intended caller.

## 2. Choose the exact repository identity

Rules match the canonical, case-insensitive `owner/name` identity in the signed
Woodpecker request. Ask Woodpecker for the repository record and use its
`full_name` value rather than guessing it:

```bash
export WOODPECKER_SERVER="https://woodpecker.example.com"
export WOODPECKER_TOKEN="replace-with-a-Woodpecker-user-token"
export REPOSITORY="example/repo"

curl -fsS \
  -H "Authorization: Bearer ${WOODPECKER_TOKEN}" \
  "${WOODPECKER_SERVER}/api/repos/lookup/${REPOSITORY}" \
  | jq -r '.full_name'
```

The command must print the identity you place in each rule's `repo` field.
Unset the user token when the lookup is complete:

```bash
unset WOODPECKER_TOKEN
```

## 3. Create least-privilege Vault data and policy

The example exposes three independent paths: a main-branch deployment, a
generic `v*` release, and an `infra-v*` release. Write only the fields the
extension will return. The values below are placeholders that show the data
shape; supply real values through your approved secret-entry process rather
than placing them in shell history:

```bash
vault kv put kv/cicd/woodpecker/deploy deploy_token="replace-me"
vault kv put kv/cicd/woodpecker/release release_token="replace-me"
vault kv put kv/cicd/woodpecker/infra-release infra_token="replace-me"
```

Create `woodpecker-secret-extension.hcl` on a trusted administration host:

```hcl
path "kv/data/cicd/woodpecker/deploy" {
  capabilities = ["read"]
}

path "kv/data/cicd/woodpecker/release" {
  capabilities = ["read"]
}

path "kv/data/cicd/woodpecker/infra-release" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

The policy uses KV v2 API paths (`kv/data/...`), while extension rules use
logical paths without `data/` (`cicd/...`). Install the policy and AppRole:

```bash
vault auth enable approle
vault policy write woodpecker-secret-extension woodpecker-secret-extension.hcl
vault write auth/approle/role/woodpecker-secret-extension \
  token_policies="woodpecker-secret-extension" \
  token_num_uses=0 \
  token_ttl="1h" \
  token_max_ttl="4h"
```

If AppRole is already enabled, `vault auth enable approle` can report that the
path is in use; do not replace an existing mount just for this extension.

## 4. Prepare the Compose deployment

From a clone of this repository:

```bash
cp deploy/compose/config.example.yml deploy/compose/config.yml
install -d -m 0700 deploy/compose/secrets
curl -fsS \
  "${WOODPECKER_SERVER}/api/signature/public-key" \
  -o deploy/compose/secrets/woodpecker_extension_public_key
vault read -field=role_id \
  auth/approle/role/woodpecker-secret-extension/role-id \
  > deploy/compose/secrets/vault_role_id
vault write -f -field=secret_id \
  auth/approle/role/woodpecker-secret-extension/secret-id \
  > deploy/compose/secrets/vault_secret_id
chmod 0444 deploy/compose/secrets/*
```

The credential directory and active `config.yml` are ignored by Git. Never
commit the Role ID, Secret ID, Vault token, or signing key material. The
directory remains mode `0700`; its files are mode `0444` so the image's
unprivileged user can read Docker Compose secret mounts without making the
host directory accessible to other users.

Edit `deploy/compose/config.yml`:

1. Set `vault.address`, `vault.namespace` when applicable, and `vault.kv.mount`.
2. Replace every `example/repo` with the exact Woodpecker `full_name` from step
   2.
3. Keep only the paths, fields, events, branches, refs, and returned secret
   names required by your pipelines.
4. Leave `allow_pull_requests` and `allow_forks` false unless both access modes
   are deliberately required and reviewed.

Validate and start it:

```bash
docker compose -f deploy/compose/compose.yml config
docker compose -f deploy/compose/compose.yml build --pull
docker compose -f deploy/compose/compose.yml up -d --no-build
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Both probes must return `ok`. `/healthz` proves that the process is alive;
`/readyz` also proves Vault/OpenBao health and token usability.

The Compose project creates a stable `woodpecker-extensions` network. If the
Woodpecker server runs in Docker, attach its service to that same network. For
example, add this to the Woodpecker Compose project:

```yaml
services:
  woodpecker-server:
    networks:
      - woodpecker-extensions

networks:
  woodpecker-extensions:
    external: true
```

Start the extension first so the network exists, then recreate the Woodpecker
server service. If Woodpecker runs directly on the same host instead, use the
loopback endpoint shown below. Do not expose the extension on a public address.

## 5. Connect Woodpecker

Add these settings to the Woodpecker server. The endpoint must be reachable
from the Woodpecker server container or process; `127.0.0.1` is usually wrong
when the services run in different containers.

```yaml
# Woodpecker and the extension share the Docker network:
WOODPECKER_SECRET_EXTENSION_ENDPOINT: "http://woodpecker-vault-secret-extension:8080/secrets"

# Or, for a Woodpecker process running directly on the extension host:
# WOODPECKER_SECRET_EXTENSION_ENDPOINT: "http://127.0.0.1:8080/secrets"

WOODPECKER_SECRET_EXTENSION_NETRC: "false"
WOODPECKER_EXTENSIONS_ALLOWED_HOSTS: "private"
```

Restart Woodpecker after applying the settings. Keep existing Woodpecker local
secrets during the initial rollout so you have a recoverable fallback.

## 6. Request a secret in a pipeline

The name under `from_secret` must equal the configured rule secret name:

```yaml
steps:
  - name: deploy
    image: alpine
    environment:
      DEPLOY_TOKEN:
        from_secret: DEPLOY_TOKEN
    commands:
      - test -n "$DEPLOY_TOKEN"
      - echo "The deployment credential was supplied"
```

Do not print the value. Woodpecker signs the complete extension request; the
extension verifies that signature before decoding trusted metadata or reading
Vault.

## 7. Prove the policy before removing fallback secrets

Run all applicable cases and inspect the extension's structured logs:

- a push to `main` receives only the main-push secrets;
- a generic `v*` tag receives only generic release secrets;
- an `infra-v*` tag receives only infrastructure-release secrets;
- a pull request, non-main push, unknown repository, and unsupported tag do not
  receive privileged secrets;
- an invalid or tampered signature does not cause a Vault read; and
- a Vault outage causes the request to fail closed without returning a partial
  response.

Logs may contain repository, event, branch, ref, status, and safe error codes.
They must not contain secret values, Vault credentials, signing keys, request
bodies, or raw Vault responses.

Only after the successful cases work should you remove duplicate local
Woodpecker secrets. Then repeat one `main` push, one generic `v*` tag, and one
`infra-v*` tag to prove Vault-only operation.

## Kubernetes

Build the image, publish it to a registry your cluster can access, and replace
`replace-with-your-registry` in `deploy/kubernetes/deployment.yml`. The project
does not publish a public image:

```bash
docker build --pull \
  -t registry.example.com/woodpecker-vault-secret-extension:latest .
docker push registry.example.com/woodpecker-vault-secret-extension:latest
```

Edit the ConfigMap in the deployment manifest, then create the credential
Secret from local files instead of writing credentials into a manifest:

```bash
kubectl create secret generic woodpecker-vault-secret-extension-secrets \
  --from-file=woodpecker_extension_public_key \
  --from-file=vault_role_id \
  --from-file=vault_secret_id
kubectl apply -f deploy/kubernetes/deployment.yml
kubectl rollout status deployment/woodpecker-vault-secret-extension
```

Run `kubectl create secret` from the directory containing those three files.
Use your cluster's secret-management mechanism in production. The included
Deployment disables service-account token mounting, runs as non-root with a
read-only root filesystem, and pulls the moving `latest` image by owner policy.

## Upgrade and rollback

Upgrade by pulling the current image and recreating the extension:

```bash
git pull --ff-only
docker compose -f deploy/compose/compose.yml build --pull
docker compose -f deploy/compose/compose.yml up -d --no-build
```

Verify `/healthz`, `/readyz`, and a successful signed extension call after every
upgrade. To roll back Woodpecker integration, restore any required local
secrets, remove or disable `WOODPECKER_SECRET_EXTENSION_ENDPOINT`, and restart
Woodpecker. Do not remove the extension first: Woodpecker could otherwise make
secret decisions while the intended fallback state is incomplete.

For configuration details and exact failure semantics, see the project
[README](../README.md) and [security policy](../SECURITY.md).
