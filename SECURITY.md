# Security Policy

Report vulnerabilities privately by opening a private advisory in the hosting platform or by contacting the repository maintainers directly. Do not include exploit details in a public issue.

This service is intentionally narrow:

- It verifies every Woodpecker request signature before decoding trusted repository or pipeline data.
- It reads only statically configured Vault/OpenBao KV paths.
- It never lists, writes, or proxies arbitrary Vault paths.
- Configured Vault paths must be canonical, their characters remain literal URL path data, and only internally defined operations can add query parameters.
- AppRole refresh operations are serialized, newly issued tokens must pass self-lookup before installation, and any failure after Vault accepts a login blocks further logins until restart. A transport failure after the complete login request is written is treated as potentially accepted and blocks further logins, while failures before request transmission remain retryable. Blocked clients report not ready without making further Vault calls, and renewal maintenance identifies the state with the non-sensitive `vault_auth_blocked` error code. Replacement leases reschedule renewal, failed maintenance is retried within the remaining lease window, shutdown waits for the renewal worker, and policy-denied reads do not churn AppRole credentials while the current token remains usable.
- Vault responses are size-bounded and rejected unless they contain exactly one complete JSON document. Authentication responses also require a non-empty token and a positive lease duration representable by the client.
- It returns only configured string fields.

Operational requirements:

- Keep the service on a private network path reachable only from Woodpecker.
- Do not mount Kubernetes service-account credentials into this workload; the extension does not call the Kubernetes API. The example Deployment disables automatic token mounting at the Pod level.
- Do not disable signature verification; production builds do not provide a disable flag.
- Use minimal Vault policies scoped to exact `kv/data/...` paths. Explicitly grant `read` on `auth/token/lookup-self` and, when renewal is enabled, `update` on `auth/token/renew-self`; do not assume the mutable `default` policy provides them.
- Configure static tokens and AppRole-issued tokens with unlimited uses (`num_uses: 0` / `token_num_uses=0`). The extension verifies this through `lookup-self` and rejects finite-use tokens so readiness probes cannot deplete them.
- Do not enable pull request or fork secrets for public repositories unless the risk is fully understood. The `pull_request` event and all `pull_request_*` variants are subject to the same restrictions, and forked or unknown-fork requests require both pull-request and fork access to be enabled.
- Treat missing or contradictory pipeline metadata as unauthorized. Events must be non-empty and free of surrounding whitespace. Populated repository aliases must agree. Tag refs require a non-empty name after `refs/tags/`, pushes require a non-empty branch and its matching `refs/heads/<branch>` ref, and pull-request events require a non-empty, non-tag ref. Configured ref and tag patterns must be non-empty and free of surrounding whitespace. Conflicting or invalid fork indicators cannot establish non-fork status. Other event types remain governed by their configured event and ref rules.
- Do not rely on redirects between Vault/OpenBao endpoints. The client rejects redirects so authentication material cannot be forwarded to another location.
- Vault health checks run in the root namespace; authentication, token management, and KV operations remain restricted to the configured tenant namespace.
- Do not enable netrc forwarding in v1.
- Rotate Vault tokens, AppRole Secret IDs, and the Woodpecker extension signing key after suspected exposure.
- Restart the extension after replacing a static inline or file-backed Vault token; `token_renewal` is intentionally rejected for token authentication.

Logs and errors are designed to avoid secret values, Vault tokens, AppRole credentials, netrc credentials, request bodies, and raw Vault response bodies. Treat all deployment manifests and local config files as sensitive if they contain file paths or operational topology.
