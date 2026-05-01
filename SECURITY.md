# Security Policy

Report vulnerabilities privately by opening a private advisory in the hosting platform or by contacting the repository maintainers directly. Do not include exploit details in a public issue.

This service is intentionally narrow:

- It verifies every Woodpecker request signature before decoding trusted repository or pipeline data.
- It reads only statically configured Vault/OpenBao KV paths.
- It never lists, writes, or proxies arbitrary Vault paths.
- It returns only configured string fields.

Operational requirements:

- Keep the service on a private network path reachable only from Woodpecker.
- Do not disable signature verification; production builds do not provide a disable flag.
- Use minimal Vault policies scoped to exact `kv/data/...` paths.
- Do not enable pull request or fork secrets for public repositories unless the risk is fully understood.
- Do not enable netrc forwarding in v1.
- Rotate Vault tokens, AppRole Secret IDs, and the Woodpecker extension signing key after suspected exposure.

Logs and errors are designed to avoid secret values, Vault tokens, AppRole credentials, netrc credentials, request bodies, and raw Vault response bodies. Treat all deployment manifests and local config files as sensitive if they contain file paths or operational topology.
