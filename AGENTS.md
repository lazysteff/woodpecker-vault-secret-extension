# Repository Agent Guidelines

## Scope and repository identity

These guidelines apply to the entire
`github.com/lazysteff/woodpecker-vault-secret-extension` repository.

- Confirm the working directory and repository identity before changing files.
- Keep extension work in this repository. Do not modify Sendico or one of its
  worktrees unless the user explicitly requests Sendico integration.
- Preserve unrelated and pre-existing worktree changes. Never discard or
  rewrite user changes merely to obtain a clean tree.
- Keep changes within the requested feature and contract boundaries. Newly
  discovered work that is not required for the requested outcome should be
  reported as follow-up work rather than silently expanding scope.

## Dependency policy

Tracking the latest available dependency is an intentional owner policy for
this repository.

- Use the latest available release of every dependency, including Go modules,
  Go toolchain versions, CI actions and tools, builder and runtime container
  images, and deployment images.
- For Go dependencies, update with `go get <module>@latest` or the equivalent
  and commit the concrete versions and checksums selected by the Go module
  toolchain.
- Where an ecosystem supports a moving `latest` reference, using that reference
  is intentional. Do not replace moving image or tool references with immutable
  digests, commit SHAs, or deliberately older versions unless the user
  explicitly changes this policy.
- Do not report mutable dependency references as a defect. Review dependency
  changes for compatibility, security, and successful validation instead.
- Keep `go.mod` and `go.sum` tidy after dependency changes and do not add an
  indirect dependency manually when the Go toolchain can manage it.

## Architecture and data flow

Preserve the existing package responsibilities and dependency direction:

- `cmd/woodpecker-vault-secret-extension` composes configuration, logging,
  authentication, lifecycle, and the HTTP server.
- `internal/config` owns YAML loading, environment expansion, defaults, secret
  file loading, and configuration validation.
- `internal/signature` owns Woodpecker HTTP signature verification.
- `internal/woodpecker` owns transport payload types, decoding, repository
  identity normalization, and pipeline metadata consistency.
- `internal/rules` is the pure authorization and secret-reference selection
  layer. It must not perform network or filesystem I/O.
- `internal/vault` owns Vault/OpenBao HTTP transport, KV v2 path construction,
  authentication, token state, renewal, and readiness checks.
- `internal/httpserver` owns routing and request orchestration through the
  package boundaries above.
- `internal/logging` owns logger construction, not domain behavior.

The trusted request flow is:

1. Bound the request body.
2. Verify the digest and HTTP signature.
3. Decode and normalize Woodpecker metadata.
4. Evaluate rules and collect secret references.
5. Read only the statically configured Vault/OpenBao KV v2 paths.
6. Return the complete Woodpecker secret response.

Do not introduce a second or shortcut data path around these stages. In
particular, never decode request metadata as trusted, evaluate authorization, or
contact Vault before signature verification succeeds. Preserve the
all-or-nothing response: a missing field, non-string value, timeout, auth
failure, or Vault failure must not produce a partial secret response.

## Security and integrity invariants

- Keep authentication and authorization fail-closed.
- Treat `pull_request` and every `pull_request_*` event as a pull-request event.
- Pull requests are denied unless explicitly allowed. Forked and unknown-fork
  pull requests require both pull-request and fork permission.
- Require every populated repository identity representation to agree before
  rules can match.
- Require a non-empty pipeline event without surrounding whitespace, and reject
  non-canonical configured event entries before serving requests.
- Preserve branch, ref, tag, and event consistency checks before Vault access.
- Permit a duplicate secret replacement only when the later rule producing the
  replacement has `allow_override: true`.
- Construct Vault paths from static configuration and keep configured path
  characters as literal URL path data. Add query parameters only through
  explicitly structured internal operations.
- Reject Vault redirects so tokens, namespace headers, Role IDs, and Secret IDs
  cannot be forwarded to another location.
- Serialize AppRole login, reauthentication, renewal, and renewal fallback so
  concurrent operations cannot overwrite a newer token or create duplicate
  logins for the same rejected token.
- Distinguish an unusable token from a valid token receiving a policy denial;
  do not consume AppRole credentials merely because an authorized Vault token
  receives `403` for a path.
- Require static and newly issued AppRole tokens to report unlimited uses and
  remain usable across admission checks to `auth/token/lookup-self` before
  installation. After Vault accepts an AppRole login, any malformed response
  or token-admission failure must block further logins until restart. Treat a
  transport failure after the complete login request was written as potentially
  accepted and block further logins as well, while keeping pre-write failures
  retryable, so readiness probes and requests cannot churn credentials.
- Keep inline and file-backed token authentication static. Reject
  `token_renewal` with token authentication and document that token rotation
  requires an extension restart.
- Bound request bodies, upstream response bodies, Vault calls, and aggregate
  secret resolution with contexts and deadlines.
- Never log or return secret values, request bodies, Vault tokens, Role IDs,
  Secret IDs, signing keys, credential file contents, or raw Vault response
  bodies. Avoid logging sensitive paths and configuration topology unless
  explicitly required and reviewed.
- Do not mount unused platform credentials into deployment workloads. The
  Kubernetes example must disable automatic service-account token mounting.

Do not change HTTP routes, request or response schemas, YAML fields, Vault path
semantics, authentication methods, or secret response formats without explicit
authorization and corresponding compatibility documentation.

## Go implementation quality

### Reuse existing definitions

- Search the repository before adding a struct, interface, sentinel error, or
  helper that represents an existing concept.
- Reuse or extend the canonical definition when semantics match. Avoid parallel
  request models, token state, path builders, or rule representations.
- Keep interfaces at actual package boundaries. Do not add speculative
  abstractions or conversion layers.
- Avoid naming stutter. Package context should supply meaning that does not need
  to be repeated in types, fields, parameters, or filenames.

### Keep packages and files cohesive

- Review touched files for mixed responsibilities, duplicated logic, and
  excessive size.
- Split code along behavioral boundaries, not arbitrary line counts. A larger
  table-driven test file may be appropriate; a smaller production file with
  unrelated state machines is not.
- Keep one primary responsibility per production file. Small private helpers
  may remain beside the behavior they support when that improves readability.
- Keep public APIs and mutable shared state minimal. Document synchronization
  invariants around concurrent token and lifecycle state.
- Remove dead code, unnecessary indirection, and abstractions created for only
  hypothetical future behavior.

### Errors, logging, and failure semantics

- Preserve sentinel causes with `%w` when callers use `errors.Is` for
  classification.
- Translate upstream and internal failures into the repository's small,
  non-sensitive HTTP error vocabulary. Do not expose raw upstream errors.
- Use structured logging at meaningful operational boundaries and include
  useful non-sensitive identifiers.
- Use `Debug` for detailed diagnostic execution, `Info` for completed requests
  and expected lifecycle events, `Warn` for recoverable upstream or lifecycle
  failures, and `Error` for failures that terminate or prevent service startup.
- Avoid logging the same error at multiple layers. Log it where enough context
  exists to make it actionable.

### Tests and documentation

- Add focused regression tests for every changed behavior, including negative
  and fail-closed paths.
- For authentication or token-state changes, cover concurrency and run the
  relevant tests with the race detector.
- Prefer deterministic coordination with channels over sleeps in concurrency
  tests.
- Keep tests at the narrowest useful layer and add an HTTP-boundary test when
  ordering or contract behavior is security-relevant.
- Update `README.md`, `SECURITY.md`, examples, and deployment documentation when
  rule semantics, security behavior, configuration, or operations change.

## Required validation

After code or dependency changes, run from the repository root:

```bash
go mod verify
go mod tidy -diff
go test -race -count=1 ./...
go vet ./...
govulncheck ./...
docker build -t woodpecker-vault-secret-extension:verify .
```

All applicable commands must succeed before reporting the task complete. Do not
silently skip, suppress, or weaken a check. If an environmental dependency such
as the Docker daemon is unavailable, report the exact command and blocker and
do not claim that gate passed.

Before final handoff, review the complete task diff for correctness,
architecture, data-flow consistency, security, integrity, maintainability, and
unintended contract changes. Fix all in-scope findings introduced by the task
and report the validation commands and outcomes.

## Release and external changes

- Do not merge, push, tag, publish an image, deploy, modify Vault, or change
  Woodpecker configuration unless the user explicitly requests that external
  action.
- When a release is requested, tag only the exact verified canonical commit and
  report any gate that could not be completed.
- Never print, log, or commit API tokens, Git credentials, Vault credentials,
  signing keys, or secret values while performing repository or release work.
