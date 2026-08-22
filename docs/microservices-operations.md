# BeeBox microservice operations

This runbook covers the ADR 0008 Gateway + Identity topology. `docs/production-operations.md` remains authoritative for Phase 1/2 signing, provider, MFA and security-state operations.

## Processes and ownership

- `beebox-gateway`: public HTTP edge. No product database or migrations.
- `beebox-identity`: internal Phase 1/2 authority. Owns PostgreSQL, migrations, providers, signing/encryption material and product HTTP behavior.
- PostgreSQL 17: correctness source for current product state.

Only Gateway is the normal public BeeBox endpoint. Direct public access to Identity must be blocked by infrastructure.

## Startup

1. Start PostgreSQL and verify it is healthy.
2. Apply migrations explicitly with the Identity artifact when required: `beebox-identity migrate`.
3. Configure a dedicated shared `BEEBOX_INTERNAL_CORRELATION_KEY` for the serving Gateway and Identity processes. The value is exactly 32 high-entropy random bytes encoded as unpadded base64url. It is not a JWT/TOTP/OAuth/application/database secret.
4. Start Identity with validated database/provider/signing/encryption/correlation configuration.
5. Wait for Identity `/health/ready`.
6. Start Gateway with the same correlation key and `BEEBOX_IDENTITY_UPSTREAM_URL` pointing to the private Identity endpoint.
7. Wait for Gateway `/health/ready`, then admit public traffic.

Serve mode never auto-migrates. `depends_on` or process start order is not a substitute for readiness.

Both serving processes fail startup when their required correlation key is absent or malformed. Operator/migration commands retain their documented behavior and do not turn the correlation key into product authority.

## Health and readiness

- Gateway `/health/live`: process liveness.
- Gateway `/health/ready`: verifies the required Identity upstream within the configured readiness timeout.
- Identity `/health/live`: process liveness.
- Identity `/health/ready`: existing database-aware readiness.

Readiness is traffic-admission evidence only; it never grants authentication or authorization.

## Configuration migration

Legacy single-process deployments commonly used `BEEBOX_HTTP_ADDR` for the public listener.

New topology:

- Gateway public address: `BEEBOX_GATEWAY_HTTP_ADDR` (default `:8080`).
- Gateway upstream: required `BEEBOX_IDENTITY_UPSTREAM_URL`.
- Shared serving correlation key: required `BEEBOX_INTERNAL_CORRELATION_KEY` on both Gateway and Identity.
- Identity internal address: `BEEBOX_IDENTITY_HTTP_ADDR` (default `127.0.0.1:8081`).
- Existing `BEEBOX_HTTP_ADDR` remains a compatibility alias for Identity; explicit `BEEBOX_IDENTITY_HTTP_ADDR` wins.
- Existing database/provider/signing/encryption configuration moves with Identity, not Gateway.

Gateway timeout/body variables are validated at startup:

- `BEEBOX_GATEWAY_CONNECT_TIMEOUT` (default `3s`)
- `BEEBOX_GATEWAY_RESPONSE_HEADER_TIMEOUT` (default `10s`)
- `BEEBOX_GATEWAY_REQUEST_TIMEOUT` (default `15s`, maximum `30s`)
- `BEEBOX_GATEWAY_READINESS_TIMEOUT` (default `2s`)
- `BEEBOX_GATEWAY_SHUTDOWN_TIMEOUT` (default `10s`)
- `BEEBOX_GATEWAY_IDLE_CONN_TIMEOUT` (default `60s`)
- `BEEBOX_GATEWAY_READ_HEADER_TIMEOUT` (default `5s`, maximum `30s`)
- `BEEBOX_GATEWAY_READ_TIMEOUT` (default `10s`, maximum `30s`)
- `BEEBOX_GATEWAY_WRITE_TIMEOUT` (default `30s`, maximum `65s`)
- `BEEBOX_GATEWAY_MAX_BODY_BYTES` (default 1 MiB, maximum 16 MiB)

The configured read timeout must be at least the read-header timeout. Gateway rejects configuration unless `WriteTimeout >= ReadTimeout + RequestTimeout + 5s`; this keeps the socket write deadline after the documented request timeout with an explicit response-serialization margin. Extreme/overflowing duration values fail validation rather than wrapping into unsafe deadlines.

Never give Gateway database credentials or Identity signing/encryption/provider secrets.

## Public request ID and trusted audit correlation

Gateway owns the public request ID. It ignores any inbound client `X-Request-ID`, strips any inbound `X-BeeBox-Internal-Correlation` and `X-BeeBox-Internal-Correlation-Signature`, then generates a fresh cryptographically random 16-byte / 32-lowercase-hex ID `G`.

Gateway forwards a complete internal diagnostic envelope containing public ID `G`, internal correlation ID `G`, and a canonical HMAC-SHA256 signature generated with the dedicated correlation key. Identity handles two separate values at its outer HTTP boundary:

- **public/wire request ID** — response `X-Request-ID` and canonical `error.request_id` only;
- **trusted audit correlation** — correlation passed to audit-sensitive application behavior.

When the HMAC verifies, both are `G`.

When the envelope is complete/canonical but the HMAC fails because Gateway and Identity use different valid keys, Identity keeps `G` only as the non-authoritative public diagnostic ID and generates a fresh audit correlation `I`. Therefore the public response remains exactly one `X-Request-ID: G`, canonical Identity errors contain `error.request_id: G`, and Identity audit evidence uses `I != G`. This intentional split preserves the support/error contract without treating an unverified value as audit provenance.

A direct Identity caller, or a malformed/incomplete envelope, cannot select audit correlation or a retained Gateway diagnostic ID using only a valid-looking `X-Request-ID`. Identity generates fresh local public and audit values. Public-ID shape, source network, Host and `X-Forwarded-*` metadata never establish trust.

The correlation key/signature must never appear in responses, logs or metrics. Public request IDs and trusted audit correlations are observability metadata only and never bypass application credentials, sessions, MFA, Origin, CSRF, tenant or authorization checks.

### Correlation-key rotation

Rotate the key as a coordinated Gateway/Identity rollout so both sides converge on the same new value. A temporary mixed-key window degrades cross-service trace/audit continuity only: the Gateway public support ID remains `G` while Identity audit correlation becomes fresh `I`. Operators should repair the key mismatch; they must not add a permissive fallback that trusts unsigned or merely well-shaped IDs as audit authority.

The HMAC authenticates only trusted audit-correlation provenance. It is not transport encryption/authentication for the complete internal HTTP connection; deployments crossing an untrusted network still need an appropriate transport-security design.

## Bounded request bodies

Current Phase 1/2 public mutation bodies are bounded API payloads, not streaming uploads.

Gateway performs a known `Content-Length` fast rejection when the declared size is over `BEEBOX_GATEWAY_MAX_BODY_BYTES`. For unknown/chunked lengths it pre-reads at most `MaxBodyBytes + 1` before dispatch:

- over limit: close/clean up the request body, do not invoke Identity, return canonical 413 `request_too_large`;
- at or below limit: replace the body with an equivalent bounded reader and proxy the exact bytes normally.

This intentionally bounds memory by the configured API-body limit and prevents an oversized unknown-length mutation from being partially dispatched. Cancellation during pre-read must exit promptly and release resources. A future genuine streaming/upload endpoint requires a separate design rather than disabling this correctness property.

## Gateway edge errors

For canonical `/v1` traffic, Gateway-generated failures use the same nested BeeBox error envelope consumed by the Go SDK:

- 413: `request_too_large`
- 502: `upstream_unavailable`
- 504: `upstream_timeout`

Messages are safe and do not expose internal hostnames/URLs, Go network errors, timeout implementation details or credentials. Each edge error includes the canonical public request ID, matching the single `X-Request-ID` response header.

Identity canonical error bodies also consume the public/wire request ID established at the outer Identity boundary. During a mixed-key correlation window they therefore still contain Gateway ID `G`, even though trusted audit correlation is the independent fresh `I`. Gateway does not parse or rewrite arbitrary business JSON to repair this contract.

Health endpoints keep their health/readiness response contract and do not pretend to be `/v1` business errors.

## Timeout and ambiguous-mutation semantics

A Gateway 504 means the Gateway did not receive the upstream response within its bounded request timeout. It does **not** mean the upstream transaction was rolled back or never committed.

For `POST`, `PUT`, `PATCH` or `DELETE`, once dispatch occurred the outcome may be unknown. Client guidance is:

1. do not blindly replay a non-idempotent mutation;
2. if the endpoint supports an idempotency key, retry only with the **same** key under that endpoint's contract;
3. otherwise fetch/reconcile authoritative state before deciding whether to retry.

Gateway never automatically retries a state-changing request. The actual-server regression test intentionally records an upstream mutation before delaying the response beyond Gateway timeout, proving that a canonical 504 can coexist with an already-applied authoritative mutation.

## Local Docker topology

`docker compose up --build` starts Gateway, Identity, PostgreSQL and Mailpit. The reference host publications are:

- Gateway HTTP: `localhost:8080`;
- Mailpit UI: `http://localhost:8025`;
- Mailpit SMTP for a **host-run Identity development process only**: `127.0.0.1:1025`, explicitly bound to host loopback.

Identity and PostgreSQL themselves remain Docker-private and have no host-published ports. Gateway and PostgreSQL share no network.

Migrate before relying on Identity readiness:

```sh
docker compose run --rm identity migrate
docker compose up --build
```

Operator commands such as signing-key generation and application bootstrap run against the Identity target.

The Compose file contains an explicit fixed **local-only development** correlation key shared between Gateway and Identity so the reference topology starts reproducibly. Do not copy that value to production; production must use independently generated high-entropy key material managed as a secret.

### Mailpit SMTP development path

The reference Compose mapping publishes Mailpit target SMTP port 1025 as host `127.0.0.1:1025`. It is intentionally **not** bound to `0.0.0.0`, so the reference topology does not expose plaintext development SMTP to the LAN/public interfaces.

A host-run Identity may use:

```sh
BEEBOX_SMTP_ADDR=127.0.0.1:1025
BEEBOX_SMTP_FROM=beebox@example.test
BEEBOX_SMTP_TLS_MODE=insecure_localhost
```

Containerized Identity must **not** use `insecure_localhost` against `mailpit:1025`; that host name is not loopback and the SMTP adapter's loopback-only security rule remains unchanged. For containerized Identity, use a TLS/STARTTLS-capable SMTP endpoint instead.

CI parses normalized `docker compose config --format json` and requires Mailpit SMTP target `1025`, published host port `1025`, and `host_ip=127.0.0.1`. CI also starts Mailpit and opens an actual TCP connection to `127.0.0.1:1025` before continuing, while retaining the existing Identity/PostgreSQL exposure and Gateway/PostgreSQL network-isolation gates.

Mailpit is a development aid only and is not a production dependency.

## Shutdown

Send SIGTERM/SIGINT and allow the configured bounded shutdown deadline. Gateway stops accepting public work and drains HTTP requests; Identity drains HTTP work and closes its PostgreSQL pool/resources. Do not hard-kill routine deployments before the bounded grace interval unless incident response requires it.

## Failure playbooks

### Gateway unavailable

Public requests fail even if Identity is healthy. Restore/replace Gateway or roll back Gateway. Do not publish Identity to the Internet as a shortcut.

### Gateway reports not ready

Check Identity `/health/ready`, private DNS/network reachability and `BEEBOX_IDENTITY_UPSTREAM_URL`. Check bounded timeout settings before raising them; do not remove timeouts or violate the write/read/request ordering invariant.

### Identity unavailable

Gateway readiness fails and requests map to safe upstream errors. Inspect Identity configuration/startup log, database readiness and provider/signing/encryption/correlation prerequisites. Gateway must not synthesize authentication results during the outage.

### Correlation mismatch

If Gateway and Identity are configured with different correlation keys, product authorization remains unaffected. For a complete canonical Gateway envelope, the client-facing Gateway diagnostic ID `G` remains stable in the public response while Identity rejects `G` as trusted audit provenance and mints a fresh `I`. Expect trace/audit continuity to split during this window. Restore matching secret configuration; do not log key/signature values and do not weaken verification while diagnosing.

### PostgreSQL unavailable

Identity readiness fails and authoritative mutations must fail closed. Restore PostgreSQL connectivity; do not introduce an edge/cache fallback that bypasses persisted authority.

### Provider outage

Use the existing Phase 1/2 provider failure semantics. Gateway does not retry ambiguous mutations or provider operations.

### Gateway returns 504 for a mutation

Treat the operation as potentially committed. Reuse the same idempotency key only when that exact endpoint supports it; otherwise query authoritative state before deciding whether another mutation is needed. Never interpret 504 as proof that nothing happened.

## Observability and correlation

Gateway access logs carry method/path/status/latency and its generated bounded public request ID, but omit query strings and credential-bearing headers. Identity audit uses that same value only when authenticated internal provenance verifies. During mixed-key provenance, public Gateway diagnostics use `G` and Identity trusted audit uses independent `I` until configuration is corrected.

Never log Authorization, Cookie/Set-Cookie, passwords, OTP/recovery codes, OAuth code/state/provider tokens, signing/encryption/correlation keys, correlation signatures or database URLs containing credentials.

## Rollout

No schema change is required by the ADR 0008 extraction. Roll out Identity first, verify readiness and current migrations, then Gateway. Canary/traffic-shift strategy is an infrastructure concern but must preserve Gateway as the public edge.

Correlation-key rotation should be coordinated with the two service revisions. If a brief mixed-key window occurs, public diagnostic continuity remains stable while trusted audit continuity splits; no product-security fallback is permitted. Restore matching key configuration promptly.

## Rollback

Because the refactor keeps the Phase 1/2 schema compatible and does not add a destructive migration, a deployment can stop routing to Gateway/Identity and restore the previous compatible `cmd/beebox` artifact. Do not run destructive down migrations. If future releases change schema compatibility, use their reviewed roll-forward/expand-contract plan instead.

## Local debugging checklist

- `docker compose config --format json` validates the topology.
- confirm Mailpit SMTP normalized mapping is target `1025`, published `1025`, `host_ip=127.0.0.1`.
- after Mailpit starts, confirm a TCP connection to `127.0.0.1:1025` succeeds from the host.
- build both Docker targets independently.
- confirm Gateway has no database environment.
- confirm Identity/PostgreSQL have no host-published ports in the reference topology.
- confirm Gateway and PostgreSQL share no Compose network.
- inspect `/health/live` and `/health/ready` separately.
- send a client-selected `X-Request-ID` and confirm Gateway replaces it.
- send client internal-correlation/signature headers and confirm Gateway strips them.
- with matching correlation keys, confirm public request ID and Identity audit correlation are equal.
- with distinct valid Gateway/Identity keys, confirm public header and canonical error body both retain Gateway `G` while Identity audit correlation becomes `I != G`.
- confirm internal correlation headers/signatures never reach the client.
- reproduce public behavior through Gateway, not by treating direct Identity access as the supported client path.
