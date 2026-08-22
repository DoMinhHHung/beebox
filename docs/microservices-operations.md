# BeeBox microservice operations

This runbook covers the ADR 0008 Gateway + Identity topology. `docs/production-operations.md` remains authoritative for Phase 1/2 signing, provider, MFA and security-state operations.

## Processes and ownership

- `beebox-gateway`: public HTTP edge. No product database or migrations.
- `beebox-identity`: internal Phase 1/2 authority. Owns PostgreSQL, migrations, providers, signing/encryption material and product HTTP behavior.
- PostgreSQL 17: correctness source for current product state.

Only Gateway is the normal public endpoint. Direct public access to Identity must be blocked by infrastructure.

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

## Request ID and trusted correlation

Gateway owns the public request ID. It ignores any inbound client `X-Request-ID`, strips any inbound `X-BeeBox-Internal-Correlation` and `X-BeeBox-Internal-Correlation-Signature`, then generates a fresh cryptographically random 16-byte / 32-lowercase-hex ID.

Gateway signs that generated ID with HMAC-SHA256 using the dedicated correlation key and forwards the generated internal ID/signature to Identity. Identity accepts it only after constant-time verification. Missing, malformed or invalid proof causes Identity to mint a fresh local correlation; a direct caller cannot choose audit correlation by supplying a valid-looking public ID.

Proxied public responses are normalized to exactly one `X-Request-ID`. Where a canonical BeeBox error body contains `error.request_id`, it must equal the public response header value.

The correlation key/signature must never appear in responses, logs or metrics. Correlation provenance is observability metadata only and never bypasses application credentials, sessions, MFA, Origin, CSRF, tenant or authorization checks.

### Correlation-key rotation

Rotate the key as a coordinated Gateway/Identity rollout so both sides converge on the same new value. A temporary mismatch must degrade only trace continuity: Identity rejects the invalid proof and creates a fresh correlation. Do not add a permissive fallback that trusts an unsigned ID. Do not reuse the old/new key as another security primitive.

The HMAC authenticates only correlation metadata. It is not transport encryption/authentication for the complete internal HTTP connection; deployments crossing an untrusted network still need an appropriate transport-security design.

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

Messages are safe and do not expose internal hostnames/URLs, Go network errors, timeout implementation details or credentials. Each edge error includes the canonical request ID, matching the single `X-Request-ID` response header.

Health endpoints keep their health/readiness response contract and do not pretend to be `/v1` business errors.

## Timeout and ambiguous-mutation semantics

A Gateway 504 means the Gateway did not receive the upstream response within its bounded request timeout. It does **not** mean the upstream transaction was rolled back or never committed.

For `POST`, `PUT`, `PATCH` or `DELETE`, once dispatch occurred the outcome may be unknown. Client guidance is:

1. do not blindly replay a non-idempotent mutation;
2. if the endpoint supports an idempotency key, retry only with the **same** key under that endpoint's contract;
3. otherwise fetch/reconcile authoritative state before deciding whether to retry.

Gateway never automatically retries a state-changing request. The actual-server regression test intentionally records an upstream mutation before delaying the response beyond Gateway timeout, proving that a canonical 504 can coexist with an already-applied authoritative mutation.

## Local Docker topology

`docker compose up --build` starts Gateway, Identity, PostgreSQL and Mailpit. Only Gateway HTTP and Mailpit UI are published by the reference Compose file; Identity and PostgreSQL use Docker-private networks. Gateway and PostgreSQL share no network.

Migrate before relying on Identity readiness:

```sh
docker compose run --rm identity migrate
docker compose up --build
```

Operator commands such as signing-key generation and application bootstrap run against the Identity target.

The Compose file contains an explicit fixed **local-only development** correlation key shared between Gateway and Identity so the reference topology starts reproducibly. Do not copy that value to production; production must use independently generated high-entropy key material managed as a secret.

Mailpit SMTP is intentionally **not** wired into containerized Identity with plaintext `insecure_localhost`: that mode is restricted to loopback by the SMTP adapter. For email-flow development either run Identity on the host against `127.0.0.1:1025` using `BEEBOX_SMTP_TLS_MODE=insecure_localhost`, or configure a TLS/STARTTLS-capable SMTP endpoint for the container. Do not weaken the SMTP trust rule for Compose convenience.

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

If Gateway and Identity are configured with different correlation keys, product authorization must remain unaffected but Identity will reject the supplied correlation proof and mint its own request correlation. Restore matching secret configuration; do not log key/signature values while diagnosing.

### PostgreSQL unavailable

Identity readiness fails and authoritative mutations must fail closed. Restore PostgreSQL connectivity; do not introduce an edge/cache fallback that bypasses persisted authority.

### Provider outage

Use the existing Phase 1/2 provider failure semantics. Gateway does not retry ambiguous mutations or provider operations.

### Gateway returns 504 for a mutation

Treat the operation as potentially committed. Reuse the same idempotency key only when that exact endpoint supports it; otherwise query authoritative state before deciding whether another mutation is needed. Never interpret 504 as proof that nothing happened.

## Observability and correlation

Gateway access logs carry method/path/status/latency and its generated bounded request ID, but omit query strings and credential-bearing headers. Identity uses the same correlation only when authenticated internal provenance verifies.

Never log Authorization, Cookie/Set-Cookie, passwords, OTP/recovery codes, OAuth code/state/provider tokens, signing/encryption/correlation keys, correlation signatures or database URLs containing credentials.

## Rollout

No schema change is required by the ADR 0008 extraction. Roll out Identity first, verify readiness and current migrations, then Gateway. Canary/traffic-shift strategy is an infrastructure concern but must preserve Gateway as the public edge.

Correlation-key rotation should be coordinated with the two service revisions. If a brief mixed-key window occurs, trace continuity may split but Identity must fail closed to a new local correlation; no product-security fallback is permitted.

## Rollback

Because the refactor keeps the Phase 1/2 schema compatible and does not add a destructive migration, a deployment can stop routing to Gateway/Identity and restore the previous compatible `cmd/beebox` artifact. Do not run destructive down migrations. If future releases change schema compatibility, use their reviewed roll-forward/expand-contract plan instead.

## Local debugging checklist

- `docker compose config` validates the topology.
- build both Docker targets independently.
- confirm Gateway has no database environment.
- confirm Identity/PostgreSQL have no host-published ports in the reference topology.
- confirm Gateway and PostgreSQL share no Compose network.
- inspect `/health/live` and `/health/ready` separately.
- send a client-selected `X-Request-ID` and confirm Gateway replaces it.
- send client internal-correlation/signature headers and confirm Gateway strips them.
- trace one generated request ID from Gateway through verified Identity correlation without adding key/signature/query material to logs.
- confirm representative proxied responses contain exactly one `X-Request-ID`.
- reproduce public behavior through Gateway, not by treating direct Identity access as the supported client path.
