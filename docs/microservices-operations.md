# BeeBox microservice operations

This runbook covers the ADR 0008 Gateway + Identity topology. `docs/production-operations.md` remains authoritative for Phase 1/2 signing, provider, MFA and security-state operations.

## Processes and ownership

- `beebox-gateway`: public HTTP edge. No product database or migrations.
- `beebox-identity`: internal Phase 1/2 authority. Owns PostgreSQL, migrations, providers, signing/encryption material and product HTTP behavior.
- PostgreSQL 17: correctness source for current product state.

Only Gateway is the normal public endpoint. Direct public access to Identity must be blocked by infrastructure.

## Startup

1. Start PostgreSQL and verify it is healthy.
2. Apply migrations explicitly with the Identity artifact when required:
   `beebox-identity migrate`.
3. Start Identity with validated database/provider/signing/encryption configuration.
4. Wait for Identity `/health/ready`.
5. Start Gateway with `BEEBOX_IDENTITY_UPSTREAM_URL` pointing to the private Identity endpoint.
6. Wait for Gateway `/health/ready`, then admit public traffic.

Serve mode never auto-migrates. `depends_on` or process start order is not a substitute for readiness.

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
- Identity internal address: `BEEBOX_IDENTITY_HTTP_ADDR` (default `127.0.0.1:8081`).
- Existing `BEEBOX_HTTP_ADDR` remains a compatibility alias for Identity; explicit `BEEBOX_IDENTITY_HTTP_ADDR` wins.
- Existing database/provider/signing/encryption configuration moves with Identity, not Gateway.

Gateway timeout/body variables are documented in `internal/gateway/config.go` and README. Invalid required values fail startup.

Never give Gateway database credentials or Identity signing/encryption/provider secrets.

## Local Docker topology

`docker compose up --build` starts Gateway, Identity, PostgreSQL and Mailpit. Only Gateway HTTP and Mailpit UI are published by the reference Compose file; Identity and PostgreSQL use the Docker network only.

Migrate before relying on Identity readiness:

```sh
docker compose run --rm identity migrate
docker compose up --build
```

Operator commands such as signing-key generation and application bootstrap run against the Identity target.

Mailpit SMTP is intentionally **not** wired into containerized Identity with plaintext `insecure_localhost`: that mode is restricted to loopback by the SMTP adapter. For email-flow development either run Identity on the host against `127.0.0.1:1025` using `BEEBOX_SMTP_TLS_MODE=insecure_localhost`, or configure a TLS/STARTTLS-capable SMTP endpoint for the container. Do not weaken the SMTP trust rule for Compose convenience.

## Shutdown

Send SIGTERM/SIGINT and allow the configured bounded shutdown deadline. Gateway stops accepting public work and drains HTTP requests; Identity drains HTTP work and closes its PostgreSQL pool/resources. Do not hard-kill routine deployments before the bounded grace interval unless incident response requires it.

## Failure playbooks

### Gateway unavailable

Public requests fail even if Identity is healthy. Restore/replace Gateway or roll back Gateway. Do not publish Identity to the Internet as a shortcut.

### Gateway reports not ready

Check Identity `/health/ready`, private DNS/network reachability and `BEEBOX_IDENTITY_UPSTREAM_URL`. Check bounded timeout settings before raising them; do not remove timeouts.

### Identity unavailable

Gateway readiness fails and requests map to safe upstream errors. Inspect Identity configuration/startup log, database readiness and provider/signing/encryption prerequisites. Gateway must not synthesize authentication results during the outage.

### PostgreSQL unavailable

Identity readiness fails and authoritative mutations must fail closed. Restore PostgreSQL connectivity; do not introduce an edge/cache fallback that bypasses persisted authority.

### Provider outage

Use the existing Phase 1/2 provider failure semantics. Gateway does not retry ambiguous mutations or provider operations.

## Observability and correlation

Gateway access logs carry method/path/status/latency and a bounded request ID, but omit query strings and credential-bearing headers. The request ID propagates to Identity so application/audit diagnostics can be correlated.

Never log Authorization, Cookie/Set-Cookie, passwords, OTP/recovery codes, OAuth code/state/provider tokens, signing/encryption keys or database URLs containing credentials.

## Rollout

No schema change is required by the ADR 0008 extraction. Roll out Identity first, verify readiness and current migrations, then Gateway. Canary/traffic-shift strategy is an infrastructure concern but must preserve Gateway as the public edge.

## Rollback

Because the refactor keeps the Phase 1/2 schema compatible and does not add a destructive migration, a deployment can stop routing to Gateway/Identity and restore the previous compatible `cmd/beebox` artifact. Do not run destructive down migrations. If future releases change schema compatibility, use their reviewed roll-forward/expand-contract plan instead.

## Local debugging checklist

- `docker compose config` validates the topology.
- build both Docker targets independently.
- confirm Gateway has no database environment.
- confirm Identity/PostgreSQL have no host-published ports in the reference topology.
- inspect `/health/live` and `/health/ready` separately.
- trace one request ID from Gateway to Identity without adding secrets/query material to logs.
- reproduce public behavior through Gateway, not by treating direct Identity access as the supported client path.
