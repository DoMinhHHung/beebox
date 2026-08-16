# Initial BeeBox Threat Model

> Status: initial repository-owned threat model for the architecture that exists today.
> Baseline inspected: `main@b22b97ef123ff68e10474d2a5da7617107809e5f`.
> Scope: current Go runtime, PostgreSQL connection lifecycle, explicit migration mode, repository configuration, and CI. Product identity capabilities do not exist yet.

## 1. Purpose and scope

This document records the security properties that can be demonstrated from the current repository, the threats that already apply, and the controls that later identity and product slices must add as their attack surface appears.

It deliberately distinguishes three states:

1. **Implemented now** — a control is present in current code, tests, or CI and can be mapped to repository evidence.
2. **Required invariant** — `Instruction.md` requires future product work to preserve the property, but no current product implementation exists to enforce it yet.
3. **Deferred capability control** — the control becomes meaningful only when the corresponding product surface exists and must not be read as implemented today.

This threat model does **not** choose a tenant model, account-linking semantics, token/JWT trust boundaries, public compatibility policy, or product data ownership. Those remain governed by `Instruction.md` and future explicit design decisions.

## 2. Current architecture and security posture

The repository currently contains one Go deployable with two process modes:

- no arguments: validate serve configuration, open one PostgreSQL pool, prove database connectivity with a bounded startup context, then open the HTTP listener;
- `migrate`: validate migration configuration, open and verify PostgreSQL, apply embedded forward migrations under a bounded migration context, then exit.

The HTTP surface contains only:

- `GET /health/live`, which is process-only and does not query PostgreSQL;
- `GET /health/ready`, which performs a current PostgreSQL ping under a per-request timeout.

PostgreSQL is an unconditional runtime dependency. The only current migration is a baseline migration that creates no product schema, table, or data; goose migration metadata is the only database table introduced when migrations run.

There are currently no users, identifiers, authentication flows, sessions, organizations, tenant-scoped product repositories, public product APIs, SDKs, product events, Redis, queues, external identity providers, or billing providers.

## 3. Assets

### Assets that exist now

| Asset | Security property to preserve |
| --- | --- |
| Runtime availability | The process should reject invalid startup state, avoid unbounded external I/O, shut down deterministically, and expose truthful health state. |
| PostgreSQL connectivity and state | The runtime must not report ready when PostgreSQL is unavailable, and database failures must not expose provider or topology details. |
| Migration integrity and history | Only reviewed embedded forward migrations should run; concurrent runners must not corrupt migration state; failed transactional migrations must not be recorded as applied. |
| Runtime and migration configuration | Invalid values must fail safely. Database connection URIs may contain credentials and must be treated as secrets. |
| Database credentials | Runtime and migration credentials have different privilege needs and compromise impacts. Credential values must not be exposed through errors, logs, examples containing real values, or HTTP responses. |
| Logs and error responses | They must remain useful for operation without exposing secrets, SQL/provider internals, topology, or future unnecessary PII. |
| Repository and CI integrity | Source, migrations, dependencies, workflow definitions, and test results are inputs to the released artifact and therefore part of the trust base. |

### Future high-value assets

Identity data, verified identifiers, credentials, sessions, organization membership, authorization state, audit records, and other tenant-scoped product data do not exist yet. Once introduced, confidentiality, integrity, tenant isolation, deletion/retention, and auditability become merge-blocking properties under `Instruction.md`.

## 4. Actors

| Actor | Current capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach the HTTP listener if deployment networking exposes it. Today it can call only health endpoints. It is untrusted. |
| Malicious external actor | May attempt malformed requests, connection exhaustion, probing, credential theft, dependency exploitation, or future cross-tenant access. It is untrusted. |
| Operator | Supplies environment configuration, chooses database endpoints/credentials, starts serve or migration mode, and controls deployment networking. Operator mistakes or credential compromise are in scope. |
| Runtime process | Reads serve configuration, owns the PostgreSQL pool, performs readiness checks, and serves HTTP. It must not require migration privileges merely to serve. |
| Migration operator / process | Intentionally performs schema mutation using the exact BeeBox artifact and a migration-capable credential. Its compromise has higher database-integrity impact than the normal runtime. |
| PostgreSQL | Current source of truth and external dependency. Availability, authentication, network path, and database authorization are outside the process boundary. |
| CI / test environment | Builds and tests repository code and starts a disposable PostgreSQL service using test-only credentials. CI configuration and third-party Actions are part of the supply-chain trust surface. |

## 5. Trust boundaries and entry points

### Boundary A — network client -> HTTP runtime

**Entry points today**

- `GET /health/live`
- `GET /health/ready`
- TCP connections to the configured HTTP listener

**Data crossing the boundary**

- HTTP method, path, headers, connection state, request cancellation
- fixed JSON health responses

No authentication, tenant identifier, product payload, cookie, bearer token, or request body is consumed by current handlers.

### Boundary B — runtime -> PostgreSQL

**Entry points today**

- pool configuration parsed from `BEEBOX_DATABASE_URL`
- startup `Ping`
- readiness `Ping`
- migration SQL and goose metadata operations in migration mode

The database URI may select credentials, host/topology, transport parameters, and database settings. PostgreSQL errors and provider details are untrusted for direct exposure to clients or logs.

### Boundary C — operator/environment -> runtime configuration

**Entry points today**

- `BEEBOX_DATABASE_URL`
- `BEEBOX_HTTP_ADDR`
- `BEEBOX_SHUTDOWN_TIMEOUT`
- `BEEBOX_DATABASE_STARTUP_TIMEOUT`
- `BEEBOX_DATABASE_READINESS_TIMEOUT`
- `BEEBOX_DATABASE_MIGRATION_TIMEOUT` in migration mode
- process arguments selecting serve versus `migrate`

Environment values are operator-controlled input and must be validated before resource acquisition where practical.

### Boundary D — migration operator/process -> PostgreSQL

The operator intentionally crosses a schema-mutation trust boundary by executing `beebox migrate`. The migration process receives a database credential capable of the reviewed DDL required by the release. A compromise or configuration error at this boundary can alter database schema and migration history.

### Boundary E — CI -> disposable test PostgreSQL

GitHub Actions starts a PostgreSQL 17 service with repository-defined test-only credentials and runs normal, integration, static-analysis, formatting, and race checks. This boundary is for disposable CI data only and must not be treated as authority for production credentials or production database mutation.

## 6. Existing controls verified in the repository

The controls below are implemented now. Statements in this section intentionally avoid operational controls that the repository merely recommends but cannot enforce.

### 6.1 Configuration and credential handling

- Serve and migration configuration require `BEEBOX_DATABASE_URL` and accept only `postgres`/`postgresql` URIs with a host and no URL fragment.
- Duration configuration used for startup, readiness, shutdown, and migration must be positive and parseable.
- Serve mode and migration mode load only the settings needed by their respective lifecycle where the code currently separates them.
- Configuration validation errors do not echo the database URI, and tests include credential markers to detect accidental disclosure.
- Database pool creation and connectivity errors are collapsed to stable process-level errors before they reach the top-level structured logger.
- Readiness failures return the stable body `{"status":"not_ready"}` rather than PostgreSQL/provider error text.

**Important limit:** current code does not enforce separate database principals, credential rotation, secret-manager use, or TLS settings. README guidance to use separate migration and runtime credentials is an operational recommendation, not an implemented authorization control.

### 6.2 Runtime availability and bounded I/O

- PostgreSQL pool creation and startup connectivity verification execute under `BEEBOX_DATABASE_STARTUP_TIMEOUT`; the HTTP listener is not opened until connectivity succeeds.
- Readiness creates a request-scoped database-check context bounded by `BEEBOX_DATABASE_READINESS_TIMEOUT` and honors request cancellation.
- The HTTP server sets explicit read-header, read, write, and idle timeouts.
- Graceful shutdown is bounded by `BEEBOX_SHUTDOWN_TIMEOUT`.
- The process owns and closes the PostgreSQL pool; listener cleanup is deterministic in serve mode.
- Liveness is process-only, avoiding a database outage turning liveness into a restart loop; readiness separately reflects current database reachability.

**Important limit:** there is no current application-level per-client rate limit, request-body size limit, tenant fairness control, or repository-configured PostgreSQL pool-size policy. The present HTTP endpoints consume no request bodies, but future product endpoints must add input and abuse bounds appropriate to their payloads and cost.

### 6.3 HTTP surface reduction

- Only `GET` is accepted for each current health endpoint; unsupported methods return `405 Method Not Allowed` with a stable error code.
- Health responses expose fixed status values rather than provider diagnostics.
- There is no current product mutation endpoint reachable from the HTTP server.

**Important limit:** the repository does not yet establish application-level TLS termination, origin policy, authentication, authorization, CSRF policy, CORS policy, or public API input validation because no product API exists. Deployment transport security must be resolved before treating the current listener as safely Internet-exposed.

### 6.4 Migration integrity and failure containment

- Migration execution is an explicit process mode; serve mode does not run migrations automatically.
- The process rejects unknown commands and extra arguments before configuration or resource acquisition.
- Migration SQL is embedded in the BeeBox binary and is not selected from a runtime filesystem, URL, environment variable, or arbitrary SQL argument.
- Embedded migration files must match the ordered versioned filename convention and contain exactly one `Up` directive.
- The migration validator rejects `Down`, `NO TRANSACTION`, and `ENVSUB` directives.
- Goose is configured with its global registry disabled and a no-op logger, reducing accidental exposure of migration/provider details through the migration library.
- The migration context must have a deadline.
- Concurrent migration runners serialize on a PostgreSQL same-session advisory lock; lock acquisition is cancellation-aware and unlock cleanup is separately bounded.
- Default SQL migrations execute transactionally. Integration tests verify that a failing migration rolls back its partial schema change and is not recorded as applied.
- Integration tests verify first apply, rerun idempotency, concurrent runners converging on one applied version, and lock-wait cancellation.
- Migration adapters and process-owned database resources are closed on completion or failure.
- Migration errors returned by the process are stable and do not include SQL, provider details, or credential markers in the tested failure paths.

**Important limit:** the repository currently has no artifact-signing, migration approval service, database-side policy that proves only the migration process can perform DDL, or automated rollback mechanism. Forward-only migration safety depends on reviewed source, artifact integrity, deployment discipline, database authorization, backups, and roll-forward correction.

### 6.5 CI and test controls

Current GitHub Actions runs:

- formatting verification with `gofmt -l .`;
- `go vet ./...`;
- `go test ./...`;
- PostgreSQL integration tests for database and migration packages against a disposable service;
- `go test -race ./...`.

Go dependencies are versioned in `go.mod`/`go.sum`.

**Important limit:** current Actions use moving major-version tags rather than immutable commit SHAs, and the repository does not yet show dedicated dependency-vulnerability scanning, provenance verification, SBOM generation, artifact signing, or policy enforcement for third-party Actions.

## 7. Threat analysis

| Threat | Boundary / asset | Current mitigation | Residual risk / required next control |
| --- | --- | --- | --- |
| Database credential disclosure through configuration errors, startup errors, readiness responses, migration errors, or logs | B, C, D; database credentials | Stable/redacted configuration, database, readiness, and migration error paths are implemented and tested. | Environment/process inspection, deployment logs, secret distribution, shell history, and operator handling remain external risks. Add deployment secret-management and rotation policy before production. Future telemetry must preserve redaction. |
| SQL, provider, or topology leakage | B, D; logs/errors | Database ping errors are normalized; readiness uses fixed status; migration library logging is disabled; tested migration/process errors are stable. | New queries, repositories, tracing, or provider adapters can reintroduce leakage. Add safe application error mapping and redaction tests with each new boundary. |
| Unauthorized schema mutation | D; database state, migration integrity | Schema mutation is separated into explicit `migrate` mode; serve mode has no automatic migration path; arbitrary runtime migration source/SQL is not accepted. | Code cannot currently enforce different PostgreSQL principals or DDL revocation. Production must give serve mode a least-privilege runtime credential and migration mode a separately controlled credential. |
| Migration tampering | Repository/CI -> D; migration history | Migrations are embedded and source shape is validated; runtime file/URL selection is absent; CI exercises migrations. | A compromised repository, dependency, build pipeline, or artifact can still alter embedded SQL. Require review protection and later provenance/signing controls appropriate to release maturity. |
| Unsafe rollback / divergent schema | D; database state | Production-facing migration API is forward-only; default migrations are transactional; failed migration behavior is integration-tested; README documents roll-forward correction. | PostgreSQL state can outlive a code rollback. Backups/restores and expand/contract safety are operational requirements; every future schema PR must define rollout and roll-forward recovery. |
| Concurrent migration corruption | D; migration history | Same-session PostgreSQL advisory lock plus integration tests for concurrent runners. | Lock identity and migration coordination remain process/repository conventions. Any future separate migration system must preserve single-writer semantics or replace them explicitly. |
| Database outage or partition | B; availability, truthful readiness | Startup fails before listening when connectivity cannot be proven; readiness performs bounded current ping and returns `503`; liveness remains process-only. | No automatic database failover or retry policy exists. Deployment/orchestration must react to readiness without creating retry storms; future user-facing operations need explicit outage semantics. |
| Slow clients / connection or I/O exhaustion | A; runtime availability | HTTP read-header, read, write, and idle timeouts bound several connection lifetimes; shutdown and database checks are bounded. | No per-IP rate limiting, connection quota, body-size limits for future product APIs, or explicit database pool-size tuning exists. Add measured limits as attack surface grows. |
| Malformed or untrusted HTTP input | A; runtime correctness | Current handlers accept no product payload and restrict methods on health routes. Go's `net/http` parser and configured server timeouts provide baseline parsing/lifecycle behavior. | Every future product endpoint must validate size, encoding, identifiers, content type, authorization context, idempotency, replay, and failure mapping. Never trust client-supplied tenant/role/owner data. |
| Future cross-tenant access / IDOR | A -> future product/data; future identity data | No product resources exist, so there is no current tenant data path to claim as protected. | **Required invariant:** every resource must carry explicit application/instance scope and organization scope where applicable; server-side authorization and repository queries must enforce scope. Add adversarial cross-tenant tests with the first product schema/API. |
| Future PII or secret exposure in logs/telemetry | Future HTTP/data/provider boundaries; identity data, credentials | Current code intentionally emits stable database/migration errors and contains no product PII. | **Required invariant:** minimize/redact PII and never log secrets across logs, metrics, traces, events, fixtures, and responses. Add structured logging/redaction tests before identity data is introduced. |
| Authentication confused with authorization | Future API boundaries; tenant data | No authn/authz implementation exists today. | **Required invariant:** authentication proves identity; authorization separately decides access. Default-deny server-side checks become mandatory with the first protected resource. |
| Dependency or CI supply-chain compromise | CI/repository; build integrity | Go dependency versions/checksums are committed; CI executes tests on PRs and `main`. | GitHub Actions are not pinned to immutable SHAs and no dedicated vulnerability/provenance/SBOM/signing control is present. Harden supply-chain policy in a dedicated scoped PR rather than implying it exists here. |
| CI credential/data escape | E; CI integrity | CI PostgreSQL uses repository-defined disposable test credentials and test data. | Do not introduce production secrets into untrusted PR workflows. Any future deployment workflow needs explicit permission minimization and environment protection review. |
| Insecure PostgreSQL or HTTP transport | A, B; credentials/data confidentiality | No repository control currently proves TLS for the HTTP listener or database connection; local examples intentionally use `sslmode=disable`. | Before production/public exposure, define transport-security ownership and enforce secure database/network configuration appropriate to deployment. Do not mistake local examples for production policy. |

## 8. Runtime and migration credentials are separate trust concerns

The runtime and migration process currently accept the same configuration key, `BEEBOX_DATABASE_URL`, but their required database privileges differ.

- **Serve mode:** needs connectivity and, once product repositories exist, only the DML privileges required by runtime operations. It should not receive DDL/migration privileges merely to start.
- **Migration mode:** intentionally requires the DDL privileges necessary for reviewed migrations and therefore has a larger integrity blast radius.

The repository currently **documents** the recommendation to use separate credentials but does not enforce database roles or privilege grants. Future deployment/IAM/database-role work must preserve this privilege separation without moving credential values into repository files, command output, or logs.

## 9. Future controls required by repository invariants

The following controls are not implemented yet because their product surfaces do not exist. They are security requirements for the PR that introduces the corresponding surface.

### First application/instance or product-data schema

- explicit application/instance scope on every resource;
- organization scope where applicable, without pre-deciding a universal organization model;
- database constraints for uniqueness, references, and domain invariants;
- repository operations that enforce tenant scope server-side;
- cross-tenant negative tests, including guessed/valid foreign IDs;
- deletion, retention, backup, restore, and migration implications documented before compliance claims.

### First authentication or identifier flow

- reviewed cryptographic/password libraries only;
- normalized verified identifiers backed by database constraints;
- explicit anti-enumeration, replay, attempt-budget, and recovery semantics appropriate to the flow;
- account linking only after an explicit approved decision; never link from an unverified claim;
- security-sensitive actions produce audit evidence once audit capability exists.

### First session, token, or key capability

- explicit issuer/audience/authorized-party and algorithm rules;
- key rotation and revocation semantics;
- short, bounded lifetimes where appropriate;
- hashed storage for secrets when lifecycle/lookup permits;
- one-time display for generated secrets where applicable;
- no token/JWT trust-boundary decision is made by this document.

### First state-changing public API

- authentication and separate authorization intent;
- bounded request body and pagination/input limits;
- deterministic validation and stable machine-readable error codes;
- explicit idempotency, retry, replay, concurrency, and transaction behavior;
- CSRF/origin/CORS protections as required by the chosen transport/session model;
- audit, observability, and safe error/redaction behavior proportionate to the action.

### First product logging, metrics, tracing, events, or external provider

- bounded-cardinality telemetry;
- secret/PII redaction by construction and tests;
- timeout and cancellation propagation;
- classified retry policy only for safe/idempotent operations;
- provider data types do not become BeeBox public contracts;
- incident/debug evidence must remain useful without leaking credentials or unnecessary identity data.

## 10. Assumptions and residual risks

1. Deployment networking, host hardening, PostgreSQL server configuration, backups, restore procedures, and secret distribution are not implemented by this repository today.
2. The current HTTP server may be placed behind infrastructure that provides TLS and network controls, but that infrastructure is not evidenced here and therefore is not counted as an existing control.
3. Local/test PostgreSQL examples using fake credentials and `sslmode=disable` are not production security guidance.
4. Separate runtime and migration principals are recommended but not enforced by current code.
5. PostgreSQL availability is required for serving; the repository has no current failover, read replica, or degraded product mode.
6. The Go module and GitHub Actions dependency chain remains part of the trusted computing base. Dedicated supply-chain scanning/provenance controls are not present yet.
7. Current error-redaction evidence covers the implemented configuration, startup, readiness, and migration paths; future database queries, handlers, providers, and telemetry require their own tests.
8. No current product data means tenant isolation and PII controls are architectural requirements rather than demonstrated runtime behavior.

## 11. Review and update triggers

Update this threat model in the same PR, or link a scoped follow-up that blocks release where necessary, when any of these occurs:

- the first product schema/table, repository, application/instance model, or organization-scoped resource is introduced;
- the first public product API or state-changing HTTP route is added;
- authentication, identifiers, account linking, MFA, recovery, sessions, tokens, cookies, API keys, OAuth, or impersonation is introduced;
- logging, tracing, metrics, audit events, webhooks, queues, Redis, background workers, or external providers begin carrying product data;
- migration behavior, database privilege assumptions, backup/restore policy, or schema rollout strategy changes;
- deployment exposes BeeBox publicly or defines TLS, proxy, domain, secret-management, or production database configuration;
- CI permissions, third-party Actions, dependency policy, artifact provenance, signing, or release workflows change;
- a bounded context is proposed for service extraction or a new network trust boundary is added;
- a security incident, vulnerability, penetration test, or production failure invalidates an assumption or reveals a missing threat;
- an ADR changes any security-relevant architecture or trust-boundary decision.

At minimum, reviewers should re-check the assets, actors, trust boundaries, threat table, implemented-control evidence, residual risks, and deferred controls against the exact current PR head.

## 12. Evidence map

The current-control statements above are grounded in these repository locations:

- `Instruction.md` — architecture, security, tenant/data, testing, and change-control invariants.
- `cmd/beebox/main.go` — process-mode selection; configuration-before-resource behavior; bounded PostgreSQL startup; separate serve/migration lifecycle; stable top-level database/migration failures; cleanup.
- `internal/platform/config/config.go` and tests — database URI validation, positive timeout validation, serve/migration configuration separation, credential-safe validation errors.
- `internal/platform/database/database.go` and tests — process-owned pgx pool, stable connectivity failure category, pool lifecycle.
- `internal/platform/httpserver/httpserver.go` and tests — fixed health surface, method restrictions, bounded readiness, stable failure body, server I/O timeouts, graceful shutdown.
- `internal/platform/migration/migration.go`, tests, and integration tests — embedded validated forward migrations, deadline requirement, transactional behavior, advisory lock serialization, stable failures, cleanup.
- `internal/platform/migration/sql/00001_runtime_baseline.sql` — no current product schema/table/data.
- `.github/workflows/ci.yml` — formatting, vet, unit, PostgreSQL integration, and race checks plus the current third-party Action references.
- `go.mod` / `go.sum` — current Go dependency versions/checksums.
- `README.md` — current operational behavior and credential-separation guidance.
