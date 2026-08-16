# Initial BeeBox Threat Model

> Status: initial repository-owned threat model for the architecture that exists today.
> Current governance baseline: `Instruction.md` plus `docs/contracts/conventions.md`.
> Scope: current Go runtime, PostgreSQL connection lifecycle, explicit migration mode, repository configuration, and CI. Product identity capabilities do not exist yet.

## 1. Purpose and scope

This document records security properties demonstrated by the current repository, threats that already apply, and controls future identity/product slices must add as their attack surface appears.

It distinguishes three states:

1. **Implemented now** — present in current code, tests, or CI and grounded in repository evidence.
2. **Required invariant** — required by `Instruction.md`/contract conventions and must be implemented by the product slice that introduces the corresponding behavior.
3. **Deferred capability control** — not meaningful until the corresponding capability exists, but not permission to defer a correctness requirement after that capability is introduced.

This threat model does **not** choose a tenant model beyond explicit application/instance scope, account-linking semantics, token/JWT trust boundaries, permanent public resource-ID encoding, Clerk compatibility, or future service data ownership.

## 2. Current architecture and security posture

The repository currently contains one Go deployable with two process modes:

- no arguments: validate serve configuration, open one PostgreSQL pool, prove database connectivity with a bounded startup context, then open the HTTP listener;
- `migrate`: validate migration configuration, open and verify PostgreSQL, apply embedded forward migrations under a bounded migration context, then exit.

The HTTP surface contains only:

- `GET /health/live`, process-only and independent of PostgreSQL;
- `GET /health/ready`, which performs a current PostgreSQL ping under a request deadline.

PostgreSQL is an unconditional runtime dependency. The current baseline migration creates no product schema/table/data; only goose migration metadata appears when migrations run.

There are currently no users, identifiers, authentication flows, sessions, organizations, tenant-scoped product repositories, public product APIs, SDKs, product events, Redis, queues, external identity providers, billing providers, or product audit subsystem.

## 3. Assets

### Current assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Reject invalid startup state, bound I/O, clean up deterministically, and expose truthful health. |
| PostgreSQL connectivity/state | Do not report ready while PostgreSQL is unavailable; do not leak provider/topology details. |
| Migration integrity/history | Run only reviewed embedded forward migrations; serialize concurrent runners; do not record failed transactional migrations as applied. |
| Runtime/migration configuration | Fail invalid values safely; database URLs may contain credentials and are secret-bearing inputs. |
| Database credentials | Runtime and migration privileges have different blast radii; credential values must not leak. |
| Logs/errors | Operationally useful without secrets, SQL/provider internals, topology, or future unnecessary PII. |
| Repository/CI integrity | Source, migrations, dependencies, workflows, and test evidence are part of the trusted build/release base. |

### Future high-value assets

Identity data, verified identifiers, credentials, sessions, organization membership, authorization state, audit records, and other application-scoped product data do not exist yet. Once introduced, confidentiality, integrity, application/instance isolation, applicable organization isolation, deletion/retention, and auditability are merge-blocking properties.

## 4. Actors

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach the HTTP listener if deployment networking exposes it. Today it can call only health endpoints. Untrusted. |
| Malicious external actor | May attempt malformed requests, connection exhaustion, probing, credential theft, dependency exploitation, or future cross-scope access. Untrusted. |
| Operator | Supplies environment configuration, chooses database endpoint/credential, starts serve or migration mode, and controls deployment networking. Mistakes/credential compromise are in scope. |
| Runtime process | Reads serve configuration, owns PostgreSQL pool, performs readiness, serves HTTP. It must not need migration privileges merely to serve. |
| Migration operator/process | Intentionally performs schema mutation with a migration-capable credential. Compromise has higher integrity impact than runtime compromise. |
| PostgreSQL | Source of truth/external dependency. Server configuration, authorization and network path are outside the Go process boundary. |
| CI/test environment | Builds/tests code and starts disposable PostgreSQL with test-only credentials. Workflow and third-party Actions are supply-chain inputs. |

## 5. Trust boundaries and entry points

### A. Network client -> HTTP runtime

Current entry points are TCP connections plus `GET /health/live` and `GET /health/ready`. Current handlers consume no product body, token, tenant identifier, cookie, or bearer credential.

### B. Runtime -> PostgreSQL

Current entry points are database URL parsing, startup `Ping`, readiness `Ping`, and migration SQL/goose metadata operations in migration mode. PostgreSQL/provider errors are untrusted for direct client/log exposure.

### C. Operator/environment -> runtime configuration

Current input includes `BEEBOX_DATABASE_URL`, `BEEBOX_HTTP_ADDR`, shutdown/startup/readiness/migration timeout variables, and process arguments selecting serve versus `migrate`.

### D. Migration operator/process -> PostgreSQL

`beebox migrate` intentionally crosses a schema-mutation boundary and requires the DDL privilege needed by reviewed migrations. A compromised migration credential has a larger database-integrity blast radius than a normal runtime credential.

### E. CI -> disposable test PostgreSQL

GitHub Actions starts PostgreSQL 17 with repository-defined test credentials and runs formatting, vet, unit, integration, and race checks. CI data/credentials are disposable test inputs, never authority for production access.

## 6. Existing controls verified now

### Configuration and credential-safe errors

- Serve/migration configuration requires a PostgreSQL URL with `postgres`/`postgresql` scheme, host, and no fragment.
- Relevant duration values must parse and be positive.
- Serve/migration modes load their lifecycle-specific settings separately.
- Validation tests use secret markers and require errors not to echo credential-bearing values.
- Database pool/open/ping and migration failures are collapsed to stable process-level errors.
- Readiness returns fixed `{"status":"not_ready"}` instead of provider diagnostics.

**Limit:** code does not enforce separate database principals, credential rotation, secret-manager use, or production TLS configuration.

### Bounded runtime I/O and lifecycle

- Startup PostgreSQL work is bounded by `BEEBOX_DATABASE_STARTUP_TIMEOUT`; listener creation waits for successful connectivity proof.
- Readiness PostgreSQL work uses request-scoped `BEEBOX_DATABASE_READINESS_TIMEOUT` and honors cancellation.
- HTTP server has explicit read-header, read, write, and idle timeouts.
- Graceful shutdown is bounded.
- Process owns/closes its PostgreSQL pool and listener resources.
- Liveness is process-only; readiness separately represents current database reachability.

**Limit:** no current application per-client rate limit, future request-body limit, tenant fairness control, or explicitly configured PostgreSQL pool-size policy exists.

### Reduced current HTTP surface

- Current health routes accept only `GET`; unsupported methods receive stable `405` errors.
- Health responses contain fixed status values rather than dependency diagnostics.
- There is no current product mutation endpoint.

**Limit:** no application-level authentication, authorization, CSRF/CORS/origin policy, public input contract, or repository-enforced HTTP TLS boundary exists because no product API exists.

### Migration integrity/failure containment

- Migration is explicit process mode; serve mode does not auto-migrate.
- Unknown/extra commands fail before configuration/resource acquisition.
- Migration SQL is embedded and cannot be selected from runtime filesystem, URL, environment, or arbitrary SQL argument.
- Migration sources must follow ordered version filenames and exactly one `Up` directive; `Down`, `NO TRANSACTION`, and `ENVSUB` are rejected.
- Goose global registry is disabled and its logger is a no-op.
- Migration execution requires a deadline.
- PostgreSQL same-session advisory locking serializes concurrent runners; lock wait/cancel/unlock are bounded.
- Default migrations are transactional; integration tests verify rollback/not-recorded behavior for failures, first apply/rerun idempotency, concurrent convergence, and lock cancellation.
- Migration adapter/process resources close on completion/failure.

**Limit:** no artifact signing, database-side proof that only migration mode may DDL, automated production rollback, or release provenance enforcement exists today.

### CI/test baseline

Current CI runs:

- `gofmt -l .` verification;
- `go vet ./...`;
- `go test ./...`;
- PostgreSQL integration tests for database/migration packages;
- `go test -race ./...`.

Go dependencies are versioned/checksummed in `go.mod`/`go.sum`.

**Limit:** current Actions use moving major tags; dedicated dependency-vulnerability scanning, SBOM, artifact signing, and provenance policy are not currently evidenced.

## 7. Threat analysis

| Threat | Current mitigation | Residual/required control |
| --- | --- | --- |
| Credential disclosure | Stable/redacted configuration, database, readiness, and migration error paths are implemented/tested. | Secret distribution, process environment, shell history, deployment logging, rotation, and production credential handling remain operational risks. |
| SQL/provider/topology leakage | Database/readiness/migration errors are normalized; goose logging is disabled. | Future repositories/providers/telemetry need their own safe error mapping and redaction tests. |
| Unauthorized schema mutation | Explicit migration mode; no serve-time migration; no arbitrary runtime migration source. | Production must separate runtime and migration privilege in database authorization; code does not enforce database roles. |
| Migration tampering | Embedded sources are validated and exercised in CI. | Repository/build/dependency compromise can still alter SQL; review/provenance hardening is future work. |
| Unsafe rollback/divergent schema | Forward-only production-facing behavior; transactional migrations; roll-forward policy. | DB state can outlive code rollback; future schema PRs need expand/contract, backup/restore awareness and roll-forward recovery. |
| Concurrent migration corruption | Advisory lock plus concurrency integration tests. | Any future migration system must preserve explicit single-writer semantics. |
| Database outage/partition | Startup fails before listening; bounded readiness returns 503; liveness remains process-only. | No automatic DB failover/degraded product mode exists; future product operations need explicit outage semantics. |
| Slow client/resource exhaustion | HTTP and DB checks are deadline-bounded. | No per-client quotas/rate limiting/body limits for future product APIs; add measured bounds when those surfaces appear. |
| Malformed/untrusted HTTP input | Current handlers accept no product payload and restrict methods. | Future endpoints must bound/validate size, encoding, identifiers, content type, authz context, idempotency/replay and error behavior. |
| Future cross-application/IDOR | No product resource path exists yet. | **Required:** every product row/resource has explicit application/instance scope; org scope only where applicable; server-selected scope and cross-scope negative tests are mandatory. |
| Future PII/secret telemetry exposure | Current paths intentionally use safe errors and contain no product PII. | **Required:** minimize/redact PII and never log secrets in logs/metrics/traces/events/fixtures/responses. |
| Authentication confused with authorization | No authn/authz exists today. | **Required:** authentication establishes identity; separate default-deny server-side authorization decides access. |
| Missing security audit fact | No security-sensitive product mutation exists today. | **Required:** the product slice that introduces a security-sensitive action must record its required audit fact as part of correctness; later asynchronous notification/provider failure must not erase a committed security fact. |
| Dependency/CI supply-chain compromise | Go versions/checksums committed; CI runs on PR/main. | Actions are not SHA-pinned and no dedicated provenance/SBOM/signing control exists. |
| CI credential/data escape | Disposable repository-defined PostgreSQL test credential/data. | Do not introduce production secrets into untrusted PR workflows; future deployment workflow needs permission/environment review. |
| Insecure transport | No current repository control proves HTTP or PostgreSQL production TLS; local examples intentionally use `sslmode=disable`. | Define/enforce transport ownership before production/public exposure; local examples are not production policy. |

## 8. Runtime and migration credentials are separate trust concerns

Both modes currently read `BEEBOX_DATABASE_URL`, but their privilege requirements differ:

- **serve mode:** connectivity and future runtime DML only; it must not receive DDL privileges merely to start;
- **migration mode:** reviewed release DDL and therefore a larger integrity blast radius.

README guidance to use separate credentials is an operational recommendation, not current database-role enforcement. Future deployment/database-role work must preserve least privilege without moving secrets into repository files, command output, logs, fixtures, or public evidence.

## 9. Future controls required with the corresponding capability

### First application/instance or product-data schema

The introducing PR must provide explicit application/instance scope, additional organization scope only where applicable, scoped uniqueness/foreign-key/domain constraints, server-scoped repository operations, adversarial cross-scope tests, and deletion/retention/backup/restore/migration implications. Organization must not silently become a universal root tenant.

### First authentication or identifier flow

The introducing PR must use reviewed crypto/password libraries, normalize verified identifiers with database constraints, define anti-enumeration/replay/attempt/recovery semantics, and avoid account-linking decisions without explicit approval. **Any security-sensitive mutation in that flow must create its required audit evidence in the same complete product slice; audit correctness cannot be deferred until a later generic audit feature.** Secondary notification/provider failure must not erase an already-committed security audit fact.

This requirement does not create an audit subsystem in Phase 0 because there is currently no product security-sensitive mutation to record.

### First session/token/key capability

The introducing PR must explicitly decide the relevant algorithm/issuer/audience/authorized-party/lifetime/rotation/revocation semantics, use cryptographic generation and hashed storage where lifecycle allows, and preserve one-time secret display where applicable. This document does not pre-authorize the trust-boundary decision.

### First state-changing public API

The introducing PR must define authentication plus separate authorization intent, bounded request/pagination inputs, deterministic validation/safe error codes, idempotency/retry/replay/concurrency/transaction behavior, applicable CSRF/origin/CORS defenses, and required audit/observability/redaction behavior.

### First product telemetry/event/provider surface

The introducing PR must define bounded-cardinality telemetry, secret/PII minimization, timeouts/cancellation, safe/idempotent retry classification, BeeBox-owned contract types, and incident evidence that remains useful without leaking protected data.

## 10. Assumptions and residual risks

1. Deployment networking, host hardening, PostgreSQL server configuration, backups/restores, and secret distribution are not implemented by this repository.
2. Upstream infrastructure may provide TLS/network controls, but unevidenced infrastructure is not counted as an existing control.
3. Local/test fake credentials and `sslmode=disable` examples are not production guidance.
4. Separate runtime/migration principals are recommended but not enforced by current code.
5. PostgreSQL availability is required for serving; no failover/read-replica/degraded product mode exists.
6. Go dependencies and GitHub Actions remain trusted build inputs; dedicated supply-chain controls are incomplete.
7. Current redaction evidence covers implemented configuration/startup/readiness/migration paths only.
8. No current product data means tenant isolation, product PII handling, and product audit persistence are required future correctness properties rather than implemented behavior.

## 11. Review/update triggers

Update/review this model when a PR introduces or changes:

- a product schema/table/repository/application/instance model or organization-scoped resource;
- a public product API/state-changing HTTP route;
- authentication, identifiers, account linking, MFA, recovery, sessions, tokens, cookies, API keys, OAuth, or impersonation;
- product logging/tracing/metrics/audit/events/webhooks/queues/Redis/workers/providers;
- migration behavior, DB privilege assumptions, backup/restore, or schema rollout strategy;
- public deployment/TLS/proxy/domain/secret-management/production DB configuration;
- CI permissions, third-party Actions, dependency/provenance/signing/release workflow;
- a new network/service boundary or service extraction;
- a security incident, vulnerability, penetration test, or production failure that invalidates an assumption;
- an ADR/security-relevant architecture decision.

Reviewers should compare assets, actors, boundaries, threat table, implemented controls, residual risks, and required future controls against the exact PR head.

## 12. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing, audit, and change-control invariants.
- `docs/contracts/conventions.md` — Phase 0 ID/error/pagination/idempotency/time/versioning/audit/tenancy semantics.
- `cmd/beebox/main.go` — process modes, configuration-before-resource behavior, bounded DB startup, serve/migrate lifecycle, stable process failures, cleanup.
- `internal/platform/config/*` — URL/timeout validation, serve/migration setting separation, safe validation errors.
- `internal/platform/database/*` — process-owned pgx pool and stable connectivity failure category.
- `internal/platform/httpserver/*` — health surface, method restriction, bounded readiness, fixed failure responses, server timeouts/shutdown.
- `internal/platform/migration/*` — embedded validated forward migrations, deadline, transaction behavior, advisory locking, stable failures/cleanup.
- `internal/platform/migration/sql/00001_runtime_baseline.sql` — no product schema/table/data.
- `.github/workflows/ci.yml` — current formatting/vet/unit/integration/race checks and third-party Action references.
- `go.mod` / `go.sum` — dependency versions/checksums.
- `README.md` — current operational behavior and migration/runtime credential guidance.
