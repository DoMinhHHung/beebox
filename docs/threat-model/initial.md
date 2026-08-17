# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this PR.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and `docs/adr/0001-application-instance-root.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration mode, first `application_instance` root persistence boundary, repository configuration, and CI.

## 1. Purpose and scope

This document records security properties demonstrated by the current repository, threats that already apply, and controls future identity/product slices must add as their attack surface appears.

It distinguishes three states:

1. **Implemented now** — present in current code, schema, tests, or CI and grounded in repository evidence.
2. **Required invariant** — required by `Instruction.md`, contract conventions, or ADR 0001 and must be implemented by the slice that introduces the corresponding behavior.
3. **Deferred capability control** — not meaningful until the corresponding capability exists, but not permission to defer a correctness requirement after that capability is introduced.

ADR 0001 ratifies one `application_instance` resource as the BeeBox v1 root product isolation boundary. It does **not** ratify a permanent public application-instance ID encoding, a universal organization tenant model, account-linking semantics, token/JWT trust boundaries, Clerk compatibility, or future service data ownership.

## 2. Current architecture and security posture

The repository contains one Go deployable with two process modes:

- no arguments: validate serve configuration, open one PostgreSQL pool, prove database connectivity with a bounded startup context, then open the HTTP listener;
- `migrate`: validate migration configuration, open and verify PostgreSQL, apply embedded forward migrations under a bounded migration context, then exit.

The HTTP surface still contains only:

- `GET /health/live`, process-only and independent of PostgreSQL;
- `GET /health/ready`, which performs a current PostgreSQL ping under a request deadline.

PostgreSQL is an unconditional runtime dependency and the initial source of truth. The embedded migrations now contain:

- version 1 runtime baseline;
- version 2 additive creation of `application_instances` with a database-generated internal identity and `timestamptz` creation timestamp.

The repository also contains a minimal BeeBox-owned application-instance model and a concrete PostgreSQL store with only two persistence primitives:

- create one application-instance root row;
- resolve exactly one root row by a trusted internal scope identity.

Integration tests create two distinct root records and prove exact resolution, missing-scope behavior, invalid-scope behavior, and stable persistence errors.

There is **no reachable application/admin creation endpoint or use case**. There are still no application credentials, users, identifiers, authentication, authorization, sessions/tokens, organizations, child product resources, public application-instance IDs, public product APIs, SDKs, Redis, queues, providers, product PII, or product audit subsystem.

## 3. Assets

### Current assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Reject invalid startup state, bound I/O, clean up deterministically, and expose truthful health. |
| PostgreSQL connectivity/state | Do not report ready while PostgreSQL is unavailable; do not leak provider/topology details. |
| Migration integrity/history | Run only reviewed embedded forward migrations; serialize concurrent runners; do not record failed transactional migrations as applied. |
| `application_instances` root rows | Preserve distinct internal identities and creation time; exact resolution must not fall through to another root. |
| Internal application-instance identity | Storage-only scope key used by trusted server code; it must not be treated as a public authorization token or permanent public resource-ID contract. |
| Runtime/migration configuration | Fail invalid values safely; database URLs may contain credentials and are secret-bearing inputs. |
| Database credentials | Runtime and migration privileges have different blast radii; credential values must not leak. |
| Logs/errors | Operationally useful without secrets, SQL/provider internals, topology, or future unnecessary PII. |
| Repository/CI integrity | Source, migrations, dependencies, workflows, and test evidence are part of the trusted build/release base. |

### Future high-value assets

Application credentials, identity data, verified identifiers, authentication factors, sessions, organization membership, authorization state, audit records, and child resources do not exist yet. Once introduced, confidentiality, integrity, application-instance isolation, applicable organization isolation, deletion/retention, and auditability are merge-blocking properties.

## 4. Actors

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach the HTTP listener if deployment networking exposes it. Today it can call only health endpoints. Untrusted. |
| Malicious external actor | May attempt malformed requests, connection exhaustion, probing, credential theft, dependency exploitation, or future cross-scope access. Untrusted. |
| Operator | Supplies environment configuration, chooses database endpoint/credential, starts serve or migration mode, and controls deployment networking. Mistakes/credential compromise are in scope. |
| Runtime process | Reads serve configuration, owns PostgreSQL pool, performs readiness, serves HTTP. It currently has no reachable product handler using application-instance persistence. |
| Trusted internal persistence caller | Future server-side code may supply an internal application-instance scope to the concrete store. The current repository has no public/client path that selects this scope. |
| Migration operator/process | Intentionally performs schema mutation with a migration-capable credential. Compromise has higher integrity impact than runtime compromise. |
| PostgreSQL | Source of truth/external dependency. Server configuration, authorization and network path are outside the Go process boundary. |
| CI/test environment | Builds/tests code and starts disposable PostgreSQL with test-only credentials. Workflow and third-party Actions are supply-chain inputs. |

## 5. Trust boundaries and entry points

### A. Network client -> HTTP runtime

Current entry points are TCP connections plus `GET /health/live` and `GET /health/ready`. Current handlers consume no product body, application-instance identity, token, organization identifier, cookie, or bearer credential.

### B. Runtime/persistence -> PostgreSQL

Current database interactions include startup/readiness `Ping`, migration SQL/goose metadata operations, and the application-instance store's atomic `INSERT ... RETURNING` plus exact `SELECT ... WHERE id = $1` resolution. PostgreSQL/provider errors are untrusted for direct client/log exposure.

### C. Trusted server scope -> application-instance store

The store accepts an internal application-instance identity only as a server-selected persistence scope. Invalid internal identities fail deterministically and missing identities return a stable BeeBox-owned not-found category. There is no unscoped list/first-row fallback.

**Limit:** this is a persistence boundary, not authorization. No authentication or reachable product use case exists yet, so the repository cannot claim that client input has been authorized into a trusted scope.

### D. Operator/environment -> runtime configuration

Current input includes `BEEBOX_DATABASE_URL`, `BEEBOX_HTTP_ADDR`, shutdown/startup/readiness/migration timeout variables, and process arguments selecting serve versus `migrate`.

### E. Migration operator/process -> PostgreSQL

`beebox migrate` intentionally crosses a schema-mutation boundary and requires the DDL privilege needed by reviewed migrations. A compromised migration credential has a larger database-integrity blast radius than a normal runtime credential.

### F. CI -> disposable test PostgreSQL

GitHub Actions starts PostgreSQL 17 with repository-defined test credentials and runs formatting, vet, normal tests, migration/database/application-instance integration tests, and race checks. CI data/credentials are disposable test inputs, never authority for production access.

## 6. Existing controls verified now

### Configuration and credential-safe errors

- Serve/migration configuration requires a PostgreSQL URL with `postgres`/`postgresql` scheme, host, and no fragment.
- Relevant duration values must parse and be positive.
- Serve/migration modes load lifecycle-specific settings separately.
- Validation tests use secret markers and require errors not to echo credential-bearing values.
- Database pool/open/ping and migration failures are collapsed to stable process-level errors.
- Readiness returns fixed `{"status":"not_ready"}` instead of provider diagnostics.

**Limit:** code does not enforce separate database principals, credential rotation, secret-manager use, or production TLS configuration.

### Bounded runtime and persistence I/O

- Startup PostgreSQL work is bounded by `BEEBOX_DATABASE_STARTUP_TIMEOUT`; listener creation waits for successful connectivity proof.
- Readiness PostgreSQL work uses request-scoped `BEEBOX_DATABASE_READINESS_TIMEOUT` and honors cancellation.
- HTTP server has explicit read-header, read, write, and idle timeouts.
- Graceful shutdown is bounded.
- The process owns one pgx PostgreSQL pool.
- Application-instance operations accept `context.Context`, preserve cancellation/deadline errors, and use short-lived `database/sql` adapters backed by the existing pool rather than creating a second pool.
- Liveness is process-only; readiness separately represents current database reachability.

### Application-instance root persistence

Implemented now:

- `application_instances` has a PostgreSQL-generated `BIGINT` identity primary key and `TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP` creation time;
- the database key is documented as internal storage identity only;
- `Create` is one atomic insert and relies on PostgreSQL identity uniqueness rather than an application pre-check;
- `Resolve` validates positive internal identity and issues one exact keyed lookup with no unscoped fallback;
- not-found and persistence failures map to BeeBox-owned stable errors rather than exposing SQL/provider diagnostics;
- integration tests create two roots, require distinct internal identities, resolve A only as A and B only as B, reject invalid identities, and require a nonexistent scope to remain not found;
- returned timestamps are normalized to UTC semantics in the BeeBox-owned model.

**Important limits:**

- the internal database key is not a public resource identifier or authorization credential;
- no public/application/admin creation API exists;
- no authentication/authorization validates how a caller obtained a trusted internal scope;
- no child resource exists yet, so this PR proves root-record distinction rather than full child-resource tenant isolation;
- no deletion lifecycle exists;
- no audit event is produced because no reachable security/admin mutation is introduced.

### Reduced current HTTP surface

- Current health routes accept only `GET`; unsupported methods receive stable `405` errors.
- Health responses contain fixed status values rather than dependency diagnostics.
- There is no current product mutation endpoint.

### Migration integrity/failure containment

- Migration is explicit process mode; serve mode does not auto-migrate.
- Unknown/extra commands fail before configuration/resource acquisition.
- Migration SQL is embedded and cannot be selected from runtime filesystem, URL, environment, or arbitrary SQL argument.
- Migration sources must follow ordered five-digit version filenames and exactly one `Up` directive; `Down`, `NO TRANSACTION`, and `ENVSUB` are rejected.
- Version 1 remains unchanged; version 2 is additive and transactional under default goose behavior.
- Goose global registry is disabled and its logger is a no-op.
- Migration execution requires a deadline.
- PostgreSQL same-session advisory locking serializes concurrent runners; lock wait/cancel/unlock are bounded.
- Integration tests require exactly two applied positive migration versions after normal migration, rerun idempotency, concurrent convergence, and exact expected tables; a synthetic version-3 failure verifies transactional rollback and non-recording.

### CI/test baseline

Current CI runs:

- `gofmt -l .` verification;
- `go vet ./...`;
- `go test ./...`;
- PostgreSQL integration tests for database, migration, and application-instance persistence packages;
- `go test -race ./...`.

Go dependencies are versioned/checksummed in `go.mod`/`go.sum`.

**Limit:** current Actions use moving major tags; dedicated dependency-vulnerability scanning, SBOM, artifact signing, and provenance policy are not currently evidenced.

## 7. Threat analysis

| Threat | Current mitigation | Residual/required control |
| --- | --- | --- |
| Cross-root lookup/fallback | Exact keyed `Resolve`; positive-ID validation; two-root integration tests; missing ID returns not found. | First child resource must enforce application-instance scope in schema, query predicates, constraints, and adversarial cross-scope tests. |
| Client-selected tenant authority | No public product route currently selects application-instance scope; internal DB identity is documented as non-authoritative/public. | First reachable product/admin path must authenticate and separately authorize server-selected scope; client-provided IDs remain input, never authority. |
| Internal DB key becoming public contract | ADR/model/docs state that generated DB identity is storage-internal; no JSON/public API model exists. | First public resource contract must explicitly ratify a BeeBox-owned opaque public ID encoding/compatibility policy. |
| Database credential disclosure | Stable/redacted configuration, database, readiness, migration and application-instance persistence errors. | Secret distribution, process environment, deployment logging, rotation and production credential handling remain operational risks. |
| SQL/provider/topology leakage | Database/readiness/migration errors are normalized; application-instance store returns stable BeeBox-owned categories. | Future repositories/providers/telemetry need their own safe error mapping/redaction tests. |
| Unauthorized schema mutation | Explicit migration mode; no serve-time migration; no arbitrary runtime migration source. | Production must separate runtime/migration database privileges; code does not enforce database roles. |
| Migration tampering | Embedded validated sources and CI migration tests. | Repository/build/dependency compromise can still alter SQL; review/provenance hardening remains future work. |
| Unsafe rollback/divergent schema | Forward-only policy; additive version 2; transactional migrations; roll-forward recovery policy. | Backup/restore must preserve root identities; later child references make destructive rollback unsafe. |
| Database outage/partition | Startup fails before listening; bounded readiness returns 503; persistence accepts caller context and returns stable failure. | Future reachable product operations need explicit user-facing outage/retry/idempotency semantics. |
| Slow client/resource exhaustion | HTTP and DB checks are deadline-bounded. | No public product payload exists; later APIs require body/rate/pagination/tenant-fairness bounds. |
| Future child-resource IDOR | Root table/store exists but no child resource exists. | **Required:** each child row references/enforces application-instance scope and repositories use server-selected scope; cross-scope tests are mandatory. |
| Future PII/secret telemetry exposure | Current product root contains no PII/secret fields and errors are stable. | **Required:** minimize/redact future identity PII and never log secrets. |
| Authentication confused with authorization | No authn/authz exists today. | **Required:** authentication establishes identity; separate default-deny server-side authorization decides access/scope. |
| Missing security audit fact | Internal persistence creation is not externally reachable and is not an admin/product action. | **Required:** the first reachable security/admin application lifecycle must record the complete audit fact required by `docs/contracts/conventions.md`; later async failure cannot erase it. |
| Dependency/CI supply-chain compromise | Go versions/checksums committed; CI runs on PR/main. | Actions are not SHA-pinned and no dedicated provenance/SBOM/signing control exists. |
| Insecure transport | No repository control proves production HTTP/PostgreSQL TLS; local examples use `sslmode=disable`. | Define/enforce transport ownership before production/public exposure. |

## 8. Ratified root isolation decision

ADR 0001 establishes `application_instance` as the single BeeBox v1 root product isolation resource.

Consequences for security review:

- future product rows belong to exactly one application instance unless a later reviewed design adds another applicable scope;
- organization scope is additional only where organization ownership is real and organization does not replace the root;
- a workspace/application/environment hierarchy is not required in v1 but can be added later with product evidence and review;
- database primary keys remain internal implementation details;
- a permanent public application-instance ID encoding remains an explicit future compatibility decision.

## 9. Future controls required with corresponding capabilities

### First child product persistence

The introducing PR must:

- carry explicit application-instance scope on every child row;
- add organization scope only where applicable;
- enforce scoped uniqueness/foreign keys/domain constraints in PostgreSQL;
- use server-selected scope in repository operations;
- include adversarial cross-application tests using otherwise valid foreign IDs;
- define deletion/retention/backup/restore/migration implications for the child relationship.

### First reachable application/admin lifecycle

The current `Create` store method is only an internal persistence primitive. A reachable lifecycle must separately add:

- authentication and authorization;
- server-selected scope/ownership semantics;
- idempotency, retry, replay, concurrency and transaction behavior;
- complete security/admin audit evidence per `docs/contracts/conventions.md`;
- stable public errors and the separately ratified public application-instance ID contract;
- abuse, observability and operational failure behavior.

### First authentication or identifier flow

The introducing PR must use reviewed crypto/password libraries, normalize verified identifiers with database constraints, define anti-enumeration/replay/attempt/recovery semantics, and avoid account-linking decisions without explicit approval. Any security-sensitive mutation must create required audit evidence in the same complete product slice.

### First session/token/key capability

The introducing PR must explicitly decide relevant algorithm/issuer/audience/authorized-party/lifetime/rotation/revocation semantics, use cryptographic generation and hashed storage where lifecycle allows, and preserve one-time secret display where applicable.

### First state-changing public API

The introducing PR must define authentication plus separate authorization intent, bounded request/pagination inputs, deterministic validation/safe error codes, idempotency/retry/replay/concurrency/transaction behavior, applicable CSRF/origin/CORS defenses, and required audit/observability/redaction behavior.

### First product telemetry/event/provider surface

The introducing PR must define bounded-cardinality telemetry, secret/PII minimization, timeouts/cancellation, safe/idempotent retry classification, BeeBox-owned contract types, and incident evidence that remains useful without leaking protected data.

## 10. Data lifecycle, assumptions and residual risks

1. Application-instance rows are durable roots in this slice; no delete or soft-delete lifecycle exists.
2. Backup/restore must preserve internal root identity and future referential meaning. No repository automation currently verifies production backup/restore.
3. Deletion/retention semantics must be designed with the first real lifecycle requiring deletion; no speculative delete column is present.
4. Deployment networking, host hardening, PostgreSQL server configuration and secret distribution are outside current repository enforcement.
5. Separate runtime/migration principals are recommended but not enforced by current code.
6. PostgreSQL availability is required for serving; no failover/read-replica/degraded product mode exists.
7. Go dependencies and GitHub Actions remain trusted build inputs; dedicated supply-chain controls are incomplete.
8. No identity/product PII exists yet.
9. Root persistence tests do not prove authorization or child-resource tenant isolation because those surfaces do not exist.

## 11. Review/update triggers

Update/review this model when a PR introduces or changes:

- a child product schema/table/repository or organization-scoped resource;
- a reachable application/admin lifecycle or public product API;
- public application-instance identifier encoding/compatibility;
- application credentials, authentication, identifiers, account linking, MFA, recovery, sessions, tokens, cookies, API keys, OAuth, or impersonation;
- product logging/tracing/metrics/audit/events/webhooks/queues/Redis/workers/providers;
- deletion/retention/backup/restore behavior;
- migration behavior, database privilege assumptions, or schema rollout strategy;
- public deployment/TLS/proxy/domain/secret-management/production DB configuration;
- CI permissions, third-party Actions, dependency/provenance/signing/release workflow;
- a new network/service boundary or service extraction;
- a security incident or security-relevant ADR.

## 12. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing, audit, and change-control invariants.
- `docs/adr/0001-application-instance-root.md` — Human-ratified v1 root isolation decision and consequences.
- `docs/contracts/conventions.md` — ID/error/idempotency/time/versioning/audit/tenancy semantics.
- `internal/platform/migration/sql/00002_application_instances.sql` — first product table and database invariants.
- `internal/platform/migration/*` — embedded forward migration validation, transactional behavior, advisory locking, stable failures and exact migration-state tests.
- `internal/applicationinstance/instance.go` — BeeBox-owned internal model and stable errors; no public wire representation.
- `internal/applicationinstance/postgres/store.go` — concrete context-aware create/exact-resolve persistence using the process-owned pool.
- `internal/applicationinstance/postgres/store_integration_test.go` — two-root distinction, missing/invalid-scope, cancellation and safe-failure evidence.
- `internal/platform/database/*` — process-owned pgx pool and `database/sql` adapter behavior.
- `.github/workflows/ci.yml` — formatting, vet, unit, database/migration/application-instance integration and race checks.
- `README.md` / `CONTRIBUTING.md` — current scope, migration behavior and repository-native verification commands.
