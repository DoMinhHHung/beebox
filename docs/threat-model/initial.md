# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this PR.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and `docs/adr/0001-application-instance-root.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration mode, `application_instance` root persistence, first application-scoped `users` child persistence, repository configuration, and CI.

## 1. Purpose and scope

This document records security properties demonstrated by the current repository, threats that already apply, and controls future identity/product slices must add as their attack surface appears.

It distinguishes three states:

1. **Implemented now** — present in current code, schema, tests, or CI and grounded in repository evidence.
2. **Required invariant** — required by `Instruction.md`, contract conventions, or ADR 0001 and must be implemented by the slice that introduces the corresponding behavior.
3. **Deferred capability control** — not meaningful until the corresponding capability exists, but not permission to defer a correctness requirement after that capability is introduced.

ADR 0001 ratifies one `application_instance` resource as the BeeBox v1 root product isolation boundary. It does **not** ratify permanent public application/user ID encoding, a universal organization tenant model, account-linking semantics, token/JWT trust boundaries, Clerk compatibility, or future service data ownership.

## 2. Current architecture and security posture

The repository contains one Go deployable with two process modes:

- no arguments: validate serve configuration, open one PostgreSQL pool, prove database connectivity with a bounded startup context, then open the HTTP listener;
- `migrate`: validate migration configuration, open and verify PostgreSQL, apply embedded forward migrations under a bounded migration context, then exit.

The HTTP surface still contains only:

- `GET /health/live`, process-only and independent of PostgreSQL;
- `GET /health/ready`, which performs a current PostgreSQL ping under a request deadline.

PostgreSQL is the initial source of truth. Embedded migrations now contain:

- version 1 runtime baseline;
- version 2 additive `application_instances` root table;
- version 3 additive `users` child table with mandatory `application_instance_id` foreign-key scope.

The repository contains two internal persistence areas:

- application-instance persistence creates and resolves root records by trusted internal root identity;
- user persistence creates a user inside a trusted application-instance scope and resolves a user only when both trusted scope and internal user identity match.

The `users` table contains only generated internal identity, application-instance foreign-key scope, and creation time. It contains no email, phone, username, profile, credential, authentication/session state, organization scope, metadata, or public identifier.

Integration tests create multiple application roots and users and prove cross-application user lookup returns not found, invalid/missing scope cannot fall through, the foreign key prevents orphan users, and concurrent user creation produces distinct database-generated identities.

There is **no reachable application/user/admin creation endpoint or product use case**. There are still no application credentials, verified identifiers, product PII profile fields, authentication, authorization, sessions/tokens, organizations, public application/user IDs, public product APIs, SDKs, Redis, queues, providers, or product audit subsystem.

## 3. Assets

### Current assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Reject invalid startup state, bound I/O, clean up deterministically, and expose truthful health. |
| PostgreSQL connectivity/state | Do not report ready while PostgreSQL is unavailable; do not leak provider/topology details. |
| Migration integrity/history | Run only reviewed embedded forward migrations; serialize concurrent runners; do not record failed transactional migrations as applied. |
| `application_instances` root rows | Preserve distinct internal identities and creation time; exact resolution must not fall through. |
| `users` child rows | Every row belongs to exactly one existing application instance; scoped resolution must never return a user from another root. |
| Internal application/user identities | Storage-only keys for trusted server persistence; never authorization tokens or permanent public resource-ID contracts. |
| Application-instance/user relationship | FK-backed referential integrity must prevent orphan user rows and survive backup/restore consistently. |
| Runtime/migration configuration | Fail invalid values safely; database URLs may contain credentials and are secret-bearing inputs. |
| Database credentials | Runtime and migration privileges have different blast radii; credential values must not leak. |
| Logs/errors | Operationally useful without secrets, SQL/provider internals, topology, or unnecessary PII. |
| Repository/CI integrity | Source, migrations, dependencies, workflows, and test evidence are part of the trusted build/release base. |

### Future high-value assets

Application credentials, verified identifiers, profile PII, authentication factors, sessions, organization membership, authorization state, audit records, and additional child resources do not exist yet. Once introduced, confidentiality, integrity, application-instance isolation, applicable organization isolation, deletion/retention, and auditability are merge-blocking properties.

## 4. Actors

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach health endpoints if deployment networking exposes them. No product route exists. Untrusted. |
| Malicious external actor | May attempt malformed requests, connection exhaustion, probing, credential theft, dependency exploitation, or future cross-scope access. Untrusted. |
| Operator | Supplies environment configuration and controls serve/migration process execution. Mistakes/credential compromise are in scope. |
| Runtime process | Owns the PostgreSQL pool and HTTP health surface; no product handler currently calls user persistence. |
| Trusted internal persistence caller | May supply internal application scope and user identity to concrete stores. No public/client path currently establishes this trust. |
| Migration operator/process | Performs reviewed DDL with a migration-capable credential; compromise has a larger integrity blast radius. |
| PostgreSQL | Source of truth/external dependency. Server authorization/network configuration is outside the Go process boundary. |
| CI/test environment | Builds/tests code and starts disposable PostgreSQL with test-only credentials. Third-party Actions are supply-chain inputs. |

## 5. Trust boundaries and entry points

### A. Network client -> HTTP runtime

Current handlers accept no product body, user identity, application-instance identity, token, organization identifier, cookie, or bearer credential.

### B. Runtime/persistence -> PostgreSQL

Current interactions include startup/readiness checks, migration SQL/goose metadata, application-instance insert/exact resolve, and user insert/exact application-scoped resolve. PostgreSQL/provider errors are untrusted for direct exposure.

### C. Trusted server scope -> application-instance store

The application-instance store accepts storage-internal root identity only as trusted server-selected persistence scope. Invalid identity fails deterministically and missing identity returns stable not-found. This is persistence behavior, not authorization.

### D. Trusted server scope -> user store

The user store requires:

- a positive trusted `application_instance` internal scope for create;
- both positive trusted application-instance scope and positive internal user identity for resolve.

Resolve uses an exact predicate equivalent to:

`WHERE application_instance_id = <trusted scope> AND id = <user id>`

A real user ID from another application returns the same stable not-found category as a missing user in the selected scope. There is no lookup by user ID alone and no first-row/unscoped fallback.

**Limit:** the repository still has no authentication/authorization path that proves how a caller obtained trusted scope. Persistence-level scoping is implemented; tenant authorization is not.

### E. Operator/environment -> runtime configuration

Current configuration includes the database URL, HTTP address, lifecycle timeouts, and process-mode arguments.

### F. Migration operator/process -> PostgreSQL

`beebox migrate` intentionally crosses a schema-mutation boundary. Serve mode does not automatically migrate.

### G. CI -> disposable test PostgreSQL

CI runs format, vet, unit, database/migration/application-instance/user PostgreSQL integration, and race checks against disposable PostgreSQL.

## 6. Existing controls verified now

### Configuration and credential-safe errors

- database/configuration validation returns stable safe categories;
- database URLs/provider diagnostics are not emitted in current stable error paths;
- readiness returns fixed safe status responses;
- migration and persistence failures map to BeeBox-owned categories rather than raw SQL/provider text.

**Limit:** separate production database principals, secret rotation/manager integration, and production TLS configuration are not repository-enforced.

### Bounded runtime and persistence I/O

- startup/readiness/migration operations are deadline-bound;
- HTTP server and graceful shutdown have explicit bounds;
- one process-owned pgx PostgreSQL pool is reused;
- application-instance and user stores accept `context.Context`, preserve cancellation/deadline failure, and use temporary `database/sql` adapters backed by the existing pool;
- temporary adapters are closed without closing the underlying pool.

### Application-instance root persistence

Implemented now:

- generated internal `BIGINT` primary key;
- `TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`;
- atomic create;
- exact root resolve;
- stable invalid/not-found/persistence errors;
- multi-root integration evidence;
- internal identity explicitly not public authority.

### Application-scoped user persistence

Implemented now:

- `users.id` is PostgreSQL-generated internal identity and primary key;
- `users.application_instance_id` is `NOT NULL` and references `application_instances(id)`;
- `users.created_at` is `TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`;
- `Create` validates trusted root scope and performs one atomic insert;
- PostgreSQL FK enforcement prevents a user under a nonexistent positive root; no application-only existence pre-check is relied on;
- `Resolve` validates scope/user identity and queries by both values;
- valid foreign user IDs cannot resolve in another application scope;
- invalid and missing identities fail deterministically without fallback;
- database failures are mapped to stable `user persistence failure` rather than raw provider/constraint diagnostics;
- returned time is normalized to UTC in the BeeBox-owned user model;
- concurrent creates rely on database identity generation and are tested for distinct identities.

**Important limits:**

- these stores are internal persistence primitives and are not reachable product/admin actions;
- application/user database IDs are not public identifiers or authorization credentials;
- authentication and authorization do not exist;
- no email/identifier/account-linking semantics exist;
- no PII-bearing user profile exists;
- no deletion/anonymization/retention lifecycle exists;
- no audit event is produced because no reachable security/admin mutation is introduced.

### Migration integrity/failure containment

- migrations are embedded, forward-only, ordered five-digit files;
- exactly one `Up` is allowed and `Down`, `NO TRANSACTION`, and `ENVSUB` are rejected;
- versions 1 and 2 remain immutable; version 3 is additive;
- migration execution is deadline-bound and serialized with advisory locking;
- normal migration integration evidence requires exactly applied positive versions 1/2/3 and exactly `application_instances`, `users`, and `goose_db_version` tables;
- rerun idempotency and concurrent convergence remain tested;
- a synthetic version-4 failure proves transactional rollback and failed-version non-recording.

### CI/test baseline

Current CI runs:

- `gofmt -l .` verification;
- `go vet ./...`;
- `go test ./...`;
- PostgreSQL integration tests for platform database, migration, application-instance persistence, and identity/user persistence;
- `go test -race ./...`.

Go dependencies remain versioned/checksummed in `go.mod`/`go.sum`.

## 7. Threat analysis

| Threat | Current mitigation | Residual/required control |
| --- | --- | --- |
| Cross-application user IDOR at persistence layer | User resolve predicates on both trusted application scope and user ID; adversarial A/B tests require foreign-scope lookup to return not found. | First reachable caller must authenticate and separately authorize server-selected scope; future child repositories need equivalent scoped predicates/constraints. |
| Orphan user rows | `NOT NULL` FK to `application_instances`; real PostgreSQL test attempts create under nonexistent positive scope and verifies no row is created. | Future schema changes must preserve referential meaning and backup/restore consistency. |
| Client-selected tenant authority | No public product route currently selects scope; internal IDs are documented non-authoritative. | First reachable product/admin path must derive trusted scope from authenticated/authorized server context. |
| Internal DB key becoming public contract | Models/docs define IDs as storage-internal; no JSON/API contract exists. | First public application/user resource contract must independently ratify opaque public ID encoding/compatibility. |
| SQL/provider/topology leakage | Migration/application/user/database failures map to stable BeeBox-owned errors. | Future repositories/providers/telemetry require the same mapping/redaction evidence. |
| Database outage/partition | Bounded readiness and context-aware persistence; safe persistence failure categories. | Reachable operations must later define retry/idempotency/user-facing outage semantics. |
| Unauthorized schema mutation | Explicit migration mode; no serve-time migration; no arbitrary runtime migration source. | Production DB privileges remain an operational trust boundary. |
| Unsafe rollback/divergent schema | Additive versions 2/3, forward-only policy, transactional migrations. | Once data/references exist, destructive rollback is unsafe; use reviewed roll-forward changes. |
| PII exposure | Current user rows contain no PII/profile/identifier data. | First PII/identifier slice must define minimization, redaction, normalization, uniqueness and safe telemetry. |
| Account takeover/linking ambiguity | No identifier/social/provider account exists. | First identifier/account-linking slice must explicitly ratify semantics and anti-enumeration/takeover controls. |
| Authentication confused with authorization | Neither exists today, so no false claim is made. | Authentication establishes identity; separate default-deny authorization must select scope for reachable operations. |
| Missing security audit fact | Persistence primitives are unreachable internal operations, not security/admin actions. | First reachable user/admin lifecycle must record complete audit facts per contract conventions and preserve them across later async failure. |
| Missing user deletion lifecycle | No delete/soft-delete API or column exists. | First real user lifecycle requiring deletion must define deletion/anonymization, retention, downstream cleanup, backup/restore and referential behavior. |
| Dependency/CI supply-chain compromise | Versioned Go deps and current-head CI. | Actions remain moving major tags; no dedicated SBOM/provenance/signing control exists. |
| Insecure transport | No repository proof of production HTTP/PostgreSQL TLS. | Transport ownership must be defined before production/public exposure. |

## 8. Ratified root isolation decision

ADR 0001 remains unchanged:

- `application_instance` is the BeeBox v1 root product isolation resource;
- every child row belongs to exactly one root unless a later reviewed design adds another applicable scope;
- organization is additional only where organization ownership actually applies and is not the root tenant;
- workspace/application/environment hierarchy is not required in v1 but may be introduced additively with evidence;
- database primary keys remain internal implementation details;
- public application/user ID encodings remain future explicit compatibility decisions.

The `users` table is the first child implementation of that decision through an explicit FK and application-scoped repository lookup.

## 9. Future controls required with corresponding capabilities

### First verified identifier / authentication flow

The introducing slice must define:

- identifier normalization and database uniqueness semantics;
- verified/unverified state and anti-enumeration behavior;
- account-linking/takeover prevention with explicit approval for semantics;
- reviewed password/crypto primitives where applicable;
- replay/attempt/recovery behavior;
- PII minimization/redaction;
- audit evidence for security-sensitive mutations.

### First reachable user/admin lifecycle

The current user `Create` is only an internal persistence primitive. A reachable lifecycle must separately define:

- authentication;
- default-deny authorization and server-selected application scope;
- idempotency/retry/replay/concurrency/transaction behavior;
- complete security/admin audit evidence per `docs/contracts/conventions.md`;
- stable public errors and separately ratified public resource IDs;
- abuse/rate/resource controls and operational failure behavior.

### First state-changing public API

The introducing slice must define versioned BeeBox-owned contracts, authentication plus separate authorization, bounded inputs, deterministic validation/safe errors, idempotency/retry/replay/concurrency, applicable browser-origin/CSRF protections, audit, observability and redaction.

### First session/token/key capability

The introducing slice must explicitly decide algorithm/issuer/audience/authorized-party/lifetime/rotation/revocation semantics and use cryptographic generation/hashed storage where lifecycle permits.

### First PII-bearing profile surface

The introducing slice must define field purpose, visibility, size bounds, redaction/logging policy, retention/export/deletion behavior and applicable authorization.

### First user deletion lifecycle

Before deletion is claimed complete, define deletion/anonymization, retention, referential behavior, downstream cleanup, backup/restore implications, retry/partial failure, authorization and audit.

## 10. Data lifecycle, assumptions and residual risks

1. Application-instance rows remain durable roots; no root delete lifecycle exists.
2. User rows are durable application-scoped identity records in this persistence slice; no delete/anonymize lifecycle exists.
3. Backup/restore must preserve root/user internal identities and their foreign-key relationship. No repository automation currently verifies production backup/restore.
4. Separate runtime/migration DB principals are recommended but not code-enforced.
5. PostgreSQL remains required for serving; no failover/degraded product mode exists.
6. No identifiers or profile PII exist yet.
7. Persistence-level scoping tests do not prove HTTP/user authorization because no reachable product caller exists.
8. Go dependencies and GitHub Actions remain trusted build inputs; dedicated supply-chain controls are incomplete.

## 11. Review/update triggers

Update/review this model when a PR introduces or changes:

- another child product schema/table/repository or organization-scoped resource;
- email/phone/username identifiers or user profile PII;
- a reachable user/application/admin lifecycle or public product API;
- public application/user identifier encoding/compatibility;
- authentication, account linking, MFA, recovery, sessions, tokens, cookies, API keys, OAuth, or impersonation;
- product logging/tracing/metrics/audit/events/webhooks/queues/Redis/workers/providers;
- deletion/retention/backup/restore behavior;
- migration behavior, database privilege assumptions, or schema rollout strategy;
- public deployment/TLS/proxy/domain/secret-management/production DB configuration;
- CI permissions, third-party Actions, dependency/provenance/signing/release workflow;
- a new network/service boundary or service extraction;
- a security incident or security-relevant ADR.

## 12. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing, audit and change-control invariants.
- `docs/adr/0001-application-instance-root.md` — Human-ratified v1 root isolation decision.
- `docs/contracts/conventions.md` — ID/error/idempotency/time/versioning/audit/tenancy semantics.
- `internal/platform/migration/sql/00002_application_instances.sql` — root table.
- `internal/platform/migration/sql/00003_users.sql` — first child table, explicit root FK and timestamp invariant.
- `internal/platform/migration/*` — forward migration validation, advisory locking, transactional failure behavior and exact migration-state tests.
- `internal/applicationinstance/*` — internal root model and concrete persistence.
- `internal/identity/user.go` — BeeBox-owned scoped user model and stable errors; no public wire representation.
- `internal/identity/postgres/store.go` — context-aware atomic create and exact application-scoped resolve using the process-owned pool.
- `internal/identity/postgres/store_integration_test.go` — A/B cross-scope denial, invalid/missing IDs, FK orphan prevention, concurrency, cancellation and safe-error evidence.
- `internal/platform/database/*` — process-owned pgx pool and temporary `database/sql` adapter behavior.
- `.github/workflows/ci.yml` — formatting, vet, unit, database/migration/application-instance/user integration and race checks.
- `README.md` / `CONTRIBUTING.md` — current scope, migration behavior and repository-native verification commands.
