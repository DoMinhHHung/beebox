# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this PR.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, `docs/adr/0001-application-instance-root.md`, and `docs/adr/0002-email-identity-v1.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration mode, `application_instance` root persistence, application-scoped users, application-scoped email identifiers, repository configuration, and CI.

## 1. Purpose and scope

This document records security properties demonstrated by the current repository, threats that already apply, and controls future identity/product slices must add as their attack surface appears.

It distinguishes three states:

1. **Implemented now** — present in current code, schema, tests, or CI and grounded in repository evidence.
2. **Required invariant** — required by repository instructions, contract conventions, or accepted ADRs and must be implemented by the slice that introduces the corresponding behavior.
3. **Deferred capability control** — not meaningful until the corresponding capability exists, but not permission to defer a correctness requirement after that capability is introduced.

ADR 0001 ratifies `application_instance` as the BeeBox v1 root product-isolation resource. ADR 0002 ratifies application-scoped email identity semantics. Neither ADR ratifies permanent public application/user/email identifier encoding, a universal organization tenant model, token/JWT trust boundaries, Clerk compatibility, or future service data ownership.

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
- version 3 additive application-scoped `users` child table;
- version 4 additive application-scoped `email_identifiers` plus the scoped referenced-key constraint required for the composite user foreign key.

Current internal persistence includes:

- application-instance create/exact resolve;
- application-scoped user create and exact `(application scope, user ID)` resolve;
- email-identifier create under trusted `(application scope, user ID)` and resolve by `(application scope, normalized email)`.

Email addresses are the first persisted BeeBox product PII. New email identifiers start unverified (`verified_at IS NULL`). The repository contains no operation that marks an identifier verified.

There is **no reachable application/user/admin identity lifecycle**. There is still no email delivery, OTP/link verification, password, signup/signin, authentication, authorization, session/token behavior, organization resource, public identifier lookup, public application/user/email ID, public product API, SDK, account-linking operation, primary-email behavior, or product audit subsystem.

## 3. Assets

### Current assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Reject invalid startup state, bound I/O, clean up deterministically, and expose truthful health. |
| PostgreSQL connectivity/state | Do not report ready while PostgreSQL is unavailable; do not leak provider/topology details. |
| Migration integrity/history | Run only reviewed embedded forward migrations; serialize concurrent runners; do not record failed transactional migrations as applied. |
| `application_instances` root rows | Preserve distinct internal identities and exact root resolution. |
| `users` child rows | Every row belongs to exactly one existing application instance; scoped lookup must not cross roots. |
| `email_identifiers` rows | Preserve application/user ownership, normalized-email uniqueness inside one application, explicit verification state, and stored email PII. |
| Email PII | Prevent unnecessary disclosure in errors, logs, metrics, traces, fixtures, review evidence, backups, and future APIs. |
| Internal application/user/email identities | Storage-only keys for trusted persistence; never authorization tokens or permanent public resource-ID contracts. |
| Scoped relationships | PostgreSQL referential integrity must preserve application -> user -> email ownership and survive backup/restore consistently. |
| Runtime/migration configuration | Fail invalid values safely; database URLs may contain credentials and are secret-bearing inputs. |
| Database credentials | Runtime and migration privileges have different blast radii; credential values must not leak. |
| Repository/CI integrity | Source, migrations, dependencies, workflows, and test evidence are part of the trusted build/release base. |

### Future high-value assets

Verified identifier evidence, credentials, password/OTP secrets, authentication factors, sessions/tokens, organization membership, authorization state, audit records, and additional profile PII do not exist yet. Once introduced, confidentiality, integrity, replay resistance, application isolation, applicable organization isolation, deletion/retention, and auditability are merge-blocking properties.

## 4. Actors

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach health endpoints if deployment networking exposes them. No product route exists. Untrusted. |
| Malicious external actor | May attempt probing, credential theft, dependency exploitation, future identifier enumeration, account takeover, or cross-scope access. Untrusted. |
| Operator | Supplies environment configuration and controls serve/migration process execution. Mistakes/credential compromise are in scope. |
| Runtime process | Owns the PostgreSQL pool and HTTP health surface; no product handler currently calls identity persistence. |
| Trusted internal persistence caller | May supply trusted application scope, user identity, and raw email to internal stores. No public/client path currently establishes this trust. |
| Migration operator/process | Performs reviewed DDL with a migration-capable credential; compromise has a larger integrity blast radius. |
| PostgreSQL | Source of truth/external dependency. Server authorization/network/storage controls are outside the Go process boundary. |
| CI/test environment | Builds/tests code and starts disposable PostgreSQL with synthetic test-only values. Third-party Actions are supply-chain inputs. |

## 5. Trust boundaries and entry points

### A. Network client -> HTTP runtime

Current handlers accept no product body, email, user identity, application-instance identity, token, organization identifier, cookie, or bearer credential.

### B. Runtime/persistence -> PostgreSQL

Current interactions include startup/readiness checks, migration SQL/goose metadata, application-instance persistence, application-scoped user persistence, and application-scoped email-identifier persistence. PostgreSQL/provider errors are untrusted for direct exposure.

### C. Trusted server scope -> application-instance store

The root store accepts storage-internal identity as trusted server-selected persistence scope. This is persistence behavior, not authorization.

### D. Trusted server scope -> user store

User resolve requires both trusted application scope and internal user ID. A valid foreign user ID resolves as not found under another application. There is no unscoped user lookup.

### E. Trusted server scope/user -> email-identifier store

Email create requires a positive trusted application scope, a positive internal user identity, and a valid BeeBox-v1 mailbox. PostgreSQL verifies that the selected user belongs to the same selected application using a composite foreign key.

Email resolve normalizes the mailbox using the same domain function and queries by both `application_instance_id` and `normalized_email`. There is no global email lookup or fallback.

**Limit:** persistence-level scoping is implemented; authentication and authorization that establish trusted scope are not.

### F. Operator/environment -> runtime configuration

Current configuration includes the database URL, HTTP address, lifecycle timeouts, and process-mode arguments.

### G. Migration operator/process -> PostgreSQL

`beebox migrate` intentionally crosses a schema-mutation boundary. Serve mode does not automatically migrate.

### H. CI -> disposable test PostgreSQL

CI runs format, vet, unit, database/migration/application-instance/identity PostgreSQL integration, and race checks. Email integration uses only synthetic `example.test` mailbox values.

## 6. Existing controls verified now

### Configuration and credential-safe errors

- configuration/database/readiness/migration failures use stable safe categories;
- provider/SQL/topology/credential details are not returned by current stable error paths;
- identity persistence maps provider failures to BeeBox-owned error categories.

### Bounded runtime and persistence I/O

- startup/readiness/migration work is deadline-bound;
- HTTP server and graceful shutdown have explicit bounds;
- one process-owned pgx PostgreSQL pool is reused;
- stores accept `context.Context`, preserve cancellation/deadline failure, and use temporary `database/sql` adapters backed by the existing pool;
- temporary adapters close without closing the underlying process pool.

### Application-instance and user persistence

Implemented now:

- database-generated internal identities;
- `TIMESTAMPTZ` server-owned creation time;
- `users.application_instance_id` is `NOT NULL` with a real root FK;
- user resolve predicates on both application scope and user ID;
- cross-application user lookup returns not found;
- FK tests prevent orphan users;
- database failures map to stable safe internal categories;
- concurrent inserts retain distinct generated identities.

### Application-scoped email identity persistence

Implemented now:

- `email_identifiers` stores explicit `application_instance_id`, `user_id`, case-preserving `email_address`, lowercase `normalized_email`, nullable `verified_at`, and `created_at`;
- a composite FK `(application_instance_id, user_id) -> users(application_instance_id, id)` prevents assigning an email claim to a user from another application;
- PostgreSQL uniqueness on `(application_instance_id, normalized_email)` is the concurrency source of truth;
- the same normalized mailbox is allowed in different application instances;
- duplicate normalized mailboxes inside one application return a stable conflict and never reassign/merge/link users;
- duplicate creation for the same user also conflicts rather than becoming implicit idempotency;
- new identifiers are unverified and there is no verification mutation in this slice;
- email create uses one atomic insert with no SELECT-then-INSERT uniqueness pre-check;
- email resolve always includes trusted application scope and normalized mailbox;
- cross-application and cross-user adversarial tests exercise real PostgreSQL constraints;
- concurrent case/space variants that normalize identically produce exactly one committed row and stable conflicts for losers;
- returned timestamps are normalized to UTC;
- stable email errors contain no email address, SQLSTATE, SQL, constraint name, credential, or topology detail.

### BeeBox v1 email normalization

Implemented domain policy:

- ASCII mailbox addresses only;
- surrounding ASCII spaces are trimmed;
- CR/LF/control characters and non-ASCII input are rejected;
- mailbox-only syntax is validated with Go standard-library parsing while display-name forms are rejected;
- accepted mailbox length is bounded;
- stored mailbox preserves trimmed input case;
- comparison key lowercases the complete mailbox;
- dots and plus tags are preserved;
- no Gmail/Workspace/Outlook/Yahoo/provider alias transformations are performed;
- SMTPUTF8/internationalized mailbox semantics are unsupported in this slice.

This is a BeeBox v1 comparison policy, not a claim about universal SMTP local-part semantics or complete RFC 5322 compatibility.

### PII minimization boundary

- email is explicitly classified as PII in model/docs;
- this PR adds no email logging, metrics, tracing, events, or public responses;
- stable errors do not include raw email;
- tests/docs use reserved synthetic `example.test` addresses rather than real-person fixtures.

**Important limits:** PostgreSQL/storage/backup encryption, production access controls, retention, export, deletion, anonymization, and compliance programs are not implemented by this repository slice.

### Migration integrity/failure containment

- migrations are embedded, forward-only, ordered five-digit files;
- exactly one `Up` is allowed and `Down`, `NO TRANSACTION`, and `ENVSUB` are rejected;
- versions 1/2/3 remain immutable; version 4 is additive and transactional under existing defaults;
- normal migration evidence requires exactly applied positive versions 1/2/3/4 and tables `application_instances`, `users`, `email_identifiers`, and `goose_db_version`;
- rerun idempotency and concurrent convergence remain tested;
- synthetic version-5 failure proves transactional rollback and failed-version non-recording.

### CI/test baseline

Current CI runs:

- `gofmt -l .` verification;
- `go vet ./...`;
- `go test ./...`;
- PostgreSQL integration for database, migration, application-instance, user, and email-identifier persistence;
- `go test -race ./...`.

## 7. Threat analysis

| Threat | Current mitigation | Residual/required control |
| --- | --- | --- |
| Cross-application email leakage | Email resolve predicates on trusted application scope + normalized email; same mailbox can coexist independently across applications; A/B tests verify isolation. | First reachable lookup must authenticate and separately authorize server-selected scope; no public lookup exists now. |
| Cross-application user/email ownership mismatch | Composite FK requires `(application_instance_id, user_id)` to identify a real user in the same application; adversarial cross-app owner insert fails. | Future schema changes must preserve scoped referential integrity. |
| Normalization/case collision | One deterministic domain normalizer plus PostgreSQL `(app, normalized_email)` uniqueness; concurrent variants converge to one row. | Any future normalization-policy change is compatibility/security-sensitive and requires migration/review. |
| Account takeover through automatic linking | ADR 0002 forbids auto-link/merge/reassignment; same-app duplicate always conflicts, including unverified claims. | Explicit linking/merge requires a separately reviewed verified-identity lifecycle and takeover analysis. |
| Email enumeration | No reachable product/public email lookup exists. | First signup/signin/recovery/identifier lookup must map internal found/not-found/conflict states to anti-enumerating public behavior with abuse controls. |
| PII leakage | No email logging/metrics/tracing/public output; stable errors omit email/provider diagnostics; synthetic fixtures only. | Future telemetry, providers, support/admin APIs, exports, backups, and incidents require explicit minimization/redaction/access policy. |
| Unverified email treated as trusted | New records have `verified_at = NULL`; no verification transition exists. | Verification slice must define OTP/link cryptography, expiry, replay, attempt budgets, delivery, transaction semantics, audit, and takeover resistance. |
| Verification replay/attempt abuse | Verification capability does not exist. | Required when verification is introduced: bounded attempts, expiry, replay resistance, resend/rate policy, audit, and anti-enumeration. |
| Cross-application user IDOR | User resolve predicates on application scope + user ID. | First reachable caller must authenticate and authorize trusted scope. |
| Internal DB keys becoming public authority | Models/docs define DB identities as storage-internal; no public contract exists. | First public resource contract must ratify opaque BeeBox IDs independently and never derive authority from possession. |
| SQL/provider/topology leakage | Persistence/migration/database failures map to stable BeeBox errors. | Future providers/telemetry need equivalent safe mapping. |
| Database outage | Readiness is bounded; persistence honors context. | Reachable workflows must define retry/idempotency/user-facing failure semantics. |
| Unauthorized schema mutation | Explicit migration mode; no serve-time migration. | Runtime/migration production DB privilege separation remains operational policy. |
| Missing security audit fact | Current persistence primitives are unreachable internal operations. | First reachable identifier/user/admin mutation must create complete audit evidence per contract conventions; async email/provider failure cannot erase it. |
| Missing email deletion/export/retention lifecycle | No delete/export/retention API exists and no soft-delete column is claimed. | First reachable lifecycle requiring deletion/export must define authorization, audit, retention, backup handling, referential cleanup, retries, and partial failure. |
| Dependency/CI supply-chain compromise | Versioned Go deps and current-head CI. | Actions remain moving major tags; dedicated SBOM/provenance/signing is not evidenced. |
| Insecure transport/storage | No repository proof of production HTTP/PostgreSQL TLS or encryption-at-rest policy. | Define/enforce production transport/storage ownership before public production claims. |

## 8. Ratified identity decisions

### ADR 0001 — root isolation

- `application_instance` remains the BeeBox v1 root isolation resource;
- organization is not the root tenant;
- public application/user IDs remain separate future compatibility decisions.

### ADR 0002 — email identity v1

- email identity is application-scoped, not globally unique;
- one normalized email belongs to at most one user inside an application;
- same normalized email may belong to independent users in different applications;
- matching email never automatically links/merges/reassigns accounts;
- an unverified claim never links accounts;
- new claims start unverified;
- v1 comparison is ASCII, outer-space-trimmed, full-mailbox lowercase with case-preserving stored address and no provider-specific alias transformations;
- SMTPUTF8, public ID encoding, primary-email UX, and explicit linking remain deferred.

## 9. Future controls required with corresponding capabilities

### First email verification flow

The introducing slice must define:

- verification proof/token/OTP generation using reviewed cryptographic randomness where applicable;
- expiry, one-time/replay semantics, bounded attempts, resend/rate behavior, and concurrency;
- email provider/delivery timeout, safe retry classification, and failure semantics;
- transaction boundary for setting `verified_at`;
- anti-enumeration and takeover resistance;
- complete required security audit evidence;
- redaction of email/provider/secret data.

### First reachable signup/signin/identifier lookup

The introducing slice must add authentication-flow semantics, separate authorization where applicable, server-selected application scope, anti-enumerating public errors, abuse/rate controls, idempotency/retry/replay behavior for mutations, and public BeeBox-owned versioned contracts.

Internal `ErrEmailIdentifierNotFound` and `ErrEmailConflict` do not authorize a public response that reveals identifier existence.

### Explicit account-linking lifecycle

A future linking/merge lifecycle requires a separate reviewed decision. It must rely on verified identity evidence, protect against account takeover, define conflicts/recovery/rollback, preserve application scope, and create required audit evidence. Email-string equality alone is insufficient.

### First password/authentication capability

Use reviewed password hashing/crypto primitives, define attempt budgets/recovery, separate authentication from authorization, and preserve anti-enumeration and audit requirements.

### First state-changing public API

Define versioned BeeBox contracts, authenticated and separately authorized server-selected scope, bounded inputs, stable safe errors, idempotency/retry/replay/concurrency, browser-origin protections where applicable, audit, observability, and PII redaction.

### First user/email deletion, export, or retention lifecycle

Before claiming completion, define deletion/anonymization, retention periods, export authorization/format, downstream cleanup, backup implications, referential behavior, retry/partial failure, and audit evidence. Email PII must be included explicitly.

### First session/token/key capability

Explicitly decide algorithm/issuer/audience/authorized-party/lifetime/rotation/revocation semantics and use cryptographic generation/hashed storage where lifecycle permits.

## 10. Data lifecycle, assumptions and residual risks

1. Application-instance rows remain durable roots; no root delete lifecycle exists.
2. User rows remain durable application-scoped identity records; no user deletion/anonymization lifecycle exists.
3. Email-identifier rows are durable PII-bearing records in this persistence slice; no email deletion/export/retention lifecycle exists.
4. Backup/restore must preserve application/user/email identities and relationships. Backup handling now includes email PII; repository automation does not verify production backup/restore or deletion from historical backups.
5. Separate runtime/migration DB principals are recommended but not code-enforced.
6. PostgreSQL remains required for serving; no failover/degraded product mode exists.
7. Persistence-level scoping does not prove HTTP authorization because no reachable product caller exists.
8. Go dependencies and GitHub Actions remain trusted build inputs; dedicated supply-chain controls are incomplete.
9. Email verification is not implemented; stored email claims must not be treated as verified identity evidence.
10. No GDPR or other regulatory compliance claim is made by this slice.

## 11. Review/update triggers

Update/review this model when a PR introduces or changes:

- email verification, OTP/link delivery, provider integration, resend or attempt logic;
- email normalization, uniqueness, account linking/merging, primary-email semantics, or SMTPUTF8 support;
- another identifier type or PII-bearing profile field;
- a reachable user/application/admin lifecycle or public product API;
- public application/user/email identifier encoding/compatibility;
- authentication, recovery, MFA, sessions, tokens, cookies, API keys, OAuth, or impersonation;
- product logging/tracing/metrics/audit/events/webhooks/queues/Redis/workers/providers;
- deletion/anonymization/export/retention/backup/restore behavior;
- migration behavior, database privilege assumptions, or schema rollout strategy;
- public deployment/TLS/proxy/domain/secret-management/production DB configuration;
- CI permissions, third-party Actions, dependency/provenance/signing/release workflow;
- a new network/service boundary or service extraction;
- a security incident or security-relevant ADR.

## 12. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing, audit and change-control invariants.
- `docs/adr/0001-application-instance-root.md` — Human-ratified v1 root isolation decision.
- `docs/adr/0002-email-identity-v1.md` — Human-ratified email scope, normalization, uniqueness, verification-state, and no-auto-link decision.
- `docs/contracts/conventions.md` — ID/error/idempotency/time/versioning/audit/tenancy semantics.
- `internal/platform/migration/sql/00002_application_instances.sql` — root table.
- `internal/platform/migration/sql/00003_users.sql` — application-scoped user table.
- `internal/platform/migration/sql/00004_email_identifiers.sql` — scoped email PII table, composite user FK and per-app normalized uniqueness.
- `internal/platform/migration/*` — forward migration validation, advisory locking, transactional failure behavior and exact migration-state tests.
- `internal/identity/email.go` / `email_test.go` — BeeBox v1 normalization, internal email model, stable errors, and deterministic validation evidence.
- `internal/identity/postgres/email_store.go` — scoped atomic create/resolve and safe conflict/error classification using the process-owned pool.
- `internal/identity/postgres/email_store_integration_test.go` — same-app conflicts, cross-app same-email coexistence, composite-FK rejection, unverified state, concurrency and safe-error evidence.
- `internal/identity/postgres/store.go` / `store_integration_test.go` — application-scoped user persistence and adversarial root isolation evidence.
- `internal/platform/database/*` — process-owned pgx pool and temporary `database/sql` adapter behavior.
- `.github/workflows/ci.yml` — formatting, vet, unit, database/migration/application-instance/identity integration and race checks.
- `README.md` / `CONTRIBUTING.md` — current scope, PII boundary, migration behavior and repository-native verification commands.
