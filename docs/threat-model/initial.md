# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this PR.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, `docs/adr/0001-application-instance-root.md`, and `docs/adr/0002-email-identity-v1.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration mode, application-scoped users/email/password credentials, internal audit persistence, transactional email/password registration, repository configuration, and CI.

## 1. Purpose and scope

This document records controls actually implemented by the current repository and the security work that remains required before internal identity primitives become reachable product behavior.

It distinguishes:

1. **Implemented now** — present in code/schema/tests/CI.
2. **Required invariant** — repository policy that the introducing slice must satisfy.
3. **Deferred capability control** — not meaningful until the capability exists, but mandatory once it does.

ADR 0001 keeps `application_instance` as the BeeBox v1 root isolation resource. ADR 0002 keeps email application-scoped, unverified by default, and forbids automatic account linking from email equality. This registration core changes neither decision and does not ratify public IDs, public password policy, token/session trust boundaries, public API compatibility, or future service ownership.

## 2. Current architecture and security posture

BeeBox remains one Go deployable. Serve mode exposes only health endpoints and never auto-migrates. `beebox migrate` explicitly applies embedded forward migrations.

Embedded migrations now contain:

- version 1 runtime baseline;
- version 2 `application_instances`;
- version 3 application-scoped `users`;
- version 4 application-scoped `email_identifiers` and scoped user referenced key;
- version 5 application-scoped `password_credentials`;
- version 6 application-scoped `audit_events`.

Current internal identity/authentication behavior includes:

- application-instance create/exact resolve;
- application-scoped user create/resolve;
- application-scoped email identifier create/resolve with deterministic ASCII normalization and no-auto-link conflict semantics;
- Argon2id password hashing and application-scoped password credential persistence;
- `RegisterEmailPassword`, which hashes the password before DB I/O and then atomically creates a user, unverified email identifier, password credential, and successful registration audit fact in one PostgreSQL transaction.

There is still **no reachable/public signup or authentication lifecycle**. No HTTP product route, OTP/email delivery, email verification transition, signin, public password policy, attempt/rate/lockout control, password reset/change, session/token behavior, public IDs, or account-linking lifecycle exists.

## 3. Assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Bounded I/O and truthful health behavior. |
| PostgreSQL state | Correct scoped relationships and atomic registration state. |
| Migration history | Embedded forward-only ordered migrations; failed transactional migrations are not recorded. |
| Application/user rows | Root and child identities remain explicitly application-scoped. |
| Email identifiers | Per-application normalized uniqueness, same-app user ownership, explicit unverified state, PII protection. |
| Password credentials | One credential per scoped user; plaintext absent; same-app ownership enforced. |
| Raw password bytes | Transient secret input to hashing only; never persisted/logged. |
| Password hashes | Sensitive credential-derived data; protected from logs/errors/telemetry and registration results. |
| Audit facts | Immutable internal correctness evidence for committed security actions; scoped, minimized, and correlated. |
| Email PII | Must not leak into audit rows, stable errors, logs, metrics, traces, fixtures, or support evidence. |
| Database/backups | Contain email PII and password hashes; compromise enables privacy loss and offline password guessing. |
| Internal IDs/correlation IDs | Storage/operation identifiers only; never public compatibility or authorization primitives. |

## 4. Actors and trust assumptions

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach health endpoints only; registration has no HTTP/public caller. |
| Malicious external actor | Future duplicate-registration, enumeration, brute-force, abuse and reset attacks become applicable when auth is reachable. |
| Trusted internal caller | May invoke registration with a trusted application scope; this PR does not define how a client obtains that trust. |
| Anonymous registration actor | Internal audit representation for the currently unauthenticated registration operation; not a fake authenticated user. |
| Operator/migration operator | Controls configuration/process execution and migration-capable DB access. |
| PostgreSQL / backup storage | Source of truth and sensitive persistence boundary. |
| CI | Executes synthetic unit and real PostgreSQL integration tests. |

## 5. Trust boundaries and entry points

### Network -> HTTP runtime

Current HTTP handlers remain health-only and accept no registration, password, email, application scope, token, cookie, or product mutation.

### Trusted server code -> registration application operation

`RegisterEmailPassword` accepts a trusted internal application scope, raw email, and raw password. It:

1. validates application scope;
2. reuses `identity.NormalizeEmail` exactly;
3. reuses the existing Argon2id `HashPassword` primitive;
4. generates a cryptographically random 16-byte internal correlation/operation identifier;
5. re-checks context cancellation;
6. passes normalized email, derived password hash and correlation ID to one transactional persistence boundary.

Password hashing happens before the database transaction so the 64 MiB Argon2 derivation does not unnecessarily occupy a DB connection/transaction.

### Registration transaction -> PostgreSQL

One transaction performs, in order:

1. insert application-scoped user;
2. insert application-scoped unverified email identifier;
3. insert application-scoped password credential;
4. insert successful security audit fact;
5. commit.

Any pre-commit failure rolls the transaction back. Registration state does not commit first and add audit afterward.

### Audit fact -> scoped user references

`audit_events.application_instance_id` is mandatory. Nullable actor/subject user references use composite `(application_instance_id, user_id)` foreign keys, so a user from application B cannot be referenced as actor/subject in an application-A audit fact. Registration uses anonymous actor kind and the newly created scoped user as subject.

## 6. Existing controls verified now

### Registration atomicity

Implemented:

- one database transaction for user + email + password + success audit;
- no distributed transaction, outbox, worker, queue or Kafka;
- duplicate email conflict rolls back the attempted user and leaves no loser credential/audit state;
- forced password-write failure rolls back user/email and leaves no audit success;
- forced audit-write failure rolls back user/email/password;
- nonexistent application fails without registration rows;
- cancellation is preserved causally and leaves no partial state;
- integration tests count complete bundles rather than checking only a happy-path return value.

### Duplicate/no-auto-link behavior

- email normalization remains ADR 0002 exactly;
- `(application_instance_id, normalized_email)` database uniqueness remains the concurrency source of truth;
- duplicate registration inside one application returns a stable internal registration conflict;
- duplicate registration never adopts/reuses the existing user, attaches a password to it, merges users, or becomes implicit login;
- the same normalized email may register independently in different application instances.

### Concurrency

Concurrent same-application variants that normalize to one email rely on PostgreSQL uniqueness. Tests precompute the expensive password hash before the DB race and prove exactly one complete user/email/password/audit bundle commits; losers leave no orphan users, credentials, or audit success facts. No mutex, Redis, distributed lock, or SELECT-before-INSERT is used.

### Audit correctness/minimization

`audit_events` requires:

- internal immutable generated event ID;
- explicit application scope;
- nonempty actor kind, action, resource category, outcome and source;
- required 16-byte correlation identifier with database uniqueness;
- required occurrence time from PostgreSQL;
- scoped nullable actor/subject user references;
- no `ON DELETE CASCADE`.

Registration success audit semantics are:

- actor: anonymous/internal unauthenticated registration actor;
- subject: newly created user;
- action: stable internal email/password registration action;
- resource: logical user-registration category;
- outcome: success;
- source: internal registration use case;
- correlation: cryptographically random internal operation identifier.

Audit rows intentionally contain no raw email, password, password hash, IP, user agent, or invented request metadata. Public audit schema, public event IDs, query/export/search/pagination, retention implementation and delivery infrastructure remain unratified.

### Password secret handling

- Argon2id parameters remain version 19, time 3, memory 65536 KiB, parallelism 4, random 16-byte salt, 32-byte derived hash;
- raw password bytes are not trimmed/normalized and are never sent to PostgreSQL;
- password is hashed before DB transaction acquisition;
- registration results expose only `User` and `EmailIdentifier`, never `PasswordHash`;
- stable registration errors do not contain password/hash/provider/SQL details;
- the 1024-byte internal bound remains resource protection, not public password policy.

### Migration integrity

- migrations remain embedded, Up-only and transactional under existing runner defaults;
- merged migrations 1-5 remain immutable;
- migration 6 is additive and contains no Down, ENVSUB, NO TRANSACTION, backfill, destructive rewrite, cascade delete, queue/outbox infrastructure or public schema;
- exact normal migration state is versions 1/2/3/4/5/6;
- exact table set includes `application_instances`, `audit_events`, `email_identifiers`, `goose_db_version`, `password_credentials`, and `users`;
- synthetic transactional failure is version 7;
- rerun idempotency, advisory locking, cancellation, concurrent convergence and failed-version non-recording remain tested.

## 7. Threat analysis

| Threat | Implemented mitigation | Residual / required future control |
| --- | --- | --- |
| Partial registration | One transaction spans user/email/password/audit; forced component failures prove rollback. | Future provider/verification work must define its own transaction/async boundaries without weakening committed state. |
| Orphan loser users during duplicate race | Email uniqueness is DB-enforced inside the same transaction; loser user insert is rolled back. | Public signup still needs request idempotency/retry semantics. |
| Missing audit after successful security mutation | Success audit insert is inside the registration transaction before commit. | Future reachable rejected/abusive attempts need an explicit audit policy. |
| Account takeover via duplicate-email adoption | Duplicate same-app registration conflicts; no auto-link/adoption/merge. | Explicit linking requires separately reviewed verified-identity proof. |
| Cross-application registration leakage | Every product/audit write carries application scope; same email can coexist independently across roots. | Future handler must derive trusted application scope server-side; client input alone cannot authorize it. |
| Cross-application audit actor/subject reference | Composite scoped FKs reject foreign-app user references. | Future audit resources must preserve correct scope constraints. |
| PII/secret leakage | Audit omits email/password/hash; stable errors/logging surfaces added by this PR omit them. | Reachable handlers, telemetry, providers and support tools must preserve minimization/redaction. |
| Offline password cracking | Argon2id + random salt; plaintext absent. | Public password policy, breach screening, backup/access hardening remain future work. |
| Argon2 resource exhaustion | Password input bounded; hashing occurs outside DB transaction. | Reachable signup/signin must add request concurrency, rate, attempt and abuse controls. |
| Email enumeration | No public registration/signin/lookup exists. | Reachable flows must map internal conflict/not-found state to anti-enumerating public behavior. |
| Audit correlation omission | Internal registration always generates a required 16-byte correlation ID. | Future HTTP work should propagate an inbound/request operation ID when appropriate rather than omit correlation. |
| Database/provider detail leakage | Transaction errors map to stable registration conflict/persistence categories. | Public API mapping must remain safe and anti-enumerating. |

## 8. Reachability boundary

The registration core remains INTERNAL. No HTTP handler, `/v1` route, JSON signup contract, public application ID, browser flow, cookie, token, session or SDK calls it.

Therefore this PR does not claim a completed public signup lifecycle. The first reachable signup slice must still define:

- trusted server-selected application scope;
- versioned request/response contract and public resource-ID policy;
- public password policy (the internal 1024-byte bound is not that policy);
- anti-enumerating public errors;
- request idempotency/retry/replay behavior;
- abuse/rate/resource controls;
- which denied/abusive attempts require audit evidence;
- telemetry redaction and operational behavior.

## 9. Deferred security lifecycles

Still not implemented:

- email OTP/link verification, delivery, resend, expiry or attempt limits;
- `verified_at` mutation;
- email/password signin and online credential lookup;
- public password policy and breach screening;
- brute-force attempt budgets, throttling, CAPTCHA or lockout;
- password change/reset/recovery/history;
- sessions/tokens/cookies/JWT/JWKS and revocation behavior;
- public APIs/IDs;
- account linking/merging;
- audit query/export/search/pagination/retention APIs or infrastructure.

## 10. Data lifecycle and residual risks

1. Registration creates durable application-scoped user, email, password credential and audit records.
2. Email remains unverified until a separately reviewed verification lifecycle changes it.
3. No user/email/password/audit deletion or retention lifecycle is implemented.
4. Backups contain email PII, password hashes and audit metadata; backup access is security-sensitive.
5. Future user deletion must define credential and audit retention/referential behavior rather than relying on cascade deletion.
6. Password reset/change must define audit and session/token consequences once those capabilities exist.
7. Public failed-attempt audit semantics remain intentionally deferred until there is a real reachable source/threat model.
8. No GDPR or other compliance claim is made.

## 11. Review/update triggers

Review this model when a change introduces or changes:

- reachable/public signup;
- email verification/OTP/provider delivery;
- signin/password verification;
- password policy, breach screening, attempts/rate/lockout;
- password change/reset/recovery;
- sessions/tokens/cookies;
- account linking/merging;
- audit query/export/retention or external event delivery;
- public IDs/API contracts;
- identity/audit logging/tracing/metrics;
- deletion/retention/backup/restore behavior;
- migration/schema ownership or new service boundaries;
- production transport/storage/secret assumptions.

## 12. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing and audit invariants.
- `docs/contracts/conventions.md` — required audit fields, audit correctness boundary, safe errors, tenancy and idempotency rules.
- `docs/adr/0001-application-instance-root.md` — v1 root isolation.
- `docs/adr/0002-email-identity-v1.md` — email scope/no-auto-link/unverified semantics.
- `internal/audit/event.go` — BeeBox-owned internal audit semantics and correlation generation.
- `internal/authentication/registration.go` — application orchestration, existing normalizer/hasher reuse, pre-transaction hashing and internal-only result.
- `internal/authentication/postgres/registration_store.go` — single transaction for user/email/password/audit.
- `internal/authentication/postgres/registration_store_integration_test.go` — success bundle, duplicate rollback, forced failure rollback, concurrency, cross-app and audit-scope evidence.
- `internal/platform/migration/sql/00006_audit_events.sql` — scoped audit table constraints.
- `internal/platform/migration/*` — exact migration state and migration-safety evidence.
- `.github/workflows/ci.yml` — formatting, vet, unit, PostgreSQL integration and race checks.
- `README.md` / `CONTRIBUTING.md` — current internal-only scope and repository-native commands.
