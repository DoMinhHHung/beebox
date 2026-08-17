# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this PR.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, `docs/adr/0001-application-instance-root.md`, and `docs/adr/0002-email-identity-v1.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration mode, `application_instance` root persistence, application-scoped users, application-scoped email identifiers, internal Argon2id password hashing, application-scoped password credentials, repository configuration, and CI.

## 1. Purpose and scope

This document records controls actually implemented by the current repository and the security work that remains required when currently internal primitives become reachable product behavior.

It distinguishes:

1. **Implemented now** — present in code/schema/tests/CI.
2. **Required invariant** — repository policy that the introducing slice must satisfy.
3. **Deferred capability control** — not meaningful until the capability exists, but mandatory once it does.

ADR 0001 keeps `application_instance` as the root isolation resource. ADR 0002 keeps email application-scoped, unverified by default, and explicitly forbids automatic account linking from email equality. This password foundation does not change either decision and does not ratify public IDs, public password policy, account-linking, token trust boundaries, Clerk compatibility, or future service data ownership.

## 2. Current architecture and security posture

BeeBox remains one Go deployable. Serve mode validates configuration, opens one PostgreSQL pool, proves bounded connectivity, then exposes only health endpoints. `beebox migrate` explicitly applies embedded forward migrations and exits. Serve mode never auto-migrates.

Embedded migrations now contain:

- version 1 runtime baseline;
- version 2 `application_instances`;
- version 3 application-scoped `users`;
- version 4 application-scoped `email_identifiers` and the scoped referenced user key;
- version 5 application-scoped `password_credentials`.

Current internal identity/authentication persistence includes:

- application-instance create/exact resolve;
- application-scoped user create and exact scoped resolve;
- email-identifier create and application-scoped resolve-by-normalized-address;
- password-credential create and exact `(application_instance_id, user_id)` resolve.

Password hashing is an internal primitive based on `golang.org/x/crypto/argon2` Argon2id. BeeBox v1 uses Argon2 version 19, time cost 3, memory 64 MiB, parallelism 4, a cryptographically random 16-byte salt, and a 32-byte derived hash. The stored envelope is strict and internal. Raw password bytes are never stored in PostgreSQL.

There is **no reachable password authentication lifecycle**. No signup, signin, email+password lookup, public password verification, password policy, login-attempt accounting, lockout/rate limiting, password change/reset, session/token creation, authorization, or security audit subsystem exists.

## 3. Assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Bounded I/O and truthful health behavior. |
| PostgreSQL state | Correct scoped relationships and safe operational failures. |
| Migration history | Embedded forward-only ordered migrations; failed transactional migrations are not recorded. |
| Application/user rows | Root and child identities remain correctly scoped and internal. |
| Email identifiers | Per-application uniqueness, same-app ownership, explicit unverified state, PII protection. |
| Password credentials | One credential per scoped user in this slice; same-app user ownership enforced by PostgreSQL. |
| Password hashes | Sensitive credential-derived data; protect from logs/errors/telemetry and unnecessary exposure. |
| Raw password bytes | Transient secret input to hash/verify only; never persisted or logged. |
| Database/backups | Now contain email PII and password hashes; access compromise can enable offline attack. |
| Internal database IDs | Storage-only, never authorization or permanent public contracts. |
| Repository/CI | Source, dependencies, migrations and exact-head verification are trusted release inputs. |

## 4. Actors and trust assumptions

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach health endpoints only; no product auth route exists. |
| Malicious external actor | Future brute-force/enumeration/reset takeover are expected threats once auth is reachable. |
| Trusted internal caller | May invoke persistence/hash primitives inside server code; no public path currently establishes this trust. |
| Operator | Controls configuration and process execution; credential/storage mistakes remain in scope. |
| Migration operator | Has DDL authority for explicit reviewed migrations. |
| PostgreSQL / backup storage | Source of truth and sensitive credential-derived storage boundary. |
| CI | Executes synthetic tests, including real PostgreSQL integration. |

## 5. Trust boundaries and entry points

### Network -> HTTP runtime

Current HTTP handlers remain health-only and accept no password, email credential, user identity, application scope, token, cookie, or product mutation.

### Trusted server code -> password hashing primitive

`HashPassword` accepts exact raw bytes. It rejects empty and oversized input, performs no trim/case/Unicode normalization, generates salt with `crypto/rand`, and derives Argon2id output. `VerifyPassword` parses only the exact supported internal envelope, checks bounded field lengths and metadata before expensive Argon2 work, recomputes Argon2id, then uses constant-time comparison.

This primitive does not resolve a user, identify an email, authenticate a request, enforce attempts, authorize a scope, create a session, or emit an audit fact.

### Trusted server scope/user -> password credential store

Password credential create requires positive trusted application scope, positive internal user ID and a valid internal `PasswordHash`. PostgreSQL enforces `(application_instance_id, user_id) -> users(application_instance_id, id)` and uses `(application_instance_id, user_id)` as the primary key. There is no existence pre-read.

Resolve queries by both application scope and user ID. There is no global user-ID-only credential lookup or email fallback.

### Runtime -> PostgreSQL

Stores reuse the process-owned pgx pool through temporary `database/sql` adapters and preserve context cancellation/deadlines. Raw provider/SQL errors are classified into stable BeeBox-owned categories.

## 6. Existing controls verified now

### Argon2id password hashing

Implemented:

- official `golang.org/x/crypto/argon2` Argon2id primitive;
- version 19 / `v=19`;
- time cost 3;
- memory 65536 KiB;
- parallelism 4;
- random 16-byte salt from `crypto/rand`;
- 32-byte derived hash;
- strict internal envelope `$argon2id$v=19$m=65536,t=3,p=4$...$...`;
- exact metadata acceptance for v1 rather than speculative algorithm agility;
- exact encoded salt/hash length checks before base64 decode;
- strict base64 decode and decoded-length validation;
- malformed/unsupported parameter rejection before Argon2 allocation;
- constant-time derived-hash comparison;
- stable mismatch and malformed-hash error categories;
- empty and greater-than-1024-byte internal inputs rejected;
- raw password bytes are not trimmed, lowercased, or Unicode-normalized;
- independently generated hashes for the same password differ because salts differ.

The 1024-byte bound is internal resource protection, not a public password-policy commitment. No minimum length, complexity, breach screening or password-history rule is ratified.

### Application-scoped password credential persistence

Implemented:

- `password_credentials(application_instance_id, user_id, password_hash, created_at)`;
- primary key `(application_instance_id, user_id)` allows exactly one credential per user in this slice;
- real composite foreign key to `users(application_instance_id,id)`;
- no `ON DELETE CASCADE`;
- one atomic insert with no SELECT-before-INSERT;
- duplicate concurrent creates rely on PostgreSQL and map to stable credential conflict;
- a user from application B cannot be assigned a credential under application A;
- foreign-application resolve returns not found;
- resolve always includes application scope and user ID;
- returned stored hash must parse as a supported BeeBox password hash;
- context cancellation/deadline is preserved;
- stable persistence errors do not expose SQL, SQLSTATE, constraint names, topology, raw passwords, or encoded hashes.

### Secret-handling boundary

- raw password is never sent to PostgreSQL by this slice;
- no password/hash logging, metrics, trace attributes, events, HTTP response, or debug dump is added;
- `PasswordHash` does not implement `fmt.Stringer`;
- tests use synthetic password values;
- no memory-zeroization claim is made because Go/runtime guarantees do not support such a claim here;
- backups now contain password hashes and therefore sensitive credential-derived data.

### Email identity controls remain unchanged

- email remains application-scoped and not globally unique;
- same-app normalized duplicates conflict rather than link accounts;
- cross-app same-email coexistence is allowed;
- new email identifiers remain unverified;
- no email verification mutation or account-linking lifecycle exists.

### Migration integrity

- migrations remain embedded, Up-only and transactionally applied under existing runner defaults;
- merged migrations 1–4 remain immutable;
- migration 5 is additive and contains no Down, ENVSUB, NO TRANSACTION, backfill or destructive rewrite;
- exact normal migration state is versions 1/2/3/4/5;
- exact table set includes `application_instances`, `email_identifiers`, `goose_db_version`, `password_credentials`, and `users`;
- synthetic transactional failure moves to version 6;
- rerun idempotency, advisory locking, cancellation, concurrent convergence and failed-version non-recording remain tested.

## 7. Threat analysis

| Threat | Implemented mitigation | Residual / required future control |
| --- | --- | --- |
| Offline password cracking after DB/backup compromise | Argon2id with 64 MiB memory, time 3, random salt; plaintext not stored. | Password strength policy, breach screening and operational backup/access protection are future concerns. Hash compromise still permits offline guessing. |
| Plaintext password leakage | Raw bytes are transient hash/verify inputs only; no persistence/logging/telemetry paths are introduced. | First reachable auth flow must preserve this boundary across handlers, tracing, support tooling and incidents. |
| Password-hash leakage | Stable errors omit encoded hashes; no telemetry is added; type has no Stringer. | Backups/admin tooling/support access need explicit access/minimization policy. |
| Argon2 resource exhaustion | Raw input bounded; stored parser accepts only exact parameters and validates metadata/lengths before Argon2 work. | Reachable signin/signup must add request concurrency, rate and attempt controls; do not allow attacker-selected KDF parameters. |
| Malformed stored hash causing unsafe allocation | Exact algorithm/version/parameter literal and encoded lengths are checked before expensive work. | Future parameter migration must remain bounded and reviewed. |
| Cross-application credential ownership | Composite FK binds application and user; adversarial A/userB insert fails. | Reachable caller must separately authenticate and authorize server-selected application scope. |
| Credential duplicate race | `(application_instance_id,user_id)` PK is concurrency source of truth. | Future password replacement/reset must define transactional transition semantics. |
| Email/account takeover through auto-linking | ADR 0002 unchanged; unverified/matching email does not link. | Explicit linking requires separately reviewed verified-identity lifecycle. |
| Email/user enumeration during signin | No reachable signin or public credential lookup exists. | First reachable signin must use anti-enumerating external behavior regardless of internal not-found/mismatch distinctions. |
| Online brute force | No reachable signin exists. | First signin requires attempt budgets, throttling/rate controls, abuse detection and safe failure semantics. |
| Password reset takeover | Reset capability does not exist. | Reset/recovery must prove identity, bound attempts/replay/expiry, audit and handle sessions safely. |
| Stale sessions after password change/reset | Password change/reset and sessions do not exist. | Future lifecycle must define session/token revocation/rotation behavior. |
| Missing audit fact | Current password hashing/store operations are unreachable internal primitives. | First reachable signup/password-change/reset/admin credential mutation must atomically preserve required audit evidence; later async provider failure cannot erase an already committed audit fact. |
| Database/provider detail leakage | Adapter errors map to BeeBox-owned categories. | Future reachable APIs must map internal distinctions to safe public contracts. |
| Secret-bearing backup compromise | Plaintext is absent but password hashes and email PII are present. | Production backup encryption/access/retention/restoration policy remains operational work. |

## 8. Reachability and audit boundary

This PR does **not** make credential creation or verification a product/admin security action. No HTTP handler, use case, signup/signin orchestration or admin mutation calls these primitives.

The first reachable signup/password-change/reset/admin credential mutation must define and implement:

- authenticated/server-selected application context as appropriate;
- authorization separately from authentication;
- anti-enumeration where identifier existence is sensitive;
- attempt/rate/resource controls;
- idempotency/retry/concurrency/transaction semantics;
- complete audit facts required by `docs/contracts/conventions.md`;
- safe public errors;
- session/token consequences where applicable.

Failure of a later asynchronous email/provider step must not erase an already committed required audit fact.

If a future change makes password verification reachable, the current internal `ErrPasswordMismatch`, not-found and credential-conflict categories are not permission to expose account existence publicly.

## 9. Data lifecycle

1. Application-instance and user rows remain durable scoped records.
2. Email identifiers remain durable PII-bearing records and unverified unless a future verification lifecycle changes that state.
3. Password credential rows are durable credential-derived records while present.
4. No plaintext password is retained by this foundation.
5. Backup/restore now contains email PII and password hashes and must preserve application/user/credential relationships.
6. Production backup access therefore grants access to material usable for offline password guessing and must be treated accordingly.
7. No credential deletion, replacement, reset, history or user-deletion cleanup is implemented.
8. Future password replacement/reset must define transaction boundaries, audit evidence, retries and session/token revocation semantics.
9. Future user deletion must explicitly define password-credential deletion/retention, backup treatment, authorization, audit and partial failure.
10. No GDPR or other compliance claim is made.

## 10. Future controls required with corresponding capabilities

### First reachable password signup/signin

Must add explicit public password policy, anti-enumeration, attempt budgets, abuse/rate controls, server-selected application context, authentication orchestration, stable public contracts, audit where required, and session/token behavior separately. The 1024-byte internal hashing bound is not that policy.

### First password change/reset/recovery

Must define proof of authority, current/recovery factor behavior, replay and expiry, transaction semantics, concurrent attempts, audit, notification failure behavior, and session/token revocation or rotation.

### First email verification flow

Must define OTP/link generation, expiry, replay, attempt budgets, resend/rate controls, provider behavior, transaction boundary for `verified_at`, anti-enumeration and audit. Password storage does not make email verified.

### First public API

Must use versioned BeeBox-owned models, authenticated and separately authorized server-selected scope, bounded inputs, safe errors, idempotency/retry/concurrency, observability redaction and required audit evidence.

### Explicit account linking

Still requires a separate reviewed decision based on verified identity evidence. Password possession or email-string equality does not silently authorize linking.

## 11. Review/update triggers

Review this model when a change introduces or changes:

- reachable signup/signin/password verification;
- public password policy or breach screening;
- password change/reset/recovery/history;
- login attempts, throttling, CAPTCHA, lockout or other abuse controls;
- session/token creation or revocation tied to password lifecycle;
- email verification/provider/OTP behavior;
- account linking/merging or primary-email semantics;
- credential deletion/retention/export/backup behavior;
- public application/user/email identifiers;
- auth/audit/logging/tracing/metrics involving credentials or PII;
- migration/schema ownership or a new service boundary;
- production storage/TLS/secret-management assumptions;
- dependency/CI/provenance controls.

## 12. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing and audit invariants.
- `docs/contracts/conventions.md` — safe errors, audit, tenancy, idempotency and public-contract rules.
- `docs/adr/0001-application-instance-root.md` — v1 root isolation.
- `docs/adr/0002-email-identity-v1.md` — email scope/no-auto-link/unverified semantics.
- `internal/authentication/password.go` / `password_test.go` — Argon2id parameters, random salt, strict parser, raw input behavior and constant-time verification.
- `internal/authentication/credential.go` — BeeBox-owned internal credential model and stable error categories.
- `internal/authentication/postgres/password_store.go` — scoped atomic create/resolve using the process pool.
- `internal/authentication/postgres/password_store_integration_test.go` — cross-app FK, no-plaintext storage, duplicate concurrency, verification and safe-error evidence.
- `internal/platform/migration/sql/00005_password_credentials.sql` — scoped credential table and composite user FK.
- `internal/platform/migration/*` — exact migration state, forward-only validation, advisory locking and transactional failure evidence.
- `internal/identity/*` — application-scoped user/email identity persistence retained unchanged.
- `.github/workflows/ci.yml` — formatting, vet, unit, database/migration/application-instance/identity/authentication integration and race checks.
- `README.md` / `CONTRIBUTING.md` — current internal-only scope and exact repository verification commands.
