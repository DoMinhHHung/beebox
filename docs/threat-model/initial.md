# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this PR.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, `docs/adr/0001-application-instance-root.md`, and `docs/adr/0002-email-identity-v1.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration mode, application-scoped users/email/password credentials, transactional registration, internal audit persistence, and the internal email OTP ownership-verification lifecycle.

## 1. Purpose and scope

This document records controls actually implemented by the repository and the controls that remain required before internal identity operations become reachable product behavior.

It distinguishes:

1. **Implemented now** — present in code/schema/tests/CI.
2. **Required invariant** — repository policy the introducing slice must satisfy.
3. **Deferred capability control** — not meaningful until that capability exists, but mandatory once it does.

ADR 0001 keeps `application_instance` as the BeeBox v1 root isolation resource. ADR 0002 keeps email application-scoped, unverified by default, and forbids automatic account linking from email equality. Email verification introduced here proves control of one stored email address only. It is **not authentication**, does not create a principal/session/token, is not MFA, and does not authorize linking or merging accounts.

This slice does not ratify public IDs, public password/OTP contracts, token/session trust boundaries, provider choice, public API compatibility, or future service ownership.

## 2. Current architecture and security posture

BeeBox remains one Go deployable. Serve mode exposes only health endpoints and never auto-migrates. `beebox migrate` explicitly applies embedded forward migrations.

Embedded migrations now contain:

- version 1 runtime baseline;
- version 2 `application_instances`;
- version 3 application-scoped `users`;
- version 4 application-scoped `email_identifiers` and scoped user referenced key;
- version 5 application-scoped `password_credentials`;
- version 6 application-scoped `audit_events`;
- version 7 application-scoped `email_verification_challenges`, plus the scoped email-identifier key required by its composite foreign key.

Current internal identity/authentication behavior includes:

- application-instance create/exact resolve;
- application-scoped user create/resolve;
- application-scoped email identifier create/resolve with deterministic ASCII normalization and no-auto-link conflict semantics;
- Argon2id password hashing and scoped password credentials;
- transactional `RegisterEmailPassword`, atomically creating user + unverified email + password credential + registration-success audit;
- six-digit cryptographically random email verification codes stored only as dedicated Argon2id-derived verifier hashes;
- bounded issue/resend challenge state with expiry, failed-attempt budget, issue window/count, cooldown and generation rotation;
- issuance audit committed with challenge mutation before delivery;
- an internal delivery port with no concrete production provider;
- verify processing that performs expensive verifier work outside the final database transaction, then re-locks/revalidates current challenge generation/state;
- denied verification audit for wrong/expired/attempt-exhausted operations reaching finalization;
- atomic `email_identifiers.verified_at` transition + challenge consumption/verifier clearing + success audit;
- replay and resend-generation race protection.

There is still no reachable/public signup or verification endpoint, production email provider, signin, public password policy, request/IP/account abuse layer, password reset/change, session/token behavior, public IDs, or account-linking lifecycle.

## 3. Assets

| Asset | Security property |
| --- | --- |
| Runtime availability | Bounded I/O and truthful health behavior. |
| PostgreSQL state | Correct scoped relationships and atomic identity/security transitions. |
| Migration history | Embedded forward-only ordered migrations; failed transactional migrations are not recorded. |
| Application/user rows | Root and child identities remain explicitly application-scoped. |
| Email identifiers | Per-application normalized uniqueness, same-app user ownership, explicit verification state, PII protection. |
| Password credentials | One credential per scoped user; plaintext absent; same-app ownership enforced. |
| Verification challenge | One current row per scoped email identifier with bounded generation/expiry/attempt/issue/consumption state. |
| Raw verification code | Transient secret generated for delivery/verification only; never persisted, logged, traced, metered or audited. |
| Verification code hash | Sensitive verifier material; persisted only as a strict internal Argon2id-derived encoding and cleared on consumption. |
| Audit facts | Append-oriented correctness evidence for committed security actions; scoped, minimized and correlated. |
| Email PII | Persisted for identity/delivery, but excluded from audit/stable errors/telemetry introduced here. |
| Database/backups | Contain email PII, password hashes, OTP verifier hashes while active, challenge metadata and audit metadata. |
| Internal IDs/correlation IDs | Storage/operation identifiers only; never public compatibility or authorization primitives. |

## 4. Actors and trust assumptions

| Actor | Capability / trust assumption |
| --- | --- |
| Unauthenticated network client | Can reach health endpoints only; no product signup/verification route exists. |
| Malicious external actor | Future enumeration, OTP guessing, resend abuse, provider abuse and credential attacks become applicable when public routes exist. |
| Trusted internal caller | Supplies server-trusted application scope plus internal email-identifier identity to verification operations. |
| Anonymous registration actor | Internal audit identity for unauthenticated registration; not an authenticated user. |
| Anonymous email-verification actor | Internal audit identity for address-control challenge/verification; not an authenticated principal. |
| Delivery adapter | External-I/O boundary that may observe destination + raw OTP + expiry. Only in-memory test fakes exist now. |
| Operator/migration operator | Controls configuration/process execution and reviewed migration-capable DB access. |
| PostgreSQL / backup storage | Source of truth and sensitive persistence boundary. |
| CI | Executes synthetic unit and real PostgreSQL integration tests. |

## 5. Trust boundaries and entry points

### Network -> HTTP runtime

Current HTTP handlers remain health-only. They accept no signup, verification code, password, email identifier, application scope, token, cookie or product mutation.

### Trusted server code -> verification issuance

`IssueEmailVerification` accepts only trusted application scope plus an internal email-identifier ID. Arbitrary destination email is not accepted as the source of truth.

The application flow:

1. validates scope and identifier shape;
2. generates exactly six decimal digits using `crypto/rand` with unbiased integer generation;
3. derives a dedicated `VerificationCodeHash` outside database I/O using the already reviewed Argon2id primitive;
4. generates an internal cryptographically random audit correlation ID;
5. re-checks cancellation;
6. enters transactional persistence.

The persistence transaction locks/resolves the actual scoped `email_identifiers` row, obtains its owner and stored destination, locks current challenge state, enforces issue window/cooldown/count rules, creates or rotates challenge generation/hash/expiry, and appends a `challenge_issued` audit fact. It commits before external delivery.

### Committed issuance -> delivery port

After challenge + issuance audit commit, the delivery port receives only destination, raw six-digit code and expiry. No production provider implementation is selected in this slice.

Provider errors return a stable delivery failure but do not roll back or delete committed challenge/audit state. Delivery has ambiguous external success/failure semantics, so later provider failure cannot erase the security fact that a challenge was issued. No automatic retry, queue, outbox or worker is introduced.

### Trusted server code -> verification

`VerifyEmailCode` accepts trusted application scope, scoped internal email-identifier ID and an exact six-digit candidate. Whitespace is not trimmed.

Verification is deliberately split:

1. load a scoped challenge snapshot outside a transaction;
2. parse and verify its stored hash using constant-time comparison outside a long-held database transaction;
3. generate correlation and re-check cancellation;
4. enter finalization with the loaded generation + match result;
5. lock the scoped email identifier then challenge in a consistent order;
6. re-check generation, verified/consumed state, DB-authoritative expiry and failed-attempt budget before mutation.

If a resend rotated generation after the snapshot was loaded, finalization returns a stable stale-challenge error and does not increment attempts or verify against the new generation.

### Verification finalization -> PostgreSQL

For a wrong candidate, one transaction increments `failed_attempts`, appends a denied verify audit fact, commits, then returns mismatch.

For an expired or already exhausted challenge reaching finalization, no verification transition occurs; a denied verify audit is appended and committed before the stable error is returned.

For a correct candidate, one transaction:

1. sets `email_identifiers.verified_at` using trusted DB time;
2. sets `consumed_at` to the same trusted time;
3. clears `code_hash`;
4. appends exactly one successful verify audit fact;
5. commits.

Concurrent correct finalizations serialize through row locks. Exactly one may create the verification transition/success audit; later contenders observe already verified/consumed state.

### Scoped relationships

Challenge ownership is enforced by a composite foreign key from `(application_instance_id,email_identifier_id)` to `email_identifiers(application_instance_id,id)`. Every issue/load/finalize query includes both values. There is no global email-identifier-ID lookup.

Audit subject references remain protected by scoped `(application_instance_id,user_id)` foreign keys.

## 6. Existing controls verified now

### Registration controls retained

- registration remains one transaction for user + email + password + success audit;
- same-app normalized email duplicates conflict without auto-link/adoption/merge;
- cross-app same normalized email may coexist;
- password hashing occurs outside the registration transaction;
- no public signup/signin behavior is introduced by verification.

### Verification-code secret handling

Implemented:

- exactly six ASCII decimal digits;
- unbiased `crypto/rand.Int` generation over `[0, 1_000_000)` with leading-zero formatting;
- dedicated `VerificationCodeHash` semantic type rather than `PasswordHash` exposure;
- internal reuse of the reviewed Argon2id implementation: v19, time 3, memory 65536 KiB, parallelism 4, random 16-byte salt and 32-byte derived value;
- strict existing envelope parsing before Argon work and constant-time derived comparison;
- no plaintext OTP persistence;
- verifier storage does not contain the plaintext code;
- malformed candidate or stored verifier metadata fails with BeeBox-owned internal categories;
- raw code crosses only the delivery port and verification call;
- no code/hash/email is added to audit, stable errors, logs, metrics or traces.

The six-digit format and internal policy values are implementation defaults, not a public compatibility contract.

### Challenge lifecycle

The current internal defaults are:

- code TTL: 10 minutes;
- max failed attempts: 5 in the active issue window;
- issue/resend window: 15 minutes;
- max issues in a window: 3;
- resend cooldown: 60 seconds.

Within one active issue window, resend increments generation and issue count, replaces code hash/expiry and **does not reset failed attempts**. Once the issue window has elapsed, a newly issued challenge may reset issue count and failed attempts for the new bounded window.

The challenge table enforces positive generation, bounded attempts/issues, one row per scoped identifier, scoped referential integrity, valid consumed/hash pairing and simple timestamp ordering. No `ON DELETE CASCADE` is used.

### Replay and race controls

- successful verification consumes the challenge and clears verifier material;
- replay never returns success merely because the email is already verified;
- concurrent successful finalization has one winner and one success audit transition;
- resend rotates generation immediately;
- stale generation finalization cannot verify after resend;
- stale generation does not increment attempts against the newer challenge;
- no mutex, Redis, distributed lock or global lookup is used.

### Audit correctness/minimization

Current email-verification audit semantics:

**Challenge issued**
- actor: anonymous email verification;
- subject: scoped owner user;
- action: `authentication.email_verification.challenge_issued`;
- resource: `email_identifier`;
- outcome: `success`;
- source: `internal_email_verification`.

**Verify denied/success**
- actor: anonymous email verification;
- subject: scoped owner user;
- action: `authentication.email_verification.verify`;
- resource: `email_identifier`;
- outcome: `denied` or `success`;
- source: `internal_email_verification`.

Issue/rotate mutation + issuance audit share a transaction. Failed-attempt increment + denied audit share a transaction. `verified_at` + challenge consumption + success audit share a transaction.

Audit records contain no email address, OTP, OTP hash, password or password hash. Delivery failure after commit does not delete the issuance fact.

Audit behavior is append-oriented at the application layer and no audit update/delete API is introduced. This is **not** a claim of tamper-proof storage or compliance-grade operational immutability.

### Migration integrity

- migrations remain embedded, Up-only and transactional under existing runner defaults;
- merged migrations 1-6 remain immutable;
- migration 7 is additive and contains no Down, ENVSUB, NO TRANSACTION, destructive rewrite, hosted backfill or cascade deletion;
- exact normal migration state is versions 1/2/3/4/5/6/7;
- exact tables are `application_instances`, `audit_events`, `email_identifiers`, `email_verification_challenges`, `goose_db_version`, `password_credentials`, and `users`;
- synthetic transactional failure is version 8;
- rerun idempotency, advisory locking, cancellation, concurrent migration convergence and failed-version non-recording remain tested.

## 7. Threat analysis

| Threat | Implemented mitigation | Residual / required future control |
| --- | --- | --- |
| Partial registration | One transaction spans user/email/password/audit. | Reachable signup still needs public idempotency/abuse contracts. |
| Duplicate-email account takeover | Same-app registration conflicts; ADR 0002 forbids automatic adoption/linking. | Explicit linking requires separately reviewed verified-identity semantics. |
| OTP plaintext leakage | Code is transient, never persisted/audited/logged by this core, and only crosses the delivery port. | Production provider, handler, telemetry and support tooling must preserve the same boundary. |
| OTP hash leakage | Dedicated sensitive verifier value is persisted only while active and cleared on consume. | DB/backups/support access remain sensitive; retention/backup policy is operational work. |
| OTP offline guessing after DB compromise | Argon2id with random salt raises per-guess cost despite small six-digit space. | A six-digit OTP remains low entropy; short expiry, attempt controls and storage/access hardening remain essential. |
| Online OTP brute force | Five-failure challenge budget is DB-enforced in the lifecycle. | Public endpoints additionally require request/IP/account/device abuse controls and fairness limits. |
| Resend abuse / attempt-budget bypass | Cooldown, issue-window count and failed-attempt preservation across same-window resend. | Public layer must add request-level abuse/rate controls and provider-cost protection. |
| Old code accepted after resend | Generation + hash rotation; finalizer requires the same generation loaded before Argon verification. | Provider UI must communicate replacement semantics without exposing sensitive state. |
| Verification replay | Successful transition consumes challenge, clears hash and rejects replay/already-verified state. | Future public errors must remain anti-enumerating where appropriate. |
| Concurrent double verification | Scoped row locks + final state recheck permit one transition/success audit. | None within this single-DB boundary; future service extraction would require a new ADR/contract. |
| Expired code verification | Finalizer uses trusted DB time and refuses transition; denied audit is recorded. | Public UX may expose safe retry/resend guidance without confirming unrelated account state. |
| Cross-application challenge takeover | Every query includes trusted app scope; composite challenge FK rejects foreign-app email IDs. | Future handler must derive scope from trusted server context rather than client authority. |
| Cross-application audit subject | Existing scoped audit-user FK rejects foreign-app subjects. | Future audit resource references must preserve scope. |
| Provider delivery ambiguity | DB challenge/audit commit precedes provider I/O; provider failure cannot erase issuance fact. | Production adapter must define timeouts, safe retries/idempotency where applicable and observability/redaction. |
| Email verification treated as authentication | Code changes only `verified_at`; no principal/session/token/link/role is created. | Future signin/MFA/account-linking features must separately define authority and trust. |
| Audit loss during mutation | Required audit fact lives in the same DB transaction as each security-state mutation. | Operational DB tamper resistance/retention/export are separate future work. |
| PII/secret leakage | Audit/stable errors omit email/code/hash and no telemetry fields are added. | Reachable APIs/providers/support tools must preserve minimization. |
| Argon2 resource exhaustion | Expensive hash work happens outside DB transactions; code input is fixed-length. | Reachable handlers require concurrency/request budgets so attackers cannot trigger unbounded Argon2 work. |
| Email enumeration | No public verification/signup/signin route exists. | Reachable contracts must map internal state to anti-enumerating public behavior. |

## 8. Security meaning of verified email

A successful internal verification performs only this identity transition:

`email_identifiers.verified_at: NULL -> trusted timestamp`

It does not:

- authenticate the user;
- create an authenticated principal;
- create a session, cookie, JWT, refresh token or bearer token;
- act as MFA or privilege elevation;
- authorize application/organization access;
- authorize account linking or merging;
- change roles or permissions.

Possession of a valid email verification code is evidence of address control for that challenge only. Future account linking remains a distinct, separately reviewed product/security decision under ADR 0002.

## 9. Reachability and provider boundary

The verification lifecycle remains INTERNAL. No HTTP handler, `/v1` route, JSON verification contract, public application/user/email/challenge ID, browser flow or SDK calls it.

There is no production email provider adapter. The delivery interface exists because email delivery is a real external-I/O boundary; tests use in-memory recording/failing fakes only. SMTP, SES, Resend, SendGrid, Postmark, Mailgun and other providers are not selected.

The first reachable verification slice must still define:

- trusted server-selected application scope;
- versioned public request/response and identifier contracts;
- anti-enumerating safe errors;
- request idempotency/retry behavior where applicable;
- request/IP/account/device abuse controls in addition to challenge-local limits;
- provider timeout/retry/idempotency and operational failure behavior;
- observability with strict OTP/email redaction;
- public resend/retry semantics without weakening generation/attempt rules.

## 10. Data lifecycle and residual risks

1. Registration creates durable application-scoped user, email, password credential and audit records.
2. Verification challenge rows are durable while present; this slice defines lifecycle transitions but no deletion/retention job.
3. Active challenge verifier hashes are sensitive despite Argon2id because six-digit codes have a small candidate space.
4. Successful verification clears the active verifier hash but leaves consumed challenge metadata and audit facts.
5. Backups may retain older verifier hashes and contain email PII/password hashes/audit metadata; backup access is security-sensitive.
6. No user/email/challenge/audit deletion, anonymization, export or retention lifecycle is implemented.
7. Future user deletion must define challenge and audit retention/referential behavior rather than relying on cascade deletion.
8. Public failed/abusive request auditing beyond the challenge-local denied facts remains a future reachable-handler policy.
9. No GDPR or other compliance claim is made.

## 11. Deferred security lifecycles

Still not implemented:

- production email provider adapter;
- reachable/public signup or verification endpoint;
- public API/resource identifiers;
- email/password signin and online credential lookup;
- public password policy and breach screening;
- request/IP/account/device CAPTCHA/rate/abuse controls;
- password change/reset/recovery/history;
- sessions/tokens/cookies/JWT/JWKS and revocation behavior;
- account linking/merging;
- audit query/export/search/pagination/retention APIs or delivery infrastructure.

## 12. Review/update triggers

Review this model when a change introduces or changes:

- a production email provider or delivery retry mechanism;
- reachable/public signup or email verification;
- signin/password verification;
- password policy, breach screening, request-level abuse/rate/lockout;
- password change/reset/recovery;
- sessions/tokens/cookies;
- account linking/merging;
- audit query/export/retention or external event delivery;
- public IDs/API contracts;
- identity/audit logging/tracing/metrics;
- challenge/user/email deletion/retention/backup/restore behavior;
- migration/schema ownership or new service boundaries;
- production transport/storage/secret assumptions.

## 13. Evidence map

- `Instruction.md` — architecture, security, tenant/data, testing and audit invariants.
- `docs/contracts/conventions.md` — required audit fields, audit correctness boundary, safe errors, tenancy and idempotency rules.
- `docs/adr/0001-application-instance-root.md` — v1 root isolation.
- `docs/adr/0002-email-identity-v1.md` — email scope/no-auto-link/verification-state semantics.
- `internal/authentication/verification_code.go` / `verification_code_test.go` — cryptographic six-digit generation, dedicated Argon2id-derived verifier semantics, strict validation and constant-time verification path.
- `internal/authentication/email_verification.go` / `email_verification_test.go` — issue/verify orchestration, real delivery port, pre-transaction hashing/verification, stable internal errors and cancellation.
- `internal/authentication/postgres/email_verification_store.go` — scoped issue/rotate/audit transaction, challenge snapshot, generation-safe finalization, failed-attempt/expiry/replay/success semantics.
- `internal/authentication/postgres/email_verification_store_integration_test.go` — real PostgreSQL issue/resend/delivery-failure/expiry/attempt/replay/generation/concurrency/cross-app/cancellation evidence.
- `internal/audit/event.go` — internal registration and email-verification audit semantics/correlation generation.
- `internal/platform/migration/sql/00007_email_verification_challenges.sql` — bounded scoped challenge schema and composite email-identifier FK.
- `internal/platform/migration/*` — exact migration state and migration-safety evidence.
- `.github/workflows/ci.yml` — formatting, vet, unit, PostgreSQL integration and race checks.
- `README.md` / `CONTRIBUTING.md` — current internal-only scope and repository-native verification commands.
