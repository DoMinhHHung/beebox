# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by the current Phase 1 checkpoint.
> Governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and accepted ADRs 0001–0003.

## 1. Scope and trust model

BeeBox is one Go modular monolith with PostgreSQL as the correctness source of truth. `application_instance` remains the root isolation boundary. Email identity remains application-scoped under ADR 0002 and equal email addresses never authorize automatic account linking or merging.

Current reachable Phase 1 behavior includes application-scoped email/password signup, email ownership verification, verified-email/password sign-in, session/refresh lifecycle, Ed25519 access JWT/JWKS, and password reset/recovery. BeeBox Phase 1 is not an OAuth/OIDC authorization server.

No Redis, queue, outbox, distributed transaction, service extraction or hosted mutation is required for these correctness guarantees.

## 2. Current persistence and migrations

Positive migrations are `00001` through `00011`. Relevant security state includes:

- application-scoped users and email identifiers;
- password credentials with same-application user FK, Argon2id verifier, credential generation and update time;
- append-oriented application-scoped audit facts;
- email verification challenges;
- public IDs, application publishable/secret credentials and exact allowed origins;
- public-auth idempotency/rate-limit state;
- sessions and one-time refresh credential verifier records;
- application-scoped password-reset challenges.

Migration `00011_password_resets.sql` is additive. Existing merged migrations are not rewritten. Password-reset challenge rows have explicit application, user and email-identifier scope with database-enforced scoped FKs and no cascade deletion.

## 3. Assets

| Asset | Security requirement |
| --- | --- |
| Application scope | Every identity/session/reset operation is selected through trusted application integration context and remains scoped in PostgreSQL. |
| Email | PII; excluded from audit facts, stable errors and telemetry added by these flows. |
| Password | Raw input is transient only; public policy is applied before Argon2id hashing. |
| Password hash | Sensitive credential-derived verifier; never returned by public APIs or logged. |
| Email verification/reset code | Raw code is transient only; verifier material is sensitive and stored with bounded lifecycle. |
| Refresh credential | Random secret stored only as a verifier hash and rotated once per successful refresh. |
| Access JWT | Bearer credential; never logged/audited; short expiry bounds offline revocation lag. |
| Signing private key | Configuration secret only; never published through JWKS or stored in PostgreSQL for convenience. |
| Audit facts | Required security-state facts commit inside the associated correctness transaction. |
| PostgreSQL/backups | Privileged boundary containing PII and credential-derived verifier material. |

## 4. Public application trust

Publishable keys are intentionally non-secret and establish application integration context only. They do not establish user, backend or admin authority. Backend secret keys are high-entropy one-time plaintext credentials with verifier-at-rest, constant-time verification and persisted revocation/current-state checks.

Public IDs remain typed opaque locators. Parsing `app_`, `usr_`, `ses_` or `cred_` values never establishes authorization or tenant ownership.

Exact stored browser origins are enforced for credentialed browser flows. No wildcard credentialed CORS authority is introduced.

## 5. Password and signup controls

Public password establishment and reset share one policy: NFC normalization, 15–128 Unicode code points, safe internal byte bound, no silent trim, no composition requirement and repository-owned common/expected-password blocking. The low-level Argon2id primitive is not itself the public policy contract.

Password verifier defaults remain Argon2id v19, time 3, memory 64 MiB, parallelism 4, random 16-byte salt and 32-byte derived value. Stored envelopes are parsed strictly and compared in constant time.

Signup is application-scoped, idempotent and does not auto-link existing email owners. Public duplicate behavior is anti-enumerating.

## 6. Email verification controls

Email confirmation proves control of one address only. It is not authentication, MFA, session establishment, authorization, account linking or account merging.

The current verification lifecycle uses six random ASCII decimal digits, verifier-only persistence, 10-minute expiry, five failed attempts, 15-minute issue window, three issues per window, 60-second cooldown, generation rotation and single-use consumption. Resend does not reset failed attempts inside the active issue window. Verification success atomically sets `verified_at`, consumes the challenge and appends its required audit fact.

## 7. Sign-in and session controls

Sign-in lookup is application + normalized email scoped and requires verified email state. Unknown identifiers execute a dummy password-hash path to reduce a cheap verifier-work timing oracle. Public invalid-credential behavior does not distinguish unknown identifier, unverified identifier, missing credential or wrong password. PostgreSQL-backed global/identifier attempt limits bound reachable abuse.

Password credential generation now participates in the final session-creation transaction. Sign-in verifies a credential snapshot outside the transaction, then session creation rechecks that the same generation is current and a scoped verified email still exists. Therefore a concurrent password reset cannot create a session from a stale password snapshot: if reset wins first, generation mismatch rejects session creation; if sign-in commits first, the reset transaction later revokes that session.

Sessions have 30-day absolute and seven-day inactivity lifetimes. Refresh credentials are one-time random secrets stored only by verifier hash. Successful refresh consumes the old credential and creates a replacement atomically. Reuse of a consumed refresh credential revokes the owning session and records audit evidence.

## 8. JWT/JWKS controls

Access tokens are five-minute Ed25519/JOSE EdDSA JWTs under accepted ADR 0003. Validation is fail-closed for wrong algorithm, missing/unknown `kid`, invalid signature, issuer/audience mismatch, expiry or premature use, with bounded clock skew. JWKS publishes public Ed25519 verification material only.

Database session revocation is immediate for BeeBox paths that consult current session state. Offline JWT consumers cannot observe revocation until token expiry; BeeBox does not claim a global JWT denylist. Password reset therefore revokes all session state immediately while already-issued stateless access JWTs can remain cryptographically valid for offline consumers until their short expiry.

## 9. Password reset/recovery controls

Password reset is application-scoped and requires a verified email plus an existing password credential to become eligible. The public request endpoint remains generic whether the identifier is unknown, unverified, ineligible, rate-limited, already challenged or affected by delivery ambiguity.

Reset codes are a dedicated semantic type: exactly eight unbiased random ASCII decimal digits generated with `crypto/rand`. Raw reset codes are never persisted. Verifier-at-rest reuses the reviewed Argon2id mechanism without treating reset codes as passwords at the domain boundary.

Challenge policy:

- TTL: 10 minutes;
- failed attempts: maximum 5;
- issue window: 15 minutes;
- maximum issues per window: 3;
- resend cooldown: 60 seconds;
- resend rotates generation/code and does not reset failed attempts inside the same window;
- a new elapsed window may reset bounded counters.

Request-level PostgreSQL rate-limit state is also application/identifier scoped without storing raw email solely for rate limiting.

Eligible request issuance commits challenge mutation and `authentication.password_reset.issued` audit before SMTP delivery. Provider I/O is outside the database transaction. Ambiguous delivery failure does not erase the committed challenge or audit fact and no automatic background retry/outbox is introduced.

Confirmation loads a scoped challenge snapshot, verifies the code and hashes the new policy-compliant password outside the long database transaction, then finalizes under row locks. Finalization rechecks application scope, verified email, challenge generation/state, expiry, attempt budget and password credential generation.

Wrong candidate commits failed-attempt increment and denied audit together. Successful reset atomically:

1. replaces the password verifier and increments credential generation;
2. consumes the challenge and clears reset verifier material;
3. revokes all current sessions for that user in the application;
4. appends reset-success audit;
5. commits once.

Consumed/expired/exhausted/stale challenges cannot repeat the password transition. Public confirmation errors do not expose account ownership or persistence/provider details.

## 10. Audit and privacy

Security mutations keep audit evidence inside the corresponding transaction. Current relevant action classes include signup, email-verification issue/deny/success, sign-in/session lifecycle, refresh replay/revocation and password-reset issue/deny/success.

Audit facts retain application scope, actor meaning, subject when known, action, resource category, outcome, correlation, occurrence time and source. They contain no email, raw password, password hash, OTP, reset code, OTP/reset verifier, application secret, refresh credential, access JWT or signing private key.

Audit storage is append-oriented at application semantics; it is not claimed to be tamper-proof or compliance-certified.

## 11. Cross-application isolation

Database constraints and scoped queries prevent:

- adopting a same-email user from another application;
- issuing/verifying email challenges through another application;
- resolving password credentials globally by numeric user ID;
- resetting a foreign application user's password;
- using one application's session/refresh state in another application;
- cross-application audit actor/subject references where user IDs are present.

Internal numeric IDs and public locators are not authorization proof.

## 12. Residual threats

| Threat | Current control / residual risk |
| --- | --- |
| Database/backup compromise | Password/OTP/reset verifiers remain offline-cracking targets; backups require privileged protection. |
| Online password/Argon2 exhaustion | Sign-in request controls bound obvious abuse; final operational tuning remains environment-dependent. |
| Signup/sign-in/reset enumeration | Public responses collapse account-sensitive distinctions; timing side channels require continued regression testing. |
| Email/SMTP compromise | Email verification/reset proves mailbox control only; provider compromise can expose delivered codes. |
| Reset code guessing | Short TTL, five-attempt budget, issuance bounds and verifier-only storage reduce risk; public request-level abuse controls remain important. |
| Reset/sign-in race | Credential-generation recheck plus reset session revocation prevents stale-password session survival. |
| Refresh theft/replay | One-time rotation and replay-triggered session revoke; ambiguous lost refresh responses may require reauthentication. |
| Access-token theft | Short-lived bearer token remains usable until expiry for offline consumers; no global denylist is claimed. |
| XSS/CSRF | HttpOnly refresh cookie reduces script access; exact Origin + SameSite=Strict protect cookie mutation paths, but XSS can still act with page authority. |
| Signing-key compromise | Requires operational key rotation and secure configuration distribution; private key is not in DB/JWKS. |

## 13. Still deferred

Checkpoint 4 does not add social auth, MFA/passkeys, organizations, account linking, generic account recovery, OAuth/OIDC authorization-server behavior, Redis, queues/outbox, service extraction, hosted deployment or compliance certification.

Phase 1 is still incomplete until Checkpoint 5 adds final Go SDK coverage, operational metrics, reproducible local setup and end-to-end exit evidence.

## 14. Evidence map

- `internal/authentication/password_reset.go` — reset secret policy and application orchestration.
- `internal/authentication/postgres/password_reset_store.go` — scoped issuance/finalization, attempt state, password replacement, session revoke and audit transactions.
- `internal/authentication/postgres/password_reset_integration_test.go` — reset persistence, secret-at-rest, attempt, cross-app, replay and revocation evidence.
- `internal/platform/migration/sql/00011_password_resets.sql` — additive reset/credential-generation schema.
- `internal/session/service.go` and `internal/session/postgres/store.go` — credential-generation sign-in finalization.
- `internal/httpapi/password_reset.go` — anti-enumerating public reset endpoints.
- `internal/authentication/smtpdelivery/password_reset.go` — bounded SMTP reset delivery.
- `api/openapi/v1.yaml` — BeeBox-owned public reset contract.
- `.github/workflows/ci.yml` — format, vet, unit, PostgreSQL integration and race gates.
