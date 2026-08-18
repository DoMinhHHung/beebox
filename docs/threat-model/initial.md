# Initial BeeBox Threat Model

> Status: repository-owned threat model for ratified Phase 1, implemented P2.1 passwordless email OTP, implemented P2.2 phone-first signup + verified-phone SMS OTP authentication, and **accepted** Phase 2 trust contracts for later work.
> Governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and accepted ADRs 0001–0006.
> ADRs 0004–0006 remain architecture/security requirements. P2.2 does not implement existing-account phone enrollment/change/removal, account linking, MFA, reverification, social providers, passkeys, recovery, device management or hosted auth.

## 1. Scope and trust model

BeeBox is one Go modular monolith with PostgreSQL as the correctness source of truth. `application_instance` is the root isolation boundary. Email and phone identity are application-scoped. Equality of email, phone or provider claims is never implicit account-link, merge or adoption authority. BeeBox is not an OAuth/OIDC authorization server.

The reachable implemented surface covers email/password signup and ownership verification, password signin/reset, P2.1 email OTP primary authentication, P2.2 phone-first SMS possession signup and verified-phone SMS OTP primary authentication, ordinary session/current/refresh/revoke/signout, Ed25519 JWT/JWKS, backend session management, bounded metrics and the Go SDK.

Existing-account phone add/change/remove/switch, social OAuth/OIDC, account-linking runtime, passkeys, MFA, generic recovery codes, step-up/reverification runtime, hosted authentication and device-management behavior remain unimplemented. Accepted ADRs 0004–0006 define the security contracts those later slices must satisfy.

## 2. Assets and secret/PII handling

| Asset | Requirement |
| --- | --- |
| Application scope | Selected from trusted server context and included in identity/session/credential lookups and mutations. |
| Email/phone | PII; not account-link authority by equality alone; excluded from unnecessary audit/log/metric/challenge/rate-limit state. |
| Phone signup fingerprint | Domain-separated SHA-256 of canonical E.164; purpose-specific non-reversible lookup key, not public identity authority. |
| Provider subject | Stable external-account identity only inside application/provider scope; not a metric label or cross-application authority. |
| Password | Raw input transient only; shared public policy before Argon2id hashing. |
| OTP/reset/recovery verifiers | Sensitive verifier material; plaintext code transient only and never returned/logged after its explicit lifecycle boundary. |
| SMS provider credential | Configuration secret only; never persisted in PostgreSQL, logged, audited or exposed through public errors/metrics. |
| Application secret | Random high-entropy plaintext returned once; verifier only persisted. |
| Refresh credential | Random secret stored only as verifier hash; one-time rotation. |
| Access JWT | Short-lived bearer credential; never logged/audited/used as a metric label. |
| Signing private key | Configuration secret only; never stored in PostgreSQL or published in JWKS. |
| Passkey | BeeBox may receive public credential material only; private key remains authenticator-owned. |
| Device metadata | PII/security metadata collected only for a documented purpose and bounded lifecycle. |
| Audit facts | Required security-state facts commit inside the mutation correctness boundary. |

## 3. Ratified application trust and tenancy

Publishable keys establish application integration context only and grant no user/backend/admin authority. Secret keys establish backend application authority only after verifier comparison and revocation checks. Public IDs are opaque locators; parsing or possessing one is not authorization.

Frontend/backend routes and persistence combine trusted application scope with the target resource. Exact configured origins remain the browser/CORS boundary. Refresh cookies are application-specific `__Host-` cookies with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain attribute.

P2.2 never takes application scope from a phone number. The same canonical phone can be an independent identifier in different applications. Database composite ownership and challenge foreign keys prevent cross-application substitution.

## 4. Ratified password, email verification and P2.1 email OTP

Public password establishment/reset uses the shared accepted policy. Signup is application-scoped, idempotent and anti-enumerating for duplicate account state. Duplicate normalized email never auto-links, adopts or merges another account.

Email verification proves mailbox control only. It is not authentication, MFA, session establishment or account-link authority. Verification/reset challenges use short TTLs, bounded attempts/issues, verifier-only persistence, rotation/single-use semantics and audit evidence as defined by Phase 1.

P2.1 email OTP is a separate primary-authentication challenge for an **existing verified** email identifier. It never creates a user, never changes `verified_at`, never fabricates password authority and does not encode an MFA bypass. Its challenge uses six `crypto/rand` digits, Argon2 verifier-only persistence, 10-minute TTL, one-minute resend cooldown, at most three issues per 15 minutes, five failed attempts, generation rotation, one-time consume, replay denial and transactional session/refresh/audit finalization.

## 5. Sessions, recovery and JWT/JWKS

Signin lookup is application scoped and preserves anti-enumeration. PostgreSQL-backed abuse controls and process KDF admission bound obvious online resource abuse. Password credential generation is rechecked across signin/reset races.

Sessions use bounded absolute/inactivity lifetimes. Refresh credentials rotate once; consumed-refresh replay revokes the session. Password-reset success replaces the verifier, increments generation, consumes reset state, revokes current sessions and audits atomically. Already-issued stateless access JWTs may remain valid for offline consumers until short expiry.

Access tokens are five-minute Ed25519/EdDSA JWTs with mandatory issuer, subject, audience, session, validity and token identifiers. Validation fails closed on algorithm/key/signature/claim/time mismatch with bounded skew. JWKS publishes public Ed25519 material only. Offline verification cannot observe immediate database revocation.

## 6. Audit, privacy and observability

Security mutations keep required audit evidence inside their correctness transaction. Audit facts retain application scope, actor meaning, applicable subject, action, resource category, outcome, correlation, occurrence time and minimized source context.

Audit/log/metric facts must not contain raw email/phone unnecessarily, password/hash, OTP/reset/recovery code, provider token/body, application secret, refresh credential, access JWT, signing private key, passkey private material or arbitrary provider errors.

Metrics use fixed bounded vocabulary only and never label by email, phone, user/session/application ID, provider subject/SID, credential ID, IP address, token/code/challenge or raw error. P2.2 SMS delivery metrics use only fixed purpose/outcome vocabulary.

## 7. P2.2 phone canonicalization and identity ownership controls

P2.2 v1 accepts a BeeBox-owned strict international E.164 representation: `+` followed by 2–15 ASCII decimal digits, first digit non-zero. Surrounding ordinary whitespace may be trimmed; BeeBox does not infer a default region or accept national formatting, embedded whitespace, punctuation, `00`, `tel:`, extensions or alphabetic digits.

`phone_identifiers` is explicitly application + user scoped and carries nullable `verified_at`. PostgreSQL enforces same-application ownership and uniqueness of a **verified** `(application_instance, phone_e164)` while allowing the same canonical phone in another application. Equality never selects, links, merges or adopts a principal.

P2.2 deliberately exposes no endpoint to add/change/remove/switch phone identifiers on an already-existing principal. Those sensitive mutations remain subject to ADR 0004/0005 recent-reverification, conflict and last-usable-method semantics in a later slice.

## 8. P2.2 phone-first signup implemented controls

Phone-first signup creates no principal when an SMS is merely requested. A request creates/rotates only `phone_signup_challenges`; it creates no `users`, `phone_identifiers` or session row. The challenge stores application scope plus a 32-byte domain-separated SHA-256 phone fingerprint, not raw phone PII.

| Threat | Implemented P2.2 control / evidence |
| --- | --- |
| Fake account ownership from code request | No user or phone identifier exists until matching possession proof finalizes successfully. |
| Raw phone proliferation | Pending signup challenge and public rate-limit subjects use domain-separated SHA-256 fingerprints; raw E.164 becomes persistent product PII only in `phone_identifiers` after proof. |
| Plaintext OTP disclosure | Six decimal digits use the existing `crypto/rand` verification-code primitive; only Argon2 verifier encoding is persisted. OTP is absent from public responses/logs/metrics/audit. |
| Existing verified phone enumeration | Same-app already-verified phone, cooldown/window suppression and eligible/account-dependent provider failure converge on generic issue behavior; an already-owned phone receives no signup SMS. |
| Abandoned unverified accounts | Issue creates no user/phone row. Expired or failed challenges leave no principal. |
| Old code after resend | Permitted resend increments generation, replaces verifier, resets attempt state and invalidates the previous code. |
| Brute-force confirmation | Five challenge-level failures plus purpose-specific global-first/pre-KDF persistent admission bound expensive verification. |
| SMS bombing/cost abuse | One-minute resend cooldown, at most three successful issues per 15-minute challenge window, plus global-first and per-phone persistent issue admission. |
| Cross-application proof substitution | Fingerprint/challenge key includes trusted application; wrong-app confirmation has no matching scoped state. |
| Concurrent success | Final transaction row-locks exact `(application, phone_fingerprint)` challenge and rechecks generation/expiry/attempt/consume state; verified-phone DB uniqueness is a second serialization invariant. At most one user/session can commit. |
| Partial principal/session success | Successful confirmation atomically inserts user, verified phone, consumes/clears challenge verifier, creates ordinary session + refresh verifier and writes required success audit. Any required DB/audit failure rolls back all of it. |
| Replay/ambiguous response | Consumed challenge cannot create another principal/session. Confirmation is intentionally not blindly retryable; after ambiguous success the new user may use phone OTP sign-in. |
| Password authority confusion | Phone-first account requires no email/password credential. P2.2 never fabricates password credential/generation state. |

## 9. P2.2 verified-phone SMS OTP sign-in implemented controls

Phone OTP sign-in is purpose-separated from signup and requires an existing `phone_identifiers` row whose `verified_at` remains non-null in the trusted application scope.

| Threat | Implemented P2.2 control / evidence |
| --- | --- |
| Unknown/unverified phone enumeration | Eligible verified phone, unknown/unverified phone, cooldown/window suppression and account-dependent provider failure preserve generic issue response for validly shaped input. |
| Cross-app sign-in | Signin challenge references `(application_instance, phone_identifier_id)` through a composite FK and issue/load/finalize queries include trusted application scope. |
| OTP reuse/rotation | One active challenge row per application/phone identifier, generation rotation, previous-code invalidation, 10-minute TTL and one-time consume/clear. |
| Guessing/KDF exhaustion | Five failed attempts and operation-separated global-first + per-phone confirm admission precede Argon2 verification; absent challenge paths perform bounded dummy KDF work. |
| Concurrent redemption | Phone identifier and challenge are rechecked under PostgreSQL row locks; only one current generation can commit challenge consumption/session creation. |
| Partial session creation | Successful consume, ordinary session, refresh verifier and success audit share one transaction; failure rolls back challenge/session state. |
| Replay | Consumed/replaced/expired/exhausted challenge returns safe invalid credentials and cannot create another session. |
| Fake password/MFA authority | Phone OTP is an ADR 0005 **primary authentication method** only. It creates the current ordinary session class because no additional-assurance runtime is configured; it does not claim MFA bypass or permanent strength ordering against password/email OTP. |

## 10. P2.2 SMS provider and partial-failure controls

BeeBox has a narrow BeeBox-owned delivery port with separate signup/signin purposes. The current production adapter uses Twilio Programmable Messaging internally; provider models, message identifiers and response bodies are not public BeeBox contracts.

Production provider routing is fixed to HTTPS and operator configuration supplies only mode/account/auth/sender plus a bounded request timeout. Partial Twilio configuration fails startup before listener creation with a stable credential-free configuration error. SMS mode defaults to disabled, so non-phone capabilities continue without provider configuration.

Provider network I/O occurs only **after** challenge persistence commits; PostgreSQL transactions are never held open across SMS network I/O. A provider error cannot be rolled back across the network and remains generic publicly where account state could otherwise leak. BeeBox does not automatically retry an ambiguous provider POST; a later explicit user request, after admission/cooldown, is the retry boundary. Provider response reads and request duration are bounded.

When SMS mode is disabled, phone issue endpoints return a uniform service-unavailable response before phone ownership/challenge state lookup. Confirmation does not itself require provider I/O, allowing a previously committed valid challenge to remain confirmable when session-signing capability is configured.

## 11. Accepted Phase 2 identity-linking requirements not implemented by P2.2

| Threat | Accepted control / required later evidence |
| --- | --- |
| Provider-email account takeover | Provider email is a claim only; email equality never auto-links. Existing-account attachment requires authenticated explicit linking and recent reverification. |
| Provider-subject reassignment | `(application_instance, provider, provider_subject)` is stable ownership identity; provider email/profile changes never transfer ownership. |
| Account-link CSRF/session substitution | Explicit-link transaction binds trusted application, initiating principal/session/equivalent context, purpose, provider attempt and required reverification. Callback never re-resolves target from a different browser session. |
| Unauthenticated linking | Forbidden. Unauthenticated social signin may use only an already-linked subject. |
| Concurrent link ownership | PostgreSQL uniqueness in application/provider scope must allow one owner; application pre-check alone is insufficient. |
| Existing-account phone enrollment/change/removal | Requires authenticated current owner, recent reverification, verified same-user target, conflict policy and remaining usable authentication/recovery path. P2.2 intentionally has no such endpoint. |
| Unlinking last usable method | Removal requires recent proof and a remaining actually usable method consistent with configured assurance. |
| Passkey ownership confusion | Credential ID has one user owner in applicable app/RP scope; private key never reaches BeeBox; email/provider changes do not transfer credential ownership. |

## 12. Accepted Phase 2 assurance, MFA and recovery requirements

| Threat | Accepted control / required later evidence |
| --- | --- |
| MFA downgrade via alternate primary method | Required MFA applies regardless of password/email OTP/phone OTP/social primary method. P2.1/P2.2 encode primary proof only, not bypass. |
| Treating arbitrary two steps as independent MFA | Factor independence/security property must be evaluated by the implemented factor set. |
| Full session before required MFA | Primary proof, pending additional assurance and fully authenticated state are conceptually distinct. No additional-assurance runtime is configured yet. |
| Stale-session sensitive mutation | Sensitive operations require recent trusted server-side reverification; accepted v1 default is 10 minutes subject to ADR 0005 method/scope/assurance checks. |
| Client-forged freshness | Client timestamps or claimed methods are not authority; evidence is server-recorded and bound to app/user/session/flow. |
| Recovery downgrade/replay | Recovery credentials are purpose-specific and one-time; replay fails closed and cannot silently erase configured assurance. |

## 13. Accepted device/privacy and hosted-auth requirements

Device and hosted-auth controls remain accepted requirements, not implemented P2.2 claims:

- no permanent cross-session device fingerprint or third-party fingerprinting;
- no precise location collection by default;
- bounded purpose/retention for any later IP/user-agent persistence;
- exact server-validated hosted-auth redirect destinations in current application scope;
- no wildcard/substring/suffix redirect authority;
- state binds application/attempt/purpose/validated redirect and, for explicit linking, initiating principal/session/reverification context;
- error redirects obey the same boundary as success redirects.

## 14. Required later Phase 2 scenario outcomes

- existing password user + provider with same verified email -> no automatic link;
- provider-first user later adds password -> authenticated enrollment after recent proof, not equality adoption;
- provider subject already owned by another user -> deny without merge/unnecessary disclosure;
- link initiated as user A but callback presents user B/non-equivalent session -> fail closed and require fresh flow;
- cross-application provider/link state substitution -> fail closed;
- unlink last usable method -> reject;
- existing-account primary email/phone change -> same-user verified target + conflicts + recent proof + audit;
- alternate primary method cannot bypass later required MFA;
- stale session sensitive mutation -> fresh reverification under ADR 0005;
- hosted redirect substitution/open redirect -> reject unless exact current-app validation and state binding pass;
- device metadata -> no new persistence without bounded purpose/retention review.

## 15. Implemented versus accepted boundary

ADRs 0001–0006 are accepted architecture/security contracts. Existing code/tests provide Phase 1 runtime evidence, P2.1 email OTP evidence and P2.2 phone-first/SMS OTP evidence described above.

P2.2 does **not** mean the remaining Phase 2 controls are deployed. No runtime evidence is claimed here for existing-account phone enrollment/change/removal/switch, social OAuth/OIDC, account-linking/merge, passkeys, MFA/TOTP, recovery codes, step-up/reverification, device management or hosted authentication.

Each later slice must provide its own concrete code, persistence/API contracts, adversarial tenant/security tests and exact-head CI before BeeBox may claim that runtime control exists.

## 16. Residual implemented-surface threats

| Threat | Current control / residual risk |
| --- | --- |
| Database/backup compromise | Password/OTP/refresh verifier material and phone PII remain sensitive offline; backups require privileged protection. |
| Online KDF exhaustion | Persistent admission and process KDF bounds reduce obvious abuse; volumetric capacity protection remains operational. |
| Signup/signin/reset/OTP enumeration | Public responses collapse account-sensitive distinctions; timing requires continued regression/operational observation. |
| Email/SMS provider compromise | Delivered OTPs depend on mailbox/carrier/provider control; provider compromise may expose codes/destination metadata. |
| SMS cost/message bombing | Global-first/per-phone admission and challenge cooldown/windows bound application behavior; upstream volumetric/provider controls remain operational concerns. |
| Provider delivery ambiguity | Challenge can commit before provider response; no automatic retry avoids duplicate sends but may require explicit user resend later. |
| Refresh theft/replay | One-time rotation and replay-triggered revoke; ambiguous response loss can force reauthentication. |
| Access-token theft | Short-lived bearer remains usable until expiry for offline consumers; no global denylist. |
| XSS/CSRF | HttpOnly/SameSite/exact-Origin reduce cookie abuse; XSS can still act with page authority. |
| Signing/SMS-provider key compromise | Requires secure configuration distribution/rotation; secret material absent from DB/JWKS/public errors. |
| Metrics exposure | No PII/secret labels, but endpoint still needs network protection. |

## 17. Evidence map

- `docs/adr/0001-application-instance-root.md` through `0006-phase2-device-privacy-hosted-auth.md` — accepted trust/assurance/privacy contracts.
- `docs/contracts/conventions.md` — tenancy, error, time, audit, versioning and idempotency conventions.
- `internal/identity/phone.go` — strict E.164 BeeBox phone value.
- `internal/platform/migration/sql/00014_phone_sms.sql` — application-scoped phone identity, verified uniqueness, fingerprint-only signup challenge, purpose-separated signin challenge and limiter vocabulary.
- `internal/authentication/phone.go` — signup/signin OTP generation, purpose separation, admission and delivery boundary.
- `internal/authentication/postgres/phone_store.go` — PostgreSQL issue/load/finalize correctness and transactional signup/session/audit semantics.
- `internal/session/phone.go` — primary-proof confirmation, KDF behavior and ordinary session/token integration.
- `internal/authentication/twiliodelivery/` — fixed HTTPS Twilio adapter with bounded I/O, stable errors and no automatic retry.
- `internal/authentication/metricsdelivery/phone.go` — bounded SMS purpose/outcome observations.
- `internal/httpapi/phone.go` — four additive v1 routes, trusted application/Origin boundary, anti-enumerating issue behavior and normal session transport.
- `api/openapi/v1.yaml` and `sdk/go/phone.go` — BeeBox-owned public/SDK phone contracts with no provider/internal IDs.
- `internal/authentication/postgres/phone_sms*_integration_test.go` — no-account-before-proof, privacy, lifecycle, attempts/expiry/replay/concurrency and transactional rollback evidence.
- `internal/platform/migration/phone_sms_migration_integration_test.go` — fresh/upgrade/constraint/vocabulary evidence.
- `internal/httpapi/phone*_test.go` — disabled/provider privacy, browser/non-browser transport and full PostgreSQL HTTP lifecycle evidence.
- `internal/authentication/twiliodelivery/*_test.go` and `cmd/beebox/phone_sms_startup_test.go` — synthetic provider/startup evidence without real SMS credentials.
- `.github/workflows/ci.yml` — formatting, vet, vulnerability, contract, SDK, unit, PostgreSQL integration and race gates.
