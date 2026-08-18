# Initial BeeBox Threat Model

> Status: repository-owned threat model for ratified Phase 1 plus **proposed** Phase 2 trust boundaries.
> Governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, accepted ADRs 0001–0003, and proposed ADRs 0004–0006.
> Proposed Phase 2 controls below are design requirements only. They are not runtime mitigations and are not accepted until Human-ratified.

## 1. Scope and trust model

BeeBox is one Go modular monolith with PostgreSQL as the correctness source of truth. `application_instance` is the root isolation boundary. Email identity is application-scoped and equal email values never authorize account linking or merging. BeeBox Phase 1 is not an OAuth/OIDC authorization server.

The reachable Phase 1 surface covers email/password signup, email ownership verification, verified-email/password signin, session creation/current-state/refresh/revoke/signout, Ed25519 access JWT/JWKS, password reset, backend secret-key session management and bounded operational metrics. The minimal Go SDK consumes this BeeBox-owned surface and can verify access tokens offline from JWKS.

Phase 2 social auth, phone, passkeys, MFA, account linking, generic recovery, hosted auth and device-management behavior are not implemented by this document. ADRs 0004–0006 only propose the security contracts that later slices must satisfy if ratified.

## 2. Assets and secret/PII handling

| Asset | Requirement |
| --- | --- |
| Application scope | Selected from trusted server context and included in identity/session/credential lookups and mutations. |
| Email/phone | PII; not account-link authority by equality alone; excluded from unnecessary audit/log/metric dimensions. |
| Provider subject | Stable external-account identity only inside application/provider scope; not a metric label or cross-application authority. |
| Password | Raw input transient only; shared public policy before Argon2id hashing. |
| OTP/reset/recovery verifiers | Sensitive verifier material; never returned/logged after their explicit lifecycle boundary. |
| Application secret | Random high-entropy plaintext returned once; verifier only persisted. |
| Refresh credential | Random secret stored only as verifier hash; one-time rotation. |
| Access JWT | Short-lived bearer credential; never logged/audited/used as a metric label. |
| Signing private key | Configuration secret only; never stored in PostgreSQL or published in JWKS. |
| Passkey | BeeBox may receive public credential material only; private key remains authenticator-owned. |
| Device metadata | PII/security metadata collected only for a documented purpose and bounded lifecycle. |
| Audit facts | Required security-state facts commit inside the mutation correctness boundary. |

## 3. Ratified Phase 1 application trust and tenancy

Publishable keys establish application integration context only and grant no user/backend/admin authority. Secret keys establish backend application authority only after verifier comparison and revocation checks. Public IDs are opaque locators; parsing or possessing one is not authorization.

Frontend/backend routes and persistence combine trusted application scope with the target resource. Exact configured origins remain the browser/CORS boundary. Refresh cookies are application-specific `__Host-` cookies with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain attribute.

## 4. Ratified Phase 1 password, signup and email verification

Public password establishment/reset uses the shared accepted policy. Signup is application-scoped, idempotent and anti-enumerating for duplicate account state. Duplicate normalized email never auto-links, adopts or merges another account.

Email verification proves mailbox control only. It is not authentication, MFA, session establishment or account-link authority. Verification/reset challenges use short TTLs, bounded attempts/issues, verifier-only persistence, rotation/single-use semantics and audit evidence as defined by Phase 1.

## 5. Ratified Phase 1 signin, sessions and recovery

Signin lookup is application + normalized email scoped and preserves anti-enumeration. PostgreSQL-backed abuse controls and process KDF admission bound obvious online resource abuse. Password credential generation is rechecked across signin/reset races.

Sessions use bounded absolute/inactivity lifetimes. Refresh credentials rotate once; consumed-refresh replay revokes the session. Password-reset success replaces the verifier, increments generation, consumes reset state, revokes current sessions and audits atomically. Already-issued stateless access JWTs may remain valid for offline consumers until short expiry.

## 6. Ratified Phase 1 JWT/JWKS

Access tokens are five-minute Ed25519/EdDSA JWTs with mandatory issuer, subject, audience, session, validity and token identifiers. Validation fails closed on algorithm/key/signature/claim/time mismatch with bounded skew. JWKS publishes public Ed25519 material only. Offline verification cannot observe immediate database revocation.

## 7. Audit, privacy and observability

Security mutations keep required audit evidence inside their correctness transaction. Audit facts retain application scope, actor meaning, applicable subject, action, resource category, outcome, correlation, occurrence time and minimized source context.

They must not contain email/phone unnecessarily, password/hash, OTP/reset/recovery code, provider token, application secret, refresh credential, access JWT, signing private key, passkey private material or arbitrary provider errors.

Metrics use fixed bounded vocabulary only and never label by email, phone, user/session/application ID, provider subject, credential ID, IP address, token/code or raw error.

## 8. Proposed Phase 2 identity-linking threats and controls

The following are **proposed controls**, not claims about current runtime.

| Threat | Proposed control / required later evidence |
| --- | --- |
| Provider-email account takeover | Provider email is a claim only; email equality never auto-links. Existing-account attachment requires authenticated explicit linking and recent reverification. |
| Provider-subject reassignment | `(application_instance, provider, provider_subject)` is stable ownership identity; provider email/profile changes never transfer ownership. |
| Malicious/conflicting explicit linking | Target user comes from authenticated server state, never client user ID; owned-subject conflicts deny without merge or unnecessary disclosure. |
| Account-link CSRF/session-switch substitution | Explicit-link transaction is bound at initiation to trusted application, initiating principal, initiating session/equivalent authenticated context, link purpose, provider attempt and applicable reverification evidence. Callback must not re-resolve the target from the browser's current session. Any principal/session/app/context substitution denies with no link mutation and requires a fresh flow. |
| Unauthenticated linking | Forbidden. Unauthenticated social signin may use only an already-linked subject. |
| Concurrent link ownership race | PostgreSQL uniqueness in application/provider scope must allow one owner; application pre-check alone is insufficient. |
| Cross-application external identity confusion | Every provider/phone/passkey lookup and mutation includes trusted `application_instance`; same external identity may exist independently in another app. Cross-application link-state substitution fails closed. |
| Unlinking last usable method | Removal requires current authenticated owner, recent reverification and a remaining actually usable auth/recovery path consistent with MFA requirements. |
| Primary identifier takeover | New primary identifier belongs to the same app/user, completes identifier-specific verification, passes uniqueness/conflict policy and requires recent proof. |
| Phone/SMS claim abuse | Phone is application-scoped, canonicalized by a reviewed representation, explicit verified/unverified state; equality/unverified claims never link accounts. Vendor SMS models do not become public authority. |
| Passkey ownership confusion | Credential ID has one user owner in the applicable app/RP scope; private key never reaches BeeBox; email/provider changes do not transfer credential ownership. |

## 9. Proposed Phase 2 assurance, MFA and recovery threats

| Threat | Proposed control / required later evidence |
| --- | --- |
| MFA downgrade via alternate login path | Required MFA applies regardless of primary method; password/email OTP/phone OTP/social switching cannot bypass required assurance. |
| Treating any two steps as independent MFA | Factor independence/security property must be evaluated by the implementing factor set; passkeys are not automatically an extra factor. |
| Full session issued before MFA complete | Primary proof, pending additional assurance and fully authenticated session are distinct; full privilege waits for required factors. |
| Stale-session sensitive mutation | Sensitive operations require recent trusted server-side reverification, not merely any old valid session. Proposed v1 freshness default is 10 minutes pending Human approval. |
| Client-forged freshness/assurance | Client timestamps or declared methods are never authority; evidence is server-recorded and bound to app/user/session/flow. |
| Recovery as permanent weaker password | Recovery credentials are purpose-specific; recovery codes are one-time; replay fails closed; recovery does not silently erase MFA/security state. |
| Reset path downgrades assurance | Factor/credential reset is separately authorized/audited and cannot leave the account below configured requirements or without a usable method. |

## 10. Proposed Phase 2 device/privacy threats

| Threat | Proposed control / required later evidence |
| --- | --- |
| Device fingerprinting/privacy creep | No permanent cross-session fingerprint or third-party fingerprinting; collect only metadata with documented security/user purpose. |
| Precise location tracking | Not allowed by default; approximate geography deferred until separately justified. |
| Indefinite IP/user-agent retention | New persistence is deferred until a concrete feature defines bounded retention, deletion and user visibility. |
| PII leakage through observability | IP/user-agent/user/app/session/device identifiers are not metric labels; audit/log use is minimized and purpose-bound. |

## 11. Proposed hosted-auth redirect and state threats

| Threat | Proposed control / required later evidence |
| --- | --- |
| Open redirect/phishing | Redirect targets are server-validated against current application configuration using exact canonical matching; arbitrary wildcard/substring/suffix matches are forbidden. |
| Redirect substitution across applications | Flow state binds trusted application and intended validated redirect; one app cannot substitute another app's target. |
| Browser-supplied callback as authority | Browser redirect/callback values are untrusted input only. |
| Malformed/userinfo/fragment redirect abuse | Reject malformed destinations, userinfo and fragments where applicable; production uses HTTPS with explicit localhost development exception only. |
| Error-path open redirect | Error redirects obey the same allowlist/application boundary as success redirects. |
| Generic state replay/substitution | State binds attempt/application/redirect/purpose and is unpredictable or integrity-protected with bounded lifetime/replay in later implementation. |
| Explicit-link state substitution | Link state/transaction additionally binds initiating principal, initiating session/equivalent non-substitutable authenticated context and required reverification authority. Revoked, switched, substituted or cross-application context cannot be replaced at callback time. |

## 12. Required scenario outcomes for P2.0

These outcomes are deterministic at the contract level. They remain proposed until Human ratification:

- existing password user + Google same verified email -> no automatic link; require authenticated explicit linking;
- provider-first user later adds password -> authenticated credential enrollment after recent proof; no email adoption lookup;
- two BeeBox users claim related provider/email identity -> no implicit merge; owned-subject conflict denies;
- provider stops reporting verified email -> existing provider-subject ownership remains; no orphan/reassignment;
- provider changes email -> ownership remains with provider subject; BeeBox primary email does not silently change;
- provider subject already owned by another user -> deny attachment without leaking that user's unnecessary details;
- explicit link while authenticated/recently reverified -> may proceed only through the initiation-bound application/principal/session-equivalent/purpose/provider-attempt/reverification transaction and only if the external subject is unowned in that application;
- link while unauthenticated -> forbidden;
- **link initiated as user A, callback redeemed while browser is authenticated as user B or presents a non-equivalent session/context -> DENY / FAIL CLOSED; do not re-resolve the target from B, do not link the provider credential to B, do not merge principals, and require a fresh link flow under the correct authenticated/reverified principal;**
- **link initiated in application A, callback/state substituted into application B or another application context -> DENY / FAIL CLOSED with no provider-ownership transfer and require a fresh correctly scoped flow;**
- initiating session/equivalent context revoked or no longer satisfies the link requirements before callback commit -> fail closed; a replacement browser session cannot continue the original transaction;
- unlink last usable authentication method -> reject;
- cross-application provider identity -> independent scope; cannot select/mutate another application's user;
- concurrent link attempt -> database-enforced single owner; losing claim fails deterministically;
- primary email/phone change -> verified same-user identifier + conflict checks + recent proof + audit;
- MFA alternate-method bypass -> forbidden;
- recovery-code downgrade/replay -> one-time, purpose-specific, replay fails closed and does not erase configured assurance;
- stale session attempting sensitive mutation -> require fresh reverification;
- passkey ownership -> one owner in applicable app/RP scope, not transferred by identifier changes;
- hosted redirect substitution/open redirect -> reject unless exact validated current-app destination and state binding pass;
- device metadata privacy -> no new device PII persistence until bounded purpose/retention is explicitly reviewed.

## 13. Current versus proposed control boundary

Accepted ADRs 0001–0003 and existing code/tests describe ratified Phase 1 behavior. ADRs 0004–0006 are proposed security contracts only. Until Human acceptance and later runtime implementation, BeeBox must not claim that social linking, MFA, passkeys, generic recovery, hosted auth or device-management mitigations above are deployed.

## 14. Residual Phase 1 threats

| Threat | Current control / residual risk |
| --- | --- |
| Database/backup compromise | Verifier material remains sensitive offline; backups require privileged protection. |
| Online KDF exhaustion | Request/KDF admission reduces obvious abuse; volumetric protection/capacity remain operational. |
| Signup/signin/reset enumeration | Public responses collapse account-sensitive distinctions; timing requires regression coverage. |
| Email/SMTP compromise | Verification/reset prove mailbox control only; provider compromise may expose delivered codes. |
| Refresh theft/replay | One-time rotation and replay-triggered revoke; ambiguous response loss can force reauthentication. |
| Access-token theft | Short-lived bearer remains usable until expiry for offline consumers; no global denylist. |
| XSS/CSRF | HttpOnly/SameSite/exact-Origin reduce cookie abuse; XSS can still act with page authority. |
| Signing-key compromise | Requires secure configuration distribution/rotation; private material absent from DB/JWKS. |
| Metrics exposure | No PII/secret labels, but endpoint still needs network protection. |

## 15. Evidence map

- `docs/adr/0001-application-instance-root.md` through `0003-phase1-public-auth-contract.md` — accepted Phase 1 trust decisions.
- `docs/adr/0004-phase2-identity-linking-external-trust.md` — proposed external identity/account-link ownership and initiation-bound explicit-link transaction.
- `docs/adr/0005-phase2-authentication-assurance-recovery.md` — proposed assurance/reverification/recovery semantics.
- `docs/adr/0006-phase2-device-privacy-hosted-auth.md` — proposed privacy/redirect trust boundary and link-specific state binding.
- `docs/phase1-exit.md`, `api/openapi/v1.yaml`, `sdk/go`, integration tests and `.github/workflows/ci.yml` — existing Phase 1 implementation evidence.

No Phase 2 runtime implementation evidence exists in this P2.0 documentation checkpoint.