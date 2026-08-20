# Initial BeeBox Threat Model

> Status: repository-owned threat model for ratified Phase 1, implemented P2.1 passwordless email OTP, P2.2 phone-first signup + verified-phone SMS OTP authentication, P2.3 social OAuth/OIDC, P2.4A/P2.4B social account linking/management, P2.5 passkeys, P2.6 TOTP MFA and P2.7 recovery codes, plus **accepted** Phase 2 trust contracts for later work.
> Governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and accepted ADRs 0001–0007.
> ADRs 0004–0007 remain architecture/security requirements. The current P2.7 boundary does not implement expanded identifier self-service, principal merge, provider-side consent/token revocation, generic P2.8 reverification, device self-service or hosted auth.

## 1. Scope and trust model

BeeBox is one Go modular monolith with PostgreSQL as the correctness source of truth. `application_instance` is the root isolation boundary. Email, phone and external identities are application-scoped. Equality of email, phone or provider profile claims is never implicit account-link, merge or adoption authority. BeeBox consumes external OAuth/OIDC providers for authentication and explicit social linking; it is not itself an OAuth/OIDC authorization server.

The reachable implemented surface covers email/password signup and ownership verification, password signin/reset, P2.1 email OTP primary authentication, P2.2 phone-first SMS possession signup and verified-phone SMS OTP primary authentication, P2.3 social OAuth/OIDC signup/signin, P2.4A/P2.4B social linking/management, P2.5 passkeys, P2.6 TOTP enrollment/removal and pending authentication, ordinary session/current/refresh/revoke/signout, Ed25519 JWT/JWKS, backend session management, bounded metrics and the Go SDK.

P2.3 provides exactly three BeeBox social-auth public operations: initiate, provider callback, and completion exchange. P2.4A additively provides `POST /v1/social-links/attempts` and reuses the existing provider callback with purpose-separated server-issued state. P2.4B adds `GET /v1/social-links` and `DELETE /v1/social-links/{social_link_id}` using opaque BeeBox-owned social-link public IDs. P2.5 adds WebAuthn, P2.6 adds TOTP lifecycle plus one common pending-MFA boundary, and P2.7 adds recovery-code completion/regeneration/dedicated TOTP replacement. Expanded identifier self-service, principal merge, generic P2.8 reverification, hosted authentication and device-management behavior remain unimplemented at this checkpoint.

## 2. Assets and secret/PII handling

| Asset | Requirement |
| --- | --- |
| Application scope | Selected from trusted server context and included in identity/session/credential/provider lookups and mutations. |
| Email/phone | PII; not account-link authority by equality alone; excluded from unnecessary audit/log/metric/challenge/rate-limit state. |
| Phone signup fingerprint | Domain-separated SHA-256 of canonical E.164; purpose-specific non-reversible lookup key, not public identity authority. |
| Provider subject | Stable external-account identity only after verified provider proof and only inside `(application, provider)` scope; never cross-application authority, a public management identifier or a metric label. |
| Social-link public ID | BeeBox-owned opaque `sli_<uuid-v4>` locator. It is safe for public resource selection but never conveys ownership; every list/delete query still scopes application + current user. |
| Provider email/name/avatar/profile claim | Transient untrusted profile material unless required for protocol parsing; not BeeBox identity/link authority and discarded by P2.3/P2.4A/P2.4B. |
| Provider authorization code | Short-lived provider bearer-like credential consumed only by the adapter over bounded backchannel I/O; never persisted, exposed or included in logs/errors/telemetry, including query-bearing provider request URLs. |
| Provider access/refresh/ID token | Adapter-local proof material only. P2.3/P2.4A/P2.4B do not persist, expose, log, audit or metric-label provider tokens; token-bearing query URLs are equally secret. |
| Social auth state | 32 random bytes returned to the browser; only SHA-256 state hash is persisted. One-time, 10-minute attempt lifetime. |
| Social-link state | `lnk_` is a dispatch namespace over a fresh 32-byte secret; only the secret's SHA-256 hash is persisted in a dedicated link-attempt row. The prefix is not authority. P2.4B cancellation is represented by `canceled_at`, not by overloading state/purpose. |
| Social-link target binding | Trusted application, initiating BeeBox user, exact persisted initiating session, provider, purpose, exact redirect and server-trusted recent-authentication evidence are stored before provider navigation and revalidated before ownership commit. |
| OIDC nonce | 32 random bytes sent to OIDC provider; only SHA-256 nonce hash is persisted and compared after verified ID-token parsing. |
| Provider PKCE verifier | Random verifier stored only as AES-256-GCM ciphertext. P2.4A uses purpose-separated link AAD so P2.3 ciphertext cannot be repurposed as link state or vice versa; P2.4B clears canceled same-provider link ciphertext. |
| Social completion code | 32 random bytes returned only after P2.3 provider proof; only SHA-256 code hash is persisted. One-time, five-minute lifetime, client S256-bound. P2.4A never creates one; successful P2.4B unlink conservatively consumes unexchanged grants for the same application/user. |
| Client completion PKCE verifier | Client-owned P2.3 secret; BeeBox persists only the S256 challenge and verifies the submitted verifier during completion exchange. |
| Password | Raw input transient only; shared public policy before Argon2id hashing. |
| OTP/reset/recovery verifiers | Sensitive verifier material; plaintext code transient only and never returned/logged after its explicit lifecycle boundary. |
| SMS provider credential | Configuration secret only; never persisted in PostgreSQL, logged, audited or exposed through public errors/metrics. |
| Social provider client secret | Configuration secret only; never persisted as identity/session data, logged, audited or exposed publicly. Facebook's selected manual flow sends it in an HTTPS query to Meta, so the outbound URL itself is secret-bearing and must never be logged. |
| Social state-protection key | Configuration-only 32-byte AES key; never persisted, logged, audited or exposed publicly. |
| Application secret | Random high-entropy plaintext returned once; verifier only persisted. |
| Refresh credential | Random secret stored only as verifier hash; one-time rotation. Refreshing the same session never changes that session's original `created_at` authentication time. |
| Access JWT | Short-lived bearer credential; never logged/audited/used as a metric label. A fresh token for an old session does not manufacture recent-authentication authority for P2.4A or P2.4B unlink. |
| Signing private key | Configuration secret only; never stored in PostgreSQL or published in JWKS. |
| Passkey | Future accepted boundary only; BeeBox may receive public credential material only and private key remains authenticator-owned when implemented. |
| Device metadata | PII/security metadata collected only for a documented purpose and bounded lifecycle. |
| Audit facts | Required security-state facts commit inside the mutation correctness boundary and contain minimized references rather than provider secrets/PII. P2.4B unlink uses only opaque `sli_` resource reference. |

## 3. Ratified application trust and tenancy

Publishable keys establish application integration context only and grant no user/backend/admin authority. Secret keys establish backend application authority only after verifier comparison and revocation checks. Public IDs are opaque locators; parsing or possessing one is not authorization.

Frontend/backend routes and persistence combine trusted application scope with the target resource. Exact configured origins remain the browser/CORS boundary. Refresh cookies are application-specific `__Host-` cookies with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain attribute.

P2.2 never takes application scope from a phone number. The same canonical phone can be an independent identifier in different applications. Database composite ownership and challenge foreign keys prevent cross-application substitution.

P2.3 never takes application scope, redirect authority or principal ownership from a provider callback. Social initiation resolves the application through the publishable-key boundary, validates the requested redirect against that application's exact redirect allowlist, then persists the trusted application/provider/redirect/client-challenge state. Callback resolves the attempt from the one-time state hash and stored provider binding; it does not accept a browser-supplied application/user/redirect as authority.

P2.4A additionally authenticates an ordinary BeeBox access token against the same resolved application, resolves the persisted current session, and binds the exact application/user/session into the dedicated link attempt. Callback-time bearer/cookie/session coincidence is ignored. The callback cannot select a target from provider email/profile, query `user_id`/`session_id`, another browser session or a callback-supplied redirect. The same provider subject may still be owned independently in different applications because ownership is application scoped.

P2.4B listing/unlink resolves the same exact publishable-key application, canonical allowed Origin and current persisted BeeBox session. The client cannot select `user_id`, `session_id`, application ID, provider subject or provider profile as management authority. A `sli_` ID that belongs to another user/application is indistinguishable from an absent ID on DELETE and never broadens a query beyond `(application_instance_id, current_user_id)`.

`application_redirect_urls` is a separate application-scoped trust list from allowed CORS origins. Production redirect URLs require HTTPS; only explicit `http://localhost` is allowed for development. Matching is exact after canonicalization. Query, fragment, userinfo, wildcard, relative/malformed and alternate escaped-path forms are rejected. Success and provider-error redirects use only the redirect stored on the consumed attempt.

## 4. Ratified password, email verification and P2.1 email OTP

Public password establishment/reset uses the shared accepted policy. Signup is application-scoped, idempotent and anti-enumerating for duplicate account state. Duplicate normalized email never auto-links, adopts or merges another account.

Email verification proves mailbox control only. It is not authentication, MFA, session establishment or account-link authority. Verification/reset challenges use short TTLs, bounded attempts/issues, verifier-only persistence, rotation/single-use semantics and audit evidence as defined by Phase 1.

P2.1 email OTP is a separate primary-authentication challenge for an **existing verified** email identifier. It never creates a user, never changes `verified_at`, never fabricates password authority and does not encode an MFA bypass. Its challenge uses six `crypto/rand` digits, Argon2 verifier-only persistence, 10-minute TTL, one-minute resend cooldown, at most three issues per 15 minutes, five failed attempts, generation rotation, one-time consume, replay denial and transactional session/refresh/audit finalization.

## 5. Sessions, recovery and JWT/JWKS

Signin lookup is application scoped and preserves anti-enumeration. PostgreSQL-backed abuse controls and process KDF admission bound obvious online resource abuse. Password credential generation is rechecked across signin/reset races.

Sessions use bounded absolute/inactivity lifetimes. Refresh credentials rotate once; consumed-refresh replay revokes the session. Password-reset success replaces the verifier, increments generation, consumes reset state, revokes current sessions and audits atomically. Already-issued stateless access JWTs may remain valid for offline consumers until short expiry.

Access tokens are five-minute Ed25519/EdDSA JWTs with mandatory issuer, subject, audience, session, validity and token identifiers. Validation fails closed on algorithm/key/signature/claim/time mismatch with bounded skew. JWKS publishes public Ed25519 material only. Offline verification cannot observe immediate database revocation.

P2.3 social completion exchange produces the same ordinary BeeBox session/access/refresh lifecycle only after the provider attempt has succeeded and the client presents the correct completion PKCE verifier. Provider tokens never become BeeBox access or refresh credentials.

For P2.4A link initiation/finalization and P2.4B unlink, a persisted current session is sufficiently recent while `now < session.created_at + 10 minutes`. The mutation path rechecks the exact same persisted session and deadline. Refresh rotation, `last_seen_at` activity, a freshly signed access token, or another new browser session cannot reset or substitute this evidence. P2.4B listing needs only a valid current session and does not require recent authentication. An older session must reauthenticate through an already-supported primary method to obtain a new ordinary session for a sensitive mutation; generic in-session P2.8 step-up is not implemented here.

P2.4B successful unlink does not revoke existing ordinary BeeBox sessions. It removes a future login-capable external identity and invalidates only still-unexchanged social completion state as specified; sign-out-everywhere/AMR/session-revocation-after-credential-removal remain separate lifecycles.

## 6. Audit, privacy and observability

Security mutations keep required audit evidence inside their correctness transaction. Audit facts retain application scope, actor meaning, applicable subject, action, resource category/reference, outcome, correlation, occurrence time and minimized source context.

Audit/log/metric facts must not contain raw email/phone unnecessarily, password/hash, OTP/reset/recovery code, provider authorization code/token/body, provider client secret/state key, application secret, refresh credential, access JWT, signing private key, passkey private material or arbitrary provider errors. Secret-bearing provider URLs/queries are treated as secret material rather than safe request metadata.

Metrics use fixed bounded vocabulary only and never label by email, phone, user/session/application ID, provider subject/SID, credential ID, IP address, token/code/challenge or raw error. P2.2 SMS delivery metrics use only fixed purpose/outcome vocabulary. P2.3/P2.4A/P2.4B social admission/audit behavior likewise uses bounded BeeBox-owned operation/result vocabulary and bounded resource references; provider subject/profile/token/error text, state plaintext, PKCE verifier or provider request URLs are not telemetry cardinality or audit payload.

P2.4A success ownership mutation and `authentication.social.link_succeeded` audit evidence share one PostgreSQL transaction. Resolved security-relevant denials use a bounded `social_link_attempt:<internal-id>` reference when trusted actor/application context exists. Unknown random states do not fabricate an actor audit record.

P2.4B successful external-identity deletion and `authentication.social.unlink_succeeded` audit share the same transaction; an audit insert failure rolls deletion, link-attempt cancellation and completion-grant invalidation back. Last-method denial keeps the identity and pending state and commits only a safe `authentication.social.unlink_denied` fact whose resource reference is the opaque `sli_` ID. Random/not-owned IDs use idempotent 204 without misleading resource-specific audit.

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

BeeBox has one narrow BeeBox-owned `PhoneOTPDelivery` port with separate signup/signin purposes. P2.2 implements four interchangeable internal transport adapters: Twilio, Vonage, Plivo and Telnyx. Provider wire models, message identifiers, response bodies and provider-specific status models remain adapter-local and are not BeeBox public contracts or identity authority.

`BEEBOX_SMS_MODE` is composition-owned and selects exactly one process-wide mode: `disabled`, `twilio`, `vonage`, `plivo` or `telnyx`. Unset mode is disabled. Unknown explicit mode and incomplete selected-provider configuration fail startup before listener creation with a stable credential-free configuration error. Provider adapters own only their own credentials/sender/timeout and fixed verified HTTPS production endpoint; normal operator configuration exposes no arbitrary provider base URL.

Provider network I/O occurs only **after** challenge persistence commits; PostgreSQL transactions are never held open across SMS network I/O. Every adapter performs exactly one context-aware bounded request, bounds response consumption, closes response bodies and maps provider-specific synchronous acceptance/failure to BeeBox-owned stable errors. Provider synchronous acceptance is not a claim of carrier or handset delivery.

P2.2 has no runtime provider routing, failover, least-cost selection, per-country switching, health-based switching or cross-provider retry. An ambiguous timeout/failure may occur after the selected provider accepted the SMS, so BeeBox never automatically submits that OTP to another provider. A later explicit user request, after admission/cooldown, is the retry boundary.

When SMS mode is disabled, phone issue endpoints return a uniform service-unavailable response before phone ownership/challenge state lookup. Confirmation does not itself require provider I/O, allowing a previously committed valid challenge to remain confirmable when session-signing capability is configured.

## 11. P2.3 social provider proof trust boundary

P2.3 supports exactly `google`, `apple`, `microsoft`, `github`, `gitlab`, `facebook`, `slack`, `discord`, `linkedin`, `x`, and `tiktok` behind one BeeBox-owned social-auth lifecycle. P2.4A reuses the same proof adapters; P2.4B performs no provider I/O. Per-application provider configuration is static at process startup. Provider endpoints are fixed by the adapter and external provider models never cross the BeeBox public/application boundary.

The application layer accepts only `ExternalIdentityProof{Provider, Subject}` after adapter proof succeeds. Provider email/name/avatar/profile values are not account-link authority and are discarded. Provider access/refresh/ID tokens never become BeeBox session credentials and are not persisted/exposed.

| Threat | Implemented P2.3/P2.4A provider control / evidence |
| --- | --- |
| Provider claim spoofing | Adapter must complete the configured OAuth/OIDC protocol before it can return `{provider, subject}`; application code never accepts browser-supplied provider subject/email as proof. |
| Provider-email account takeover | ADR 0007/0004 forbid provider-email import/linking authority. Equal provider/BeeBox email creates no implicit attachment, merge, adoption, transfer or verification side effect. |
| Provider subject reassignment | Ownership key is `(application_instance_id, provider, provider_subject)`; profile/email changes cannot select another owner. PostgreSQL enforces unique ownership. |
| Cross-application subject reuse | Same provider subject may independently exist in different applications; every lookup/finalization uses trusted application scope. Cross-app tests prove independence. |
| Provider token leakage | Access/refresh/ID tokens remain adapter-local and are discarded after subject proof; no public response/persistence/audit/metric contains them. |
| Provider profile leakage | Email/name/avatar/profile extras are parsed only where needed for provider response decoding and discarded; subject tests prove they cannot substitute for an invalid/missing stable ID. |
| Vendor error leakage | Provider-specific bodies/descriptions/statuses map to BeeBox-owned proof/unavailable failure categories; callback produces a generic application error marker rather than raw vendor details. |

Slack is an OIDC adapter on the same proof boundary, not a separate account model. Current Slack first-party discovery/Sign in with Slack/token evidence pins `https://slack.com` as issuer, the dedicated OpenID authorization/token/JWKS endpoints, `response_type=code`, explicit `response_mode=query`, scope exactly `openid`, RS256 ID tokens and nonce validation. BeeBox selects Slack's supported HTTP Basic confidential-client token authentication, disables provider-side PKCE for this normal server-side SIWS configuration, never calls Slack userinfo, and returns only verified ID-token `sub` into the application layer. Optional email/profile/team/user claims are discarded.

Facebook uses the accepted current Meta **base manual Website** flow, not the separately documented OIDC+PKCE extension. BeeBox pins authorization to `https://www.facebook.com/v25.0/dialog/oauth` and code exchange to `https://graph.facebook.com/v25.0/oauth/access_token` because the applicable current Meta manual-flow examples directly demonstrate v25.0 for both; this is not a claim that v25.0 is Meta's globally latest API version. The selected base flow uses no `openid` scope, provider PKCE or OIDC nonce. Facebook identity proof keeps the audited current consumer-sample endpoint unversioned at `https://graph.facebook.com/me?fields=id`, presents `access_token` as the documented query parameter, and accepts only the returned app-scoped User `id` as a bounded opaque string subject. Email/name/profile values cannot substitute. Bearer support for this exact request is not required by BeeBox and is not claimed unsupported.

## 12. P2.3 redirect, state and callback CSRF controls

Social initiation requires an exact current-application redirect allowlist entry and a client S256 completion challenge. The canonical redirect is validated before attempt creation and persisted into the attempt. Browser/provider callback input cannot replace it.

Every P2.3 attempt uses 32 bytes from `crypto/rand` for `state`; only `SHA-256(state)` is stored. The attempt lifetime is 10 minutes. Callback first base64url-decodes and hashes state, then atomically consumes the exact `(state_hash, callback_provider)` attempt before any provider token/profile exchange. Wrong-provider, expired, unknown and replayed state fail closed and cannot trigger provider proof.

This implements ADR 0006's generic social-state binding to the provider attempt, trusted application, purpose and exact redirect. P2.4A adds the stricter existing-principal/session/recent-authentication binding described in section 17 without changing already-merged P2.3 state semantics.

| Threat | Implemented P2.3 control / evidence |
| --- | --- |
| State substitution / callback CSRF | 256-bit unpredictable state; hash-only persistence; exact provider binding; one-time consume before provider I/O. |
| Cross-app callback substitution | Attempt resolves trusted application/public-provider configuration from stored state rather than callback-supplied application input. |
| Open redirect | Stored redirect had to match the exact application's canonical allowlist; callback returns only that stored value for both success and generic provider failure. |
| Redirect query/code injection | Configured application redirect cannot contain query/fragment; BeeBox exclusively appends its bounded completion/error query parameter. |
| Callback replay | Consumed state cannot be loaded a second time, so provider code is not automatically exchanged again. |

## 13. P2.3 OIDC, provider-code and backchannel controls

OIDC providers use provider-specific issuer/JWKS configuration and validate RS256 signature, client audience, expiry, not-before when present, nonce and non-empty stable subject before returning proof. Nonce is random and only its SHA-256 hash is persisted. Tests cover issuer, audience, signature, expiry, nonce, subject, Microsoft tenant isolation and JWKS key rotation/cache behavior with deterministic local RSA/JWKS fixtures.

Providers whose selected current contract uses PKCE receive a BeeBox-generated high-entropy provider verifier and S256 challenge. The verifier is persisted only as AES-256-GCM ciphertext using a configuration key, with associated data binding application, provider and state hash. P2.4A uses a distinct link-purpose AAD domain separator rather than weakening P2.3's existing ciphertext format. Providers whose selected contract does not use PKCE rely on the provider's confidential-client/token endpoint semantics plus BeeBox state/redirect binding; BeeBox does not invent provider protocol parameters outside the selected contract. Slack falls into this latter group for the selected normal confidential Website SIWS flow. Facebook also falls into this group because BeeBox explicitly selects Meta's base manual Website flow rather than its separately documented OIDC+PKCE extension; this does not assert a universal Meta PKCE negative. Neither provider choice alters BeeBox's separate mandatory P2.3 client completion S256 PKCE.

Facebook code exchange is a dedicated single GET to the fixed v25.0 token endpoint with `client_id`, exact `redirect_uri`, `client_secret`, and one-time provider `code` in the HTTPS query. It does not use the generic OAuth POST-form exchange, HTTP Basic, `grant_type`, or `code_verifier`. Facebook Graph identity proof is one GET to unversioned `/me` with exactly `fields=id` plus the provider `access_token` query parameter and no Authorization header. Because these query strings contain credentials/tokens, BeeBox must never log, audit, metric-label, return, or include the full request URL/query in errors.

Provider authorization codes are never persisted. Every token/profile/JWKS request uses context-aware bounded HTTP with a five-second provider timeout, bounded response body, closed body, no redirects and no automatic retries. Provider outage/timeout is a safe authentication/link failure; PostgreSQL correctness does not depend on provider availability after a completed BeeBox transaction.

| Threat | Implemented P2.3/P2.4A provider control / evidence |
| --- | --- |
| OIDC mix-up/issuer confusion | Provider-specific issuer/JWKS and explicit audience/nonce/signature/time validation; Microsoft issuer is tenant-bound. |
| OIDC nonce replay/substitution | Nonce generated per attempt, hash-only persistence, verified after signature/claim validation and attempt one-time consumption. |
| Provider authorization-code interception | Provider-side S256 PKCE is used for providers whose selected contract supports/requires it; selected confidential-client contracts without provider PKCE rely on their provider token/client-auth semantics plus BeeBox state/redirect binding. Facebook's base manual flow additionally sends its configured client secret in the documented fixed HTTPS token-exchange query and never logs that URL. |
| JWKS key rotation/cache staleness | OIDC verifier caches keys but performs bounded refresh behavior on an unknown `kid`; deterministic tests exercise rotation and prevent unbounded refresh loops. |
| Provider outage/backchannel abuse | Explicit timeout/body limit/no retry/no redirect; failures collapse to BeeBox-owned error and cannot hold a DB transaction open. |
| Compromised provider client credentials | Blast radius is the configured `(application, provider)` connection and provider trust relationship; credentials are configuration-only. BeeBox cannot protect an upstream provider account after credential compromise, so operator rotation/revocation remains required. |

## 14. P2.3 completion-code leakage, replay and concurrency controls

A P2.3 provider callback never directly places an ordinary BeeBox access/refresh token into the application redirect. On successful provider proof BeeBox generates a separate 32-byte completion code and persists only its SHA-256 hash, application/user binding, original client S256 challenge and a five-minute expiry. P2.4A link callbacks never create this grant type.

The P2.3 client must exchange that code with the original RFC7636 verifier. Wrong verifier, expired grant, cross-application grant and replay fail as the same invalid-completion category. Successful exchange atomically consumes the grant, creates the ordinary BeeBox session, persists the refresh verifier and writes required audit evidence. Any required persistence/audit failure rolls back session creation and grant consumption.

Concurrent completion redemption is serialized in PostgreSQL: exactly one exchange may commit a session/refresh verifier; competing redemption observes consumed/invalid state. P2.4B unlink conservatively consumes all still-unconsumed social completion grants for the same application/user inside the unlink transaction. If exchange commits first, the resulting ordinary session remains; if unlink commits first, later exchange fails closed. The SDK intentionally does not blindly retry completion exchange after an ambiguous response.

| Threat | Implemented P2.3/P2.4B control / evidence |
| --- | --- |
| Completion code leaked from redirect/history | Code alone is insufficient; client must possess the original high-entropy PKCE verifier matching the stored S256 challenge. |
| Completion replay | One-time grant is consumed transactionally; replay cannot create another session. |
| Cross-app completion substitution | Grant is application scoped and exchange uses trusted application context from the publishable-key/origin boundary. |
| Concurrent redeem | PostgreSQL transaction/locking yields at most one successful session. |
| Unlink after provider proof but before exchange | Successful unlink consumes pending user-scoped completion grants; an exchange that wins first creates an ordinary session that P2.4B intentionally does not revoke. |
| Partial session/audit commit | Grant consume + session + refresh verifier + required audit share one correctness transaction. |

## 15. P2.3 external identity and new-subject principal creation controls

ADR 0007 authorizes normal provider-first signup: when a verified `(application, provider, provider_subject)` has no owner, P2.3 creates a new application-scoped user and attaches exactly that external identity. When it already exists, BeeBox resolves exactly the existing owner.

`external_identities` carries explicit application + user ownership and PostgreSQL uniqueness on `(application_instance_id, provider, provider_subject)`. P2.3 finalization also serializes concurrent first use for one external identity so speculative principal creation cannot leave duplicate/orphan users. Tests prove concurrent first callbacks converge on one user/external identity while each valid attempt may receive its own completion grant.

Provider email equality never changes this decision. If a provider returns an email equal to a verified BeeBox email owned by another existing principal, P2.3 creates a separate provider-first principal and no `email_identifiers` row from the provider claim. No P2.3 path merges principals.

P2.4A is the implemented path for explicitly attaching a newly proved external identity to an existing authenticated BeeBox principal, under the stricter ADR 0004/0005/0006 bindings in section 17. P2.4B may remove that ownership association but never transfers it to another existing principal. After unlink commits, a later valid P2.3 proof observes an unowned provider subject and follows ADR 0007 new-principal behavior rather than silently authenticating or resurrecting the former owner.

## 16. P2.3/P2.4A/P2.4B abuse controls, provider outage and privacy

Migration `00015_social_oauth.sql` adds bounded persistent public-auth admission namespaces for P2.3 social attempt and completion exchange. Migration `00016_social_account_linking.sql` adds fixed `social_link_attempt_global` and `social_link_attempt_user_provider` namespaces. The latter binds request creation to a fixed global/application bucket plus a SHA-256 user/provider subject bucket; no email/session/provider-subject value becomes a metric or limiter label. These bounds reduce request/provider amplification without making Redis part of correctness.

Migration `00017_social_account_management.sql` adds only an opaque public social-link ID, scoped listing index and `social_link_attempts.canceled_at`; it does not add provider credentials, generic policy state or distributed infrastructure. Listing is bounded to default 20/maximum 100 and cursor state contains only creation time plus opaque public ID. Delete is idempotent for syntactically valid absent/not-owned/cross-app IDs, preventing a direct resource-existence oracle.

Social auth/link attempts and P2.3 completion grants are subject to short TTLs and bounded cleanup. Expired/consumed/canceled social-link attempts are eligible for maintenance cleanup. Audit uses BeeBox-owned action/resource vocabulary and bounded resource references; metrics/logging must never introduce provider subject, email/profile claims, token/code/client secret, state/nonce, exact provider error body, secret-bearing provider request URL/query or other high-cardinality secrets/PII.

Provider outage is fail-closed for new provider proof: BeeBox does not retry a potentially ambiguous provider token exchange automatically and does not route to another identity provider. P2.4B last-method computation does not live-probe provider/email/SMS health; it uses structural runtime configuration so correctness is deterministic while external delivery uptime remains an operational residual risk. Existing ordinary BeeBox sessions do not require provider availability to remain valid under their own session lifecycle.

## 17. P2.4A explicit authenticated social-link controls

P2.4A attaches a verified provider subject only to the **already-authenticated initiating BeeBox principal**. Its authoritative server-side context is `(application, initiating user, exact initiating session, purpose=social_link, provider attempt, exact trusted redirect, persisted session.created_at freshness evidence)`. Initiation derives app/user/session from the publishable key plus validated ordinary access token and persisted session; the public JSON cannot select a target user/session or provider subject.

The link attempt persists only the state hash and exact bound context. `lnk_` is merely callback dispatch; the dedicated attempt row is authority. P2.3 and P2.4A states are not interchangeable: stripping `lnk_` routes the secret to the unchanged P2.3 state store, where no matching auth attempt exists; adding `lnk_` routes P2.3 state to the dedicated link store, where no matching link attempt exists. Link-purpose provider-PKCE ciphertext also uses distinct AAD.

Before any ownership mutation, the final PostgreSQL transaction locks and rechecks the exact initiating session ID, application, user, revocation, idle/absolute expiry and original `created_at`. Recent authentication is valid only before `session.created_at + 10 minutes`. Reissuing an access token, refreshing credentials or updating activity for that same session does not reset `created_at`. A replacement browser session cannot acquire the old attempt's authority.

Provider-subject ownership remains `(application_instance_id, provider, provider_subject)`. P2.4A creation/finalization and P2.4B unlink share a domain-separated application/user/provider advisory transaction lock; P2.4A finalization and unlink then acquire the existing provider-subject lock in that order. Unowned subject attaches to the bound user; same-owner subject is idempotent success; another owner produces one generic denial with no transfer, merge or unnecessary owner disclosure. No `UNIQUE(application,user,provider)` policy is added, so multiple distinct subjects for one provider/user are not prohibited by this slice.

| Threat | Implemented P2.4A control / evidence |
| --- | --- |
| Link-CSRF / session switch | Target principal and exact session are bound before provider navigation; callback does not inspect browser current session for authority. User A/session A remains target even if browser later presents session B. |
| Initiating session revoked after initiation | Final transaction locks/rechecks exact session and fails generically with no ownership mutation. A replacement session cannot substitute. |
| Initiating session expires after initiation | Idle and absolute expiry are rechecked at final commit; expired session fails closed. |
| Fresh at initiation but stale at commit | Attempt expiry is capped by both attempt TTL and initiating `session.created_at + 10m`; final transaction independently rechecks the same freshness deadline. |
| Refresh/activity resets freshness | Refresh/access-token rotation and `last_seen_at` do not change `session.created_at`; integration tests prove an old session remains ineligible. |
| Cross-application state/redirect substitution | Link attempt has composite application/user/session FKs and stored exact redirect; callback query cannot replace app/user/session/redirect. Same provider subject may still be owned independently in another application. |
| Purpose/state cross-use | Dedicated link table + hash-only state + `lnk_` dispatch namespace + purpose-separated PKCE AAD; auth attempt cannot finalize as link and link attempt cannot produce P2.3 completion/session state. |
| Provider callback path mismatch | Stored provider must equal callback provider before attempt consumption/proof; mismatch fails closed. |
| Provider-subject already owned by another user | Generic `social_link_failed`, no transfer/merge, owner remains unchanged and is not exposed. |
| Concurrent claims for one subject | Provider-subject advisory transaction lock plus unique `(application, provider, subject)` ownership yields at most one owner; loser safely denies. |
| Link/unlink resurrection | Shared app/user/provider management lock establishes a commit order. Unlink cancels same-provider pending attempts while holding it; canceled consume/finalize fails closed and provider PKCE ciphertext is cleared. |
| Provider email collision | Provider email/profile has zero ownership authority and is not inserted/verified/changed; linking consumes only verified `{provider, subject}`. |
| Provider token/code/profile leakage | Authorization code and provider token/profile material are transient adapter-local values; no link-attempt persistence, public response, redirect, audit or metric contains them. |
| Success without audit | New attachment and required success audit are one transaction; induced audit failure rolls back the external-identity insert. |
| Security denial without trusted actor | Resolved attempts may write bounded denial audit evidence for the bound actor/application; unknown random state does not invent an actor. |
| Link callback creates or rotates BeeBox auth state | P2.4A finalizer never creates a user, BeeBox session, refresh credential or P2.3 completion grant. PostgreSQL/HTTP tests assert those counts. |

P2.4A still does **not** implement principal merge or generic P2.8 step-up/reverification; P2.4B management remains a separate self-service lifecycle described next.

## 18. P2.4B linked social account management controls

`GET /v1/social-links` is current-user account metadata, not an ownership-discovery API. It authenticates one publishable key, exact canonical allowed Origin and ordinary bearer access token, verifies the persisted current session under the exact application/user, and queries only that scope. Responses use only `sli_<uuid-v4>`, provider and `created_at`; provider subject, provider profile/email, provider credentials/tokens and internal BIGINT IDs never cross the management boundary.

`DELETE /v1/social-links/{social_link_id}` is a sensitive mutation. It requires the same current persisted session plus server-trusted freshness from `session.created_at` under the ten-minute bound, and revalidates that exact session inside the transaction after mutation locks are held. A syntactically valid absent, already-deleted, other-user or other-application locator returns the same `204 No Content` without mutation or target-specific denial audit.

The last-usable-method predicate is intentionally concrete rather than a generic policy engine. After excluding the target: password counts only with a password credential **and** verified email; email OTP counts only with configured SMTP/email delivery and verified email; phone OTP counts only with enabled/configured SMS and verified phone; each remaining social identity and same-scope passkey count only when currently usable. Unverified identifiers, TOTP/recovery additional-assurance state, the current session itself and password-reset possibility count as zero primary methods.

| Threat | Implemented P2.4B control / evidence |
| --- | --- |
| IDOR / cross-application social-link ID | Public locator is opaque; every resolution is scoped by exact application + current user. Other-user/app valid IDs return the same idempotent 204 as absence. |
| Resource enumeration | Valid absent/not-owned/cross-app delete produces no ownership-specific response or target audit. Listing exposes only the current user's scoped rows. |
| Internal/provider identity disclosure | Public list/delete contract exposes `sli_` only; provider subject, provider email/profile, provider tokens and BIGINT IDs never appear. |
| Stale/revoked session mutation | Handler validates current session and unlink transaction rechecks exact app/user/session, revoked state, idle/absolute expiry, original `created_at` and `< created_at+10m`. Refreshing the same session cannot reset freshness. |
| Last-method removal | Predicate recomputed inside the same transaction under user serialization immediately before deletion. If no usable alternative remains, identity stays and a safe denied audit commits. |
| Last-two concurrent unlink | User-row serialization makes the two transactions observe an ordered method inventory; at most one of the final two usable identities can be removed. |
| Configuration availability drift | Email/SMS/social alternatives count only when structurally enabled/configured in the current process/application. No live provider probe makes deletion correctness depend on transient network health. |
| P2.4A attempt created during unlink | Shared app/user/provider management advisory lock linearizes creation and unlink. If create commits first, unlink cancels it; if unlink commits first, the later attempt is post-unlink state rather than a stale attempt crossing the cancellation boundary. |
| P2.4A finalization after unlink | Finalization shares management lock, re-reads canceled attempt after lock and then uses subject lock. Unlink-first makes old finalization fail; finalize-first may attach before unlink subsequently removes. No post-unlink resurrection. |
| P2.3 proof versus unlink | Both use the existing provider-subject lock. Proof-first may create pending completion then unlink deletes/invalidate it; unlink-first means later P2.3 sees unowned subject and follows ADR 0007 rather than authenticating former owner. |
| Pending P2.3 completion after unlink | Successful unlink consumes all still-unconsumed same-app/user completion grants. Exchange-first ordinary session may remain; unlink-first makes later exchange fail. |
| Partial success cleanup | Link-attempt cancellation, PKCE clearing, pending-completion invalidation, identity delete and success audit are one transaction. Induced audit failure rolls every success-side mutation back. |
| Denial partially cleans state | Last-method denial occurs before cancellation/grant consumption/delete. Tests prove pending link attempt, PKCE ciphertext and completion grant remain intact while safe denial audit commits. |
| Existing-session surprise revocation | P2.4B does not implement sign-out-everywhere or AMR/session-method tracking. Successful unlink leaves existing ordinary sessions unrevoked. |
| Provider-side revocation confusion | BeeBox does not persist provider access/refresh tokens and DELETE performs no vendor disconnect/consent/token-revocation call; public docs state this explicitly. |
| Audit leaks provider identity | Success/denial audit uses exact app/current actor+subject and opaque `sli_` reference only; no raw provider subject/email/profile/token/state/PKCE material. |

## 19. Implemented TOTP assurance and accepted recovery requirements

| Threat | Control and evidence |
| --- | --- |
| MFA downgrade via alternate primary method | Active TOTP applies after password, email OTP, phone OTP, social or passkey primary proof through the shared assurance finalizer. |
| Treating arbitrary two steps as independent MFA | Factor independence/security property must be evaluated by the implemented factor set. |
| Full session before required MFA | Active TOTP produces only a five-minute hash-only pending transaction. Session/access/refresh authority is issued atomically only after valid non-replayed TOTP completion. |
| Stale-session sensitive mutation | Sensitive operations require recent trusted server-side reverification. P2.4A/P2.4B implement only the narrow `session.created_at` 10-minute model; richer P2.8 step-up is not implemented. |
| Client-forged freshness | Client timestamps or claimed methods are not authority; evidence is server-recorded and bound to app/user/session/flow. P2.4A/P2.4B already enforce this for social linking/unlink. |
| Recovery downgrade/replay | Recovery credentials are purpose-specific and one-time; replay fails closed and cannot silently erase configured assurance. |

## 20. Accepted device/privacy and hosted-auth requirements

Device and hosted-auth controls remain accepted requirements, not implemented P2.4B claims:

- no permanent cross-session device fingerprint or third-party fingerprinting;
- no precise location collection by default;
- bounded purpose/retention for any later IP/user-agent persistence;
- exact server-validated hosted-auth redirect destinations in current application scope;
- no wildcard/substring/suffix redirect authority;
- generic social redirect/state controls implemented by P2.3/P2.4A do not imply a hosted-auth UI exists;
- P2.4A link state binds initiating principal/session and its accepted recent-authentication context;
- P2.4B management stays self-service/current-user scoped and does not introduce hosted-auth principal selection;
- error redirects obey the same boundary as success redirects.

## 21. Required later Phase 2 scenario outcomes

P2.4A/P2.4B now provide concrete evidence for explicit social-link session-switch/conflict/concurrency, cross-app/provider-email collision, unlink last-method, anti-enumeration and link/signin/completion race scenarios. Remaining later outcomes include:

- provider-first user later adds password -> authenticated enrollment after recent proof, not equality adoption;
- existing-account primary email/phone change -> same-user verified target + conflicts + recent proof + audit;
- alternate primary method cannot bypass later required MFA;
- other sensitive mutations outside P2.4A/P2.4B stale-session boundary -> fresh reverification under ADR 0005/P2.8;
- hosted redirect substitution/open redirect -> reject unless exact current-app validation and state binding pass;
- device metadata -> no new persistence without bounded purpose/retention review;
- principal merge, if ever added, requires a separately authorized product/security contract and is not implied by linking/unlinking.

## 22. Implemented versus accepted boundary

ADRs 0001–0007 are accepted architecture/security contracts. Existing code/tests provide Phase 1 runtime evidence and P2.1 through P2.7 evidence. TOTP evidence is detailed in `docs/threat-model/totp-mfa.md`; recovery evidence is detailed in `docs/threat-model/recovery-codes.md`.

P2.3 **does** mean social signup/signin runtime exists for the exact eleven provider keys, including exact application redirect/state/completion controls, external-identity ownership, provider proof adapters, provider-token non-retention and provider-email non-authority. P2.4A/P2.4B implement explicit authenticated social linking/management. P2.5 implements passkeys. P2.6 implements TOTP MFA with a downgrade-resistant tagged result and atomic pending completion. P2.7 implements recovery-code completion, regeneration and dedicated TOTP replacement. It does **not** mean principal merge, generic P2.8 reverification, provider-side consent revocation, device management or hosted authentication are deployed.

The deterministic provider-contract suite proves BeeBox request/response compatibility with independently accepted provider wire contracts without requiring live user accounts. Slack uses current first-party Slack SIWS/token/discovery evidence and deterministic local OIDC/JWKS fixtures; no live Slack account or credential is required. Facebook uses the Human-accepted current Meta manual Website/access-token/User evidence plus audited `fbsamples/fedcm-example-app@4a244376676473fe639f6ab186386c60eca21f8d` consumer `/me` evidence. Its deterministic tests independently pin the selected v25.0 authorization/token literals, dedicated GET/query exchange, unversioned `/me?fields=id` query-token request, opaque-string `id`, safe error collapse, no retry and secret/token non-leakage. This does not claim v25.0 is Meta's globally latest version, does not claim Bearer is unsupported, and does not opt into Meta's separately documented OIDC+PKCE extension.

The suite does not prove real developer-console configuration, real credentials, provider app-review approval, consent/account availability, or provider production uptime. Each later slice must provide its own concrete code, persistence/API contracts, adversarial tenant/security tests and exact-head CI before BeeBox may claim that runtime control exists.

## 23. Residual implemented-surface threats

| Threat | Current control / residual risk |
| --- | --- |
| Database/backup compromise | Password/OTP/refresh verifier material, phone PII and external-identity/link-attempt ownership metadata remain sensitive offline; backups require privileged protection. |
| Online KDF/request exhaustion | Persistent admission and process KDF bounds reduce obvious abuse; volumetric capacity protection remains operational. |
| Signup/signin/reset/OTP enumeration | Public responses collapse account-sensitive distinctions; timing requires continued regression/operational observation. |
| Email/SMS provider compromise | Delivered OTPs depend on mailbox/carrier/provider control; provider compromise may expose codes/destination metadata. |
| SMS cost/message bombing | Global-first/per-phone admission and challenge cooldown/windows bound application behavior; upstream volumetric/provider controls remain operational concerns. |
| SMS provider delivery ambiguity | Challenge can commit before provider response; no automatic retry/failover avoids duplicate sends but may require explicit user resend later. |
| Social provider compromise | BeeBox trusts a correctly verified provider subject according to the configured protocol; compromise of the provider account or upstream provider can therefore authenticate/link that external identity after BeeBox's local authority checks. Provider email is still not link authority. |
| Social client-credential compromise | Configuration compromise may allow abuse of that provider application/connection; operator-side provider credential rotation/revocation is required. Secrets are not stored as BeeBox identity data. |
| Social provider outage | New social proof/link finalization fails closed under bounded timeout/no retry. Existing BeeBox sessions continue under BeeBox session state. P2.4B structural provider availability can still count a configured provider during an upstream outage by design. |
| Social completion-code theft | P2.3 code is short-lived/one-time and client S256-bound, but compromise of both redirect code and verifier can authorize the intended completion until expiry unless successful unlink invalidates the pending grant first. |
| Social-link browser compromise | Exact Origin/redirect/state/session binding prevents callback-time principal substitution, but XSS or compromise while a valid fresh user session is present can initiate account-management actions with that browser/application authority. |
| Social-link state theft | State is high entropy, one-time and bounded by exact app/user/session/provider/recent-auth context; theft can at most drive the already-bound attempt before expiry and cannot retarget another principal. P2.4B cancellation invalidates old pending state after unlink. |
| Social-link public-ID disclosure | `sli_` is a locator only; delete remains current app/user scoped and anti-enumerating. Leakage may reveal identifier shape but not provider subject/ownership. |
| Last-method configuration drift | Predicate uses current structural process configuration rather than live provider health. This avoids transient-network correctness dependency but means a configured-yet-outage provider may be considered usable until configuration changes. |
| OAuth redirect/browser compromise | Exact redirect/state/PKCE reduce substitution; XSS or compromised application redirect origin can still act with that application's browser authority. |
| Facebook protocol/version drift | BeeBox intentionally pins the applicable Meta manual Website auth/token examples to v25.0 while leaving the audited consumer `/me` endpoint unversioned. Future Meta contract/version changes require explicit revalidation; conflicting global version renderings are not generalized into this contract. |
| Facebook query-credential leakage | The selected Meta flow places client secret + code in the token-exchange query and access token in the Graph query. HTTPS protects transport, while BeeBox forbids logging/auditing/metric-labeling/returning those URLs or provider error material. Upstream proxies/observability must preserve the same rule. |
| Refresh theft/replay | One-time rotation and replay-triggered revoke; ambiguous response loss can force reauthentication. Refresh never refreshes P2.4A/P2.4B `session.created_at` freshness. |
| Access-token theft | Short-lived bearer remains usable until expiry for offline consumers; no global denylist. P2.4A/P2.4B additionally require current persisted session state and ten-minute authentication age for sensitive mutation. |
| XSS/CSRF | HttpOnly/SameSite/exact-Origin and social state/redirect/session controls reduce browser abuse; XSS can still act with page authority. |
| Signing/SMS/social-provider key compromise | Requires secure configuration distribution/rotation; secret material absent from DB/JWKS/public errors. |
| Metrics exposure | No PII/secret labels, but endpoint still needs network protection. |

## 24. Evidence map

- `docs/adr/0001-application-instance-root.md` through `0006-phase2-device-privacy-hosted-auth.md` — accepted root isolation, identity/linking, assurance and privacy/redirect contracts.
- `docs/adr/0007-phase2-social-signup-claims.md` — accepted P2.3 new-subject principal creation, provider-email non-authority, exact eleven-provider amendment and P2.4 boundary.
- `docs/contracts/conventions.md` — tenancy, error, time, audit, versioning and idempotency conventions.
- `internal/identity/phone.go` — strict E.164 BeeBox phone value.
- `internal/platform/migration/sql/00014_phone_sms.sql` — application-scoped phone identity, verified uniqueness, fingerprint-only signup challenge, purpose-separated signin challenge and limiter vocabulary.
- `internal/authentication/phone.go` — signup/signin OTP generation, purpose separation, admission and provider-neutral delivery boundary.
- `internal/authentication/postgres/phone_store.go` — PostgreSQL issue/load/finalize correctness and transactional signup/session/audit semantics.
- `internal/session/phone.go` — primary-proof confirmation, KDF behavior and ordinary session/token integration.
- `internal/authentication/twiliodelivery/`, `vonagedelivery/`, `plivodelivery/` and `telnyxdelivery/` — fixed-production-endpoint adapters with bounded I/O, stable errors and no automatic retry/fallback.
- `cmd/beebox/sms.go` — static one-provider-per-process composition and fail-closed mode/config selection.
- `internal/authentication/metricsdelivery/phone.go` — bounded SMS purpose/outcome observations.
- `internal/httpapi/phone.go` — four additive v1 routes, trusted application/Origin boundary, anti-enumerating issue behavior and normal session transport.
- `api/openapi/v1.yaml` and `sdk/go/phone.go` — BeeBox-owned public/SDK phone contracts with no provider/internal IDs.
- `internal/authentication/postgres/phone_sms*_integration_test.go` — no-account-before-proof, privacy, lifecycle, attempts/expiry/replay/concurrency and transactional rollback evidence.
- `internal/platform/migration/phone_sms_migration_integration_test.go` — fresh/upgrade/constraint/vocabulary evidence.
- `internal/httpapi/phone*_test.go` — disabled/provider privacy, browser/non-browser transport and full PostgreSQL HTTP lifecycle evidence.
- provider `*_delivery/*_test.go`, `cmd/beebox/sms_test.go` and `cmd/beebox/phone_sms_startup_test.go` — synthetic provider/composition/startup evidence without live SMS credentials or network sends.
- `internal/platform/migration/sql/00015_social_oauth.sql` — exact redirect allowlist, external-identity uniqueness, exact eleven-provider checks, hash-only social state/completion grants and social abuse-control vocabulary.
- `internal/applicationinstance/redirect.go` and `internal/applicationinstance/postgres/redirect_store.go` — exact canonical redirect boundary and application-scoped persistence/audit.
- `internal/authentication/social.go` — shared P2.3 state/nonce/provider-PKCE/completion lifecycles, exact provider vocabulary, TTLs, replay behavior and bounded social admission interface.
- `internal/authentication/postgres/social_store.go` — P2.3 transactional external-identity resolution/creation, concurrent first-use serialization, completion/session/audit correctness.
- `internal/session/social.go` — P2.3 client S256 completion proof and ordinary BeeBox session/token integration.
- `internal/authentication/socialprovider/registry.go` — strict per-application/provider startup config and state-key requirements; P2.4B reuses resolution only to determine structural social-method availability.
- `internal/authentication/socialprovider/adapter.go` — fixed provider endpoints, bounded token/profile/JWKS I/O, OIDC verification, dedicated Facebook GET/query token + Graph proof, and subject-only application boundary reused by P2.4A.
- `internal/authentication/socialprovider/facebook_contract_test.go` and `facebook_graph_contract_test.go` — independent current Facebook v25 manual auth/token literals, dedicated GET/query exchange, unversioned query-token `/me`, opaque-string subject, provider-shaped failure, redirect/no-retry and secret/token non-leakage evidence.
- `internal/authentication/socialprovider/provider_contract_test.go` — exact independently encoded eleven-provider production literal matrix, including Facebook's dedicated token-exchange mode rather than misrepresenting it as an OAuth AuthStyle.
- `internal/authentication/socialprovider/slack_contract_test.go`, `slack_subject_contract_test.go`, `slack_registry_test.go`, other `*_contract_test.go`, `protocol_test.go`, `adapter_test.go` and `registry_test.go` — deterministic provider-shaped success/error/protocol/subject/JWKS/config evidence; Slack remains shared OIDC with explicit query response mode and Basic token auth.
- `internal/authentication/postgres/social_store_integration_test.go` — P2.3 provider-email collision separation, existing subject reuse, cross-app isolation, concurrent first callback, state/completion replay, session/refresh and audit rollback evidence.
- `internal/httpapi/social.go`, `internal/httpapi/social_test.go` and `internal/httpapi/social_e2e_integration_test.go` — P2.3 direct handler and PostgreSQL-backed initiate/callback/exchange browser-boundary evidence.
- `internal/platform/migration/sql/00016_social_account_linking.sql` — P2.4A dedicated application/user/session-bound link attempts, exact provider/purpose vocabulary, hash-only state/nonce, bounded lifetime and fixed admission operations.
- `internal/authentication/social_link.go` — P2.4A 10-minute session freshness, exact link-purpose state, purpose-separated provider-PKCE protection and shared-provider proof orchestration.
- `internal/authentication/postgres/social_link_store.go` — exact-session revalidation, management/provider-subject serialization, unowned/same-owner/other-owner semantics, canceled-at rejection and transactional link-success audit.
- `internal/httpapi/social_link.go` — authenticated initiate boundary, strict JSON, exact Origin/application/session resolution, shared callback purpose routing and stored-redirect-only result markers.
- `internal/authentication/social_link_test.go`, `internal/httpapi/social_link_test.go`, `internal/authentication/postgres/social_link*_integration_test.go` and `internal/httpapi/social_link_e2e_integration_test.go` — purpose separation, session switch/revocation/staleness, conflict/concurrency, provider-email non-authority, cross-app ownership, bounded admission, audit rollback and real-handler/PostgreSQL evidence.
- `internal/platform/migration/social_link_migration_integration_test.go` and `internal/platform/maintenance/social_link_cleanup_integration_test.go` — clean upgrade/constraints/exact vocabulary and bounded retention evidence.
- `internal/platform/migration/sql/00017_social_account_management.sql` — `sli_<uuid-v4>` backfill/default/uniqueness/check, scoped listing index and explicit link-attempt cancellation timestamp.
- `internal/authentication/social_account_management.go` and `internal/authentication/postgres/social_account_management_store.go` — bounded cursor/list service, server-trusted unlink freshness, concrete usable-method predicate, user/management/subject lock ordering, pending-state invalidation and atomic unlink audit.
- `internal/authentication/postgres/social_account_management_integration_test.go` and `social_account_management_crossflow_integration_test.go` — scoped listing, last-method matrix, concurrent unlink, P2.4A create/finalize races, P2.3 proof/completion races, denial-state preservation, existing-session retention and induced audit rollback evidence.
- `internal/httpapi/social_account_management.go` and `internal/httpapi/social_account_management_test.go` — exact publishable-key/Origin/current-session boundary, minimized list response, pagination/error/CORS/no-store behavior and opaque-ID unlink contract.
- `internal/platform/migration/social_account_management_migration_integration_test.go` — clean/00016-upgrade public-ID/default/index/cancellation constraint evidence.
- `api/openapi/v1.yaml`, `api/openapi/openapi_test.go`, `sdk/go/social_account_management.go` and SDK tests — P2.4B public/SDK listing/unlink contract with bounded query encoding, opaque IDs and no provider-subject/internal-ID model.
- `.github/workflows/ci.yml` — formatting, vet, vulnerability, OpenAPI, SDK, repeated social provider-contract, full unit, PostgreSQL integration and race gates.
