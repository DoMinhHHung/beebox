# Initial BeeBox Threat Model

> Status: repository-owned threat model for ratified Phase 1, implemented P2.1 passwordless email OTP, implemented P2.2 phone-first signup + verified-phone SMS OTP authentication, implemented P2.3 social OAuth/OIDC, and **accepted** Phase 2 trust contracts for later work.
> Governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and accepted ADRs 0001–0007.
> ADRs 0004–0007 remain architecture/security requirements. P2.3 does not implement existing-account phone enrollment/change/removal, P2.4 account linking/unlinking, MFA, reverification runtime, passkeys, recovery, device management or hosted auth.

## 1. Scope and trust model

BeeBox is one Go modular monolith with PostgreSQL as the correctness source of truth. `application_instance` is the root isolation boundary. Email, phone and external identities are application-scoped. Equality of email, phone or provider profile claims is never implicit account-link, merge or adoption authority. BeeBox consumes external OAuth/OIDC providers for authentication in P2.3; it is not itself an OAuth/OIDC authorization server.

The reachable implemented surface covers email/password signup and ownership verification, password signin/reset, P2.1 email OTP primary authentication, P2.2 phone-first SMS possession signup and verified-phone SMS OTP primary authentication, P2.3 social OAuth/OIDC signup/signin, ordinary session/current/refresh/revoke/signout, Ed25519 JWT/JWKS, backend session management, bounded metrics and the Go SDK.

P2.3 adds exactly three BeeBox social-auth public operations: initiate, provider callback, and completion exchange. It does not add provider-specific public models or provider-token APIs. Existing-account phone add/change/remove/switch, P2.4 explicit social linking/unlinking, passkeys, MFA, generic recovery codes, step-up/reverification runtime, hosted authentication and device-management behavior remain unimplemented. Accepted ADRs 0004–0007 define the security contracts applicable to implemented social signup/signin and later explicit-link slices.

## 2. Assets and secret/PII handling

| Asset | Requirement |
| --- | --- |
| Application scope | Selected from trusted server context and included in identity/session/credential/provider lookups and mutations. |
| Email/phone | PII; not account-link authority by equality alone; excluded from unnecessary audit/log/metric/challenge/rate-limit state. |
| Phone signup fingerprint | Domain-separated SHA-256 of canonical E.164; purpose-specific non-reversible lookup key, not public identity authority. |
| Provider subject | Stable external-account identity only after verified provider proof and only inside `(application, provider)` scope; never cross-application authority or a metric label. |
| Provider email/name/avatar/profile claim | Transient untrusted profile material unless required for protocol parsing; not BeeBox identity/link authority and discarded by P2.3. |
| Provider authorization code | Short-lived provider bearer-like credential consumed only by the adapter over bounded backchannel I/O; never persisted, exposed or included in logs/errors/telemetry, including query-bearing provider request URLs. |
| Provider access/refresh/ID token | Adapter-local proof material only. P2.3 does not persist, expose, log, audit or metric-label provider tokens; token-bearing query URLs are equally secret. |
| Social state | 32 random bytes returned to the browser; only SHA-256 state hash is persisted. One-time, 10-minute attempt lifetime. |
| OIDC nonce | 32 random bytes sent to OIDC provider; only SHA-256 nonce hash is persisted and compared after verified ID-token parsing. |
| Provider PKCE verifier | Random verifier stored only as AES-256-GCM ciphertext bound to application/provider/state; cleared when the attempt is consumed. |
| Social completion code | 32 random bytes returned only after provider proof; only SHA-256 code hash is persisted. One-time, five-minute lifetime, client S256-bound. |
| Client completion PKCE verifier | Client-owned secret; BeeBox persists only the S256 challenge and verifies the submitted verifier during completion exchange. |
| Password | Raw input transient only; shared public policy before Argon2id hashing. |
| OTP/reset/recovery verifiers | Sensitive verifier material; plaintext code transient only and never returned/logged after its explicit lifecycle boundary. |
| SMS provider credential | Configuration secret only; never persisted in PostgreSQL, logged, audited or exposed through public errors/metrics. |
| Social provider client secret | Configuration secret only; never persisted as identity/session data, logged, audited or exposed publicly. Facebook's selected manual flow sends it in an HTTPS query to Meta, so the outbound URL itself is secret-bearing and must never be logged. |
| Social state-protection key | Configuration-only 32-byte AES key; never persisted, logged, audited or exposed publicly. |
| Application secret | Random high-entropy plaintext returned once; verifier only persisted. |
| Refresh credential | Random secret stored only as verifier hash; one-time rotation. |
| Access JWT | Short-lived bearer credential; never logged/audited/used as a metric label. |
| Signing private key | Configuration secret only; never stored in PostgreSQL or published in JWKS. |
| Passkey | BeeBox may receive public credential material only; private key remains authenticator-owned. |
| Device metadata | PII/security metadata collected only for a documented purpose and bounded lifecycle. |
| Audit facts | Required security-state facts commit inside the mutation correctness boundary and contain minimized references rather than provider secrets/PII. |

## 3. Ratified application trust and tenancy

Publishable keys establish application integration context only and grant no user/backend/admin authority. Secret keys establish backend application authority only after verifier comparison and revocation checks. Public IDs are opaque locators; parsing or possessing one is not authorization.

Frontend/backend routes and persistence combine trusted application scope with the target resource. Exact configured origins remain the browser/CORS boundary. Refresh cookies are application-specific `__Host-` cookies with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain attribute.

P2.2 never takes application scope from a phone number. The same canonical phone can be an independent identifier in different applications. Database composite ownership and challenge foreign keys prevent cross-application substitution.

P2.3 never takes application scope, redirect authority or principal ownership from a provider callback. Social initiation resolves the application through the publishable-key boundary, validates the requested redirect against that application's exact redirect allowlist, then persists the trusted application/provider/redirect/client-challenge state. Callback resolves the attempt from the one-time state hash and stored provider binding; it does not accept a browser-supplied application/user/redirect as authority.

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

## 6. Audit, privacy and observability

Security mutations keep required audit evidence inside their correctness transaction. Audit facts retain application scope, actor meaning, applicable subject, action, resource category/reference, outcome, correlation, occurrence time and minimized source context.

Audit/log/metric facts must not contain raw email/phone unnecessarily, password/hash, OTP/reset/recovery code, provider authorization code/token/body, provider client secret/state key, application secret, refresh credential, access JWT, signing private key, passkey private material or arbitrary provider errors. Secret-bearing provider URLs/queries are treated as secret material rather than safe request metadata.

Metrics use fixed bounded vocabulary only and never label by email, phone, user/session/application ID, provider subject/SID, credential ID, IP address, token/code/challenge or raw error. P2.2 SMS delivery metrics use only fixed purpose/outcome vocabulary. P2.3 social admission/audit behavior likewise uses bounded BeeBox-owned operation/result vocabulary and bounded resource references; provider subject/profile/token/error text or provider request URLs are not telemetry cardinality or audit payload.

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

P2.3 supports exactly `google`, `apple`, `microsoft`, `github`, `gitlab`, `facebook`, `slack`, `discord`, `linkedin`, `x`, and `tiktok` behind one BeeBox-owned social-auth lifecycle. Per-application provider configuration is static at process startup. Provider endpoints are fixed by the adapter and external provider models never cross the BeeBox public/application boundary.

The application layer accepts only `ExternalIdentityProof{Provider, Subject}` after adapter proof succeeds. Provider email/name/avatar/profile values are not account-link authority and are discarded. Provider access/refresh/ID tokens never become BeeBox session credentials and are not persisted/exposed.

| Threat | Implemented P2.3 control / evidence |
| --- | --- |
| Provider claim spoofing | Adapter must complete the configured OAuth/OIDC protocol before it can return `{provider, subject}`; application code never accepts browser-supplied provider subject/email as proof. |
| Provider-email account takeover | ADR 0007 forbids provider-email import/linking authority. Equal provider/BeeBox email creates no attachment, merge, adoption, transfer or verification side effect. Integration tests prove a separate principal is created. |
| Provider subject reassignment | Ownership key is `(application_instance_id, provider, provider_subject)`; profile/email changes cannot select another owner. PostgreSQL enforces unique ownership. |
| Cross-application subject reuse | Same provider subject may independently exist in different applications; every lookup/finalization uses trusted application scope. Cross-app tests prove independence. |
| Provider token leakage | Access/refresh/ID tokens remain adapter-local and are discarded after subject proof; no public response/persistence/audit/metric contains them. |
| Provider profile leakage | Email/name/avatar/profile extras are parsed only where needed for provider response decoding and discarded; subject tests prove they cannot substitute for an invalid/missing stable ID. |
| Vendor error leakage | Provider-specific bodies/descriptions/statuses map to BeeBox-owned proof/unavailable failure categories; callback produces a generic application error marker rather than raw vendor details. |

Slack is an OIDC adapter on the same proof boundary, not a separate account model. Current Slack first-party discovery/Sign in with Slack/token evidence pins `https://slack.com` as issuer, the dedicated OpenID authorization/token/JWKS endpoints, `response_type=code`, explicit `response_mode=query`, scope exactly `openid`, RS256 ID tokens and nonce validation. BeeBox selects Slack's supported HTTP Basic confidential-client token authentication, disables provider-side PKCE for this normal server-side SIWS configuration, never calls Slack userinfo, and returns only verified ID-token `sub` into the application layer. Optional email/profile/team/user claims are discarded.

Facebook uses the accepted current Meta **base manual Website** flow, not the separately documented OIDC+PKCE extension. BeeBox pins authorization to `https://www.facebook.com/v25.0/dialog/oauth` and code exchange to `https://graph.facebook.com/v25.0/oauth/access_token` because the applicable current Meta manual-flow examples directly demonstrate v25.0 for both; this is not a claim that v25.0 is Meta's globally latest API version. The selected base flow uses no `openid` scope, provider PKCE or OIDC nonce. Facebook identity proof keeps the audited current consumer-sample endpoint unversioned at `https://graph.facebook.com/me?fields=id`, presents `access_token` as the documented query parameter, and accepts only the returned app-scoped User `id` as a bounded opaque string subject. Email/name/profile values cannot substitute. Bearer support for this exact request is not required by BeeBox and is not claimed unsupported.

## 12. P2.3 redirect, state and callback CSRF controls

Social initiation requires an exact current-application redirect allowlist entry and a client S256 completion challenge. The canonical redirect is validated before attempt creation and persisted into the attempt. Browser/provider callback input cannot replace it.

Every attempt uses 32 bytes from `crypto/rand` for `state`; only `SHA-256(state)` is stored. The attempt lifetime is 10 minutes. Callback first base64url-decodes and hashes state, then atomically consumes the exact `(state_hash, callback_provider)` attempt before any provider token/profile exchange. Wrong-provider, expired, unknown and replayed state fail closed and cannot trigger provider proof.

This implements ADR 0006's generic social-state binding to the provider attempt, trusted application, purpose and exact redirect. P2.3 does not carry an existing BeeBox principal through the flow and therefore does not implement the stricter P2.4 explicit-link principal/session/reverification binding.

| Threat | Implemented P2.3 control / evidence |
| --- | --- |
| State substitution / callback CSRF | 256-bit unpredictable state; hash-only persistence; exact provider binding; one-time consume before provider I/O. |
| Cross-app callback substitution | Attempt resolves trusted application/public-provider configuration from stored state rather than callback-supplied application input. |
| Open redirect | Stored redirect had to match the exact application's canonical allowlist; callback returns only that stored value for both success and generic provider failure. |
| Redirect query/code injection | Configured application redirect cannot contain query/fragment; BeeBox exclusively appends its bounded completion/error query parameter. |
| Callback replay | Consumed state cannot be loaded a second time, so provider code is not automatically exchanged again. |

## 13. P2.3 OIDC, provider-code and backchannel controls

OIDC providers use provider-specific issuer/JWKS configuration and validate RS256 signature, client audience, expiry, not-before when present, nonce and non-empty stable subject before returning proof. Nonce is random and only its SHA-256 hash is persisted. Tests cover issuer, audience, signature, expiry, nonce, subject, Microsoft tenant isolation and JWKS key rotation/cache behavior with deterministic local RSA/JWKS fixtures.

Providers whose selected current contract uses PKCE receive a BeeBox-generated high-entropy provider verifier and S256 challenge. The verifier is persisted only as AES-256-GCM ciphertext using a configuration key, with associated data binding application, provider and state hash. It is recovered only after the matching attempt is consumed and is cleared from persistence as part of consumption. Providers whose selected contract does not use PKCE rely on the provider's confidential-client/token endpoint semantics plus BeeBox state/redirect binding; BeeBox does not invent provider protocol parameters outside the selected contract. Slack falls into this latter group for the selected normal confidential Website SIWS flow. Facebook also falls into this group because BeeBox explicitly selects Meta's base manual Website flow rather than its separately documented OIDC+PKCE extension; this does not assert a universal Meta PKCE negative. Neither provider choice alters BeeBox's separate mandatory client completion S256 PKCE.

Facebook code exchange is a dedicated single GET to the fixed v25.0 token endpoint with `client_id`, exact `redirect_uri`, `client_secret`, and one-time provider `code` in the HTTPS query. It does not use the generic OAuth POST-form exchange, HTTP Basic, `grant_type`, or `code_verifier`. Facebook Graph identity proof is one GET to unversioned `/me` with exactly `fields=id` plus the provider `access_token` query parameter and no Authorization header. Because these query strings contain credentials/tokens, BeeBox must never log, audit, metric-label, return, or include the full request URL/query in errors.

Provider authorization codes are never persisted. Every token/profile/JWKS request uses context-aware bounded HTTP with a five-second provider timeout, bounded response body, closed body, no redirects and no automatic retries. Provider outage/timeout is a safe authentication failure; PostgreSQL correctness does not depend on provider availability after a completed BeeBox transaction.

| Threat | Implemented P2.3 control / evidence |
| --- | --- |
| OIDC mix-up/issuer confusion | Provider-specific issuer/JWKS and explicit audience/nonce/signature/time validation; Microsoft issuer is tenant-bound. |
| OIDC nonce replay/substitution | Nonce generated per attempt, hash-only persistence, verified after signature/claim validation and attempt one-time consumption. |
| Provider authorization-code interception | Provider-side S256 PKCE is used for providers whose selected contract supports/requires it; selected confidential-client contracts without provider PKCE rely on their provider token/client-auth semantics plus BeeBox state/redirect binding. Facebook's base manual flow additionally sends its configured client secret in the documented fixed HTTPS token-exchange query and never logs that URL. |
| JWKS key rotation/cache staleness | OIDC verifier caches keys but performs bounded refresh behavior on an unknown `kid`; deterministic tests exercise rotation and prevent unbounded refresh loops. |
| Provider outage/backchannel abuse | Explicit timeout/body limit/no retry/no redirect; failures collapse to BeeBox-owned error and cannot hold a DB transaction open. |
| Compromised provider client credentials | Blast radius is the configured `(application, provider)` connection and provider trust relationship; credentials are configuration-only. BeeBox cannot protect an upstream provider account after credential compromise, so operator rotation/revocation remains required. |

## 14. P2.3 completion-code leakage, replay and concurrency controls

A provider callback never directly places an ordinary BeeBox access/refresh token into the application redirect. On successful provider proof BeeBox generates a separate 32-byte completion code and persists only its SHA-256 hash, application/user binding, original client S256 challenge and a five-minute expiry.

The client must exchange that code with the original RFC7636 verifier. Wrong verifier, expired grant, cross-application grant and replay fail as the same invalid-completion category. Successful exchange atomically consumes the grant, creates the ordinary BeeBox session, persists the refresh verifier and writes required audit evidence. Any required persistence/audit failure rolls back session creation and grant consumption.

Concurrent completion redemption is serialized in PostgreSQL: exactly one exchange may commit a session/refresh verifier; competing redemption observes consumed/invalid state. The SDK intentionally does not blindly retry completion exchange after an ambiguous response.

| Threat | Implemented P2.3 control / evidence |
| --- | --- |
| Completion code leaked from redirect/history | Code alone is insufficient; client must possess the original high-entropy PKCE verifier matching the stored S256 challenge. |
| Completion replay | One-time grant is consumed transactionally; replay cannot create another session. |
| Cross-app completion substitution | Grant is application scoped and exchange uses trusted application context from the publishable-key/origin boundary. |
| Concurrent redeem | PostgreSQL transaction/locking yields at most one successful session. |
| Partial session/audit commit | Grant consume + session + refresh verifier + required audit share one correctness transaction. |

## 15. P2.3 external identity and new-subject principal creation controls

ADR 0007 authorizes normal provider-first signup: when a verified `(application, provider, provider_subject)` has no owner, BeeBox creates a new application-scoped user and attaches exactly that external identity. When it already exists, BeeBox resolves exactly the existing owner.

`external_identities` carries explicit application + user ownership and PostgreSQL uniqueness on `(application_instance_id, provider, provider_subject)`. Finalization also serializes concurrent first use for one external identity so speculative principal creation cannot leave duplicate/orphan users. Tests prove concurrent first callbacks converge on one user/external identity while each valid attempt may receive its own completion grant.

Provider email equality never changes this decision. If a provider returns an email equal to a verified BeeBox email owned by another existing principal, P2.3 creates a separate provider-first principal and no `email_identifiers` row from the provider claim. No P2.3 path merges principals.

P2.4 remains the only future authorized path for explicitly attaching a newly proved external identity to an existing authenticated BeeBox principal, and it must satisfy ADR 0004/0005/0006 linking/reverification/state requirements.

## 16. P2.3 abuse controls, provider outage and privacy

Migration `00015_social_oauth.sql` adds bounded persistent public-auth admission namespaces for social attempt and completion exchange: global/application-provider and global/application dimensions. These bounds reduce obvious request amplification and provider/backchannel abuse without making Redis part of correctness.

Social attempts/completions are also subject to short TTLs and cleanup. Expired/consumed state is eligible for bounded maintenance cleanup. Audit uses BeeBox-owned action/resource vocabulary and bounded resource references; metrics/logging must never introduce provider subject, email/profile claims, token/code/client secret, state/nonce, exact provider error body, secret-bearing provider request URL/query or other high-cardinality secrets/PII.

Provider outage is fail-closed for new provider proof: BeeBox does not retry a potentially ambiguous provider token exchange automatically and does not route to another identity provider. Existing ordinary BeeBox sessions do not require provider availability to remain valid under their own session lifecycle.

## 17. Accepted Phase 2 identity-linking requirements not implemented by P2.3

| Threat | Accepted control / required later evidence |
| --- | --- |
| Provider-email account takeover | Provider email is a claim only; email equality never auto-links. Existing-account attachment requires authenticated explicit linking and recent reverification. P2.3 already enforces the no-auto-link half but does not implement attachment. |
| Provider-subject reassignment | `(application_instance, provider, provider_subject)` is stable ownership identity; provider email/profile changes never transfer ownership. |
| Account-link CSRF/session substitution | P2.4 explicit-link transaction must bind trusted application, initiating principal/session/equivalent context, purpose, provider attempt and required reverification. Callback must never re-resolve target from a different browser session. |
| Unauthenticated linking | Forbidden. P2.3 unauthenticated social auth may resolve an already-owned subject or create a new separate principal only; it cannot attach a new subject to an unrelated existing principal. |
| Concurrent link ownership | PostgreSQL uniqueness in application/provider scope must allow one owner; application pre-check alone is insufficient. |
| Existing-account phone enrollment/change/removal | Requires authenticated current owner, recent reverification, verified same-user target, conflict policy and remaining usable authentication/recovery path. P2.2/P2.3 intentionally have no such endpoint. |
| Unlinking last usable method | Removal requires recent proof and a remaining actually usable method consistent with configured assurance. |
| Passkey ownership confusion | Credential ID has one user owner in applicable app/RP scope; private key never reaches BeeBox; email/provider changes do not transfer credential ownership. |

## 18. Accepted Phase 2 assurance, MFA and recovery requirements

| Threat | Accepted control / required later evidence |
| --- | --- |
| MFA downgrade via alternate primary method | Required MFA applies regardless of password/email OTP/phone OTP/social primary method. P2.1/P2.2/P2.3 encode primary proof only, not bypass. |
| Treating arbitrary two steps as independent MFA | Factor independence/security property must be evaluated by the implemented factor set. |
| Full session before required MFA | Primary proof, pending additional assurance and fully authenticated state are conceptually distinct. No additional-assurance runtime is configured yet. |
| Stale-session sensitive mutation | Sensitive operations require recent trusted server-side reverification; accepted v1 default is 10 minutes subject to ADR 0005 method/scope/assurance checks. |
| Client-forged freshness | Client timestamps or claimed methods are not authority; evidence is server-recorded and bound to app/user/session/flow. |
| Recovery downgrade/replay | Recovery credentials are purpose-specific and one-time; replay fails closed and cannot silently erase configured assurance. |

## 19. Accepted device/privacy and hosted-auth requirements

Device and hosted-auth controls remain accepted requirements, not implemented P2.3 claims:

- no permanent cross-session device fingerprint or third-party fingerprinting;
- no precise location collection by default;
- bounded purpose/retention for any later IP/user-agent persistence;
- exact server-validated hosted-auth redirect destinations in current application scope;
- no wildcard/substring/suffix redirect authority;
- generic social redirect/state controls implemented by P2.3 do not imply a hosted-auth UI exists;
- explicit-link state must additionally bind initiating principal/session-equivalent and reverification context;
- error redirects obey the same boundary as success redirects.

## 20. Required later Phase 2 scenario outcomes

- existing password user + provider with same verified email -> P2.3 already proves no automatic link; P2.4 must require explicit authenticated link;
- provider-first user later adds password -> authenticated enrollment after recent proof, not equality adoption;
- provider subject already owned by another user -> deny without merge/unnecessary disclosure for explicit-link attempts;
- link initiated as user A but callback presents user B/non-equivalent session -> fail closed and require fresh flow;
- cross-application provider/link state substitution -> fail closed;
- unlink last usable method -> reject;
- existing-account primary email/phone change -> same-user verified target + conflicts + recent proof + audit;
- alternate primary method cannot bypass later required MFA;
- stale session sensitive mutation -> fresh reverification under ADR 0005;
- hosted redirect substitution/open redirect -> reject unless exact current-app validation and state binding pass;
- device metadata -> no new persistence without bounded purpose/retention review.

## 21. Implemented versus accepted boundary

ADRs 0001–0007 are accepted architecture/security contracts. Existing code/tests provide Phase 1 runtime evidence, P2.1 email OTP evidence, P2.2 phone-first/SMS OTP evidence, and P2.3 social OAuth/OIDC evidence described above.

P2.3 **does** mean social signup/signin runtime exists for the exact eleven provider keys, including exact application redirect/state/completion controls, external-identity ownership, provider proof adapters, provider-token non-retention and provider-email non-authority. It does **not** mean P2.4 explicit account linking/unlinking, MFA/TOTP, recovery codes, step-up/reverification, passkeys, device management or hosted authentication are deployed.

The deterministic provider-contract suite proves BeeBox request/response compatibility with independently accepted provider wire contracts without requiring live user accounts. Slack uses current first-party Slack SIWS/token/discovery evidence and deterministic local OIDC/JWKS fixtures; no live Slack account or credential is required. Facebook uses the Human-accepted current Meta manual Website/access-token/User evidence plus audited `fbsamples/fedcm-example-app@4a244376676473fe639f6ab186386c60eca21f8d` consumer `/me` evidence. Its deterministic tests independently pin the selected v25.0 authorization/token literals, dedicated GET/query exchange, unversioned `/me?fields=id` query-token request, opaque-string `id`, safe error collapse, no retry and secret/token non-leakage. This does not claim v25.0 is Meta's globally latest version, does not claim Bearer is unsupported, and does not opt into Meta's separately documented OIDC+PKCE extension.

The suite does not prove real developer-console configuration, real credentials, provider app-review approval, consent/account availability, or provider production uptime. Each later slice must provide its own concrete code, persistence/API contracts, adversarial tenant/security tests and exact-head CI before BeeBox may claim that runtime control exists.

## 22. Residual implemented-surface threats

| Threat | Current control / residual risk |
| --- | --- |
| Database/backup compromise | Password/OTP/refresh verifier material, phone PII and external-identity ownership metadata remain sensitive offline; backups require privileged protection. |
| Online KDF/request exhaustion | Persistent admission and process KDF bounds reduce obvious abuse; volumetric capacity protection remains operational. |
| Signup/signin/reset/OTP enumeration | Public responses collapse account-sensitive distinctions; timing requires continued regression/operational observation. |
| Email/SMS provider compromise | Delivered OTPs depend on mailbox/carrier/provider control; provider compromise may expose codes/destination metadata. |
| SMS cost/message bombing | Global-first/per-phone admission and challenge cooldown/windows bound application behavior; upstream volumetric/provider controls remain operational concerns. |
| SMS provider delivery ambiguity | Challenge can commit before provider response; no automatic retry/failover avoids duplicate sends but may require explicit user resend later. |
| Social provider compromise | BeeBox trusts a correctly verified provider subject according to the configured protocol; compromise of the provider account or upstream provider can therefore authenticate that external identity. Provider email is still not link authority. |
| Social client-credential compromise | Configuration compromise may allow abuse of that provider application/connection; operator-side provider credential rotation/revocation is required. Secrets are not stored as BeeBox identity data. |
| Social provider outage | New social proof fails closed under bounded timeout/no retry. Existing BeeBox sessions continue under BeeBox session state. |
| Social completion-code theft | Code is short-lived/one-time and client S256-bound, but compromise of both redirect code and verifier can authorize the intended completion until expiry. |
| OAuth redirect/browser compromise | Exact redirect/state/PKCE reduce substitution; XSS or compromised application redirect origin can still act with that application's browser authority. |
| Facebook protocol/version drift | BeeBox intentionally pins the applicable Meta manual Website auth/token examples to v25.0 while leaving the audited consumer `/me` endpoint unversioned. Future Meta contract/version changes require explicit revalidation; conflicting global version renderings are not generalized into this contract. |
| Facebook query-credential leakage | The selected Meta flow places client secret + code in the token-exchange query and access token in the Graph query. HTTPS protects transport, while BeeBox forbids logging/auditing/metric-labeling/returning those URLs or provider error material. Upstream proxies/observability must preserve the same rule. |
| Refresh theft/replay | One-time rotation and replay-triggered revoke; ambiguous response loss can force reauthentication. |
| Access-token theft | Short-lived bearer remains usable until expiry for offline consumers; no global denylist. |
| XSS/CSRF | HttpOnly/SameSite/exact-Origin and social state/redirect controls reduce browser abuse; XSS can still act with page authority. |
| Signing/SMS/social-provider key compromise | Requires secure configuration distribution/rotation; secret material absent from DB/JWKS/public errors. |
| Metrics exposure | No PII/secret labels, but endpoint still needs network protection. |

## 23. Evidence map

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
- `internal/authentication/social.go` — shared state/nonce/provider-PKCE/completion lifecycles, exact provider vocabulary, TTLs, replay behavior and bounded social admission interface.
- `internal/authentication/postgres/social_store.go` — transactional external-identity resolution/creation, concurrent first-use serialization, completion/session/audit correctness.
- `internal/session/social.go` — client S256 completion proof and ordinary BeeBox session/token integration.
- `internal/authentication/socialprovider/registry.go` — strict per-application/provider startup config and state-key requirements.
- `internal/authentication/socialprovider/adapter.go` — fixed provider endpoints, bounded token/profile/JWKS I/O, OIDC verification, dedicated Facebook GET/query token + Graph proof, and subject-only application boundary.
- `internal/authentication/socialprovider/facebook_contract_test.go` and `facebook_graph_contract_test.go` — independent current Facebook v25 manual auth/token literals, dedicated GET/query exchange, unversioned query-token `/me`, opaque-string subject, provider-shaped failure, redirect/no-retry and secret/token non-leakage evidence.
- `internal/authentication/socialprovider/provider_contract_test.go` — exact independently encoded eleven-provider production literal matrix, including Facebook's dedicated token-exchange mode rather than misrepresenting it as an OAuth AuthStyle.
- `internal/authentication/socialprovider/slack_contract_test.go`, `slack_subject_contract_test.go`, `slack_registry_test.go`, other `*_contract_test.go`, `protocol_test.go`, `adapter_test.go` and `registry_test.go` — deterministic provider-shaped success/error/protocol/subject/JWKS/config evidence; Slack remains shared OIDC with explicit query response mode and Basic token auth.
- `internal/authentication/postgres/social_store_integration_test.go` — provider-email collision separation, existing subject reuse, cross-app isolation, concurrent first callback, state/completion replay, session/refresh and audit rollback evidence.
- `internal/httpapi/social.go` and social HTTP tests — initiate/callback/exchange browser boundary, exact redirect behavior, generic provider failure and provider-token non-leakage.
- `api/openapi/v1.yaml` and `sdk/go/social.go` — BeeBox-owned public social contract and client operations with exact eleven-provider vocabulary.
- `.github/workflows/ci.yml` — formatting, vet, vulnerability, OpenAPI, SDK, repeated social provider-contract, full unit, PostgreSQL integration and race gates.