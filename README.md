# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go. Clerk's public product capabilities are a benchmark only; BeeBox owns its contracts, implementation, identifiers, persistence and security decisions.

BeeBox's merged Phase 1 B2C foundation provides application-scoped email/password signup and verification, signin, rotating sessions/refresh credentials, Ed25519 access JWTs/JWKS, password reset, backend session management, a minimal Go SDK, operational metrics and reproducible local dependencies. The merged Phase 2 increments include the P2.0 trust/contract baseline, P2.1 passwordless email OTP primary authentication for existing verified email identifiers, P2.2 phone-first signup plus verified-phone SMS OTP primary authentication, P2.3 social OAuth/OIDC, P2.4A explicit authenticated social account linking, and P2.4B self-service linked social account listing/unlink. This integration branch implements P2.5 Passkeys/WebAuthn, P2.6 TOTP MFA and P2.7 recovery codes, including a tagged primary-authentication result and pending MFA continuation for every implemented primary method. It does **not** yet claim principal merge, provider-side OAuth consent revocation, generic P2.8 reverification, expanded session/identifier/profile self-service, secure email links, hosted authentication, or later Phase 2 checkpoints.

## Project documentation

- [Repository instructions](Instruction.md)
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md)
- [ADR 0002: email identity v1](docs/adr/0002-email-identity-v1.md)
- [ADR 0003: Phase 1 public auth contract](docs/adr/0003-phase1-public-auth-contract.md)
- [ADR 0004: Phase 2 identity linking and external trust](docs/adr/0004-phase2-identity-linking-external-trust.md)
- [ADR 0005: Phase 2 authentication assurance and recovery](docs/adr/0005-phase2-authentication-assurance-recovery.md)
- [ADR 0006: Phase 2 device privacy and hosted-auth trust](docs/adr/0006-phase2-device-privacy-hosted-auth.md)
- [ADR 0007: Phase 2 social signup claims and principal creation](docs/adr/0007-phase2-social-signup-claims.md)
- [Initial threat model](docs/threat-model/initial.md)
- [P2.5 passkey threat-model delta](docs/threat-model/passkeys.md)
- [P2.6 TOTP MFA threat model](docs/threat-model/totp-mfa.md)
- [P2.7 recovery-code threat model](docs/threat-model/recovery-codes.md)
- [Contract and tenancy conventions](docs/contracts/conventions.md)
- [Phase 1 exit evidence](docs/phase1-exit.md)
- [OpenAPI v1](api/openapi/v1.yaml)
- [Go SDK](sdk/go)

## Prerequisites

- Go 1.26.x
- Git
- Docker with Compose for the documented local dependencies

## Local quickstart

Start synthetic PostgreSQL 17 and Mailpit dependencies:

```sh
docker compose up -d
```

Use the local database only; repository commands never mutate a hosted database automatically:

```sh
export BEEBOX_DATABASE_URL='postgres://beebox:beebox_local@127.0.0.1:5432/beebox?sslmode=disable'
go run ./cmd/beebox migrate
```

Generate Ed25519 signing configuration. The private key is intentional one-time command output; do not commit or log it:

```sh
go run ./cmd/beebox generate-signing-key
```

Export the returned values plus a stable HTTPS issuer identity:

```sh
export BEEBOX_ISSUER='https://auth.example.test'
export BEEBOX_SIGNING_KID='<kid>'
export BEEBOX_SIGNING_PRIVATE_KEY='<private_key>'
export BEEBOX_SIGNING_PUBLIC_KEY='<public_key>'
```

Bootstrap one application and explicit local browser origin. The secret key is also intentional one-time output:

```sh
go run ./cmd/beebox bootstrap-application http://localhost:3000
```

Save the emitted `application_id`, `publishable_key` and `secret_key` outside source control, then configure local SMTP capture:

```sh
export BEEBOX_SMTP_ADDR='127.0.0.1:1025'
export BEEBOX_SMTP_FROM='beebox@example.test'
export BEEBOX_SMTP_TLS_MODE='insecure_localhost'
export BEEBOX_HTTP_ADDR=':8080'
go run ./cmd/beebox
```

Mailpit's local UI is available on port `8025`. A developer can exercise the established password flow against `http://127.0.0.1:8080`:

1. `POST /v1/sign-ups` with `X-BeeBox-Publishable-Key` and `Idempotency-Key`;
2. read the verification code in Mailpit and call `POST /v1/email-verifications/confirm`;
3. call `POST /v1/sign-ins`;
4. inspect `GET /.well-known/jwks.json` and the returned Ed25519 JWT claims/signature;
5. call `GET /v1/sessions/current` with the access token;
6. rotate the refresh credential with `POST /v1/sessions/refresh`;
7. revoke the current session with `POST /v1/sessions/sign-out`;
8. request and confirm a password reset through Mailpit;
9. verify the old password no longer signs in and the new password does.

For an already verified email identifier, the P2.1 passwordless flow is:

1. `POST /v1/sign-ins/email-otp` with the publishable key and `{"email":"user@example.test"}`;
2. read the purpose-specific **BeeBox sign-in code** from Mailpit;
3. `POST /v1/sign-ins/email-otp/confirm` with the same email and six-digit code;
4. use the returned ordinary access/session state exactly like password sign-in, including `GET /v1/sessions/current` and normal refresh rotation.

The request endpoint intentionally returns the same generic accepted behavior for eligible delivery and protected account-dependent states such as unknown/unverified identifiers or resend suppression. Email verification and email OTP authentication are different purposes: OTP signin never creates a user and never changes `verified_at`.

### P2.2 phone-first flow

P2.2 accepts phone input only in strict international E.164 canonical form: `+` followed by 2–15 ASCII decimal digits, first digit non-zero. Surrounding ordinary whitespace may be trimmed. BeeBox does not infer a default region and does not accept national formatting, embedded spaces, dashes, parentheses, `00` prefixes, `tel:` URIs, extensions or alphabetic digits.

SMS is optional and disabled by default. Exactly one provider is selected by the operator for a BeeBox process with `BEEBOX_SMS_MODE=disabled|twilio|vonage|plivo|telnyx`; clients and public API requests never select the provider.

Twilio:

```sh
export BEEBOX_SMS_MODE='twilio'
export BEEBOX_TWILIO_ACCOUNT_SID='<account-sid>'
export BEEBOX_TWILIO_API_KEY_SID='<api-key-sid>'
export BEEBOX_TWILIO_API_KEY_SECRET='<api-key-secret>'
export BEEBOX_TWILIO_FROM='<configured-sender>'
export BEEBOX_TWILIO_TIMEOUT='5s' # optional; maximum 30s
```

The Account SID identifies the owning Twilio account used in the Messages resource URL. BeeBox authenticates production Twilio requests with the API Key SID as the HTTP Basic username and the API Key Secret as the password. These values are process configuration only; never commit or log the API Key Secret.

Vonage:

```sh
export BEEBOX_SMS_MODE='vonage'
export BEEBOX_VONAGE_API_KEY='<api-key>'
export BEEBOX_VONAGE_API_SECRET='<api-secret>'
export BEEBOX_VONAGE_FROM='<configured-sender>'
export BEEBOX_VONAGE_TIMEOUT='5s' # optional; maximum 30s
```

Plivo:

```sh
export BEEBOX_SMS_MODE='plivo'
export BEEBOX_PLIVO_AUTH_ID='<auth-id>'
export BEEBOX_PLIVO_AUTH_TOKEN='<auth-token>'
export BEEBOX_PLIVO_FROM='<configured-sender>'
export BEEBOX_PLIVO_TIMEOUT='5s' # optional; maximum 30s
```

Telnyx:

```sh
export BEEBOX_SMS_MODE='telnyx'
export BEEBOX_TELNYX_API_KEY='<api-key>'
export BEEBOX_TELNYX_FROM='<configured-sender>'
export BEEBOX_TELNYX_TIMEOUT='5s' # optional; maximum 30s
```

Twilio, Vonage, Plivo and Telnyx are interchangeable internal transport adapters behind BeeBox-owned `PhoneOTPDelivery`; vendor request/response models and provider identifiers are not public BeeBox contracts. BeeBox performs one bounded synchronous provider request per send attempt. Provider API acceptance means only that the selected provider synchronously accepted/processed the request according to its API contract; it does not prove carrier or handset delivery.

P2.2 intentionally has no runtime provider routing, failover, load balancing or cross-provider retry. An ambiguous timeout/failure may occur after a provider accepted the SMS, so BeeBox never automatically sends the same OTP through another provider. A later explicit user request, subject to cooldown/rate controls, is the retry boundary.

When `BEEBOX_SMS_MODE` is absent or `disabled`, BeeBox still starts normally and existing email/password/P2.1 functionality remains available. Phone **issue** endpoints return a uniform `service_unavailable` before phone ownership/challenge state is inspected. An unknown explicit mode or incomplete configuration for the selected provider fails startup before listener creation rather than silently falling back. Confirmation itself does not require provider I/O, so an already committed valid challenge can still be confirmed when session signing capability remains configured.

Phone-first signup is deliberately no-account-before-proof:

1. `POST /v1/sign-ups/phone` with `{"phone":"+84901234567"}`;
2. BeeBox stores only a domain-separated SHA-256 phone fingerprint plus an Argon2 verifier for the pending signup challenge; no user or `phone_identifiers` row exists yet;
3. receive the purpose-specific SMS code through the configured provider;
4. `POST /v1/sign-ups/phone/confirm` with the same phone and six-digit code;
5. only successful possession proof atomically creates the user, verified phone identifier, ordinary BeeBox session, refresh verifier and required audit evidence.

Phone signup confirmation is one-time and must not be blindly retried after an ambiguous client response. If the database commit succeeded but the response was lost, a retry may safely fail as replay; the newly created principal can use phone OTP sign-in.

After a phone identifier is verified, primary authentication is:

1. `POST /v1/sign-ins/phone-otp` with the canonical E.164 phone;
2. receive the purpose-specific BeeBox sign-in SMS code;
3. `POST /v1/sign-ins/phone-otp/confirm` with the same phone and code;
4. use the returned ordinary access/session/refresh behavior exactly like the other primary methods.

Phone equality never links, merges or adopts principals. P2.2 intentionally exposes no endpoint to add, change, remove or switch a phone on an already-existing account; those sensitive account-management operations require later accepted reverification/last-method semantics.

### P2.3 social OAuth/OIDC

P2.3 implements one BeeBox-owned lifecycle for exactly these provider keys:

- `google`
- `apple`
- `microsoft`
- `github`
- `gitlab`
- `facebook`
- `slack`
- `discord`
- `linkedin`
- `x`
- `tiktok`

Connections are configured statically per application. `BEEBOX_SOCIAL_CONNECTIONS` is a strict JSON array; each entry contains `application_id`, `provider`, `client_id`, and `client_secret`, with `microsoft_tenant` required only for Microsoft and required to be an explicit tenant GUID. Unknown fields, unknown providers, duplicate `(application, provider)` entries, missing credentials, and malformed Microsoft tenant values fail startup. Provider endpoints are fixed in code rather than operator-overridable URLs.

A placeholder-only configuration shape is:

```sh
export BEEBOX_SOCIAL_CONNECTIONS='[
  {
    "application_id": "<application-public-id>",
    "provider": "google",
    "client_id": "<provider-client-id>",
    "client_secret": "<provider-client-secret>"
  }
]'
```

When social connections are configured, `BEEBOX_ISSUER` provides the canonical callback base, producing `BEEBOX_ISSUER + /v1/social-auth/callback/{provider}`. The issuer must be HTTPS except for the explicit `http://localhost` development exception and cannot contain a path/query/fragment. `BEEBOX_SOCIAL_STATE_KEY` is an unpadded base64url encoding of exactly 32 random bytes and is required when the configured provider set uses provider-side PKCE; it protects provider PKCE verifier state with AES-256-GCM. Keep all provider credentials and the state key outside source control and logs. For Apple, `client_secret` is the operator-generated Sign in with Apple client-secret JWT; BeeBox does not ingest an Apple private key in P2.3.

Provider configuration is optional. If `BEEBOX_SOCIAL_CONNECTIONS` is absent or empty, the normal non-social runtime remains available. A configured social runtime fails closed if its required signing/provider configuration is incomplete.

Social completion redirects use a dedicated exact application redirect allowlist, separate from browser CORS origins. Add a redirect with the application **public** ID:

```sh
go run ./cmd/beebox add-redirect '<application-public-id>' 'https://app.example.test/auth/complete'
```

The redirect representation is exact after BeeBox canonicalization: production requires HTTPS; only `http://localhost` is allowed for local development; query strings, fragments, userinfo, wildcards, malformed/relative URLs and alternate escaped-path spellings are rejected. P2.3 owns the callback completion query parameters, so application redirects cannot contain a query string.

The browser lifecycle is:

1. the client generates a completion PKCE verifier and its S256 challenge;
2. `POST /v1/social-auth/attempts` uses `X-BeeBox-Publishable-Key`, the browser `Origin`, one of the eleven provider keys, an exact allowlisted application redirect URL, and the client S256 challenge;
3. BeeBox stores a one-time 10-minute social attempt with only a SHA-256 state hash plus the validated redirect/application/provider bindings, then returns the provider authorization URL;
4. the provider returns to `GET /v1/social-auth/callback/{provider}`; BeeBox consumes state before provider proof, performs the configured OAuth/OIDC proof, and redirects only to the stored allowlisted application redirect;
5. on success the redirect contains a short-lived opaque BeeBox completion code, not provider tokens or an ordinary BeeBox session;
6. `POST /v1/social-auth/exchange` presents that completion code plus the original client PKCE verifier; the one-time five-minute completion grant is consumed and only then produces the normal BeeBox session/access/refresh transport.

Provider-side PKCE and OIDC nonce behavior is provider-specific and enforced by the provider adapter. OIDC providers validate the configured issuer boundary, RS256 signature/JWKS, client audience, expiry/not-before where present, nonce and non-empty subject. Provider HTTP/JWKS I/O is bounded, has explicit timeouts/body limits, performs no automatic retry, and maps vendor failures to BeeBox-owned safe errors.

Slack uses Sign in with Slack OIDC through the same shared provider lifecycle. BeeBox requests exactly `openid`, explicitly requests `response_mode=query` for the existing GET callback, verifies the Slack issuer/audience/RS256 signature/JWKS/expiry/nonce and uses only the verified ID-token `sub` as provider subject. The selected confidential Website flow uses HTTP Basic client authentication at the token endpoint and does not enable provider-side PKCE; Slack `email`, `profile`, legacy `identity.*` scopes and the userinfo endpoint are not used. This does not change the mandatory client-owned S256 completion PKCE between the application and BeeBox.

Facebook uses Meta's documented base manual Website authorization-code flow rather than the separately documented OIDC+PKCE extension. BeeBox pins the applicable manual-flow authorization and token examples to `https://www.facebook.com/v25.0/dialog/oauth` and `https://graph.facebook.com/v25.0/oauth/access_token`; this is a selected contract pin, not a claim that v25.0 is Meta's globally latest API version. The base flow sends no `openid` scope, provider PKCE challenge/verifier or OIDC nonce. Code exchange is a single bounded GET with `client_id`, exact `redirect_uri`, `client_secret` and `code` in the query. Facebook identity proof deliberately keeps the current consumer-sample Graph endpoint unversioned as `https://graph.facebook.com/me?fields=id`, adds the documented `access_token` query parameter, requests no email/profile fields, and treats the returned app-scoped User `id` as a bounded opaque string. BeeBox does not need to settle whether Meta also accepts Bearer presentation for this exact flow and does not claim Bearer is unsupported.

ADR 0007 defines social signup ownership. A successfully verified `(application, provider, provider_subject)` that is not already owned creates a **new separate application-scoped BeeBox principal** plus exactly that external identity. If the external identity already exists, it resolves its existing BeeBox user. PostgreSQL uniqueness on `(application_instance_id, provider, provider_subject)` and transaction/advisory-lock behavior serialize concurrent first callbacks.

Provider email is deliberately non-authoritative: P2.3 does not import provider email into `email_identifiers`, does not mark a BeeBox email verified from a provider claim, and never uses email equality to link, attach, merge, adopt or transfer a principal. Provider email/name/avatar/profile claims are discarded after any transient proof parsing. Provider access, refresh and ID tokens remain adapter-local and are not persisted, logged, exposed to the application, or returned as BeeBox credentials.

### P2.4A explicit authenticated social account linking

P2.4A adds a deliberately separate lifecycle for attaching a provider subject to an **already-authenticated** BeeBox user. `POST /v1/social-links/attempts` requires exactly one application publishable key, one exact allowed browser `Origin`, and an ordinary BeeBox bearer access token. BeeBox validates the token against the resolved application, loads the persisted current session, and fixes the target application, user, exact initiating session, provider and exact allowlisted redirect before the browser leaves for the provider. The request body contains only `provider` and `redirect_url`; client-supplied user/session/provider-subject/profile authority is rejected.

Recent authentication in this first slice is intentionally narrow rather than a premature generic step-up framework. The persisted initiating session is recent enough only while `now < session.created_at + 10 minutes`. Refreshing or rotating credentials for that same old session does not change `session.created_at` and therefore does not reset link freshness. An older session receives `reverification_required`; today the user reauthenticates using an already-supported primary method to obtain a new ordinary session and starts a new link attempt. Future P2.8 may introduce richer in-session step-up/reverification, but P2.4A does not claim that runtime exists.

The link attempt uses the existing provider callback URL and a purpose-separated `lnk_` state namespace backed by a dedicated persisted attempt; the prefix is dispatch only, not authority. State is stored only as SHA-256, provider PKCE verifier state uses link-purpose-separated AES-GCM AAD where required, and OIDC nonce state remains hash-only. The callback consumes the exact attempt before provider proof and uses the same eleven audited provider adapters as P2.3.

Immediately before ownership mutation, PostgreSQL revalidates the exact bound session inside the correctness transaction: the same session must still exist under the same application/user, remain unrevoked/unexpired, and remain inside the original 10-minute authentication window. A different browser session present at callback time cannot substitute for it. If the bound session was revoked, expired, became stale, or was otherwise substituted, linking fails closed.

Ownership remains exactly `(application_instance, provider, provider_subject)`. An unowned verified provider subject is attached to the bound initiating user; the same subject already owned by that user is an idempotent logical success; ownership by another user in the same application is a generic denial with no transfer or merge. Concurrent claims serialize through the provider-subject ownership lock and database uniqueness. P2.4B additionally uses an application/user/provider management advisory lock around link-attempt creation and final ownership attachment, with lock order management lock then provider-subject lock, so unlink and linking have a deterministic linear order. Provider email equality remains irrelevant: provider email/profile data is not imported into BeeBox identity state and cannot cause link, merge, verification or transfer.

A successful link callback redirects only to the stored trusted redirect with `beebox_link=success`. A resolved denial/proof/session/ownership failure uses the same stored redirect with `beebox_error=social_link_failed`; unknown/unresolvable state does not enable any callback-supplied redirect. The link callback never creates a BeeBox user, rotates/creates a BeeBox session, or creates a P2.3 completion grant. Provider authorization codes and provider access/refresh/ID tokens remain transient adapter data and are not persisted or exposed.

### P2.4B linked social account management

`GET /v1/social-links` lists only the current authenticated user's external identities in the exact application selected by the publishable key and canonical allowed `Origin`. The response is bounded (default 20, maximum 100), ordered by `created_at` plus BeeBox public link ID, and uses an opaque cursor. Each item contains only the provider, creation time and an opaque BeeBox-owned `sli_<uuid-v4>` locator. Provider subject, provider email/profile, provider tokens, internal database IDs and unnecessary user identifiers are not exposed. Listing requires a valid current persisted session but does not require that session to be younger than ten minutes.

`DELETE /v1/social-links/{social_link_id}` targets only that opaque locator under the current application/user scope. Unlink requires the exact persisted current session to remain valid and fresh while `now < session.created_at + 10 minutes`; refreshing an access/refresh credential for the same old session does not reset this freshness. A syntactically valid absent, already removed, other-user or cross-application ID returns the same idempotent `204 No Content` and does not disclose ownership.

A real unlink is denied with `409 last_authentication_method` unless at least one currently usable path remains after removal. Password counts only when both a password credential and a verified email exist. Email OTP counts only when SMTP/email OTP delivery is configured and a verified email exists. Phone OTP counts only when SMS mode is enabled and a verified phone exists. A remaining social identity counts only when its provider connection is configured for that exact application. A stored passkey counts only when it belongs to the exact same application/user under the implemented passkey authentication contract; cross-application credentials never count. TOTP is an additional factor and its recovery codes complete only pending MFA, so neither independently counts as a remaining primary authentication method. The current session itself and merely possible password reset are not authentication methods for this predicate.

Unlink serializes with concurrent unlink, P2.4A create/finalize and P2.3 provider-subject proof. Successful removal cancels still-relevant same-user/provider P2.4A link attempts and clears their provider PKCE ciphertext, and conservatively consumes all still-unexchanged P2.3 social completion grants for the same application/user. Last-method denial performs none of that success cleanup. Deletion and success audit share one PostgreSQL transaction; audit failure rolls the identity deletion and pending-state cleanup back. Existing ordinary BeeBox sessions are **not** revoked by unlink.

P2.4B removes only BeeBox's external-identity ownership association. BeeBox does not retain provider access/refresh tokens for this lifecycle and therefore does not call Google/GitHub/etc. provider-side disconnect, consent or token-revocation APIs. Principal/account merge remains absent; provider email is still never linking authority.

### P2.5 Passkeys / WebAuthn

P2.5 uses the maintained `github.com/go-webauthn/webauthn` verifier behind BeeBox-owned interfaces; BeeBox does not implement WebAuthn cryptography or protocol parsing itself and does not expose library structs as public API models. The browser contract transports WebAuthn creation/assertion JSON opaquely.

Registration is an authenticated sensitive mutation. `POST /v1/passkeys/registration/attempts` requires the exact resolved application, canonical allowed `Origin`, current persisted BeeBox session and accepted recent-authentication window. BeeBox derives the RP ID server-side from the trusted Origin, binds application/user/session/Origin/RP/purpose into a short-lived one-time `pka_<uuid-v4>` ceremony, persists only a SHA-256 challenge hash plus verifier session data, and never receives the authenticator-owned private key. `POST /v1/passkeys/registration/complete` consumes the exact ceremony and verifies challenge, Origin, RP ID, user handle, authenticator response and required user verification through the maintained verifier before atomically storing credential verification state and audit evidence. Duplicate/cross-application/wrong-user/replayed/expired proofs fail closed.

Authentication is discoverable/resident-credential based. `POST /v1/passkeys/authentication/attempts` issues an application/Origin/RP-bound one-time ceremony. `POST /v1/passkeys/authentication/complete` resolves a credential only inside the exact application and RP scope, requires WebAuthn user verification, and updates verifier-owned credential state such as signature-counter state. A passkey is a **primary authentication method**, not an MFA bypass: when TOTP is active, successful passkey proof returns only the pending-MFA result and no session/access/refresh authority. Without active TOTP, session/refresh/audit finalization remains atomic.

`GET /v1/passkeys` returns at most the bounded current-user passkey set with only opaque `pky_<uuid-v4>` ID, optional user-visible name and creation time. It never exposes credential ID, public-key blob, counter state, user handle, internal ID or authenticator response. `DELETE /v1/passkeys/{passkey_id}` requires the exact current application/user/session plus recent authentication and is rejected with `last_authentication_method` when no other usable authentication path remains. Removal and required audit evidence are atomic.

Passkey ceremonies have a maximum five-minute lifetime and are one-time even if maintenance has not yet deleted them. Expired/consumed attempts are cleaned by the existing bounded security-state maintenance primitive using dedicated expiry/consumption indexes; cleanup is not a correctness dependency. The threat and transaction details are recorded in `docs/threat-model/passkeys.md`.

The deterministic provider-contract suite uses synthetic local HTTP/OIDC/JWKS fixtures and does not require live social accounts or live provider credentials. It proves BeeBox request/response compatibility with provider wire contracts independently encoded from current provider-owned evidence, not developer-console setup, real credentials, provider app review, user consent/account availability, or provider production uptime. Slack has deterministic authorization, confidential token exchange, RS256 ID-token/nonce, subject-boundary, safe-error, no-userinfo and no-retry coverage based on current Slack first-party SIWS/token/discovery evidence. Facebook has deterministic authorization, dedicated GET/query token exchange, Graph query-token identity proof, strict opaque-string subject, provider-shaped error collapse, redirect/no-retry and secret/token non-leakage coverage.

The SDK offline verifier intentionally requires the configured HTTPS issuer. For local plaintext HTTP development, use the local JWKS endpoint for inspection/testing or place BeeBox behind a local TLS endpoint rather than weakening production issuer semantics.

Serve mode never auto-migrates.

## Public authentication surface

Application context for frontend/auth flows comes from `X-BeeBox-Publishable-Key`. Publishable keys are non-secret context selectors, not backend or user authority. Backend session operations use a verified BeeBox secret key. Access-token authenticated routes also re-check persisted session state where immediate BeeBox-side revocation is required.

Reachable endpoints include:

- `POST /v1/sign-ups` — signup with shared public password policy and idempotency;
- `POST /v1/sign-ups/phone` — generic bounded request for phone-first SMS possession proof without pre-creating an account;
- `POST /v1/sign-ups/phone/confirm` — one-time proof that atomically creates a new phone-first principal and ordinary session;
- `POST /v1/email-verifications` — generic bounded verification issue/resend;
- `POST /v1/email-verifications/confirm` — email ownership confirmation only;
- `POST /v1/sign-ins` — verified email/password signin with anti-enumerating failures and PostgreSQL attempt limits;
- `POST /v1/sign-ins/email-otp` — generic bounded request for a passwordless sign-in code for an existing verified identifier;
- `POST /v1/sign-ins/email-otp/confirm` — one-time email OTP primary proof producing the normal BeeBox session/access/refresh transport;
- `POST /v1/sign-ins/phone-otp` — generic bounded SMS OTP request for an existing verified phone identifier;
- `POST /v1/sign-ins/phone-otp/confirm` — one-time verified-phone primary proof producing the normal BeeBox session/access/refresh transport;
- `POST /v1/social-auth/attempts` — start a configured provider flow from an exact application redirect plus client S256 completion challenge;
- `POST /v1/social-links/attempts` — start an explicit social link from the server-resolved fresh current BeeBox session; no client principal selector is accepted;
- `GET /v1/social-links` — bounded self-service list of the current app/user's linked social identities using opaque BeeBox link IDs;
- `DELETE /v1/social-links/{social_link_id}` — fresh-session self-service unlink with anti-enumerating idempotent 204 and last-usable-method protection;
- `GET /v1/social-auth/callback/{provider}` — shared provider callback that purpose-routes only BeeBox-issued auth/link state and redirects to only the previously stored allowlisted application redirect;
- `POST /v1/social-auth/exchange` — one-time completion-code + client PKCE verifier exchange producing the ordinary BeeBox session/access/refresh transport for P2.3 social authentication only;
- `POST /v1/passkeys/registration/attempts` and `/v1/passkeys/registration/complete` — recent-auth bound passkey enrollment using opaque WebAuthn browser JSON;
- `POST /v1/passkeys/authentication/attempts` and `/v1/passkeys/authentication/complete` — discoverable passkey primary authentication with required user verification and ordinary BeeBox session issuance;
- `GET /v1/passkeys` — bounded current-user passkey metadata list;
- `DELETE /v1/passkeys/{passkey_id}` — fresh-auth passkey removal with last-usable-method protection;
- `POST /v1/mfa/totp/enrollments` and `/v1/mfa/totp/enrollments/confirm` — encrypted TOTP enrollment and atomic activation with an initial ten-code recovery set;
- `GET /v1/mfa/totp` and `DELETE /v1/mfa/totp` — minimized current-user TOTP state and protected removal;
- `POST /v1/mfa/totp/complete` — one-time pending-authentication completion with TOTP;
- `POST /v1/mfa/recovery-codes/complete` — one-time pending-authentication completion with a recovery code without altering TOTP;
- `GET /v1/mfa/recovery-codes` and `POST /v1/mfa/recovery-codes/regenerate` — count-only recovery state and one-time-display atomic regeneration;
- `POST /v1/mfa/totp/replacements` and `/v1/mfa/totp/replacements/confirm` — dedicated primary-proof plus recovery-code TOTP replacement that retains the old credential until confirmation;
- `POST /v1/sessions/refresh` — one-time refresh rotation; replay revokes the session;
- `GET /v1/sessions/current` — access JWT plus current database session-state validation;
- `POST /v1/sessions/sign-out` — current-session revoke/signout;
- `GET /v1/backend/sessions/{session_id}` — secret-key scoped backend session lookup;
- `POST /v1/backend/sessions/{session_id}/revoke` — secret-key scoped backend revoke;
- `POST /v1/password-resets` and `/v1/password-resets/confirm` — anti-enumerating recovery and password replacement;
- `GET /.well-known/jwks.json` — active and retiring public Ed25519 verification keys;
- `GET /metrics` — bounded operational counters and database-pool occupancy gauges. Protect this operational endpoint at the deployment/network boundary as appropriate.

See `api/openapi/v1.yaml` for the BeeBox-owned public contract. No public response exposes internal BIGINT IDs, challenge rows, WebAuthn library structs, provider models, provider credentials or provider tokens.

## Security semantics

### Passwords, email verification, and email OTP

Public password establishment/reset uses one shared policy: NFC normalization, 15–128 Unicode code points, the existing safe byte bound, no silent trimming, no mandatory composition rules, and the repository-owned common/expected-password blocklist. The low-level Argon2id primitive remains separate from public policy.

Email identity is application-scoped under ADR 0002. Equal normalized emails in different applications are independent. Same-application duplicate registration never auto-links, merges or adopts an existing account. Email verification proves mailbox control only; it does not create authentication/session state or account-link authority.

P2.1 email OTP is a separate authentication-purpose challenge for an **existing verified** identifier. Codes are exactly six numeric digits generated with `crypto/rand`, persisted only as Argon2 verifier material, valid for 10 minutes, subject to a one-minute resend cooldown, at most three issues per 15-minute window, and at most five failed confirmation attempts per generation. A permitted reissue rotates generation/code and invalidates the previous code. Successful redemption consumes the generation once; challenge consumption, session/refresh-verifier persistence, and required successful audit evidence share one PostgreSQL correctness transaction.

Unknown and unverified identifiers do not become eligible, do not become verified, and do not create users. Public request behavior is anti-enumerating. Email OTP is an ADR 0005 **primary authentication method**; it does not encode a future MFA bypass. Because no additional-assurance runtime is configured in P2.1, successful OTP proof currently creates the same ordinary session class as password signin.

### Phone identity and SMS OTP

P2.2 phone identity is explicitly `application_instance` scoped. The same canonical E.164 value may exist independently in different applications. PostgreSQL enforces uniqueness of a **verified** phone inside one application, but equality is never account-link, merge or adoption authority.

Phone signup challenges are purpose-separated from phone sign-in challenges. Pending signup stores a 32-byte domain-separated SHA-256 fingerprint instead of raw phone PII. Sign-in challenges reference the existing phone identifier rather than duplicate the phone. Raw canonical phone is persisted only where it is the actual product identity (`phone_identifiers.phone_e164`) and is otherwise excluded from challenge rows, rate-limit subjects, audit facts, metric labels and logs.

Both phone signup and phone sign-in OTPs reuse the reviewed six-digit `crypto/rand` verification-code primitive and persist only Argon2 verifier material. They use a 10-minute TTL, one-minute resend cooldown, at most three successful issues per 15-minute window, five failed confirmations, generation rotation, previous-code invalidation, one-time consumption and replay denial. Persistent public-auth admission uses operation-separated global-first and per-phone fingerprint namespaces to bound SMS cost/cardinality and pre-KDF confirmation work without making Redis part of correctness.

Successful phone signup confirmation commits new user + verified phone + ordinary session + refresh verifier + required audit evidence in one PostgreSQL transaction. Successful phone OTP sign-in similarly commits challenge consumption + session + refresh verifier + audit atomically. Neither path creates a password credential. Phone OTP is an ADR 0005 **primary authentication method**; it does not encode a future MFA bypass or a permanent factor-strength ordering.

### Social OAuth/OIDC

P2.3 treats the provider proof as a primary authentication method, not MFA and not account-link authority. Every attempt is bound to trusted application scope, one provider, one exact prevalidated application redirect, one purpose, one client completion S256 challenge, and an unpredictable one-time state. Provider-side PKCE verifiers, where used, are encrypted in persisted attempt state and cleared on consumption; OIDC nonces are persisted only as hashes. Callback state is consumed before provider token/profile exchange so replay cannot repeat provider proof or principal/session creation.

A successful provider proof returns only `{provider, subject}` into the BeeBox application layer. Subject ownership is database-enforced inside the application/provider namespace. Provider email/name/avatar/profile claims and access/refresh/ID tokens are not account identifiers, are not persisted as profile convenience, and do not cross the adapter proof boundary. Completion codes are one-time, five-minute, hash-only in PostgreSQL and require the original client PKCE verifier before normal session issuance. Concurrent redemption yields at most one committed session.

### Explicit social account linking

P2.4A is authenticated account management, not another social signin path. Its authority is the server-bound tuple of application, initiating BeeBox user, exact initiating persisted session, link purpose, provider proof attempt and that session's trusted `created_at`. Callback browser state, provider email/profile and arbitrary user/session IDs never select the target. The exact session is re-read and locked immediately before provider-subject ownership mutation, so revocation, expiry, staleness or substitution fails closed.

The provider-subject advisory lock and database uniqueness remain the final ownership invariant, while the P2.4B application/user/provider management lock serializes link-attempt creation/finalization with unlink. A same-owner proof is idempotent success; an other-owner proof is a generic denial. Success ownership mutation and required success audit evidence are one transaction. Denied audits use only bounded BeeBox references when a trusted attempt/actor was resolved; random unknown callback state does not fabricate actor evidence.

### Linked social account listing and unlink

P2.4B listing is ordinary authenticated account metadata access: it is scoped by exact application + current persisted BeeBox user/session, bounded and paginated, and exposes only provider + opaque `sli_` ID + creation time. Unlink is a security mutation: the exact session must still be valid and its original `created_at` must remain within ten minutes. Access-token/refresh rotation for that same session does not manufacture new freshness.

Last-method protection is configuration-aware. Password requires a password credential and verified email; email OTP additionally requires configured SMTP delivery; phone OTP additionally requires enabled SMS delivery; remaining social identities require an active provider connection for the exact application; and P2.5 passkeys count only when stored for the exact application/user. Unconfigured methods, unverified identifiers, cross-application passkeys, current-session existence, TOTP/recovery additional-assurance state and password-reset possibility do not count as primary methods. Concurrent removal is serialized so racing removals cannot strand the account.

Successful unlink cancels pending same-user/provider P2.4A link state, clears provider PKCE ciphertext, conservatively invalidates still-unexchanged P2.3 social completion grants for the same user/application, deletes the identity and records success audit atomically. Denial commits only its safe audit and preserves all pending state. Existing ordinary sessions remain active. Provider-side consent/token revocation and account merge are separate unimplemented lifecycles.

### Passkeys / WebAuthn

Passkey private keys always remain inside the authenticator. BeeBox stores only the server-side credential state necessary to verify future assertions. The selected maintained WebAuthn library owns protocol validation including challenge, RP ID hash, Origin, authenticator data/signature, user handle, user verification and signature-counter/clone semantics; BeeBox maps failures into stable application errors instead of exposing verifier internals.

Registration/removal require a valid current persisted session and accepted recent authentication; refreshing an old session does not reset its original `created_at`. One-time ceremony state is exact application/Origin/RP/purpose scoped, expires within five minutes and is consumed atomically before replay can succeed. Authentication resolves the credential owner only through the exact application/RP credential mapping and creates the same ordinary BeeBox session class as the other primary methods. P2.5 deliberately does not classify WebAuthn user verification as an independent second factor.

Successful registration + audit, successful authentication credential-state update + session/refresh + audit, and successful removal + audit each have transactional rollback evidence. Passkey list responses are intentionally minimized. Last-method checks are symmetric with social unlink: a usable passkey may preserve social unlink, and passkey removal requires another usable method.

### TOTP MFA and recovery codes

Every implemented primary method—password, verified-email OTP, verified-phone OTP, social proof and passkey—enters the same five-minute pending-MFA boundary when TOTP is active. The public `status` union never includes session/access/refresh authority in `mfa_required`. TOTP uses HMAC-SHA1, six digits, a 30-second step and the previous/current/next window; the credential row records the last accepted timestep so one step can authorize at most once under concurrency. Setup secrets are stored only in AES-256-GCM envelopes using the bounded HKDF-separated operator keyring described in `docs/production-operations.md`.

TOTP activation creates exactly ten independent 26-symbol Crockford Base32 recovery codes. Only application/user/set-bound SHA-256 verifiers are persisted. A code can complete one existing pending-MFA authentication once and never disables or mutates TOTP. Regeneration invalidates the entire old set atomically. Dedicated TOTP replacement consumes a recovery code but leaves the old TOTP active until a valid proof from the replacement secret atomically installs it and creates a fresh set. Recovery codes cannot mint generic reverification authority or remove arbitrary factors. See `docs/threat-model/totp-mfa.md` and `docs/threat-model/recovery-codes.md` for transaction and threat evidence.

### Sessions and tokens

Sessions use a 30-day absolute lifetime and seven-day inactivity lifetime. Refresh credentials are random opaque secrets stored only as verifier hashes and rotate on every successful refresh. Reuse of a consumed refresh credential revokes its owning session. SDK methods do not blindly retry refresh operations; an ambiguous lost refresh response can require reauthentication.

Access tokens are five-minute Ed25519/JOSE EdDSA JWTs with strict `kid`, issuer, audience, signature and time validation and at most 30 seconds of accepted skew. JWKS publishes public key material only. Offline JWT verifiers cannot observe immediate database revocation; token expiry bounds that stale-auth window. BeeBox current-session endpoints additionally check database session state.

Password reset revokes all current sessions for the application-scoped user. Already-issued access JWTs can remain cryptographically valid for offline consumers until their short expiry; BeeBox does not claim a global JWT denylist.

## Minimal Go SDK

`sdk/go` provides a small HTTP client for:

- signup;
- phone-first SMS OTP request/confirm;
- request/resend/confirm email verification;
- password signin;
- request/confirm passwordless email OTP signin;
- request/confirm verified-phone SMS OTP signin;
- create social-auth attempt;
- create an authenticated social-link attempt from a caller-supplied existing BeeBox access token and Origin;
- list linked social accounts with bounded pagination;
- unlink one opaque social-link ID from the caller's current BeeBox session context;
- exchange a social completion code using the client PKCE verifier;
- begin/complete passkey registration by transporting opaque browser WebAuthn JSON;
- begin/complete passkey authentication without exposing go-webauthn types;
- list current-user passkey metadata;
- remove one opaque passkey resource from the current session context;
- current session;
- refresh;
- signout;
- request/confirm password reset;
- backend get/revoke session.

The SDK intentionally does not open a browser or invoke an authenticator itself. It transports browser-generated WebAuthn JSON opaquely and does not automatically retry one-time passkey completion or passkey removal security mutations. It also does not follow provider authorization/callback redirects or automatically retry one-time social completion/linking operations. The SDK never exposes provider subjects or handles provider access/refresh/ID tokens.

It provides a concurrency-safe offline Ed25519 JWT verifier with bounded HTTP access, JWKS caching, one controlled refresh on unknown `kid`, strict EdDSA/public-JWK validation and issuer/audience/time checks. The SDK does not log OTPs/credentials/tokens, persist browser credentials, automatically resend email/SMS OTPs, automatically retry OTP confirmation, automatically retry signin, or blindly replay refresh credentials.

## Operational metrics

`GET /metrics` emits bounded OpenMetrics/Prometheus text without high-cardinality identity labels. Current metrics include authentication operation outcomes, SMTP delivery outcome, SMS delivery purpose/outcome and PostgreSQL pool acquired/idle/total/max connection gauges. Email/phone, user/session/application IDs, OTP/challenge IDs, provider subject/SID, provider tokens, provider credential values/error bodies, tokens/JTI, passkey credential IDs, IP addresses and raw errors are not metric labels.

## Configuration

Core runtime values include:

- `BEEBOX_DATABASE_URL`
- `BEEBOX_HTTP_ADDR` (default `:8080`)
- `BEEBOX_SHUTDOWN_TIMEOUT`
- `BEEBOX_DATABASE_STARTUP_TIMEOUT`
- `BEEBOX_DATABASE_READINESS_TIMEOUT`
- `BEEBOX_DATABASE_MIGRATION_TIMEOUT`
- SMTP settings (`BEEBOX_SMTP_ADDR`, `BEEBOX_SMTP_FROM`, TLS/auth/timeout settings)
- optional SMS mode `BEEBOX_SMS_MODE=disabled|twilio|vonage|plivo|telnyx` plus exactly one selected provider's credentials/sender and optional bounded timeout;
- signing settings (`BEEBOX_ISSUER`, `BEEBOX_SIGNING_KID`, `BEEBOX_SIGNING_PRIVATE_KEY`, `BEEBOX_SIGNING_PUBLIC_KEY`, optional retiring public keys);
- optional social connection JSON `BEEBOX_SOCIAL_CONNECTIONS` keyed by application public ID + one of the exact eleven provider keys;
- `BEEBOX_SOCIAL_STATE_KEY`, an unpadded base64url 32-byte key required when the configured social provider set uses provider PKCE;
- `BEEBOX_ISSUER` also defines the social provider callback base when social connections are enabled.

Passkeys require no BeeBox-held authenticator private key or extra provider credential. They reuse the configured application Origin allowlist and normal signing/session runtime. Production credential-bearing SMTP requires secure transport. `insecure_localhost` is explicit local/test behavior only. Signing private material, all SMS provider authentication material, social provider client secrets and the social state key are configuration-only and are not stored as BeeBox identity/session data or exposed through metrics/public errors.

## Migration policy

Migrations `00001` through `00017` are immutable merged history. Migration `00013_email_otp_signin.sql` introduced the purpose-separated email OTP sign-in challenge table. Migration `00014_phone_sms.sql` introduced application-scoped phone identifiers and purpose-separated phone challenge state. Migration `00015_social_oauth.sql` introduced redirect allowlists, external identities, social attempts/completion grants and social limiter/audit vocabulary. Migration `00016_social_account_linking.sql` introduced exact-session-bound social-link attempts. Migration `00017_social_account_management.sql` introduced opaque `sli_` IDs, scoped listing and link cancellation state.

P2.5 adds only `00018_passkeys.sql`. It additively introduces application/user-scoped passkey credentials with opaque `pky_<uuid-v4>` IDs, application-unique credential IDs and RP scope; short-lived one-time passkey ceremonies with opaque `pka_<uuid-v4>` IDs, SHA-256 challenge hashes, exact registration-vs-authentication binding constraints, session/application/user foreign keys where applicable, and indexed expiry/consumption cleanup paths. It also adds the composite session key required to enforce exact application/user/session foreign-key scope. Migration tests cover clean application, upgrade from exact version 17, public-ID/uniqueness constraints, challenge-hash/raw-secret boundary and required indexes. No merged SQL migration is modified. Serve mode does not auto-migrate.

P2.6 preserves `00018` and adds `00019_totp_mfa.sql` for one logical application/user TOTP credential, encrypted enrollment envelopes and five-minute hash-only pending-MFA transactions. P2.7 adds ordered migration `00020_recovery_codes.sql`: application/user/TOTP-bound recovery sets, 32-byte recovery-code verifiers, atomic consumption/invalidation state, dedicated replacement-enrollment binding and bounded per-session sensitive-operation admission. Tests cover clean application, exact `00019` predecessor upgrade, public-ID/hash/active-set constraints and transaction/concurrency behavior. Migrations `00001` through `00018` are not modified; `00019` contains only the P2.6 correction on this unmerged branch. Serve mode still does not auto-migrate.

## Verification

```sh
gofmt -l .
go vet ./...
govulncheck ./...
go test ./api/openapi
go test ./sdk/go
go test ./internal/authentication/... -count=1
go test ./internal/httpapi -count=1
go test ./internal/authentication/socialprovider -count=1
go test ./internal/authentication/socialprovider -count=20
go test ./...
BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' \
  go test -tags=integration \
    ./internal/platform/database \
    ./internal/platform/migration \
    ./internal/platform/maintenance \
    ./internal/applicationinstance/postgres \
    ./internal/identity/postgres \
    ./internal/authentication/postgres \
    ./internal/session/postgres \
    ./internal/httpapi
go test -race ./...
```

GitHub Actions runs the same gates on pull-request heads. The social-provider contract gate runs both single and repeated deterministic provider tests. P2.3/P2.4 coverage remains in place for tenant isolation, callback/linking state, cross-flow serialization, pending-state invalidation, last-method protection and audit rollback. P2.5 adds WebAuthn protocol negative coverage, HTTP application/Origin/session binding, one-time expiry/replay checks, cross-application credential isolation, passkey/social last-method matrix, migration upgrade/constraints/index checks, bounded ceremony cleanup, SDK parity and induced audit-failure rollback for registration/authentication/removal. P2.6/P2.7 add all-primary MFA gating, same-timestep/pending replay concurrency, exact 32-byte verifier reads, recovery-code generation/binding, five-failure lockout, concurrent one-use, regeneration/replacement atomicity, audit rollback, migration upgrade/constraints, bounded cleanup and OpenAPI/SDK parity. Provider-contract tests remain synthetic and require no live provider accounts or credentials.

## Health endpoints

- `GET /health/live` — process liveness only.
- `GET /health/ready` — bounded current PostgreSQL readiness check.

## Phase boundary

`docs/phase1-exit.md` remains the evidence matrix for the completed Phase 1 baseline. The merged P2.0 trust baseline, P2.1 email OTP, P2.2 phone-first/SMS OTP, P2.3 social OAuth/OIDC, P2.4A explicit authenticated social linking and P2.4B linked-account management are established Phase 2 increments. This integration branch additionally implements P2.5 Passkeys/WebAuthn, P2.6 TOTP MFA and P2.7 recovery codes.

Principal/account merge, generic P2.8 reverification runtime, provider-side social consent/token revocation, expanded session/identifier/profile self-service, secure email links, hosted authentication/theme/localization, organizations, machine authentication, webhooks, billing, OAuth/OIDC authorization-server behavior and compliance certification remain outside the completed P2.7 boundary.
