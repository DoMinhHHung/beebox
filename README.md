# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go. Clerk's public product capabilities are a benchmark only; BeeBox owns its contracts, implementation, identifiers, persistence and security decisions.

BeeBox's merged Phase 1 B2C foundation provides application-scoped email/password signup and verification, signin, rotating sessions/refresh credentials, Ed25519 access JWTs/JWKS, password reset, backend session management, a minimal Go SDK, operational metrics and reproducible local dependencies. P2.1 added passwordless email OTP primary authentication for existing verified email identifiers. This branch adds the P2.2 phone-first signup and verified-phone SMS OTP primary-authentication slice. It does **not** claim the rest of Phase 2 is implemented.

## Project documentation

- [Repository instructions](Instruction.md)
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md)
- [ADR 0002: email identity v1](docs/adr/0002-email-identity-v1.md)
- [ADR 0003: Phase 1 public auth contract](docs/adr/0003-phase1-public-auth-contract.md)
- [ADR 0004: Phase 2 identity linking and external trust](docs/adr/0004-phase2-identity-linking-external-trust.md)
- [ADR 0005: Phase 2 authentication assurance and recovery](docs/adr/0005-phase2-authentication-assurance-recovery.md)
- [ADR 0006: Phase 2 device privacy and hosted-auth trust](docs/adr/0006-phase2-device-privacy-hosted-auth.md)
- [Initial threat model](docs/threat-model/initial.md)
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

Save the emitted `publishable_key` and `secret_key` outside source control, then configure local SMTP capture:

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
export BEEBOX_TWILIO_AUTH_TOKEN='<auth-token>'
export BEEBOX_TWILIO_FROM='<configured-sender>'
export BEEBOX_TWILIO_TIMEOUT='5s' # optional; maximum 30s
```

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
- `POST /v1/sessions/refresh` — one-time refresh rotation; replay revokes the session;
- `GET /v1/sessions/current` — access JWT plus current database session-state validation;
- `POST /v1/sessions/sign-out` — current-session revoke/signout;
- `GET /v1/backend/sessions/{session_id}` — secret-key scoped backend session lookup;
- `POST /v1/backend/sessions/{session_id}/revoke` — secret-key scoped backend revoke;
- `POST /v1/password-resets` and `/v1/password-resets/confirm` — anti-enumerating recovery and password replacement;
- `GET /.well-known/jwks.json` — active and retiring public Ed25519 verification keys;
- `GET /metrics` — bounded operational counters and database-pool occupancy gauges. Protect this operational endpoint at the deployment/network boundary as appropriate.

See `api/openapi/v1.yaml` for the BeeBox-owned public contract. No public response exposes internal BIGINT IDs, challenge rows, or database/provider models.

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
- current session;
- refresh;
- signout;
- request/confirm password reset;
- backend get/revoke session.

It also provides a concurrency-safe offline Ed25519 JWT verifier with bounded HTTP access, JWKS caching, one controlled refresh on unknown `kid`, strict EdDSA/public-JWK validation and issuer/audience/time checks. The SDK does not log OTPs/credentials/tokens, persist browser credentials, automatically resend email/SMS OTPs, automatically retry OTP confirmation, automatically retry signin, or blindly replay refresh credentials.

## Operational metrics

`GET /metrics` emits bounded OpenMetrics/Prometheus text without high-cardinality identity labels. Current metrics include authentication operation outcomes, SMTP delivery outcome, SMS delivery purpose/outcome and PostgreSQL pool acquired/idle/total/max connection gauges. Email/phone, user/session/application IDs, OTP/challenge IDs, provider identifiers/error codes, tokens/JTI, credential IDs, IP addresses and raw errors are not metric labels.

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
- signing settings (`BEEBOX_ISSUER`, `BEEBOX_SIGNING_KID`, `BEEBOX_SIGNING_PRIVATE_KEY`, `BEEBOX_SIGNING_PUBLIC_KEY`, optional retiring public keys).

Production credential-bearing SMTP requires secure transport. `insecure_localhost` is explicit local/test behavior only. Signing private material and all SMS provider authentication material are configuration-only and are not stored in PostgreSQL or exposed through metrics/public errors.

## Migration policy

Migrations `00001` through `00014` are embedded, forward-only and explicitly invoked. Migration `00013_email_otp_signin.sql` additively introduced the purpose-separated email OTP sign-in challenge table and OTP-specific public-auth admission vocabulary. Migration `00014_phone_sms.sql` additively introduces application-scoped phone identifiers, purpose-separated phone signup and phone sign-in challenges, bounded cleanup indexes and phone-specific public-auth admission vocabulary while preserving every earlier limiter operation. Applied migrations are immutable. Serve mode does not auto-migrate. Schema corrections after dependent data exists use a reviewed forward migration; no destructive automatic rollback is claimed.

## Verification

```sh
gofmt -l .
go vet ./...
govulncheck ./...
go test ./api/openapi
go test ./sdk/go
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

GitHub Actions runs the same gates on pull-request heads. P2.2 integration coverage adds no-account-before-proof phone signup, strict application/phone ownership, fingerprint/verifier-only challenge state, cooldown/rotation/attempt/expiry/replay behavior, concurrent one-time account/session creation, verified-only phone sign-in, ordinary session/refresh lifecycle and migration/provider-boundary evidence while preserving Phase 1 and P2.1 regression suites. Provider adapter tests use synthetic credentials and local `httptest` servers only; CI never sends a live SMS.

## Health endpoints

- `GET /health/live` — process liveness only.
- `GET /health/ready` — bounded current PostgreSQL readiness check.

## Phase boundary

`docs/phase1-exit.md` remains the evidence matrix for the completed Phase 1 baseline. P2.1 email OTP and this P2.2 phone-first/SMS OTP slice are the implemented Phase 2 runtime increments. Existing-account phone add/change/remove/switch, social OAuth/OIDC, account-linking runtime, passkeys/WebAuthn, MFA/TOTP, recovery codes, step-up/reverification runtime, device management, hosted authentication, organizations, machine authentication, webhooks, billing, OAuth/OIDC authorization-server behavior and compliance certification remain unimplemented.
