# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go. Clerk's public product capabilities are a benchmark only; BeeBox owns its contracts, implementation, identifiers, persistence and security decisions.

BeeBox's merged Phase 1 B2C foundation provides application-scoped email/password signup and verification, signin, rotating sessions/refresh credentials, Ed25519 access JWTs/JWKS, password reset, backend session management, a minimal Go SDK, operational metrics and reproducible local dependencies. This branch adds the P2.1 passwordless email OTP primary-authentication slice for existing verified email identifiers. It does **not** claim the rest of Phase 2 is implemented.

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

The SDK offline verifier intentionally requires the configured HTTPS issuer. For local plaintext HTTP development, use the local JWKS endpoint for inspection/testing or place BeeBox behind a local TLS endpoint rather than weakening production issuer semantics.

Serve mode never auto-migrates.

## Public authentication surface

Application context for frontend/auth flows comes from `X-BeeBox-Publishable-Key`. Publishable keys are non-secret context selectors, not backend or user authority. Backend session operations use a verified BeeBox secret key. Access-token authenticated routes also re-check persisted session state where immediate BeeBox-side revocation is required.

Reachable endpoints include:

- `POST /v1/sign-ups` — signup with shared public password policy and idempotency;
- `POST /v1/email-verifications` — generic bounded verification issue/resend;
- `POST /v1/email-verifications/confirm` — email ownership confirmation only;
- `POST /v1/sign-ins` — verified email/password signin with anti-enumerating failures and PostgreSQL attempt limits;
- `POST /v1/sign-ins/email-otp` — generic bounded request for a passwordless sign-in code for an existing verified identifier;
- `POST /v1/sign-ins/email-otp/confirm` — one-time email OTP primary proof producing the normal BeeBox session/access/refresh transport;
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

### Sessions and tokens

Sessions use a 30-day absolute lifetime and seven-day inactivity lifetime. Refresh credentials are random opaque secrets stored only as verifier hashes and rotate on every successful refresh. Reuse of a consumed refresh credential revokes its owning session. SDK methods do not blindly retry refresh operations; an ambiguous lost refresh response can require reauthentication.

Access tokens are five-minute Ed25519/JOSE EdDSA JWTs with strict `kid`, issuer, audience, signature and time validation and at most 30 seconds of accepted skew. JWKS publishes public key material only. Offline JWT verifiers cannot observe immediate database revocation; token expiry bounds that stale-auth window. BeeBox current-session endpoints additionally check database session state.

Password reset revokes all current sessions for the application-scoped user. Already-issued access JWTs can remain cryptographically valid for offline consumers until their short expiry; BeeBox does not claim a global JWT denylist.

## Minimal Go SDK

`sdk/go` provides a small HTTP client for:

- signup;
- request/resend/confirm email verification;
- password signin;
- request/confirm passwordless email OTP signin;
- current session;
- refresh;
- signout;
- request/confirm password reset;
- backend get/revoke session.

It also provides a concurrency-safe offline Ed25519 JWT verifier with bounded HTTP access, JWKS caching, one controlled refresh on unknown `kid`, strict EdDSA/public-JWK validation and issuer/audience/time checks. The SDK does not log OTPs/credentials/tokens, persist browser credentials, automatically resend OTPs, automatically retry OTP confirmation, automatically retry signin, or blindly replay refresh credentials.

## Operational metrics

`GET /metrics` emits bounded OpenMetrics/Prometheus text without high-cardinality identity labels. Current metrics include authentication operation outcomes, SMTP delivery outcome and PostgreSQL pool acquired/idle/total/max connection gauges. Email, user/session/application IDs, OTP/challenge IDs, tokens/JTI, credential IDs, IP addresses and raw errors are not metric labels.

## Configuration

Core runtime values include:

- `BEEBOX_DATABASE_URL`
- `BEEBOX_HTTP_ADDR` (default `:8080`)
- `BEEBOX_SHUTDOWN_TIMEOUT`
- `BEEBOX_DATABASE_STARTUP_TIMEOUT`
- `BEEBOX_DATABASE_READINESS_TIMEOUT`
- `BEEBOX_DATABASE_MIGRATION_TIMEOUT`
- SMTP settings (`BEEBOX_SMTP_ADDR`, `BEEBOX_SMTP_FROM`, TLS/auth/timeout settings)
- signing settings (`BEEBOX_ISSUER`, `BEEBOX_SIGNING_KID`, `BEEBOX_SIGNING_PRIVATE_KEY`, `BEEBOX_SIGNING_PUBLIC_KEY`, optional retiring public keys).

Production credential-bearing SMTP requires secure transport. `insecure_localhost` is explicit local/test behavior only. Signing private material is configuration-only and is not stored in PostgreSQL or published through JWKS.

## Migration policy

Migrations `00001` through `00013` are embedded, forward-only and explicitly invoked. Migration `00013_email_otp_signin.sql` additively introduces the purpose-separated OTP sign-in challenge table and OTP-specific public-auth admission vocabulary. Applied migrations are immutable. Serve mode does not auto-migrate. Schema corrections after dependent data exists use a reviewed forward migration; no destructive automatic rollback is claimed.

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

GitHub Actions runs the same gates on pull-request heads. P2.1 integration coverage exercises application-scoped OTP issue, verifier-only storage, cooldown/rotation/attempt/replay behavior, concurrent one-time redemption, ordinary session/refresh issuance, and successful audit persistence while preserving the existing Phase 1 password/session tests.

## Health endpoints

- `GET /health/live` — process liveness only.
- `GET /health/ready` — bounded current PostgreSQL readiness check.

## Phase boundary

`docs/phase1-exit.md` remains the evidence matrix for the completed Phase 1 baseline. This P2.1 slice adds passwordless email OTP only. It does not claim phone/SMS, social OAuth/OIDC, account-linking runtime, passkeys/WebAuthn, MFA/TOTP, recovery codes, step-up/reverification runtime, device management, hosted authentication, organizations, machine authentication, webhooks, billing, OAuth/OIDC authorization-server behavior or compliance certification.
