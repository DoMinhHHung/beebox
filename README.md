# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go. Clerk's public product capabilities are a benchmark only; BeeBox owns its contracts, implementation, identifiers, persistence and security decisions.

Phase 1 currently provides application-scoped email/password signup and email verification, verified-email password sign-in, sessions with rotating refresh credentials, Ed25519 access JWTs/JWKS, and the password-reset lifecycle implemented by this checkpoint. Phase 1 is not complete until the final SDK/metrics/local-setup/exit-evidence checkpoint is Human-merged and verified on `main`.

## Project documentation

- [Repository instructions](Instruction.md)
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md)
- [ADR 0002: email identity v1](docs/adr/0002-email-identity-v1.md)
- [ADR 0003: Phase 1 public auth contract](docs/adr/0003-phase1-public-auth-contract.md)
- [Initial threat model](docs/threat-model/initial.md)
- [Contract and tenancy conventions](docs/contracts/conventions.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [OpenAPI v1](api/openapi/v1.yaml)

## Prerequisites

- Go 1.26.x
- Git
- PostgreSQL 17-compatible server

## Run locally

Apply reviewed embedded migrations explicitly:

    BEEBOX_DATABASE_URL='postgres://beebox_migrator:local-password@127.0.0.1:5432/beebox?sslmode=disable' \
      go run ./cmd/beebox migrate

Start BeeBox:

    BEEBOX_DATABASE_URL='postgres://beebox:local-password@127.0.0.1:5432/beebox?sslmode=disable' \
      go run ./cmd/beebox

Serve mode never auto-migrates.

Trusted operator commands bootstrap applications, configure exact origins, rotate/revoke application credentials and generate local Ed25519 signing-key material. Generated application secrets and private signing material are explicit one-time command output, not logs.

## Public Phase 1 surface

The current `/v1` contract is application-scoped through a BeeBox publishable key and exact stored browser origins where an Origin is present. Public resource IDs are opaque locators; possessing or parsing one does not establish authorization.

Implemented public authentication flows include:

- `POST /v1/sign-ups` — application-scoped email/password signup with shared public password policy and idempotency;
- `POST /v1/email-verifications` and `/v1/email-verifications/confirm` — bounded email ownership verification;
- `POST /v1/sign-ins` — verified-email/password sign-in with anti-enumerating invalid-credential behavior and PostgreSQL-backed attempt limits;
- `POST /v1/sessions/refresh` — one-time refresh rotation; consumed-token replay revokes the session;
- `GET /.well-known/jwks.json` — active/retiring public Ed25519 verification keys when token capability is configured;
- `POST /v1/password-resets` — generic anti-enumerating reset request;
- `POST /v1/password-resets/confirm` — bounded reset-code confirmation, shared public password policy, password replacement and all-session revocation.

See `api/openapi/v1.yaml` for request/response contracts. Credential/token responses use `Cache-Control: no-store`. Provider/database details, email PII and secret material are not returned in stable errors.

## Password reset security semantics

Password reset uses a dedicated eight-digit cryptographically random code with a 10-minute TTL, five failed attempts, a 15-minute issuance window, at most three issues per window and a 60-second resend cooldown. The raw reset code is transient; PostgreSQL stores only Argon2id verifier material.

A successful confirmation transaction atomically:

1. rechecks application scope, verified email ownership, challenge generation/state and password credential generation;
2. replaces the password hash and increments credential generation;
3. consumes the reset challenge and clears its verifier;
4. revokes every current session for that user in the application;
5. appends the required success audit fact.

Wrong-code attempt increments and denied audit are committed together. Reset request state remains anti-enumerating. SMTP delivery occurs after challenge/audit commit; ambiguous provider failure does not erase the security fact or challenge.

Resetting a password immediately revokes BeeBox session state for refresh/current-state checks. Already-issued stateless access JWTs may remain cryptographically valid for offline verifiers until their short expiry; no global JWT denylist is claimed.

## Password and email semantics

Public password establishment/reset uses one shared policy: NFC normalization, 15–128 Unicode code points, the existing safe byte bound, no silent trimming, no mandatory composition rules, and the repository-owned common/expected-password blocklist. The low-level Argon2id primitive remains separate from public policy.

Email identity remains application-scoped under ADR 0002. Equal normalized email addresses in different applications are independent. Same-application duplicate registration never auto-links, merges or adopts an existing account. Email verification proves address control only; it is not a session, MFA factor or account-link authorization.

## Sessions and tokens

Phase 1 session defaults are 30-day absolute lifetime and 7-day inactivity lifetime. Refresh credentials are random opaque secrets stored only as verifier hashes and rotate on every successful refresh. Reuse of a consumed refresh credential revokes its owning session.

Access tokens are five-minute Ed25519/JOSE EdDSA JWTs with strict algorithm and `kid` validation, configured issuer, application audience, user/session public subjects and bounded clock skew. JWKS publishes public key material only. Offline JWT verifiers cannot observe immediate database session revocation; the short access-token lifetime bounds that stale-auth window.

## Configuration

Core database/runtime configuration includes:

- `BEEBOX_DATABASE_URL`
- `BEEBOX_HTTP_ADDR` (default `:8080`)
- `BEEBOX_SHUTDOWN_TIMEOUT`
- `BEEBOX_DATABASE_STARTUP_TIMEOUT`
- `BEEBOX_DATABASE_READINESS_TIMEOUT`
- `BEEBOX_DATABASE_MIGRATION_TIMEOUT`

SMTP delivery uses the existing bounded SMTP configuration (`BEEBOX_SMTP_ADDR`, `BEEBOX_SMTP_FROM`, TLS/auth/timeout settings). Credentials are never logged. Production credential-bearing SMTP requires secure transport; explicitly insecure localhost/test behavior remains local-only.

Signing-key configuration is documented by ADR 0003 and generated safely with:

    go run ./cmd/beebox generate-signing-key

## Migration policy

Migrations are embedded, forward-only and explicitly invoked. Applied migrations are immutable. The current positive sequence is `00001` through `00011`; checkpoint 4 adds:

- `00011_password_resets.sql` — password credential generation/update metadata, reset rate-limit operations and application-scoped password-reset challenge persistence.

`password_reset_challenges` has scoped user/email foreign keys and no cascade deletion. Serve mode does not auto-migrate, and repository work never mutates a hosted database automatically.

## Health endpoints

- `GET /health/live` — process liveness only.
- `GET /health/ready` — bounded current PostgreSQL readiness check.

## Verification

Format:

    gofmt -l .

Static analysis:

    go vet ./...

Unit tests:

    go test ./...

PostgreSQL integration tests:

    BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' \
      go test -tags=integration \
        ./internal/platform/database \
        ./internal/platform/migration \
        ./internal/applicationinstance/postgres \
        ./internal/identity/postgres \
        ./internal/authentication/postgres \
        ./internal/session/postgres

Race detector:

    go test -race ./...

GitHub Actions runs the same repository gates on pull-request heads.

## Security and data lifecycle

Email is PII. Password hashes, email-verification verifier hashes, reset-code verifier hashes, application-secret verifiers and refresh-token verifiers are sensitive data. Backups containing these values require privileged protection. Raw passwords, OTPs, reset codes, application secrets, refresh secrets, access tokens and signing private keys must not enter logs, metrics or audit facts.

Password reset creates no account link, organization membership, role or privilege. Phase 2+ capabilities such as social auth, MFA/passkeys, organizations, account linking, machine auth, webhooks, billing and compliance certification are not claimed.

## Phase 1 status

Checkpoint 4 adds the password reset/recovery lifecycle but does **not** finish Phase 1. Remaining campaign work is Checkpoint 5: final OpenAPI/Go SDK coverage, operational metrics, reproducible local setup and end-to-end Phase 1 exit evidence.
