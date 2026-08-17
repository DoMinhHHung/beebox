# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime, PostgreSQL connection, explicit migration runner, Phase 0 governance/contracts baseline, the v1 `application_instance` root isolation boundary, application-scoped internal user/email/password persistence, an internal transactional email/password registration core, an internal email OTP ownership-verification lifecycle, and the Checkpoint 1 public-trust foundation for typed public IDs, application integration credentials, exact browser origins, and trusted operator bootstrap. Email is persisted PII; password hashes and OTP verifier hashes are sensitive derived data. Public signup/signin, sessions, production email delivery, JWT/JWKS, password reset, and public product APIs are not implemented yet.

## Project documentation

- [Repository instructions](Instruction.md) — product, architecture, security, data, testing, delivery, and change-control invariants.
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md) — the Human-ratified v1 root product isolation decision.
- [ADR 0002: email identity v1](docs/adr/0002-email-identity-v1.md) — the Human-ratified application-scoped email normalization, uniqueness, verification-state, and no-auto-link decision.
- [ADR 0003: Phase 1 public auth contract](docs/adr/0003-phase1-public-auth-contract.md) — **proposed while this checkpoint PR is open**; Human squash-merge of the checkpoint constitutes acceptance before any public auth route may rely on it.
- [Initial threat model](docs/threat-model/initial.md) — current assets, actors, trust boundaries, implemented controls, required future controls, residual risks, and review triggers.
- [Contract and tenancy conventions](docs/contracts/conventions.md) — Phase 0 semantics for resource IDs, errors, pagination, idempotency, time, API versioning, audit events, and tenancy.
- [Contributing](CONTRIBUTING.md) — current branch/PR workflow, repository checks, migration policy, and contribution evidence.
- [Security policy](SECURITY.md) — safe vulnerability-reporting guidance and the repository's current reporting-channel limitations.

## Prerequisites

- Go 1.26.x
- Git
- a reachable PostgreSQL instance

The module declares Go 1.26.0 as its minimum supported Go version.

## Run locally

Start BeeBox with a PostgreSQL connection URI:

    BEEBOX_DATABASE_URL='postgres://beebox:local-password@127.0.0.1:5432/beebox?sslmode=disable' go run ./cmd/beebox

BeeBox verifies PostgreSQL connectivity before opening the HTTP listener. The HTTP server listens on `:8080` by default after that check succeeds.

Apply pending embedded migrations explicitly before starting a new runtime version:

    BEEBOX_DATABASE_URL='postgres://beebox_migrator:local-password@127.0.0.1:5432/beebox?sslmode=disable' go run ./cmd/beebox migrate

`beebox migrate` applies forward migrations and exits. The no-argument serve mode never runs migrations or mutates database schema automatically.

Checkpoint 1 also provides trusted local operator commands. They are not HTTP management APIs and do not auto-migrate schema. They use the configured PostgreSQL connection and a bounded operator context.

Generate local Ed25519 signing-key configuration material:

    go run ./cmd/beebox generate-signing-key

The private key is printed only as explicit one-time command output. It is not logged or persisted by BeeBox.

After migration 00008 has been applied, bootstrap an application with initial publishable/secret credentials and optional exact origins:

    BEEBOX_DATABASE_URL='postgres://beebox_migrator:local-password@127.0.0.1:5432/beebox?sslmode=disable' \
      go run ./cmd/beebox bootstrap-application https://app.example.test

The generated application secret is intentionally displayed once by the command. Store it securely; only its SHA-256 verifier is persisted.

Additional operator commands support adding an exact origin and scoped credential rotation/revocation. Public resource IDs and credential IDs are locators only and never authorization evidence.

## Configuration

### BEEBOX_DATABASE_URL

Required PostgreSQL connection URI. The value must use the `postgres` or `postgresql` scheme and include a host.

Example for a local development database:

    postgres://beebox:local-password@127.0.0.1:5432/beebox?sslmode=disable

Treat this value as a secret when it contains credentials. BeeBox does not include the URI or PostgreSQL provider details in configuration, startup, readiness, or structured-log errors.

### BEEBOX_HTTP_ADDR

Address used by the HTTP server.

Default:

    :8080

### BEEBOX_SHUTDOWN_TIMEOUT

Maximum amount of time allowed for graceful HTTP shutdown. Default: `10s`.

### BEEBOX_DATABASE_STARTUP_TIMEOUT

Maximum time allowed to create the PostgreSQL pool and prove connectivity before startup fails. Default: `5s`.

### BEEBOX_DATABASE_READINESS_TIMEOUT

Maximum time allowed for each PostgreSQL readiness check. Default: `1s`.

### BEEBOX_DATABASE_MIGRATION_TIMEOUT

Maximum total time allowed for migration lock acquisition and forward migration execution. Default: `30s`. The current trusted operator database commands also use this existing bound as their operation deadline.

Duration values use Go duration syntax and must be greater than zero.

## Migration policy

SQL migrations are compiled into the BeeBox binary and cannot be selected from a runtime filesystem, URL, argument, or environment value. The runner applies only `Up`, executes default SQL migrations transactionally, and serializes concurrent runners with a PostgreSQL same-session advisory lock.

Applied migration files are immutable. New database changes use new ordered versions and rolling-safe expand/contract sequencing. Production operations do not expose `Down`, reset, redo, force, manual version overrides, or arbitrary SQL.

Current migrations are:

- `00001_runtime_baseline.sql` — anchors forward migration history without product schema/data;
- `00002_application_instances.sql` — creates the `application_instances` root table;
- `00003_users.sql` — creates the minimal application-scoped `users` child table;
- `00004_email_identifiers.sql` — creates application-scoped email identifiers and scoped user referential integrity;
- `00005_password_credentials.sql` — creates one internal password credential per application-scoped user;
- `00006_audit_events.sql` — creates the minimal internal application-scoped audit-fact table used by current security mutations;
- `00007_email_verification_challenges.sql` — creates one bounded internal email-verification challenge per scoped email identifier;
- `00008_phase1_public_integration.sql` — backfills and constrains typed random UUIDv4 public IDs for applications/users and adds application-scoped integration credentials plus exact allowed origins.

Application public IDs use `app_<uuidv4>` and user public IDs use `usr_<uuidv4>`. Credential records use `cred_<uuidv4>`. Internal BIGINT primary keys remain internal persistence identities. Parsing or possessing a public ID does not establish authorization or tenant scope.

Application publishable keys use `bb_pk_<uuidv4>` and are intentionally non-secret application-context locators. Backend secret keys use `bb_sk_<credential-uuidv4>.<32-byte-base64url-secret>`; the locator is not authority and only a 32-byte SHA-256 verifier is persisted. Credentials are revocable/rotatable and application scoped.

Use separate credentials where possible:

- migration/operator mode receives a short-lived credential allowed to perform the reviewed operation;
- serve mode receives a least-privilege runtime credential and never needs migration privileges merely to start.

Migration failures, connectivity failures, lock timeouts, and cancellation exit nonzero, close acquired resources, do not open an HTTP listener, and report stable errors without SQL, provider, topology, credential secret, password, password-hash, OTP, OTP-hash, or email details.

## Health endpoints

### Liveness

    GET /health/live

Successful response:

    {"status":"ok"}

Liveness is process-only and never calls PostgreSQL.

### Readiness

    GET /health/ready

Successful response:

    {"status":"ready"}

Readiness performs a current bounded PostgreSQL connectivity check. Failure returns HTTP `503 Service Unavailable` with the stable response:

    {"status":"not_ready"}

Only `GET` is accepted for health endpoints. Unsupported methods return HTTP `405 Method Not Allowed`.

## Verification

Format:

    gofmt -w .

Static analysis:

    go vet ./...

Tests:

    go test ./...

Race detector:

    go test -race ./...

PostgreSQL integration tests:

    BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' go test -tags=integration ./internal/platform/database ./internal/platform/migration ./internal/applicationinstance/postgres ./internal/identity/postgres ./internal/authentication/postgres

Regular and race tests do not require a local PostgreSQL instance. GitHub Actions provisions an isolated PostgreSQL service and runs the integration command explicitly.

## Current scope

The repository currently contains:

- one Go process and one process-owned PostgreSQL pool;
- explicit embedded forward-only migrations serialized by an advisory lock;
- the `application_instances` v1 root product-isolation table;
- application-scoped internal users and scoped email identifiers;
- stable BeeBox-owned `app_<uuidv4>` and `usr_<uuidv4>` public locators backed by additive migration defaults/constraints while internal BIGINT IDs remain internal;
- application-scoped publishable and backend-secret credential records with `cred_<uuidv4>` locators, strict kind/value checks, revocation state, and secret-use timestamp;
- publishable-key resolution that establishes application integration context only, with no user/admin authority;
- backend-secret authentication using 32 random secret bytes, SHA-256 verifier-at-rest, constant-time comparison, and current-state recheck before accepting backend application scope;
- scoped atomic credential rotation: the new credential is created and the old credential revoked in one transaction, with separate correlated append-oriented audit facts; cross-application rotation/revocation is rejected;
- exact application allowed-origin persistence with no wildcard, path, query, fragment, or userinfo and database duplicate protection;
- trusted operator commands for application bootstrap, origin addition, scoped credential rotation/revocation, and local Ed25519 key generation; one-time secrets/private material are command output rather than logs;
- deterministic BeeBox v1 ASCII email normalization with no provider-specific rewriting;
- internal Argon2id password hashing using version 19, time 3, 64 MiB memory, parallelism 4, random 16-byte salt, and 32-byte derived hash;
- application-scoped password credentials with a composite same-application user foreign key;
- internal append-oriented audit persistence with explicit application scope, required action/resource/outcome/source/correlation fields, optional scoped actor/subject user references, and no PII/credential payload;
- an internal `RegisterEmailPassword` operation that atomically persists one scoped user, one unverified email identifier, one password credential, and one successful registration audit fact;
- an internal six-digit email verification code primitive generated with `crypto/rand`; codes are stored only as dedicated Argon2id-derived `VerificationCodeHash` values;
- one `email_verification_challenges` row per scoped email identifier, with a 10-minute code lifetime, five-failure verification budget, 15-minute issue window, three issues per window, 60-second resend cooldown, and generation rotation;
- internal issue/resend orchestration that commits challenge state plus required audit before invoking its delivery port;
- verification finalization that rechecks current challenge generation/state and atomically persists denied/success security facts;
- PostgreSQL evidence for expiry, attempt exhaustion, resend behavior, replay resistance, stale-generation rejection, concurrent one-winner verification, cancellation, cross-application challenge isolation, public-trust credential scoping, and audit persistence;
- proposed ADR 0003 defining the Phase 1 public authentication contract pending Human acceptance by squash merge.

Email addresses are persisted PII. Password hashes and verification-code hashes are sensitive derived data. Application secret plaintext is one-time operator output and is not persisted. Raw passwords and raw verification codes remain transient inputs only.

Email verification proves control of an address only. It does **not** authenticate a BeeBox user, create an authenticated principal, act as MFA, establish a session/token/cookie, authorize account linking, merge accounts, or grant privileges. ADR 0002 no-auto-link semantics remain unchanged.

**No public product authentication route is exposed by Checkpoint 1.** Serve mode still exposes only health endpoints. The proposed ADR intentionally establishes trust/contract defaults before reachable `/v1` routes are implemented.

Still unimplemented in Phase 1: reachable signup/email-verification HTTP, request-level abuse/idempotency controls, production SMTP delivery, public password-policy enforcement, signin, session persistence, access JWT/JWKS, refresh credentials, browser auth cookies, password reset/recovery, OpenAPI public routes, SDK, metrics, and final local/E2E exit evidence.

Phase 1 remains incomplete.

## Rollout and rollback

No hosted database mutation is performed by repository changes alone. For a reviewed release, run the exact promoted binary/image with `migrate` before using operator commands or code that depends on migration 00008. Normal serve mode still does not auto-migrate.

Checkpoint 1 contains no public auth route, provider deployment, IAM/secret/domain mutation, or hosted backfill. BeeBox production migration policy remains forward-only: once data depends on additive public integration schema, corrections use reviewed forward migrations rather than destructive automatic rollback.
