# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime, PostgreSQL connection, explicit migration runner, Phase 0 governance/contracts baseline, the v1 `application_instance` root isolation boundary, application-scoped internal user/email/password persistence, an internal transactional email/password registration core, and an internal email OTP ownership-verification lifecycle. Email is persisted PII; password hashes and OTP verifier hashes are sensitive derived data. Public signup/signin, sessions, authorization, organizations, production email delivery, and public product APIs are not implemented yet.

## Project documentation

- [Repository instructions](Instruction.md) — product, architecture, security, data, testing, delivery, and change-control invariants.
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md) — the Human-ratified v1 root product isolation decision and its intentionally unresolved public-ID boundary.
- [ADR 0002: email identity v1](docs/adr/0002-email-identity-v1.md) — the Human-ratified application-scoped email normalization, uniqueness, verification-state, and no-auto-link decision.
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

`beebox migrate` applies forward migrations and exits. The no-argument serve mode never runs migrations or mutates database schema automatically. Unknown commands and extra arguments fail with `usage: beebox [migrate]` before configuration, database, or listener acquisition.

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

Maximum total time allowed for migration lock acquisition and forward migration execution. Default: `30s`.

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
- `00007_email_verification_challenges.sql` — adds the scoped email-identifier key needed for referential integrity and creates one bounded internal verification challenge per application-scoped email identifier, with generation, expiry, failed-attempt, issue-window/cooldown, consumption, and verifier-hash state.

Database identities remain internal persistence details. `audit_events.id`, audit correlation IDs, email identifier IDs, and verification challenge state do not ratify any public identifier encoding. No public product, verification, or audit API exists.

Use separate credentials where possible:

- migration mode receives a short-lived credential allowed to perform reviewed DDL;
- serve mode receives a least-privilege runtime credential and never needs migration privileges merely to start.

Migration failures, connectivity failures, lock timeouts, and cancellation exit nonzero, close acquired resources, do not open an HTTP listener, and report stable errors without SQL, provider, topology, credential, password, password-hash, OTP, OTP-hash, or email details.

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
- deterministic BeeBox v1 ASCII email normalization with no provider-specific rewriting;
- internal Argon2id password hashing using version 19, time 3, 64 MiB memory, parallelism 4, random 16-byte salt, and 32-byte derived hash;
- application-scoped password credentials with a composite same-application user foreign key;
- internal append-oriented audit persistence with explicit application scope, required action/resource/outcome/source/correlation fields, optional scoped actor/subject user references, and no PII/credential payload;
- an internal `RegisterEmailPassword` operation that atomically persists one scoped user, one unverified email identifier, one password credential, and one successful registration audit fact;
- an internal six-digit email verification code primitive generated with `crypto/rand`; codes are stored only as dedicated Argon2id-derived `VerificationCodeHash` values;
- one `email_verification_challenges` row per scoped email identifier, with a 10-minute code lifetime, five-failure verification budget, 15-minute issue window, three issues per window, 60-second resend cooldown, and generation rotation;
- internal issue/resend orchestration that resolves the stored scoped destination, hashes before database I/O, atomically commits challenge state plus a `challenge_issued` audit fact, and invokes a narrow delivery port only after commit;
- delivery-failure semantics that preserve the already committed challenge and issuance audit because provider delivery can be ambiguous;
- internal verification that loads a scoped generation snapshot, performs Argon2 verification outside the final transaction, then re-locks/rechecks current generation/state before mutating anything;
- atomic wrong-code failed-attempt increment plus denied audit, and atomic successful `verified_at` transition plus challenge consumption/verifier clearing plus success audit;
- PostgreSQL evidence for expiry, attempt exhaustion, resend cooldown/window behavior, replay resistance, stale-generation rejection, concurrent one-winner verification, cancellation, and cross-application challenge isolation;
- Phase 0 governance/security/contracts documentation plus ADRs 0001 and 0002.

Email addresses are persisted PII. Password hashes and verification-code hashes are sensitive derived data. Raw passwords and raw verification codes are transient inputs only; plaintext verification codes cross only the internal delivery port and are never persisted or written to audit records.

Email verification in this repository proves control of an address only. It does **not** authenticate a BeeBox user, create an authenticated principal, act as MFA, establish a session/token/cookie, authorize account linking, merge accounts, or grant privileges. ADR 0002 no-auto-link semantics remain unchanged.

The verification lifecycle is internal and unreachable from HTTP/public APIs. No production email provider adapter exists; tests use in-memory fake delivery only. Public signup/verification contracts, request/IP/account abuse controls, signin, public password policy, password reset/change, sessions/tokens, public IDs, account linking, organizations, or audit query/export/retention APIs remain unimplemented.

A future reachable signup/verification contract must still define server-selected application scope, versioned public models/IDs, anti-enumerating safe errors, request idempotency/retry behavior, request-level abuse controls, provider behavior, and compatibility semantics.

Phase 1 remains incomplete.

## Rollout and rollback

No hosted database mutation is performed by repository changes alone. For a reviewed release, run the exact promoted binary/image with `migrate` before starting code that depends on `email_verification_challenges`. Normal serve mode still does not auto-migrate.

A production email provider adapter and any public verification handler require separate reviewed changes after the persistence/application core is promoted. BeeBox production migration policy remains forward-only: once data depends on the additive schema, corrections use reviewed forward migrations rather than destructive automatic rollback.
