# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime, PostgreSQL connection, explicit migration-runner foundation, and Phase 0 governance/contract baseline. Product capabilities such as users, authentication, sessions, organizations, product schemas, and persistence queries are not implemented yet.

## Project documentation

- [Repository instructions](Instruction.md) — product, architecture, security, data, testing, delivery, and change-control invariants.
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

Example:

    BEEBOX_HTTP_ADDR=127.0.0.1:9090 BEEBOX_DATABASE_URL='postgres://beebox:local-password@127.0.0.1:5432/beebox?sslmode=disable' go run ./cmd/beebox

The value must contain a valid numeric TCP port.

### BEEBOX_SHUTDOWN_TIMEOUT

Maximum amount of time allowed for graceful HTTP shutdown.

Default:

    10s

The value uses Go duration syntax and must be greater than zero.

Example:

    BEEBOX_SHUTDOWN_TIMEOUT=5s BEEBOX_DATABASE_URL='postgres://beebox:local-password@127.0.0.1:5432/beebox?sslmode=disable' go run ./cmd/beebox

### BEEBOX_DATABASE_STARTUP_TIMEOUT

Maximum time allowed to create the PostgreSQL pool and prove connectivity before startup fails. The HTTP listener is not opened until this check succeeds.

Default:

    5s

The value uses Go duration syntax and must be greater than zero.

### BEEBOX_DATABASE_READINESS_TIMEOUT

Maximum time allowed for each PostgreSQL check made by the readiness endpoint.

Default:

    1s

The value uses Go duration syntax and must be greater than zero.

### BEEBOX_DATABASE_MIGRATION_TIMEOUT

Maximum total time allowed for migration lock acquisition and forward migration execution.

Default:

    30s

The value uses Go duration syntax and must be greater than zero. It is loaded only by `beebox migrate`; an invalid or irrelevant migration value does not change serve-mode validation.

## Migration policy

SQL migrations are compiled into the BeeBox binary and cannot be selected from a runtime filesystem, URL, argument, or environment value. The runner uses the maintained goose Provider API, applies only `Up`, executes each default SQL migration transactionally, and serializes concurrent runners with a PostgreSQL same-session advisory lock. Lock acquisition and cleanup are bounded.

Applied migration files are immutable. New database changes use a new ordered version and rolling-safe expand/contract sequencing. Production operations do not expose `Down`, reset, redo, force, manual version overrides, or arbitrary SQL.

Version `00001_runtime_baseline.sql` intentionally contains only a harmless statement. It anchors forward migration history and creates no product schema, table, or data. On first execution, the only created table is goose migration metadata (`goose_db_version`).

Use separate credentials where possible:

- migration mode receives a short-lived credential allowed to perform the reviewed DDL required by the target release;
- serve mode receives a least-privilege runtime credential and never needs migration privileges merely to start.

Migration failures, connectivity failures, lock timeouts, and cancellation exit nonzero, close acquired resources, do not open an HTTP listener, and report stable errors without SQL, provider, topology, or credential details.

## Health endpoints

### Liveness

    GET /health/live

Successful response:

    {"status":"ok"}

Liveness is process-only. It remains successful while the process can serve HTTP requests and never calls PostgreSQL.

### Readiness

    GET /health/ready

Successful response:

    {"status":"ready"}

Readiness performs a current, bounded PostgreSQL connectivity check. A healthy database returns HTTP `200` with the response above. A failed, canceled, or timed-out check returns HTTP `503 Service Unavailable` with a stable response that does not expose provider details:

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

PostgreSQL integration test (requires a real test database and never skips when selected):

    BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' go test -tags=integration ./internal/platform/database ./internal/platform/migration

Regular and race tests do not require a local PostgreSQL instance. GitHub Actions provisions an isolated PostgreSQL service and runs the integration command explicitly.

## Current scope

This bootstrap contains:

- one Go process;
- startup configuration validation;
- structured logging with `log/slog`;
- explicit HTTP server timeouts;
- graceful SIGINT and SIGTERM shutdown;
- bounded shutdown timeout;
- one process-owned PostgreSQL pool with deterministic cleanup;
- bounded PostgreSQL connectivity verification before HTTP startup;
- process-only liveness and PostgreSQL-aware readiness endpoints;
- a real PostgreSQL integration test in CI;
- an explicit, embedded, forward-only PostgreSQL migration mode;
- transactional migrations serialized by a bounded advisory lock;
- a version-1 runtime baseline and migration metadata only;
- focused automated tests;
- minimal GitHub Actions CI;
- Phase 0 threat-model, contract-convention, contribution, and security-reporting documentation.

There are no product schemas, product tables, product data, queries, repositories, Redis, or identity behaviors in this slice. Those capabilities are intentionally deferred to later vertical slices.

## Rollout and rollback

This foundation intentionally makes PostgreSQL an unconditional runtime dependency. Every environment must provide a valid `BEEBOX_DATABASE_URL` and a reachable database before BeeBox can serve HTTP traffic.

Before rollout, verify the environment's backup and restore policy. Run the exact binary or immutable image being promoted with `migrate` and a migration-capable credential, observe a zero exit, then start or promote no-argument serve mode with its least-privilege runtime credential. Do not run a different migration artifact from the runtime artifact it prepares.

Code rollback does not automatically downgrade database state. The version-1 baseline changes no product schema or data, so its metadata may remain harmlessly after a code rollback. Future failed or incompatible schema changes are corrected by reviewed roll-forward migrations and expand/contract sequencing, never an automatic production `Down`.
