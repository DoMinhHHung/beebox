# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime and PostgreSQL connection foundation only. Product capabilities such as users, authentication, sessions, organizations, schemas, migrations, and persistence queries are not implemented yet.

## Prerequisites

- Go 1.26.x
- Git
- a reachable PostgreSQL instance

The module declares Go 1.26.0 as its minimum supported Go version.

## Run locally

Start BeeBox with a PostgreSQL connection URI:

    BEEBOX_DATABASE_URL='postgres://beebox:local-password@127.0.0.1:5432/beebox?sslmode=disable' go run ./cmd/beebox

BeeBox verifies PostgreSQL connectivity before opening the HTTP listener. The HTTP server listens on `:8080` by default after that check succeeds.

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

    BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' go test -tags=integration ./internal/platform/database

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
- focused automated tests;
- minimal GitHub Actions CI.

There are no migrations, schemas, product tables, queries, repositories, Redis, or identity behaviors in this slice. Those capabilities are intentionally deferred to later vertical slices.

## Rollout and rollback

This foundation intentionally makes PostgreSQL an unconditional runtime dependency. Every environment must provide a valid `BEEBOX_DATABASE_URL` and a reachable database before BeeBox can serve HTTP traffic. Configure the two positive database timeout values only when their defaults do not fit the environment.

Reverting this change restores the previous HTTP-only runtime and static readiness behavior. No data rollback is required because this foundation creates no schema and runs no migration.
