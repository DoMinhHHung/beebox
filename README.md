# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime foundation only. Product capabilities such as users, authentication, sessions, organizations, and persistence are not implemented yet.

## Prerequisites

- Go 1.26.x
- Git

The module declares Go 1.26.0 as its minimum supported Go version.

## Run locally

Start BeeBox with the default configuration:

    go run ./cmd/beebox

The HTTP server listens on `:8080` by default.

## Configuration

### BEEBOX_HTTP_ADDR

Address used by the HTTP server.

Default:

    :8080

Example:

    BEEBOX_HTTP_ADDR=127.0.0.1:9090 go run ./cmd/beebox

The value must contain a valid numeric TCP port.

### BEEBOX_SHUTDOWN_TIMEOUT

Maximum amount of time allowed for graceful HTTP shutdown.

Default:

    10s

The value uses Go duration syntax and must be greater than zero.

Example:

    BEEBOX_SHUTDOWN_TIMEOUT=5s go run ./cmd/beebox

## Health endpoints

### Liveness

    GET /health/live

Successful response:

    {"status":"ok"}

Liveness indicates that the BeeBox process is running and able to serve HTTP requests.

### Readiness

    GET /health/ready

Successful response:

    {"status":"ready"}

For this initial runtime, readiness means startup configuration completed successfully and the HTTP process can serve requests.

There is currently no database, Redis, external provider, migration system, or background worker, so this endpoint does not claim to verify those dependencies.

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

## Current scope

This bootstrap contains:

- one Go process;
- startup configuration validation;
- structured logging with `log/slog`;
- explicit HTTP server timeouts;
- graceful SIGINT and SIGTERM shutdown;
- bounded shutdown timeout;
- liveness and readiness endpoints;
- focused automated tests;
- minimal GitHub Actions CI.

Identity product capabilities and infrastructure integrations are intentionally deferred to later vertical slices.
