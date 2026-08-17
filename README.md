# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime, PostgreSQL connection, explicit migration runner, Phase 0 governance/contracts baseline, and the first Phase 1 persistence boundary: the internal `application_instance` isolation root. Users, credentials, authentication, sessions, organizations, and public product APIs are not implemented yet.

## Project documentation

- [Repository instructions](Instruction.md) — product, architecture, security, data, testing, delivery, and change-control invariants.
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md) — the Human-ratified v1 root product isolation decision and its intentionally unresolved public-ID boundary.
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

Current migrations are:

- `00001_runtime_baseline.sql` — anchors forward migration history without product schema/data;
- `00002_application_instances.sql` — additively creates the first product table, `application_instances`, with a database-internal generated identity and `timestamptz` creation time.

The database identity in `application_instances.id` is an internal persistence detail. It is not a permanent public BeeBox application-instance identifier and no public product API exists in this slice.

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

PostgreSQL integration tests (require a real disposable test database and never skip when selected):

    BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' go test -tags=integration ./internal/platform/database ./internal/platform/migration ./internal/applicationinstance/postgres

Regular and race tests do not require a local PostgreSQL instance. GitHub Actions provisions an isolated PostgreSQL service and runs the integration command explicitly.

## Current scope

The repository currently contains:

- one Go process;
- startup configuration validation and structured logging;
- explicit HTTP server timeouts and graceful shutdown;
- one process-owned PostgreSQL pool with deterministic cleanup;
- bounded PostgreSQL connectivity verification before HTTP startup;
- process-only liveness and PostgreSQL-aware readiness endpoints;
- an explicit, embedded, forward-only PostgreSQL migration mode;
- transactional migrations serialized by a bounded advisory lock;
- the `application_instances` root product-isolation table;
- a minimal BeeBox-owned internal application-instance model;
- a concrete PostgreSQL persistence primitive that creates and exactly resolves trusted internal application-instance scope;
- integration evidence that two root instances remain distinguishable and missing/invalid scope does not fall through to another row;
- Phase 0 threat-model, contract-convention, contribution, and security-reporting documentation;
- ADR 0001 recording the v1 application-instance root decision.

There are still no application credentials, users, identifiers, authentication, authorization, sessions/tokens, organization resources, child product resources, public application-instance identifiers, public product routes, OpenAPI product contracts, SDKs, Redis, queues, or product audit subsystem. The internal `Create` persistence primitive is not a reachable application/admin creation lifecycle and does not by itself claim public idempotency, authorization, or audit completeness.

Application-instance rows are durable roots in this slice. No delete or soft-delete lifecycle is defined. Backup/restore must preserve their internal identity and future referential meaning; deletion/retention semantics belong to the first real lifecycle that needs them.

## Rollout and rollback

This foundation intentionally makes PostgreSQL an unconditional runtime dependency. Every environment must provide a valid `BEEBOX_DATABASE_URL` and a reachable database before BeeBox can serve HTTP traffic.

For a reviewed release, run the exact binary or immutable image being promoted with `migrate` and a migration-capable credential before starting code that depends on the new table. Normal no-argument serve mode still does not auto-migrate.

BeeBox production migration policy is forward-only. Before production product data depends on `application_instances`, code can be reverted while the additive table remains harmless. Once later rows reference the root, destructive database rollback is not automatic; corrections use reviewed roll-forward migrations and expand/contract sequencing.
