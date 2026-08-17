# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime, PostgreSQL connection, explicit migration runner, Phase 0 governance/contracts baseline, the v1 `application_instance` root isolation boundary, and the first application-scoped internal user persistence slice. Users currently have no identifiers, profile data, credentials, authentication, authorization, sessions, organizations, or public product API.

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

### BEEBOX_DATABASE_STARTUP_TIMEOUT

Maximum time allowed to create the PostgreSQL pool and prove connectivity before startup fails.

Default:

    5s

### BEEBOX_DATABASE_READINESS_TIMEOUT

Maximum time allowed for each PostgreSQL readiness check.

Default:

    1s

### BEEBOX_DATABASE_MIGRATION_TIMEOUT

Maximum total time allowed for migration lock acquisition and forward migration execution.

Default:

    30s

The duration values use Go duration syntax and must be greater than zero.

## Migration policy

SQL migrations are compiled into the BeeBox binary and cannot be selected from a runtime filesystem, URL, argument, or environment value. The runner applies only `Up`, executes default SQL migrations transactionally, and serializes concurrent runners with a PostgreSQL same-session advisory lock.

Applied migration files are immutable. New database changes use new ordered versions and rolling-safe expand/contract sequencing. Production operations do not expose `Down`, reset, redo, force, manual version overrides, or arbitrary SQL.

Current migrations are:

- `00001_runtime_baseline.sql` — anchors forward migration history without product schema/data;
- `00002_application_instances.sql` — creates the `application_instances` root table with an internal generated identity and `timestamptz` creation time;
- `00003_users.sql` — creates the minimal `users` child table with an internal generated identity, mandatory `application_instance_id` foreign key, and `timestamptz` creation time.

The database identities in `application_instances.id` and `users.id` are internal persistence details. They are not permanent public BeeBox resource identifiers, and no public product API exists in this slice.

Use separate credentials where possible:

- migration mode receives a short-lived credential allowed to perform reviewed DDL;
- serve mode receives a least-privilege runtime credential and never needs migration privileges merely to start.

Migration failures, connectivity failures, lock timeouts, and cancellation exit nonzero, close acquired resources, do not open an HTTP listener, and report stable errors without SQL, provider, topology, or credential details.

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

PostgreSQL integration tests (require a real disposable test database and never skip when selected):

    BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' go test -tags=integration ./internal/platform/database ./internal/platform/migration ./internal/applicationinstance/postgres ./internal/identity/postgres

Regular and race tests do not require a local PostgreSQL instance. GitHub Actions provisions an isolated PostgreSQL service and runs the integration command explicitly.

## Current scope

The repository currently contains:

- one Go process;
- startup configuration validation and structured logging;
- explicit HTTP server timeouts and graceful shutdown;
- one process-owned PostgreSQL pool with deterministic cleanup;
- bounded PostgreSQL startup/readiness behavior;
- explicit embedded forward-only migrations serialized by an advisory lock;
- the `application_instances` v1 root product-isolation table and internal persistence model;
- concrete application-instance `Create` and exact trusted-scope `Resolve` persistence;
- the `users` table as the first child product table, with mandatory `application_instance_id` foreign-key scope;
- a minimal BeeBox-owned internal user model containing only internal identity, application-instance scope, and creation time;
- concrete scoped user `Create` and `Resolve(applicationScope, userID)` persistence;
- PostgreSQL integration evidence that a user from application A does not resolve under application B, missing/invalid scope cannot fall through, foreign keys prevent orphan users, and concurrent inserts retain unique generated identities;
- Phase 0 governance/security/contracts documentation and ADR 0001.

The user persistence surface is internal only. It does **not** implement user management, authentication, authorization, public creation, public IDs, email/phone/username identifiers, profile data, credentials, sessions/tokens, organizations, or a product audit subsystem. The store does not define how a future HTTP/client caller obtains a trusted application scope.

User rows are durable application-scoped identity records in this slice. No deletion, anonymization, or retention lifecycle is defined. Backup/restore must preserve user/application-instance relationships and internal identities; the first real user lifecycle that needs deletion must define retention, downstream cleanup, and referential behavior before claiming completion.

Phase 1 remains incomplete.

## Rollout and rollback

No hosted database mutation is performed by repository changes alone. For a reviewed release, run the exact promoted binary/image with `migrate` and a migration-capable credential before starting code that depends on `users`. Normal serve mode still does not auto-migrate.

BeeBox production migration policy is forward-only. Before production data depends on the additive `users` table, code can be reverted while the schema remains harmless. Once data depends on it, schema correction uses a reviewed forward migration; destructive rollback is not automatic.
