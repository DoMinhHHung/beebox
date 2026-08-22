# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go. Clerk's public product capabilities are a benchmark only; BeeBox owns its contracts, identifiers, persistence model, security boundaries and implementation.

BeeBox now runs the initial microservice topology ratified by ADR 0008:

```text
Public client
    |
    v
+------------------+
| BeeBox Gateway   |  public edge, no product DB
+------------------+
    |
    | bounded HTTP
    v
+-----------------------+
| BeeBox Identity       |  Phase 1 + Phase 2 authority
| Service               |
+-----------------------+
    |
    v
PostgreSQL
```

`application_instance` remains the root isolation boundary. The service split changes deployment/composition, not the public Phase 1/2 security contract.

## Runtime ownership

### BeeBox Gateway

`cmd/beebox-gateway` is the normal public HTTP process. It reverse-proxies the canonical BeeBox API to Identity Service, creates/propagates bounded request IDs, reconstructs trusted forwarding metadata, applies request/upstream bounds, emits safe access logs, reports liveness/readiness and shuts down gracefully.

Gateway does **not** connect to the product database, run migrations, verify passwords, decide session/token authority, perform MFA/RBAC checks or resolve tenant/user ownership. It does not automatically retry ambiguous state-changing requests.

### BeeBox Identity Service

`cmd/beebox-identity` owns all currently merged Phase 1/2 behavior and mutable PostgreSQL state: application credentials/origins, users/identifiers/profile, password/email/phone/social/passkey authentication, explicit linking, TOTP/recovery/reverification, sessions/JWT/JWKS, email links, hosted auth, providers and related audit.

Identity keeps these behaviors together because their correctness paths share security-sensitive PostgreSQL transactions and concurrency/replay invariants. It also owns the existing migration chain. Identity must remain private/internal in deployment, but it still enforces authn/authz/tenant/Origin/CSRF/redirect rules itself; Gateway network position is never authorization evidence.

`cmd/beebox` is retained only as a schema-compatible migration/rollback compatibility path during this transition. New public topology uses Gateway + Identity.

## Current B2C capability

Phase 1/2 currently provides application-scoped:

- email/password signup, verification, reset and sign-in;
- email OTP and secure email sign-in links;
- phone-first signup and verified-phone OTP;
- social OAuth/OIDC for the ratified provider vocabulary plus explicit linking/unlinking;
- Passkeys/WebAuthn;
- TOTP MFA, recovery codes and protected replacement;
- purpose/session-bound reverification;
- rotating sessions, self-service session inventory/revocation, JWT/JWKS;
- identifier/profile self-service with ownership and last-method safeguards;
- minimal hosted authentication with Origin/CSRF/CSP/redirect/cookie hardening;
- OpenAPI and the maintained Go SDK.

BeeBox does not claim principal merge, cross-application identity transfer, Enterprise SSO/SCIM, OAuth authorization-server behavior, billing, remembered-device risk scoring, global JWT denylisting or compliance certification unless a later phase explicitly implements them.

## Security invariants

- `application_instance` is the root tenant boundary; organization is additional scope, never a replacement.
- Public IDs are locators only. Authentication does not replace authorization.
- Identifier equality never implicitly links/adopts/transfers principals.
- PostgreSQL constraints/transactions remain the current correctness authority for ownership, uniqueness, replay, admission and security-state mutation.
- Gateway has no product DB authority and direct Identity exposure must not be used to bypass the public edge.
- Active TOTP blocks ordinary session/access/refresh issuance until MFA completes.
- Sensitive mutations use explicit reverification where required.
- Browser refresh credentials remain in hardened app-specific `__Host-` cookies and are not duplicated into JSON.
- Secrets/codes/tokens are not intentionally logged or persisted plaintext outside their permitted lifecycle. Query strings are omitted from Gateway access logs because OAuth/email-link material may appear there.
- Provider/network I/O is bounded; ambiguous mutations are not blindly retried.

## Phase 3.0 baseline

P3.0 is contract/ADR only. It does **not** implement organization tables, handlers or a new service.

ADR 0009 ratifies:

- `application_instance` as root tenancy;
- application-scoped organizations with opaque stable IDs and scoped slugs;
- same-application membership authority;
- session/request-scoped active organization rather than a global user field;
- application-owned default/custom role vocabulary and membership assignment;
- stable permissions with default-deny subject/resource/action/scope evaluation;
- feature definitions separate from billing entitlements;
- authoritative persisted authorization state until a separate JWT/cache freshness policy exists;
- transactional minimized security audit;
- one future Organization/Authorization bounded context with exclusive mutable data ownership.

See `docs/contracts/phase3-organization-authorization.md`.

## Documentation

- [Repository instructions](Instruction.md)
- [ADR 0008: Gateway and Identity deployment boundaries](docs/adr/0008-gateway-identity-microservices.md)
- [ADR 0009: Phase 3 organization/authorization baseline](docs/adr/0009-phase3-organization-authorization.md)
- [P3.0 organization/authorization contract](docs/contracts/phase3-organization-authorization.md)
- [Microservice threat-model delta](docs/threat-model/microservices.md)
- [Microservice operations/runbook](docs/microservices-operations.md)
- [General contract/tenancy conventions](docs/contracts/conventions.md)
- [Phase 2 exit evidence](docs/phase2-exit.md)
- [Production operations](docs/production-operations.md)
- [OpenAPI v1](api/openapi/v1.yaml)
- [Go SDK](sdk/go)

Earlier ADRs 0001-0007 and Phase 2 threat models remain authoritative for the behavior they ratified.

## Prerequisites

- Go 1.26.x
- Git
- Docker with Compose for the reference multi-process topology

## Local microservice quickstart

The reference Compose topology contains `gateway`, `identity`, PostgreSQL 17 and Mailpit. Only Gateway (`localhost:8080`) and Mailpit UI (`localhost:8025`) are host-published. Identity and PostgreSQL are private to the Compose network.

First apply migrations with the Identity artifact:

```sh
docker compose run --rm identity migrate
```

Generate Ed25519 signing material. The private key is intentional one-time output; keep it outside source control and logs:

```sh
docker compose run --rm identity generate-signing-key
```

Export the returned values so Compose passes them only to Identity:

```sh
export BEEBOX_ISSUER='https://auth.example.test'
export BEEBOX_SIGNING_KID='<kid>'
export BEEBOX_SIGNING_PRIVATE_KEY='<private_key>'
export BEEBOX_SIGNING_PUBLIC_KEY='<public_key>'
```

Then start the topology:

```sh
docker compose up --build
```

Public probes:

```sh
curl -fsS http://localhost:8080/health/live
curl -fsS http://localhost:8080/health/ready
```

Gateway readiness reflects required Identity availability. Identity readiness remains database-aware. Startup ordering is not authorization evidence and does not replace readiness.

Bootstrap a local application through the Identity operator command:

```sh
docker compose run --rm identity bootstrap-application http://localhost:3000
```

Save the emitted application/publishable/secret credentials outside source control.

### Local email capture

Mailpit UI is published on `http://localhost:8025`, but containerized Identity is intentionally not configured to send plaintext SMTP to `mailpit:1025`: BeeBox's `insecure_localhost` SMTP mode is loopback-only by design.

For local email-flow testing either:

1. run Identity on the host with `BEEBOX_SMTP_ADDR=127.0.0.1:1025`, `BEEBOX_SMTP_FROM=beebox@example.test`, `BEEBOX_SMTP_TLS_MODE=insecure_localhost`; or
2. configure Identity with a TLS/STARTTLS-capable SMTP endpoint.

Do not weaken the SMTP trust rule just for container convenience.

## Running processes without Compose

Migrate and run Identity:

```sh
export BEEBOX_DATABASE_URL='postgres://...'
export BEEBOX_IDENTITY_HTTP_ADDR='127.0.0.1:8081'
go run ./cmd/beebox-identity migrate
go run ./cmd/beebox-identity
```

Then run Gateway:

```sh
export BEEBOX_GATEWAY_HTTP_ADDR=':8080'
export BEEBOX_IDENTITY_UPSTREAM_URL='http://127.0.0.1:8081'
go run ./cmd/beebox-gateway
```

`BEEBOX_HTTP_ADDR` remains a compatibility alias for Identity; explicit `BEEBOX_IDENTITY_HTTP_ADDR` wins. Existing provider/database/signing/encryption configuration belongs to Identity, not Gateway.

## Gateway configuration

Required:

- `BEEBOX_IDENTITY_UPSTREAM_URL` — absolute `http`/`https` Identity base URL without userinfo/query/fragment/base path.

Optional validated bounds:

- `BEEBOX_GATEWAY_HTTP_ADDR` (default `:8080`)
- `BEEBOX_GATEWAY_CONNECT_TIMEOUT` (default `3s`)
- `BEEBOX_GATEWAY_RESPONSE_HEADER_TIMEOUT` (default `10s`)
- `BEEBOX_GATEWAY_REQUEST_TIMEOUT` (default `15s`)
- `BEEBOX_GATEWAY_READINESS_TIMEOUT` (default `2s`)
- `BEEBOX_GATEWAY_SHUTDOWN_TIMEOUT` (default `10s`)
- `BEEBOX_GATEWAY_IDLE_CONN_TIMEOUT` (default `60s`)
- `BEEBOX_GATEWAY_MAX_BODY_BYTES` (default 1 MiB; bounded maximum 16 MiB)

Invalid required configuration fails startup rather than silently selecting an unsafe fallback.

## Identity configuration and migrations

Identity uses the existing BeeBox database/provider/signing/encryption settings. `BEEBOX_IDENTITY_HTTP_ADDR` defaults to `127.0.0.1:8081`. Existing `BEEBOX_HTTP_ADDR` is preserved for compatibility.

Serve mode does not auto-migrate. Migrations are explicitly run by Identity and historical merged migration files are not rewritten. ADR 0008 itself needs no schema migration.

TOTP encryption remains fail-closed: if persisted TOTP ciphertext references a key, the configured keyring must contain that key before Identity can start serving the affected state.

## Primary authentication and browser transport

Canonical headless primary proofs include password, email OTP, phone OTP, social OAuth/OIDC, Passkeys and email links. If active TOTP exists, successful primary proof produces pending-MFA authority only until TOTP or accepted recovery-code completion.

Browser requests carrying an allowed Origin receive refresh authority through a hardened application-specific `__Host-beebox-refresh-*` cookie (`Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Strict`). Gateway preserves the Identity `Set-Cookie`; it must not convert the secret back into JSON.

Non-browser token transport follows the existing public contract. Origin, CSRF, redirect and account-linking semantics remain owned by Identity.

## Sessions and self-service

Access JWTs are short-lived Ed25519 tokens. Refresh credentials rotate and remain application/session scoped. Current-user session inventory is bounded and minimizes device/IP metadata. Server-side revocation is immediate for persisted session authority; already-issued offline JWT verification remains bounded by the documented token lifetime.

Reverification grants are one-time and bound to the exact application, user, target session and purpose. Client resource IDs never create authority.

## Hosted authentication

Hosted auth is a first-party client of canonical headless behavior, not a separate identity implementation. It keeps exact Origin/CSRF/redirect checks, restrictive CSP/no-store/no-referrer headers, scanner-safe email-link consumption and hardened cookies.

Set `BEEBOX_HOSTED_AUTH_ORIGIN` only to an exact canonical trusted origin. Arbitrary tenant HTML/CSS/JavaScript remains out of scope.

## Optional providers and TOTP keys

SMS is disabled by default and selects exactly one configured provider; incomplete selected-provider configuration fails startup and ambiguous sends are not cross-provider retried.

Social connections use the strict `BEEBOX_SOCIAL_CONNECTIONS` configuration and BeeBox-owned protocol flow. Provider access/refresh/ID tokens stay adapter-local and are not BeeBox credentials. Provider email equality does not link principals.

TOTP secrets use the configured bounded encryption keyring:

```sh
export BEEBOX_SECRET_ENCRYPTION_KEYS='<key-id>:<base64url-raw-32-byte-key>'
export BEEBOX_SECRET_ENCRYPTION_ACTIVE_KEY_ID='<key-id>'
```

Rotation is additive; retain historical keys while persisted ciphertext references them.

## Rollout and rollback

For a release with migrations: apply Identity-owned migrations, deploy/verify Identity readiness, then deploy/verify Gateway and send public traffic to Gateway. Never expose Identity publicly because Gateway is unhealthy.

This refactor adds no destructive schema change. While schema compatibility remains intact, rollback can restore the previous `cmd/beebox` application artifact. Do not use destructive automatic down migrations. See the microservice runbook for failure handling.

## Verification

Repository CI validates:

```sh
go build ./cmd/beebox-gateway
go build ./cmd/beebox-identity
go vet ./...
govulncheck ./...
go test ./api/openapi
go test ./sdk/go
go test ./...
go test -race ./...
```

CI also runs repeated social-provider contract/race tests, the full PostgreSQL 17 integration suite including `./internal/gateway`, `docker compose config`, topology ownership assertions and independent Docker builds for both service targets.

Phase 1/2 security coverage remains required after the service split; architecture does not justify deleting or weakening old tests.
