# ADR 0008: Gateway and Identity Service deployment boundaries

- Status: accepted
- Date: 2026-08-22
- Human authority: explicit architecture authorization for PR #27

## Context

BeeBox began as a modular monolith because Phase 1 and Phase 2 authentication, identity, MFA and session state need strong transactional consistency and a small implementation surface. The Human has now explicitly authorized a deployment-boundary change to microservices. The goal is not to fragment security behavior; it is to establish one production edge and one independently runnable identity runtime while preserving the already-proven Phase 1/2 correctness boundary.

This ADR supersedes the repository's previous one-deployable default. It does not weaken the tenancy, credential, audit, API, migration or security decisions in ADRs 0001-0007.

## Decision

The initial BeeBox service topology is:

```text
Public clients
     |
     v
BeeBox Gateway
     |
     | bounded HTTP
     v
BeeBox Identity Service
     |
     v
PostgreSQL
```

### BeeBox Gateway

The Gateway is the public HTTP edge. It owns:

- public listener lifecycle;
- routing/reverse proxying to Identity Service;
- request/correlation ID creation or safe propagation;
- sanitized forwarding metadata;
- safe structured access logging that omits query strings and secrets;
- bounded request bodies and bounded upstream transport timeouts;
- liveness and readiness, where readiness depends on the required Identity upstream;
- graceful shutdown and safe upstream failure mapping.

The Gateway owns **no product PostgreSQL tables, migration runner, password verification, token trust decision, session authorization, identifier ownership, MFA decision, organization membership decision or RBAC policy**. Network position is never authentication or authorization evidence.

Client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and related metadata are stripped/reconstructed at the edge. Hop-by-hop headers are not forwarded as application metadata. The Gateway preserves the canonical public method/path/query/body/status/header semantics, including BeeBox security cookies.

### BeeBox Identity Service

Identity Service is independently runnable and owns all currently implemented Phase 1 and Phase 2 identity/authentication/session behavior. That includes application credentials and origins, users and identifiers, password/email/phone/social/passkey authentication, explicit linking/unlinking, TOTP/recovery/reverification, sessions/JWT/JWKS, email links, hosted auth, provider adapters and related audit.

Identity Service exclusively owns the current mutable BeeBox product PostgreSQL state and the existing migration chain. Authentication, identity, MFA and session behavior remain together because current security transitions deliberately share database transactions and concurrency invariants. We will not split them into password, OTP, passkey, social, MFA, token or session services merely to increase service count.

Identity Service still validates application scope, authentication, authorization, Origin, CSRF, redirect and security state itself. Requests arriving from Gateway do not receive elevated trust.

### Data ownership

- Gateway has no product database connection and runs no migrations.
- Identity Service exclusively owns current Phase 1/2 product tables and migrations.
- No mutable table may have multiple service owners.
- Cross-service workflows must not use distributed transactions.
- Moving a process boundary alone is not a reason to change schema; this ADR requires no migration.

Future services must own their mutable data exclusively. Stable BeeBox-owned public references are used across service contracts rather than raw PostgreSQL primary keys.

## Service communication and failure semantics

Gateway -> Identity uses ordinary HTTP. gRPC, a message bus, Kafka and service mesh are not required by this boundary.

The Gateway transport has bounded connect, response-header/request and idle-connection lifetimes. Request cancellation propagates to the upstream. Upstream unavailability and timeout map to stable edge failures without exposing internal addresses or transport detail.

The Gateway does not automatically retry ambiguous state-changing `POST`, `PUT`, `PATCH` or `DELETE` requests. A caller-owned idempotency contract may support a future classified retry, but network ambiguity alone never authorizes replay.

Identity business errors and security responses remain canonical; the Gateway does not reinterpret application authorization.

## Lifecycle and deployment order

Both processes validate required configuration and fail startup rather than silently selecting unsafe fallbacks.

A normal rollout is:

1. apply reviewed Identity-owned migrations using the Identity artifact when a release contains migrations;
2. start/update Identity Service and wait for Identity readiness;
3. start/update Gateway and wait for Gateway readiness;
4. direct public traffic only to Gateway.

Serve mode never implies migration execution. Readiness is a traffic-admission signal, not authorization evidence.

Both processes own graceful shutdown with bounded deadlines. Identity closes PostgreSQL/provider resources; Gateway closes its listener and upstream transport. Cancellation must not create unbounded goroutines.

## Network boundary

Gateway is the public entry point. Identity Service should bind to a loopback/private interface by default and deployment infrastructure must prevent direct Internet exposure. Operators must not expose Identity as an alternate public path around edge controls.

Private network placement is defense in depth only. Identity continues to enforce authentication, application/tenant isolation and authorization on every request. This ADR does not introduce service mesh or mandatory mTLS infrastructure. A deployment that crosses an untrusted network must add an appropriate transport-security design before doing so.

## Observability

Gateway creates or accepts only bounded/syntactically valid correlation identifiers and propagates a trusted value to Identity. Identity's existing request/audit path continues to record minimized correlation evidence where applicable.

Logs and metric labels must never contain passwords, OTPs, recovery codes, refresh/access tokens, OAuth authorization codes, provider tokens, signing/encryption keys or unbounded query values. Gateway access logs intentionally omit query strings because OAuth/code/state and email-link material may appear there.

## Clean Architecture consequence

The service split is a composition and adapter boundary, not permission to move business rules outward. Domain/application packages remain independent of Gateway, HTTP, SQL and provider SDK types. `internal/gateway` is edge/adapter code. Process entrypoints own concrete wiring. Interfaces are introduced only at real boundaries.

## Rollout and rollback

This refactor requires no destructive schema change. The previous `cmd/beebox` single-process artifact is retained as a compatibility/rollback path while it remains schema-compatible. Rollback is an application deployment action: remove public traffic from Gateway/Identity and restore the previous compatible artifact. Database rollback is not automatic and historical migrations are never rewritten.

If a future schema change prevents application rollback, that release must define expand/contract or roll-forward semantics separately.

## Future extraction criteria

A future bounded context may become another runtime only when an ADR defines concrete ownership, contract, failure behavior, SLO/operability and migration/rollback evidence. Phase 3 Organization/Authorization is one coherent future bounded context; P3.0 defines its contract only and does not create an empty service.

BeeBox continues to forbid service-per-function/handler/table decomposition, shared mutable table ownership and distributed transactions. Kafka, Kubernetes, service mesh, CQRS and event sourcing remain out of scope until separately justified by evidence.

## Consequences

The network hop adds an availability/latency boundary and therefore requires explicit timeout, readiness, observability and failure handling. In exchange BeeBox gains independently buildable Gateway and Identity artifacts and a clear public/internal trust boundary without sacrificing Phase 1/2 transactional correctness.
