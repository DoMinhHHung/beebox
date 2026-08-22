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
- fresh canonical public request-ID creation;
- authenticated correlation metadata for the Gateway -> Identity hop;
- sanitized forwarding metadata;
- safe structured access logging that omits query strings and secrets;
- bounded pre-dispatch request bodies and bounded upstream/server timeouts;
- liveness and readiness, where readiness depends on the required Identity upstream;
- graceful shutdown and safe canonical upstream failure mapping.

For every public request, Gateway ignores any inbound `X-Request-ID`, removes any client-supplied internal correlation/signature headers, and generates a fresh cryptographically random 16-byte ID rendered as 32 lowercase hexadecimal characters. That ID is the single public `X-Request-ID` for the request. Gateway signs the exact ID with HMAC-SHA256 using the dedicated `BEEBOX_INTERNAL_CORRELATION_KEY` and domain-separated purpose input, then forwards the generated public ID, internal correlation ID and signature to Identity.

The Gateway owns **no product PostgreSQL tables, migration runner, password verification, token trust decision, session authorization, identifier ownership, MFA decision, organization membership decision or RBAC policy**. Network position, possession of a correlation ID, or possession of the internal correlation key is never authentication or authorization evidence.

Client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and related metadata are stripped/reconstructed at the edge. Hop-by-hop headers are not forwarded as application metadata. The Gateway preserves the canonical public method/path/query/body/status/header semantics, including BeeBox security cookies.

Gateway-generated `/v1` failures use the same BeeBox nested error envelope as Identity. Stable edge codes are `request_too_large` for 413, `upstream_unavailable` for 502 and `upstream_timeout` for 504. Safe messages and the canonical request ID are returned without internal hostnames, URLs, credentials, Go/network errors or timeout implementation detail.

### BeeBox Identity Service

Identity Service is independently runnable and owns all currently implemented Phase 1 and Phase 2 identity/authentication/session behavior. That includes application credentials and origins, users and identifiers, password/email/phone/social/passkey authentication, explicit linking/unlinking, TOTP/recovery/reverification, sessions/JWT/JWKS, email links, hosted auth, provider adapters and related audit.

Identity Service exclusively owns the current mutable BeeBox product PostgreSQL state and the existing migration chain. Authentication, identity, MFA and session behavior remain together because current security transitions deliberately share database transactions and concurrency invariants. We will not split them into password, OTP, passkey, social, MFA, token or session services merely to increase service count.

Identity Service still validates application scope, authentication, authorization, Origin, CSRF, redirect and security state itself. Requests arriving from Gateway do not receive elevated product trust.

Identity establishes two distinct observability values at the outer HTTP composition boundary:

1. **Public/wire request ID** — diagnostic-only metadata used for the Identity response `X-Request-ID` and canonical BeeBox `error.request_id`.
2. **Trusted audit correlation** — the correlation value passed into audit-sensitive application behavior. A Gateway candidate may be reused here only when its HMAC proof verifies with the configured dedicated key.

With valid matching Gateway/Identity correlation keys, both values are the Gateway-generated ID `G`. With a complete, well-formed Gateway-style envelope whose signature encoding is canonical but whose HMAC does not verify under the Identity key, Identity retains `G` only as the non-authoritative public/wire diagnostic ID and generates a fresh audit correlation `I`. The public header and canonical error body therefore remain `G`, while audit evidence uses `I`. This split is intentional during a mixed-key rollout and prevents loss of the public support/error identifier without trusting unverified provenance as audit authority.

A direct Identity request, or a malformed/incomplete Gateway-style envelope, cannot select either value through a client `X-Request-ID`. Identity generates a fresh local public request ID and a fresh local audit correlation. Public-ID shape, private network source, `Host`, `X-Forwarded-*` headers or Gateway reachability never establish audit trust. Neither the public request ID nor the audit correlation can grant authentication, tenant, session, MFA or authorization authority.

Wrapper handlers consume trusted audit correlation from request context rather than independently minting competing audit IDs. Public error/request-ID production consumes the distinct public/wire request ID.

### Data ownership

- Gateway has no product database connection and runs no migrations.
- Identity Service exclusively owns current Phase 1/2 product tables and migrations.
- No mutable table may have multiple service owners.
- Cross-service workflows must not use distributed transactions.
- Moving a process boundary alone is not a reason to change schema; this ADR requires no migration.

Future services must own their mutable data exclusively. Stable BeeBox-owned public references are used across service contracts rather than raw PostgreSQL primary keys.

## Service communication and failure semantics

Gateway -> Identity uses ordinary HTTP. gRPC, a message bus, Kafka and service mesh are not required by this boundary.

The Gateway transport has bounded connect, response-header/request and idle-connection lifetimes. Request cancellation propagates to the upstream. Upstream unavailability and timeout map to stable canonical BeeBox edge failures without exposing internal addresses or transport detail.

Gateway server deadlines are service-specific rather than weakening Identity defaults. `ReadHeaderTimeout <= ReadTimeout`, request timeout is bounded to at most 30 seconds, and startup rejects any configuration where `WriteTimeout < ReadTimeout + RequestTimeout + 5s`. The reference defaults are 5s read-header, 10s read, 15s whole-request and 30s write. The write deadline therefore leaves a concrete safety margin for the Gateway to serialize a canonical timeout response instead of letting the socket deadline win first.

Current Phase 1/2 public bodies are bounded API requests, not streaming-upload contracts. Gateway performs a known-length fast rejection when possible and otherwise reads at most `MaxBodyBytes + 1` before dispatch. If the body exceeds the configured limit, Gateway closes it, never calls Identity and returns canonical 413. A body at or below the limit is replayed to the proxy byte-for-byte with bounded memory. A future genuine streaming/upload endpoint requires a separate contract and must not bypass this correctness property.

The Gateway does not automatically retry state-changing `POST`, `PUT`, `PATCH` or `DELETE` requests. A 504 after dispatch does **not** prove that Identity failed to commit: the outcome may be unknown. Clients must not blindly replay a non-idempotent mutation. If the operation supports an idempotency key, the same key must be reused; otherwise the client should reconcile/fetch authoritative state before deciding whether to retry. Operation-specific replay/idempotency contracts remain authoritative.

Identity business errors and security responses remain canonical; the Gateway does not reinterpret application authorization and does not parse/rewrite arbitrary Identity JSON to repair request correlation.

## Internal correlation secret

`BEEBOX_INTERNAL_CORRELATION_KEY` is dedicated observability/transport metadata infrastructure. It is a raw 32-byte high-entropy key encoded as unpadded base64url. Gateway and Identity serving the same topology must normally be configured with the same value, and both fail startup when their required key configuration is absent or malformed.

The key is not reused as a JWT signing key, TOTP encryption key, social OAuth state key, application secret or database credential. It and correlation signatures are never logged or returned publicly. The HMAC authenticates only provenance of trusted audit correlation metadata; it cannot bypass application credentials, sessions, MFA, Origin, CSRF, tenant checks or authorization.

Rotation is a coordinated service rollout concern. Deploy matching key material to both sides of the Gateway/Identity hop. During a temporary mixed-key window, a well-formed Gateway diagnostic envelope keeps its public edge ID `G` stable in the proxied response while Identity rejects `G` as trusted audit provenance and mints `I`. Trace/audit continuity therefore intentionally splits until configuration converges, but the public support/error ID remains internally consistent and no product authority is granted. Operators should restore matching key configuration rather than introducing a permissive unsigned fallback. Do not add a PKI/service mesh solely for this correlation mechanism.

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

Private network placement is defense in depth only. Identity continues to enforce authentication, application/tenant isolation and authorization on every request. The correlation HMAC authenticates only trusted audit-correlation provenance, not the whole service connection. This ADR does not introduce service mesh or mandatory mTLS infrastructure. A deployment that crosses an untrusted network must add an appropriate transport-security design before doing so.

## Observability

Gateway always creates the public edge request ID; a caller cannot select it by supplying `X-Request-ID`. Gateway normalizes proxied responses so exactly one public `X-Request-ID` value is emitted. Identity's canonical error body uses the public/wire request ID already established at the outer Identity boundary, so Gateway does not need to parse/rewrite business JSON.

When Gateway proof verifies, public request ID and trusted audit correlation are equal. When a complete Gateway-style envelope is well formed but its HMAC does not verify, the public request ID remains the Gateway diagnostic value while the trusted audit correlation is fresh and independent. Direct/malformed requests receive fresh Identity public and audit values. This divergence is observability degradation only; correlation never authorizes product behavior.

Logs and metric labels must never contain passwords, OTPs, recovery codes, refresh/access tokens, OAuth authorization codes, provider tokens, signing/encryption/correlation keys, correlation signatures or unbounded query values. Gateway access logs intentionally omit query strings because OAuth/code/state and email-link material may appear there.

## Clean Architecture consequence

The service split is a composition and adapter boundary, not permission to move business rules outward. Domain/application packages remain independent of Gateway, HTTP, SQL and provider SDK types. `internal/gateway` is edge/adapter code. Process entrypoints own concrete wiring. Interfaces are introduced only at real boundaries.

## Rollout and rollback

This refactor requires no destructive schema change. The previous `cmd/beebox` single-process artifact is retained as a compatibility/rollback path while it remains schema-compatible. Rollback is an application deployment action: remove public traffic from Gateway/Identity and restore the previous compatible artifact. Database rollback is not automatic and historical migrations are never rewritten.

If a future schema change prevents application rollback, that release must define expand/contract or roll-forward semantics separately.

## Future extraction criteria

A future bounded context may become another runtime only when an ADR defines concrete ownership, contract, failure behavior, SLO/operability and migration/rollback evidence. Phase 3 Organization/Authorization is one coherent future bounded context; P3.0 defines its contract only and does not create an empty service.

BeeBox continues to forbid service-per-function/handler/table decomposition, shared mutable table ownership and distributed transactions. Kafka, Kubernetes, service mesh, CQRS and event sourcing remain out of scope until separately justified by evidence.

## Consequences

The network hop adds an availability/latency boundary and therefore requires explicit timeout, readiness, observability and failure handling. Bounded pre-dispatch body buffering intentionally trades at most the configured small API-body memory bound for the guarantee that an oversized unknown-length mutation is never partially dispatched. Authenticated correlation adds one dedicated shared secret that must be coordinated operationally but does not become product authority. A brief mixed-key window intentionally splits public diagnostic continuity from trusted audit continuity rather than weakening HMAC verification.

In exchange BeeBox gains independently buildable Gateway and Identity artifacts and a clear public/internal deployment boundary without sacrificing Phase 1/2 transactional correctness.
