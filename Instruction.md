# BeeBox Repository Instructions

> Status: engineering constitution and delivery plan.  
> Product benchmark reviewed: Clerk public documentation on 2026-08-16.  
> Applies to every human, AI agent, branch, pull request, service, SDK, migration and deployment unless a newer accepted ADR explicitly overrides a section.

## 1. Product definition

BeeBox is an open-source, developer-first identity and access platform written primarily in Go. It aims to provide the public product capabilities developers expect from Clerk—authentication, user/session management, organizations, authorization, machine identities, webhooks, administration and billing entitlements—through BeeBox-owned contracts and implementation.

“Clerk clone” means **public capability parity as a product benchmark**, not source-code, API, UI, documentation, trademark, asset or proprietary-behavior copying. BeeBox owns its naming, contracts, threat models, implementation, design system and release policy.

### Goals

- Secure defaults for B2C and B2B identity flows.
- Fast local setup and a clear self-hosting path.
- Stable versioned APIs and SDKs, with Go first.
- Headless APIs plus optional hosted/prebuilt UI.
- Strong tenant isolation, auditability, observability and migration safety.
- Explicit bounded-context ownership that can evolve without rewriting identity correctness.

### Non-goals for initial releases

- Bit-for-bit or endpoint-for-endpoint Clerk compatibility.
- A microservice per feature, function, endpoint or table.
- Shared mutable table ownership or distributed transactions.
- Kubernetes, Kafka, service mesh, CQRS, event sourcing or multi-region active-active without measured need and a ratified design.
- Inventing cryptography or authentication protocols.

## 2. Architecture decision: Gateway + bounded-context services

ADR 0008 supersedes the original one-deployable modular-monolith baseline. BeeBox now starts its microservice topology with the **smallest coherent extraction**:

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

### Gateway

`cmd/beebox-gateway` is the public HTTP edge. It owns public listener lifecycle, reverse proxying, canonical public request IDs, authenticated Gateway -> Identity correlation metadata, forwarding-header sanitization, bounded pre-dispatch API bodies, bounded transport/server timeouts, safe access logs, health/readiness and graceful shutdown.

Gateway must ignore client `X-Request-ID`, strip client copies of BeeBox internal correlation/signature headers and generate a fresh cryptographically random 16-byte / 32-lowercase-hex public request ID for every edge request. It signs that generated ID with HMAC-SHA256 using the dedicated `BEEBOX_INTERNAL_CORRELATION_KEY`; Identity may reuse it only after constant-time verification. The public caller receives exactly one `X-Request-ID` value.

Gateway owns **no product database tables, migrations or product authorization**. It never verifies passwords, grants sessions, resolves identifier ownership, performs MFA/RBAC decisions or trusts client forwarding/correlation metadata as authority. Possession of a request ID or the internal correlation key is never application/user/tenant authorization. Gateway must not automatically retry ambiguous state-changing requests.

Gateway-generated canonical `/v1` failures use the same BeeBox nested error envelope as Identity. Stable edge codes are `request_too_large` (413), `upstream_unavailable` (502) and `upstream_timeout` (504); error bodies and response headers use the same canonical request ID and must not expose internal transport detail.

### Identity Service

`cmd/beebox-identity` is the internal Phase 1/2 authority. Identity/authentication/session behavior remains in one service because current correctness paths share security-sensitive PostgreSQL transactions, replay/concurrency invariants and audit boundaries. Identity exclusively owns the current Phase 1/2 mutable PostgreSQL state and migrations.

Identity remains independently responsible for application scope, authentication, authorization, Origin/CSRF/redirect validation and all security-state decisions. Being reachable from Gateway grants no product trust.

Identity establishes correlation once at the outer HTTP composition boundary. A valid-looking direct `X-Request-ID` without authenticated internal proof is not authoritative and must be replaced with a fresh Identity correlation. Phase 1/2 wrapper handlers consume request-context correlation rather than independently creating competing request IDs.

### Service/data ownership rules

- No service-per-function/handler/table decomposition.
- No shared mutable table ownership.
- No distributed transactions.
- Cross-service APIs use stable BeeBox-owned identifiers, never raw PostgreSQL primary keys as public contracts.
- HTTP is sufficient for Gateway -> Identity. Do not add gRPC/message buses for appearance.
- External/internal I/O is bounded by context, timeouts and safe retry semantics.
- Identity should be private/internal by deployment topology; direct Internet exposure is not a supported bypass path.
- PostgreSQL remains correctness authority for owned persistent state. Redis may cache derived state but cannot be required for correctness without an explicit freshness/invalidation design.
- `BEEBOX_INTERNAL_CORRELATION_KEY` is dedicated observability infrastructure: raw 32-byte high-entropy key, unpadded base64url, same value on the serving Gateway/Identity hop, never reused for JWT/TOTP/OAuth/application/database authority, never logged or returned.
- Correlation MAC proves provenance of tracing metadata only. It is not a replacement for transport security on an untrusted internal network.

A future bounded context may become another runtime only when an ADR defines a stable contract, exclusive data ownership, failure modes, SLO/operability, deployment order, migration and rollback. Do not create empty services before the behavior exists. ADR 0009 defines Phase 3 Organization/Authorization as one coherent future bounded context; P3.0 is contract-only.

## 3. Clean Architecture rules

Clean Architecture is a dependency rule, not a folder-count target.

- **Domain:** entities, policies, state machines and invariants. No HTTP, SQL, queue, vendor SDK, environment or framework imports.
- **Application:** use cases/orchestration. Depends inward and owns transaction/authorization intent plus stable errors.
- **Ports:** interfaces only at real I/O, clock/random/crypto or provider boundaries. No interface per struct.
- **Adapters:** HTTP, PostgreSQL, provider SDK/protocol, telemetry and Gateway edge code depend inward.
- **Composition:** process startup, concrete wiring, configuration, lifecycle, migrations and shutdown.

Public API/event models never double as database/vendor models. Vendor types do not cross BeeBox public boundaries. Existing good package boundaries stay in place when moving files would only create churn.

Current layout direction:

```text
cmd/beebox-gateway/           public edge process
cmd/beebox-identity/          Phase 1/2 Identity process
cmd/beebox/                   compatibility/rollback operator path while schema-compatible
internal/gateway/             edge proxy/configuration adapter
internal/platform/            config, database, HTTP lifecycle, crypto primitives
internal/identity/            users, identifiers, profiles
internal/authentication/      signup/signin, factors, linking, recovery, reverification
internal/session/             sessions, tokens, refresh/revocation
internal/audit/               security audit behavior
api/openapi/                  versioned public HTTP contract
sdk/go/                       maintained Go SDK
migrations/                   Identity-owned ordered migrations
docs/adr/                     architecture decisions
docs/contracts/               language-neutral contracts
docs/threat-model/            threat models/deltas
```

Future organization/authorization, machine-auth, webhook and billing packages/runtimes appear only with implemented behavior and explicit ownership; do not create empty scaffolding.

## 4. Capability inventory

This is a product benchmark/roadmap, not a claim that every capability ships today. Each shipped capability needs configuration, public contract, persistence/ownership, authorization, validation, failure semantics, audit/observability, tests, documentation and deletion/revocation lifecycle where applicable.

### 4.1 Applications and environments

- Application/instance isolation, credentials, rotation/revocation and allowed origins/redirects/domains.
- Environment-specific authentication/session/organization/security/provider/branding policy.
- Admin views, application logs, safe redaction, production-readiness checks and controlled import/export.

### 4.2 Sign-up, sign-in and verification

- Email/phone/password, OTP, email links, social OAuth/OIDC, explicit account linking/unlinking.
- Passkeys/WebAuthn, MFA, recovery codes, factor reset and step-up/reverification.
- Configurable verification, account-linking rules, registration modes, invitations/tickets and abuse defenses.
- Enterprise SAML/OIDC and directory provisioning only in later ratified phases.
- Every primary proof must preserve enumeration resistance, rate/attempt budgets, replay prevention and tenant scope.

### 4.3 User management

- User CRUD/list/search with bounded pagination, profile/avatar/locale/external ID and timestamps.
- Multiple identifiers with verification/primary semantics.
- Linked providers/passkeys/factors/session administration.
- Metadata only with explicit visibility/size policy.
- Lock/ban, deletion/export/retention and support impersonation with actor/subject audit.

### 4.4 Sessions and tokens

- Session create/list/touch/refresh/revoke/expire with explicit inactivity/absolute lifetime.
- Secure cookies and bearer transport, CSRF/authorized-origin protections.
- Short-lived signed JWTs/JWKS, key rotation and strict issuer/audience/time validation.
- Reverification for sensitive operations and explicit revocation/freshness limits.

### 4.5 Organizations and B2B identity

- Organizations, memberships, active organization, invitations and verified domains.
- Default/custom roles, fine-grained permissions and default-deny server authorization.
- Organization-scoped Enterprise SSO/directory sync only after its own trust/ownership contracts.
- Organization UI/API/SDK flows after P3 runtime contracts stabilize.

ADR 0009 and `docs/contracts/phase3-organization-authorization.md` are the P3.0 baseline. `application_instance` remains the root tenant boundary; organization is additional scope.

### 4.6 Authorization and entitlements

- Subject/resource/action/scope authorization for users, organizations, machines and support actors.
- Application-owned role/permission vocabulary with authoritative membership state.
- UI visibility is never an authorization control.
- Feature definitions do not automatically equal paid entitlements.
- Mutable authorization claim freshness, cache invalidation and permission-change propagation require explicit design.

### 4.7 Machine authentication and OAuth platform

- User/org API keys, machine identities and M2M tokens with scopes, expiry, rotation/revocation and audit.
- OAuth applications/authorization server behavior only through versioned contracts with PKCE, consent, scopes, introspection/revocation as required.

### 4.8 APIs, SDKs, UI and developer experience

- Versioned Frontend/Backend APIs, stable IDs/errors/pagination/idempotency/deprecation.
- Go SDK first; frontend/other SDKs follow stable contracts.
- Headless primitives plus hosted/prebuilt surfaces, theming/localization and safe redirect/legal/support configuration.
- Quickstarts, examples, upgrade guides and reproducible generation.

### 4.9 Webhooks, events, audit and logs

- Versioned events, signed webhooks, bounded retry/replay and idempotency.
- Transactional outbox only when asynchronous committed-state delivery is actually introduced.
- Security/admin audit with minimized actor/subject/application/organization/action/resource/result/time/correlation evidence.

### 4.10 Billing

- B2C/B2B plans/features/subscriptions, checkout/trials/discounts/seats/entitlements and a provider adapter only in the billing phase.
- Payment/provider state never silently becomes identity correctness authority.

### 4.11 Operations

- Health/readiness, bounded graceful shutdown, structured safe logs, metrics/traces/correlation, SLOs/alerts/runbooks.
- Backups/restores, key/secret rotation, migration safety, retention/deletion and incident response.
- Advanced multi-region/compliance only after explicit residency/consistency/recovery requirements.

## 5. Core domain and security invariants

These are merge-blocking:

- Every resource belongs to an explicit application and, where applicable, organization. Server-side queries enforce scope.
- Authentication proves identity; authorization independently decides access. Never trust client tenant/user/owner/role/permission/entitlement fields.
- Public resource IDs are locators only.
- Verified identifiers are normalized consistently and protected by database constraints. Equality never implicitly links principals.
- Password/OTP/token/key/recovery secrets use reviewed primitives/libraries and cryptographic randomness. Store derived/hashed/encrypted forms according to lifecycle; never log secrets.
- PII is minimized/redacted in logs, metrics, traces, events, fixtures and errors.
- Tokens validate an allowlisted algorithm, signature, issuer/audience/authorized party and time claims with explicit rotation/revocation limitations.
- Security mutations define validation, uniqueness, idempotency, replay, concurrency and transaction behavior.
- Important relational invariants use PostgreSQL constraints/serialization, not application pre-checks alone.
- Security-sensitive required audit stays in the correctness transaction.
- Provider/network failure maps to stable safe errors and never leaks vendor/internal detail.
- All I/O propagates context and has bounded resources/timeouts; ambiguous mutations are not blindly retried.
- Gateway `/v1` edge failures remain canonical BeeBox errors: nested envelope, stable 413/502/504 codes, safe messages and matching request-ID header/body.
- A Gateway 504 after dispatch does not prove a state-changing operation failed to commit. Clients reuse the same supported idempotency key or reconcile authoritative state before retrying.
- Current bounded API request bodies are validated before upstream dispatch, including unknown/chunked lengths. An oversized body must not partially reach Identity.
- Request/correlation IDs are observability only and cannot influence authorization or tenant scope.

Use standard Go cryptography and established OAuth/OIDC/WebAuthn/SAML/JWT guidance as applicable; never invent cryptographic primitives.

## 6. Data, APIs and events

- PostgreSQL is the initial source of truth for each owning service.
- A mutable table has one service owner.
- Historical merged migrations are never rewritten. New migrations are ordered and rolling/rollback-safe; breaking evolution uses expand/contract.
- Repositories expose domain-oriented operations, not generic CRUD abstractions.
- Public HTTP APIs use explicit versions such as `/v1`; machine-readable error codes remain stable and separate from safe messages.
- Lists are bounded/paginated/deterministically ordered and cursors are tenant-scoped.
- Public/event/schema contracts are language-neutral and versioned. Never change an existing field/event meaning in place.

## 7. Reliability, performance and observability

- Correctness first; optimize from a measured workload.
- Propagate `context.Context`; close rows/bodies/timers/connections/goroutines.
- Bound payloads, pagination, queues, retries, fan-out, caches and concurrency.
- Retry only classified transient and safe/idempotent work, with bounded backoff when appropriate.
- Metrics labels have bounded cardinality. Logs/traces carry safe correlation identifiers, never credentials.
- Gateway server deadlines are service-specific: read timeout must cover read-header timeout and write timeout must remain after read + whole-request timeout with an explicit safety margin. Invalid ordering fails startup; do not weaken Identity server defaults to make Gateway timeouts work.
- For bounded Phase 1/2 API bodies, pre-dispatch buffering is intentional correctness behavior. Future streaming/upload endpoints require a separate contract and resource model.
- Performance claims require benchmarks/profiles/query plans/load evidence.

## 8. Testing strategy

Tests are risk-based:

- domain/application unit tests for state/invariants/authorization;
- PostgreSQL integration for constraints, transactions, migrations and races;
- API/SDK/provider contract tests;
- Gateway -> owning service -> PostgreSQL integration for critical public journeys;
- negative/unauthorized/cross-tenant/replay/expiry/partial-failure/concurrency cases;
- Go race tests and fuzz/property tests where useful.

Gateway boundary tests must cover client request-ID/internal-header spoofing, authenticated correlation provenance, direct-Identity invalid-proof fallback, exactly-one public request ID, canonical SDK-decodable 413/502/504, actual-server timeout/deadline behavior, mutation-outcome ambiguity without automatic retry, and unknown/chunked body-limit exact-boundary/cancellation/cleanup behavior.

Repository CI must run on the exact current head. Current required checks include formatting, independent Gateway/Identity builds, Docker/Compose topology validation, vet, `govulncheck`, OpenAPI, Go SDK, social-provider stress/race checks, `go test ./...`, PostgreSQL 17 integration including Gateway and full `go test -race ./...`.

## 9. Phased delivery

### Phase 0 — Repository/contracts
Go module, lifecycle, config, health, PostgreSQL, migrations, CI and conventions.

### Phase 1 — B2C core
Application isolation/credentials, users/email/password, sessions/JWT/JWKS, refresh/revoke, OpenAPI and Go SDK.

### Phase 2 — Passwordless/social/MFA/self-service
Email/phone OTP and links, social OAuth/linking, passkeys, TOTP/recovery, reverification, session/account self-service, hosted/headless baseline and hardening.

### Phase 3 — Organizations and authorization
P3.0 contract first; later vertical slices implement organizations, memberships, invitations, active organization, domains, roles, permissions, authorization helpers and B2B surfaces. Do not implement runtime beyond the authorized slice.

### Phase 4 — Enterprise and machine identity
Enterprise SSO/directory provisioning, API keys, machine identities, M2M and OAuth platform.

### Phase 5 — Webhooks/admin/operational maturity
Transactional event delivery when needed, webhook/audit/admin workflows, retention/export/deletion, restore/SLO/alert exercises.

### Phase 6 — Billing and further justified bounded-context extraction
Billing/entitlements plus additional service extraction only where ownership/scale/isolation/deploy evidence satisfies Section 2.

Each PR should normally be a smallest complete vertical outcome. A Human may explicitly authorize a larger architectural PR; that authorization does not relax security/data/test gates.

## 10. PR workflow

1. Personalization Router inspects actual remote state and creates task-specific Supervisor/Checker prompts.
2. Implementer/Supervisor works from actual `main`, repository instructions and task packet, creates or updates only the authorized branch/Draft PR, verifies locally/CI and hands evidence off.
3. Checker independently verifies current-head scope, acceptance, security, tests, reviews and mergeability and returns `ALLOW`, `DO NOT MERGE` or `BLOCKED`.
4. Human alone performs the authorized Ready/merge action.
5. Main Branch Inspector audits exact merged state when requested.

Never push feature work directly to `main`, force-push without explicit authority, hide CI failures or merge from an implementation role.

A PR body records Summary/Why/Scope/Non-goals/Design/Security & tenant impact/API-data-migration impact/Tests & exact results/Rollout/Rollback/Risks/Follow-ups.

## 11. Definition of Done

A change is done only when behavior/non-goals are explicit; domain/security/tenant invariants are enforced; contracts/docs/generated artifacts are current; risk-appropriate happy/negative/authz/tenant/concurrency/failure tests pass; secrets/PII/audit are safe; timeout/retry/idempotency/cleanup behavior is defined; rollout/rollback are credible; required checks pass on final head; and independent Checker evidence has no blocking finding before Human merge.

“Handler exists”, “UI renders”, “CI green” and “works on my machine” are not definitions of done by themselves.

## 12. Decision priority and change control

Prioritize:

1. correctness and tenant/data integrity;
2. security/privacy/reliability as release gates;
3. simplest complete ownership/transaction design;
4. maintainability and explicit contracts;
5. developer experience;
6. performance after measurement.

Changes to product identity, tenant model, account-link semantics, token trust boundary, public compatibility policy, mutable data ownership or service/deployment trust boundaries require an ADR and explicit maintainer/Human authority. ADR 0008 is the authorized record for the current microservice transition. Agents must surface future conflicts rather than quietly reinterpreting this document.
