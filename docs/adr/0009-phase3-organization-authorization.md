# ADR 0009: Phase 3 organization and authorization contract baseline

- Status: accepted
- Date: 2026-08-22
- Human authority: P3.0 contract authorization for PR #27

## Context

Phase 3 adds B2B organization scope and server-side authorization on top of the existing `application_instance` root tenant boundary. P3.0 deliberately ratifies semantics before any organization persistence or API runtime is implemented. This prevents public IDs, session claims, role strings or a new service boundary from accidentally becoming authority.

ADR 0008 defines the current Gateway + Identity Service deployment topology. This ADR defines the future Organization/Authorization bounded context and its security contract only.

## Decision

### Root tenancy

`application_instance` remains BeeBox's global root isolation boundary. An organization is an additional scope inside exactly one application instance; it never replaces or widens that root.

An organization-like name or slug in two applications identifies independent resources. Every authoritative organization lookup starts from trusted application scope.

### Organization resource

An organization has:

- a stable opaque BeeBox-owned public ID;
- exactly one owning `application_instance`;
- a name;
- an application-scoped slug;
- creation/update timestamps.

The public ID is a locator only. Possessing it grants no membership or permission.

Slug uniqueness is scoped to the owning application and must ultimately be database-enforced under concurrency. Organization lists are bounded, cursor-paginated and deterministic; the initial ordering contract is `(created_at, public_id)` ascending unless a versioned public contract later states otherwise.

P3.0 does not ratify arbitrary organization metadata or soft-delete lifecycle states. If a later Phase 3 slice exposes metadata or additional lifecycle states, that contract must define visibility, mutation authorization, bounded serialized size and deletion/retention semantics before persistence is added.

### Membership

Membership is an application + organization + user relationship with its own stable opaque BeeBox-owned public ID. A membership may connect only a user and organization belonging to the same application instance.

`user_id`, `organization_id` and `membership_id` supplied by clients are locators/input only. The server first establishes trusted application and authenticated user context, then resolves authoritative organization and membership state inside that scope. IDs never establish authority by themselves.

A user has at most one active membership in a given organization. Membership uniqueness and same-application ownership require database constraints when runtime persistence is introduced.

### Active organization

Active organization is request/session context, not one globally mutable property on the user record. Two sessions for one user may safely operate in different organizations without racing a shared user setting.

Selecting or using an active organization requires a currently valid authoritative membership. Membership removal, suspension or other future invalidation immediately removes organization authorization even if a stale browser, session hint or token still names that organization.

Client state may suggest a requested organization but the server resolves membership on every authoritative use under the initial design.

### Roles

Role definitions are owned by the application so one application has a stable vocabulary usable across its organizations. A role has a stable BeeBox-owned identifier and application-scoped name/key; human-readable/client-supplied role strings never establish authority.

Phase 3 may support application-defined default and custom roles. Assignment belongs to organization membership, not to the global user.

If the runtime introduces a required-owner/administrator lifecycle invariant, mutations that remove or demote that authority must be serialized and database-backed so concurrent operations cannot leave the organization without the required authority. P3.0 ratifies that fail-closed continuity rule; the implementation slice must choose concrete reserved role/permission vocabulary before exposing it publicly.

### Permissions and authorization

Permissions use stable BeeBox-owned identifiers/names and are evaluated as:

`subject + resource + action + scope -> allow | deny`

Authorization is default-deny. UI visibility is never authorization.

Every server-side decision uses:

- trusted application scope;
- authenticated subject;
- authoritative organization/resource scope;
- current membership state;
- authoritative role assignment and permission definitions.

A client-provided organization, role or permission value is never enough to permit an operation.

### Feature definitions

Phase 3 may define stable feature vocabulary used by authorization policy. A feature definition is not a billing entitlement, purchased plan or payment state. Billing/entitlement lifecycle remains later work and may not silently change authorization correctness in P3.0.

### JWT and claim freshness

The current short-lived Phase 2 access JWT must not silently become the freshness policy for mutable organization roles or permissions. P3.0 therefore does not make a complete mutable role/permission set authoritative merely by embedding it in the existing JWT.

Initial server-side organization authorization prefers authoritative persisted state. If later work places organization/permission hints in tokens, those claims are non-authoritative unless a separate ADR defines bounded staleness, versioning/revocation, invalidation and outage behavior. Redis may cache derived state but is not correctness authority.

### Audit

Security-sensitive organization/authorization mutations require minimized security audit evidence containing, as applicable:

- actor;
- subject;
- application;
- organization;
- action;
- resource/reference;
- result;
- correlation ID;
- occurrence time.

Required audit writes belong to the same correctness transaction as the authoritative mutation. Audit must omit secrets and unnecessary PII.

## Future Organization/Authorization bounded context

P3.0 defines one coherent future bounded context owning:

- organizations;
- memberships;
- invitations;
- verified organization domains;
- role definitions;
- permission definitions;
- membership role/permission assignments;
- authorization persistence.

P3.0 does **not** create an Organization service, tables, handlers or APIs.

If this context becomes a separate runtime in later Phase 3 work, it exclusively owns its mutable data. Identity Service must not directly mutate those tables and the future service must not directly mutate Identity-owned tables. Cross-service contracts use stable BeeBox-owned public references, not raw PostgreSQL primary keys.

User deletion/deactivation, application deletion and other lifecycle propagation across Identity and Organization/Authorization remain explicit unresolved Phase 3 runtime questions. They must define ordering, idempotency, retry and degraded-mode behavior before implementation. P3.0 does not introduce Kafka, an outbox runtime or distributed transactions to pre-answer those questions.

## Security consequences

- `application_instance` remains the non-negotiable root tenant boundary.
- Organization IDs, membership IDs, role strings and stale token hints are never standalone authority.
- Membership removal invalidates organization authorization even when stale client state persists.
- Permission evaluation starts denied and requires authoritative scoped state.
- Mutable authorization freshness is explicit rather than accidentally tied to the five-minute access-token lifetime.
- Required audit and ownership invariants must share mutation correctness boundaries when runtime is implemented.

## Non-goals

This ADR does not implement organization CRUD, memberships, invitations, domains, RBAC runtime, billing, Enterprise SSO, SCIM or a new microservice. Those require later Phase 3 vertical slices and their own implementation evidence.
