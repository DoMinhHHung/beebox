# Phase 3.0 organization and authorization contract

Status: ratified by ADR 0009. This document is normative for later Phase 3 implementation. P3.0 contains no organization runtime or schema.

## Scope and terminology

- **Application**: the existing `application_instance`, BeeBox's root isolation boundary.
- **Organization**: an application-scoped B2B resource.
- **Membership**: the authoritative relation between one same-application user and organization.
- **Active organization**: request/session-scoped selected organization context.
- **Role definition**: application-owned reusable authorization vocabulary.
- **Permission**: stable BeeBox-owned authorization capability.
- **Feature definition**: optional product/authorization vocabulary, not a billing entitlement.

All public IDs are opaque BeeBox-owned stable locators. They do not convey authority.

## Organization

Required logical fields:

| Field | Contract |
| --- | --- |
| `id` | stable opaque BeeBox public ID |
| `application_instance` | exactly one trusted root owner; not client authority |
| `name` | validated human-readable name; exact limits belong to the runtime API contract |
| `slug` | normalized application-scoped locator; uniqueness enforced in PostgreSQL when persisted |
| `created_at`, `updated_at` | server-owned UTC timestamps |

P3.0 does not expose arbitrary metadata. A later contract must bound serialized metadata size and visibility before adding it. P3.0 also does not invent soft-delete/archive states; lifecycle/deletion semantics must be specified with the CRUD slice.

Organization listing is bounded and cursor-based. The baseline deterministic order is `(created_at ASC, public_id ASC)`. Cursors are opaque and must be scoped so a cursor from one application cannot enumerate another.

## Membership

A membership is valid only when:

1. organization and user both exist in the same application;
2. the authoritative membership row is current/active according to the then-ratified lifecycle;
3. the request's trusted application scope matches that application.

The persistence design must enforce same-application ownership and at-most-one active membership for `(organization,user)` under concurrency. Client `organization_id`, `user_id` or `membership_id` only selects a candidate resource; none is authorization evidence.

Server mutation flow is always: establish trusted application -> establish authenticated/authorized actor -> resolve authoritative organization/user/membership -> enforce policy -> mutate + required audit atomically.

## Active organization

Active organization is never a global mutable user property. It is a request/session choice that can differ across simultaneous sessions.

Selection requires current membership. Every authoritative organization-scoped operation revalidates current membership and authorization. Removing/suspending a membership therefore defeats stale browser/session/token selection immediately under the initial server-side authorization model.

A future cached or tokenized active-organization hint may improve ergonomics but cannot become correctness authority without an explicit freshness/revocation design.

## Roles

Role definitions belong to one application and may be assigned to memberships in any organization of that application. Each role definition has a stable BeeBox-owned ID/key plus human-readable metadata as later bounded by the public contract.

The system may provide default roles and application-defined custom roles. A membership carries role assignment; the global user does not.

Role names supplied by a client are never authorization evidence. Authorization resolves current membership assignment and the role definition under trusted application scope.

If the concrete organization lifecycle requires at least one owner/administrator authority, the database/application transaction must prevent concurrent removal/demotion from leaving zero required authorities. A pre-check without serialization or a database invariant is insufficient.

## Permissions and default-deny evaluation

Permission definitions use stable BeeBox-owned IDs/names. Evaluation is modeled as:

```text
(subject, resource, action, scope) -> allow | deny
```

The default result is `deny`.

An allow decision requires all of:

- trusted application scope;
- authenticated subject;
- authoritative resource/organization scope;
- current authoritative membership where organization scope is required;
- current authoritative role/permission assignment;
- an explicit policy granting the requested action.

Frontend/UI hiding is never an authorization control. Unknown permission names, missing membership, cross-application references, stale membership and ambiguous scope fail closed.

## Feature definitions versus billing

Phase 3 may define features used by application policy, but `feature` does not mean paid entitlement. Plans, purchases, subscription status, seat billing and payment-provider state remain later billing work. P3.0 introduces no payment dependency into authorization correctness.

## JWT and freshness

The Phase 2 access token lifetime is not permission freshness policy. P3.0 does not make a full mutable role/permission set authoritative via existing JWT claims.

Initial Phase 3 server authorization must read authoritative persisted state. Any later token/cached authorization design must separately specify:

- maximum staleness;
- state/version identifiers;
- role/membership removal propagation;
- revocation/invalidation;
- cache outage behavior;
- safe fallback behavior;
- observability.

Redis, if introduced, is a cache and never the correctness authority.

## Audit contract

Security-sensitive mutations require minimized durable audit evidence in the same correctness transaction as the authoritative change. The event must make it possible to answer who changed what in which application/organization and whether it succeeded without storing secrets or unnecessary PII.

Minimum facts when applicable: actor, subject, application, organization, action, resource/reference, result, correlation ID and time.

## Future service/data ownership

The future Organization/Authorization bounded context owns organizations, memberships, invitations, verified organization domains, role definitions, permission definitions, assignments and authorization persistence.

If later extracted as a runtime:

- it exclusively mutates its tables;
- Identity exclusively mutates Identity-owned Phase 1/2 tables;
- neither service reaches through the other's database ownership boundary;
- cross-service contracts use stable BeeBox public IDs rather than raw database primary keys;
- a distributed transaction is not introduced.

Lifecycle propagation such as user deletion/deactivation is intentionally unresolved in P3.0. The implementation slice must define idempotency, ordering, partial failure and reconciliation before selecting synchronous or asynchronous communication. No Kafka/outbox runtime is created by this baseline.

## Required later implementation tests

Any P3 runtime PR must include, as applicable:

- same-app positive membership/authorization;
- cross-application organization/user/membership denial;
- public-ID/role-string substitution denial;
- stale active-organization denial after membership removal;
- default-deny unknown/missing permission;
- concurrent last-owner/admin removal protection;
- deterministic bounded pagination and cursor scope;
- audit failure rollback for security-sensitive mutation;
- concurrent slug/membership uniqueness;
- cache/token stale-state tests if a freshness design is later introduced.

## P3.0 non-goals

No CRUD handlers, tables, migrations, invitations, domains, RBAC evaluator runtime, organization service, Enterprise SSO, SCIM, billing or webhooks are implemented by this contract.
