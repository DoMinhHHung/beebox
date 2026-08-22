# P3.2 organization membership and active-organization threat-model delta

Status: P3.2 implementation contract for persisted organization membership and request-scoped active-organization resolution. This extends ADR 0009 and the P3.1 organization-core threat model. It does not introduce roles, permissions, public B2B APIs, organization selection persistence, or a new service boundary.

## Assets and authority

- `application_instance` remains the root tenant boundary.
- A membership is authoritative only when one current PostgreSQL row binds the exact application, organization and user.
- Organization, user and membership IDs are opaque locators only. Possession of any locator does not create membership or organization authority.
- PostgreSQL row existence is the freshness authority. P3.2 adds no Redis permission cache, JWT organization claim, membership claim, role claim or permission claim.
- `MutationContext` carries already-trusted application/actor/correlation facts for internal mutation and audit. It is not the P3.3 authorization decision.

## Cross-application substitution

`organization_memberships` stores `application_instance_id` explicitly and uses composite foreign keys to both `organizations(application_instance_id,id)` and `users(application_instance_id,id)`. The database therefore rejects app-A user -> app-B organization state even if application code is defective. Repository reads and mutations additionally predicate the trusted application. A membership locator from another application converges to the same not-found category as an absent locator.

## Duplicate membership race

Current membership is represented by row existence and `(application_instance_id,organization_id,user_id)` is unique. Create uses one scoped `INSERT ... SELECT`; there is no correctness-bearing pre-check. Concurrent duplicate creates therefore converge at the PostgreSQL unique constraint to exactly one current membership.

## Active organization and stale hints

Active organization is request/use-case context, not a globally mutable property on `users` or `sessions`. Resolution performs one authoritative join over the requested organization, authenticated user and current membership inside the trusted application. A stale browser/session/request hint naming an organization cannot bypass the current membership row.

After a membership-removal transaction commits, every later authoritative resolver query observes no current row and denies that organization. P3.2 does not claim retroactive cancellation of a request that completed its authorization decision before a concurrent removal committed.

A user may simultaneously belong to multiple organizations and separate calls may independently resolve different organizations. There is no global "switch organization" write, avoiding last-writer-wins races between tabs or sessions.

## Membership removal and lifecycle

Removal physically deletes the current membership row. Re-adding the same user to the same organization creates a new membership UUID. P3.2 does not add suspended, banned, pending, invited, archived, disabled, soft-deleted, owner or billing-seat states.

The existing runtime exposes no supported physical user or application deletion path. Membership foreign keys therefore use PostgreSQL `NO ACTION` semantics and deliberately do not add cascade behavior. ADR 0009's user/application deletion and deactivation propagation remains unresolved future lifecycle work.

## Audit atomicity and minimization

Membership create/remove and required audit evidence share one PostgreSQL transaction. Audit failure rolls the membership insert/delete back. The audit fact stores:

- trusted application;
- actor user;
- target/subject user;
- action (`organization.membership.created` or `organization.membership.removed`);
- resource category `organization_membership`;
- `resource_reference` equal to the stable organization opaque locator;
- success outcome, trusted correlation and occurrence time.

The organization is therefore directly recoverable from the durable audit fact even after the membership row is removed. The target user plus organization reference reconstructs the affected relation without leaking PostgreSQL BIGINT IDs or inventing a composite string. Names, slugs, email, tokens and credentials are not audited.

Existing application-scoped actor/subject audit foreign keys reject cross-application attribution and cause the surrounding membership mutation to roll back.

## JWT, session and cache freshness

P3.2 does not modify access-token claims or token verification. JWTs continue to carry only the existing Phase 1 identity/session claims; no organization/membership/role/permission authority is added. `users.active_organization_id` and `sessions.active_organization_id` do not exist. There is no membership/permission cache. PostgreSQL current membership state is revalidated whenever this P3.2 active-organization resolver is used.

## Primary threats and controls

| Threat | Control/evidence |
| --- | --- |
| app-A user bound to app-B organization | Composite scoped FKs plus direct PostgreSQL negative integration coverage. |
| Membership-ID substitution | Every membership get/remove predicates trusted application; cross-app locator test fails closed. |
| Organization/user locators treated as authority | Active resolver requires the exact current membership tuple; non-member test denies. |
| Concurrent duplicate membership creation | DB unique tuple is final arbiter; concurrent integration test converges to one row/success. |
| Stale active-org hint after removal | Resolver always joins current membership; post-commit stale-hint test denies. |
| Global active-org races across tabs/sessions | No user/session active-org column or switch mutation exists. |
| Audit commits independently of membership mutation | Create/remove and audit share one transaction; both rollback paths are integration-tested. |
| Mutable authorization becomes stale in JWT/cache | No org/membership/role/permission JWT claims and no cache are introduced. |

## Deferred boundaries

P3.3+ remains responsible for roles, permissions, authoritative actor authorization, invitations, domains and public B2B APIs. Organization/user/application deletion propagation remains intentionally unresolved and must not be inferred from P3.2 membership FKs.
