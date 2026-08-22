# P3.3 authoritative organization authorization threat-model delta

Status: P3.3 implementation security delta for application-owned roles, exact permissions, membership role assignment and server-side authorization evaluation. ADR 0009 and the Phase 3 organization/authorization contract remain authoritative.

## Authority model

`application_instance` remains the root tenant boundary. PostgreSQL current state is the only P3.3 authorization authority. An allow decision requires the exact trusted application, authenticated user, organization, current membership, current one-role assignment, same-application role, same-application exact permission definition and an explicit current role-permission grant.

Client role strings, role IDs, permission IDs/keys, membership IDs and organization IDs are locators or vocabulary only. The evaluator accepts no role or permission locator from its caller. Any missing policy prerequisite returns default `DENY`; a PostgreSQL/system failure is returned as a stable persistence error rather than being confused with policy state.

## Role-string privilege escalation and no magic owner/admin

Role definitions are application-owned reusable vocabulary. Keys such as `admin`, `owner` and `member` have no built-in semantics. There is no hidden root role, owner bypass, role hierarchy, inherited role, implicit wildcard or default grant. Integration coverage assigns `admin` and `owner` roles without grants and proves authorization remains denied.

P3.3 introduces no mandatory owner/admin existence, bootstrap super-user, reserved role key or last-owner continuity rule. If a later product contract makes an owner/admin mandatory, that lifecycle requires a separately ratified serialized/database-enforced design.

## Exact permission semantics

Permission definitions are application-owned exact `(resource, action)` capabilities with independent stable internal UUID locators and machine keys. PostgreSQL prevents ambiguous duplicate `(application, resource, action)` definitions. Wildcards, globs, hierarchy, inheritance, permission implication and explicit deny assignments do not exist. Absence of an exact current grant is `DENY`.

Unknown but syntactically valid resources/actions therefore fail closed. Invalid programmer/domain vocabulary fails validation before persistence.

## Cross-application substitution

Role and permission definitions store application scope explicitly. Role-permission grants use composite same-application foreign keys to both definitions. Membership-role assignments use composite same-application foreign keys to the membership and role. PostgreSQL therefore makes app-A membership -> app-B role and app-A role -> app-B permission persisted states impossible even if application code is defective.

All mutation lookups additionally predicate trusted application scope. Opaque UUID possession never selects tenant authority.

## Freshness and stale authority

Every authorization decision executes a bounded authoritative PostgreSQL join. There is no Redis permission cache, process correctness cache, user-global role, session role snapshot or JWT organization/membership/role/permission authority.

Consequently, after the relevant transaction commits:

- membership removal -> next check denies;
- membership role clear -> next check denies;
- membership role replacement -> next check uses only the replacement role;
- permission grant revoke -> next check denies that exact capability;
- permission grant add -> next check may allow that exact capability.

This does not claim retroactive cancellation of work whose authorization decision completed before a concurrent mutation committed.

Membership removal retains P3.2 physical-delete semantics. Assignment foreign keys use PostgreSQL `NO ACTION`; the membership-removal transaction explicitly deletes that membership's subordinate role assignment before deleting the membership. No cascade lifecycle is introduced.

## Concurrent role changes

A membership carries zero or one current role assignment. `SetMembershipRole` locks the authoritative membership row and upserts a primary-keyed `(application, membership)` assignment. Concurrent replacements serialize on that membership and converge to one current assignment. P3.3 deliberately does not implement multi-role permission union.

Role and permission definition uniqueness and duplicate role-permission grants are database-enforced under concurrency; application pre-checks are not correctness authority.

## Audit atomicity and minimization

Role creation, permission creation, grant/revoke and membership-role set/clear write required audit evidence in the same transaction as the authorization mutation. Audit failure rolls the mutation back.

P3.3 additively extends the internal `audit_events` schema with bounded nullable `organization_reference` and `related_resource_reference` fields because one pre-existing `resource_reference` cannot unambiguously represent organization plus primary authorization resource plus related role/permission. The fields are internal audit facts, not public events.

Representation is minimized:

- role creation: role UUID as primary resource;
- permission creation: permission UUID as primary resource;
- role-permission grant/revoke: role UUID primary + permission UUID related;
- membership-role set/clear: membership UUID primary + organization UUID + role UUID related + target subject user.

No raw PostgreSQL IDs, role names, organization names/slugs, email, token or credential data is copied into audit facts. Authorization reads are not synchronously audited by P3.3.

## Primary threats and controls

| Threat | P3.3 control / evidence |
| --- | --- |
| Role string `admin`/`owner` escalates privilege | No magic role branches; explicit no-grant integration tests remain `DENY`. |
| Cross-app role/permission assignment | Composite scoped FKs plus direct PostgreSQL negative tests. |
| Stale membership authorizes after removal | Evaluator joins the current membership row every call; removal deletes subordinate assignment transactionally. |
| Stale role assignment | One current assignment is re-read every call; clear/replacement freshness is tested. |
| Stale permission grant | Exact grant relation is re-read every call; grant/revoke freshness is tested. |
| Unknown resource/action becomes implicit allow | Default deny plus exact persisted permission resource/action predicate. |
| Wildcard/inheritance broadens privilege | Vocabulary grammar rejects wildcard characters; no hierarchy/union implementation exists. |
| Concurrent role changes produce two roles | Membership-row serialization plus one-row assignment primary key. |
| Mutation commits without audit | Same PostgreSQL transaction; representative create/grant/revoke/assignment rollback tests. |
| JWT/cache carries stale authorization | Production token claim set is unchanged and regression-tested; no Redis/cache path exists. |

## Deferred boundaries

Role/permission destructive deletion and retention are intentionally absent. Mandatory owner/admin lifecycle remains absent. Public organization/RBAC APIs, SDKs/UI, invitations, domains, read-time authorization telemetry policy, tokenized/cached authorization and service extraction remain P3.4+ or separately ratified work.
