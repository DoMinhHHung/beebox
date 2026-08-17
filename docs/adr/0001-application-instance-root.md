# ADR 0001: application_instance as the v1 root isolation resource

- Status: accepted
- Scope: BeeBox Phase 1 v1 product persistence
- Authority: Human-ratified architecture decision

## Context

BeeBox requires every product row/resource to belong to an explicit application/instance scope while organization scope is additional only where applicable. Phase 1 needs a concrete root persistence boundary before users, credentials, authentication, sessions, or organization-owned resources are introduced.

The broader product roadmap may eventually need workspace grouping, separate application/environment concepts, or another hierarchy, but there is no current product evidence requiring those layers in the first persistence slice.

## Decision

BeeBox v1 uses one resource, named `application_instance`, as the root product isolation boundary.

- Each future product row belongs to exactly one `application_instance` unless a later reviewed design adds another applicable scope.
- Organization is not the root tenant. Organization scope is additional only for organization-owned or organization-specific resources.
- BeeBox does not model a required `workspace -> application -> environment` hierarchy in v1.
- The PostgreSQL primary key used for `application_instances` is storage-internal. It is not BeeBox's permanent public application-instance identifier.
- This ADR does not ratify UUID, ULID, integer, prefixed, Clerk-compatible, or any other public resource-ID wire encoding.
- No public application-instance API, credential lifecycle, user behavior, authentication, authorization, session/token behavior, or organization resource is introduced by this decision.

## Consequences

- The first product table is `application_instances`, containing only the internal identity and creation timestamp needed for the root persistence primitive.
- Server-side persistence resolves an application instance by trusted internal scope and must not use client-provided identifiers as authorization evidence.
- Future child resources must carry/enforce the appropriate `application_instance` scope in schema, repositories, and tests.
- Future organization-owned resources add organization scope without replacing the application-instance root.
- A future workspace/application/environment hierarchy may be introduced additively if product evidence justifies it; this ADR does not forbid that evolution.
- The first public application-instance contract must separately ratify its public identifier encoding and compatibility semantics before release.
- The first reachable application/admin creation lifecycle must separately define authentication, authorization, idempotency/retry/replay, required audit evidence, public errors, abuse controls, and operational behavior.

## Data lifecycle implications

Application-instance rows are durable roots in this slice. No delete or soft-delete lifecycle is defined. Backup and restore must preserve their internal identity and future referential meaning. Deletion/retention semantics must be designed with the first real lifecycle that requires deletion.

Database evolution remains forward-only. Migration `00002_application_instances.sql` is additive and has no `Down`; later corrections use reviewed roll-forward migrations.
