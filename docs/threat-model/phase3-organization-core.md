# Phase 3.1 organization core threat-model delta

Status: implementation security delta for the P3.1 Organization resource foundation. ADR 0009 and the Phase 3 organization/authorization contract remain authoritative.

## Scope

P3.1 adds authoritative PostgreSQL persistence and internal domain/application behavior for organizations. It does not expose a public organization HTTP API, SDK, membership, active-organization selection, invitations, verified domains, roles, permissions, JWT organization claims or a new service.

`application_instance` remains the root tenant boundary. An organization is additional scope inside exactly one trusted application.

## Threats and controls

| Threat | P3.1 control / evidence |
| --- | --- |
| Client/resource locator selects another tenant | Every get/list/update query requires trusted `application_instance` scope in addition to the organization locator. Cross-application substitution returns not-found behavior. |
| Slug collision races create duplicate organizations | PostgreSQL uniquely constrains `(application_instance_id, slug)`. The application layer normalizes first, but the database is the concurrency authority. Same normalized slug remains valid in different applications. |
| Ambiguous public-ID compatibility is accidentally ratified | P3.1 stores a database-generated UUIDv4 `opaque_id` as an internal stable locator only. No `org_...` or other public wire encoding is introduced. A later public API contract must ratify its own representation. |
| Unbounded organization enumeration | List size is bounded. Ordering is deterministic by `(created_at ASC, opaque_id ASC)`. |
| Cursor reuse crosses tenants | Cursor payload binds the trusted application internal scope and list position. AES-256-GCM with a dedicated application-layer cursor key keeps the position opaque and provides tamper evidence. Invalid, malformed or cross-application cursors fail before repository enumeration. The cursor key is not authorization authority and is not the Gateway correlation key. |
| Resource update escapes application scope | Update matches both trusted application ID and organization locator in one statement. A locator from another application cannot select the row. |
| Security/admin mutation commits without required audit | Create/update and their minimized audit fact share one PostgreSQL transaction. Audit insert failure rolls the organization mutation back. |
| Audit actor crosses application scope | Existing audit foreign-key scope requires the actor user to belong to the same application carried by the audit fact. |
| Audit leaks unnecessary data | Audit stores bounded action/category/outcome, organization opaque reference, trusted correlation and actor/application references. Organization name and slug are not copied into audit facts. |
| Organization state becomes authorization by accident | P3.1 defines no membership, role, permission or active-organization authority. Possessing an organization locator or slug grants nothing. |

## Residual boundaries

P3.1 has no public cursor configuration or organization wire API. A later public surface must define deployment-safe cursor-key provisioning/rotation together with the public pagination contract; this PR does not create a new environment variable or reuse an unrelated BeeBox secret.

P3.1 MutationContext records an already-trusted actor/application for correctness and audit; it is not an authorization grant and must not be exposed directly as a public admin API.

Organization deletion/archive, membership ownership, invitation lifecycle, active organization, roles, permissions and authorization evaluation require their separately authorized Phase 3 slices.
