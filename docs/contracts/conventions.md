# BeeBox Contract and Tenancy Conventions

> Status: Phase 0 repository baseline. These semantics constrain future product/data PRs but do not create a public API, schema, SDK, or tenant model by themselves.

This document refines `Instruction.md` without overriding it. If a future public contract or trust-boundary decision conflicts with these semantics, the change requires the repository's normal ADR/maintainer process rather than a silent reinterpretation.

## 1. Resource identifiers

BeeBox owns resource identifiers exposed by BeeBox contracts.

Required semantics:

- identifiers are stable for the lifetime of the represented resource and opaque to clients;
- public semantics must not depend on PostgreSQL primary-key type, sequence layout, shard, table name, or other storage implementation detail;
- an identifier must not encode authority such as application ownership, organization ownership, role, permission, entitlement, or authorization state;
- possession or successful parsing of an identifier never proves authorization;
- identifiers must be unambiguous within the public resource namespace that defines them, and persisted resources must retain enough explicit application/instance scope to prevent an identifier collision or lookup from bypassing tenancy enforcement;
- server-side repository/application code resolves a resource inside a trusted scope rather than accepting a client-provided identifier as a scope decision.

### Wire encoding is not yet ratified

No public product resource exists today. BeeBox therefore does **not** commit in Phase 0 to UUID, ULID, prefixed IDs, integer IDs, or another permanent public wire encoding. The first PR that exposes a public resource identifier must ratify the concrete encoding and compatibility rules before release. That decision must preserve the semantics above and must not smuggle tenant or authorization information into the identifier.

## 2. Errors

Public-facing errors separate machine behavior from safe human explanation.

- A stable machine-readable error code identifies the BeeBox error category.
- A human-readable message is safe to display/log at its intended boundary and is not the compatibility key.
- Provider, database, SQL, topology, vendor SDK, stack, credential, token, or secret details must not cross a public error boundary.
- Validation and failure classification must be deterministic for the same contract state; adapter-specific failures map to BeeBox-owned categories.
- When a request/correlation identifier exists, safe error responses may expose that identifier for support correlation. Its format is not an authorization primitive and must not carry secrets or unnecessary PII.
- Authentication, recovery, identifier lookup, invitation, and similar security-sensitive flows must preserve anti-enumeration properties. A more specific internal failure category must not force a public message/code that confirms whether a protected account or identifier exists.

A new public error code or compatibility-significant change must be reviewed as part of the versioned contract that exposes it.

## 3. Pagination

Every list contract is bounded.

- There is no unbounded `list all` product API.
- Each endpoint defines a maximum page size. Requests above the maximum are rejected or capped according to that endpoint's documented contract; the behavior must be deterministic.
- Ordering is deterministic and includes a stable tie-breaker so repeated pagination cannot depend on incidental database row order.
- Mutable collections should use opaque cursors rather than exposing database offsets or ordering internals when cursor semantics can provide a stable contract.
- A cursor is scoped to the list contract and relevant server-selected tenant/application context. Clients must not be able to edit a cursor to select another scope.
- Invalid, malformed, tampered, unsupported-version, or otherwise unusable cursors fail with a stable machine-readable client error. An expired cursor, when a cursor design has expiry, fails deterministically rather than silently restarting from page one.
- Cursor contents, encoding, signing, retention, and expiry are ratified with the first concrete paginated public contract; this document does not invent a persistence/cache mechanism.

## 4. Idempotency

Idempotency is required for mutations where a client can safely retry but duplicate execution could create an additional resource, repeat a side effect, or produce an incorrect state transition. Examples include create operations, externally triggered security/administrative mutations, payment/provider operations, and other retryable commands once those capabilities exist.

Baseline semantics:

- the idempotency namespace includes the server-selected application/instance scope and logical operation; organization/subject scope is added where required by that operation;
- the key itself is opaque client input and never selects tenant authority;
- the server associates the key with a canonical request fingerprint or equivalent request identity;
- same scoped key + same logical request replays/returns the original logical result, including a previously committed failure/success category when the concrete contract requires it;
- same scoped key + conflicting payload/request identity fails deterministically and must not execute the competing mutation;
- concurrent attempts using the same scoped key must converge on one logical execution/result through transactionally enforceable persistence once storage is introduced;
- records have a documented retention/expiry policy appropriate to retry windows and security requirements. Expiry is a semantic requirement, not a mandate for Redis, queues, or another infrastructure component;
- if a mutation cannot safely support replay, its contract must explicitly define why and how retries are handled instead of silently ignoring duplicate risk.

## 5. Time

- Persisted and public contract time semantics are UTC. Local server/user time zones must not change ordering, expiry, or persisted security meaning.
- Externally serialized timestamps use RFC 3339 / ISO 8601-compatible UTC timestamps. Unless a concrete contract explicitly requires otherwise, emit UTC with a `Z` offset and sufficient precision to preserve the event/order semantics being represented.
- Domain/event models distinguish **occurrence time** (when the represented fact happened) from processing/receipt/persistence time when both matter.
- Clock-sensitive security behavior such as token validity, OTP expiry, replay windows, signatures, or lockouts may tolerate only an explicitly documented bounded clock skew. There is no implicit unlimited grace period.
- Server-side trusted time is used for security decisions; client-supplied timestamps are data unless the contract explicitly validates and authorizes their meaning.

## 6. API versioning and compatibility

- Public HTTP product APIs live under an explicit version such as `/v1`, as required by `Instruction.md`.
- BeeBox public models are BeeBox-owned contract models. Database rows and provider/vendor SDK types never become public models by reuse.
- An incompatible meaning change, removal, required-field change, or behavior change requires a new version or an explicit documented migration/deprecation path.
- Adding a field must not redefine, overload, or contradict the meaning of an existing field.
- Existing fields/events are never reused with a new semantic meaning.
- Deprecation requires documentation, migration guidance, and removal criteria; telemetry is required once a production contract exists and can provide meaningful usage evidence.
- This baseline does not promise Clerk endpoint compatibility or any vendor-compatible wire contract.

## 7. Audit-event semantics

Security and administrative audit facts are correctness evidence, not optional notification artifacts.

A security-sensitive action introduced by a product slice is incomplete unless that slice records the required audit fact as part of the action's correctness boundary. Failure of later asynchronous email, webhook, notification, provider delivery, or other secondary work must not erase an audit fact for an action that already committed.

The audit record/event contract for such an action includes, as applicable:

- immutable event identifier;
- occurred-at timestamp;
- actor identity, including support/impersonating actor when applicable;
- subject identity where the action has a distinct subject;
- explicit application/instance scope;
- organization scope only where applicable;
- action name/category;
- resource type/reference where applicable;
- result/outcome, including denied or failed security-sensitive attempts when the concrete threat model requires them;
- source/context sufficient for investigation without storing secrets or unnecessary PII;
- correlation/request identifier when available;
- redaction/minimization rules for secrets and PII.

The storage mechanism, table design, outbox, worker, event bus, and export pipeline are **not** selected by this Phase 0 document. A future slice chooses only the smallest mechanism that can satisfy its correctness, transaction, retention, and operational requirements. Kafka, queues, or outbox infrastructure are not implied by these semantics.

## 8. Tenancy and scope

BeeBox's root isolation invariant is explicit application/instance scope.

- Every product resource and persisted row belongs to an explicit application/instance.
- Organization scope is additional only where the resource is organization-owned or organization-specific. Organization is **not** a universal tenant/root model.
- A client-supplied application ID, organization ID, owner ID, resource ID, role, permission, or entitlement is input to validate, never sufficient authorization evidence.
- Authentication establishes identity; authorization independently decides whether that identity may act in the server-selected scope.
- Application/use-case code derives or selects trusted scope from authenticated/authorized server context. Repository operations accept/enforce that trusted scope and do not perform unscoped product lookups that can return another application's row.
- Database uniqueness constraints and foreign keys must include or otherwise enforce the correct application/instance scope; organization scope is included where required by the domain invariant. An application-only pre-check is insufficient under concurrency.
- Public identifiers remain opaque and must not be decoded to establish ownership.
- The first product persistence/API slice must include negative cross-tenant tests, including valid identifiers belonging to a different application/instance and, where applicable, a different organization.
- Deletion, retention, backup/restore, import/export, and migration behavior must preserve scope and must not create cross-tenant visibility.

## 9. Decisions intentionally left open

This baseline does not decide:

- concrete permanent public resource-ID wire encoding;
- account-linking semantics;
- token/JWT issuer, audience, authorized-party, revocation, or other trust-boundary choices beyond existing `Instruction.md` invariants;
- organization as a universal tenant model;
- data ownership between future extracted services;
- Clerk API compatibility;
- concrete cursor encoding/signing;
- concrete idempotency storage infrastructure;
- concrete audit persistence or delivery infrastructure.

The PR that first makes one of these decisions externally binding must surface it explicitly for review rather than treating this Phase 0 document as prior authorization.

## 10. Review checklist for future contract PRs

A future public/product PR that touches these conventions should demonstrate:

- explicit application/instance and applicable organization scope;
- stable/opaque identifiers without encoded authority;
- BeeBox-owned safe errors;
- bounded deterministic pagination when listing;
- idempotency/retry/concurrency semantics for relevant mutations;
- UTC/versioned time semantics;
- explicit API/event versioning and compatibility impact;
- required audit facts for security-sensitive actions;
- negative authorization and cross-tenant tests;
- no implicit public compatibility/trust-boundary decision outside the PR's approved scope.
