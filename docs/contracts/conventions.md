# BeeBox Contract and Tenancy Conventions

> Status: Phase 0 repository baseline plus references to proposed Phase 2 trust decisions. Proposed ADRs do not create runtime behavior, public API, schema or SDK contracts until Human-ratified.

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

Concrete public-ID encodings are ratified by the public contract that exposes them. Existing accepted contracts, including ADR 0003, remain authoritative for already introduced identifiers.

## 2. Errors

Public-facing errors separate machine behavior from safe human explanation.

- A stable machine-readable error code identifies the BeeBox error category.
- A human-readable message is safe to display/log at its intended boundary and is not the compatibility key.
- Provider, database, SQL, topology, vendor SDK, stack, credential, token, or secret details must not cross a public error boundary.
- Validation and failure classification must be deterministic for the same contract state; adapter-specific failures map to BeeBox-owned categories.
- When a request/correlation identifier exists, safe error responses may expose that identifier for support correlation. Its format is not an authorization primitive and must not carry secrets or unnecessary PII.
- Authentication, recovery, identifier lookup, invitation, linking and similar security-sensitive flows must preserve anti-enumeration properties. More specific internal state must not force a public response that confirms another account or identifier exists.

A new public error code or compatibility-significant change must be reviewed as part of the versioned contract that exposes it.

## 3. Pagination

Every list contract is bounded.

- There is no unbounded `list all` product API.
- Each endpoint defines a maximum page size and deterministic ordering with a stable tie-breaker.
- Mutable collections should use opaque cursors when cursor semantics provide a stable contract.
- Cursors are scoped to the list contract and trusted server-selected tenant/application context; clients cannot edit them to select another scope.
- Invalid, malformed, tampered, unsupported-version or expired cursors fail deterministically.
- Cursor encoding/signing/retention is selected by the concrete paginated contract and does not imply Redis or other infrastructure.

## 4. Idempotency, retry and concurrency

Idempotency is required where safe client retry could otherwise duplicate resources, side effects or state transitions.

- the namespace includes server-selected application scope and logical operation, plus subject/organization scope where required;
- a client key never selects tenant authority;
- same scoped key plus same logical request converges on one logical result;
- conflicting payload for the same scoped key fails deterministically without executing the competing mutation;
- concurrency-sensitive ownership or uniqueness invariants are database-enforced when persistence exists; application pre-check alone is insufficient;
- replay/retention semantics are explicit for the concrete operation;
- if replay cannot be safe, the contract explains retry behavior instead of ignoring duplicate risk.

## 5. Time

- Persisted/public time semantics are UTC.
- Externally serialized timestamps use RFC 3339 / ISO 8601-compatible UTC values.
- Occurrence time is distinguished from processing/receipt time where both matter.
- Clock-sensitive security behavior has explicit bounded skew; there is no unlimited grace period.
- Server-side trusted time is used for security decisions; client timestamps are input, not authority.

## 6. API versioning and compatibility

- Public HTTP product APIs live under explicit versions such as `/v1`.
- BeeBox public models are BeeBox-owned. Database rows and provider/vendor SDK types never become public models by reuse.
- Incompatible meaning changes require a new version or explicit migration/deprecation path.
- Existing fields/events are never silently reused with a new semantic meaning.
- This baseline does not promise Clerk endpoint compatibility or vendor-compatible wire contracts.

The proposed Phase 2 ADRs add no route, OpenAPI operation, SDK method or provider wire model. Any externally binding Phase 2 API shape must be reviewed in the implementing slice.

## 7. Audit-event semantics

Security and administrative audit facts are correctness evidence, not optional notification artifacts. A security-sensitive committed mutation keeps required audit evidence inside its correctness boundary; later asynchronous/provider failure must not erase that fact.

Every required audit fact includes:

- immutable event identifier and occurred-at time;
- actor and applicable subject;
- explicit application scope and organization scope only where applicable;
- action plus resource category/reference;
- result/outcome, including denied attempts when the concrete threat model requires them;
- correlation/operation identifier;
- minimized safe source/context;
- redaction/minimization rules for secrets and PII.

For future Phase 2 mutations this includes, where security-relevant, link/unlink attempts and results, primary-identifier changes, factor enrollment/removal/reset, passkey registration/revocation, recovery credential regeneration/use and reverification decisions.

Provider tokens, email, phone, OTP, recovery code, password/credential material and arbitrary raw provider errors must not become audit facts merely because the operation concerns them.

The storage mechanism, table design, outbox, worker, event bus and export pipeline are not selected here.

## 8. Tenancy and scope

BeeBox's root isolation invariant is explicit application/instance scope.

- Every product resource and persisted row belongs to an explicit `application_instance`.
- Organization scope is additional only where the resource is organization-owned or organization-specific; organization is not a universal root.
- Client-supplied application/user/organization/resource IDs, roles, permissions or entitlements are input to validate, never authorization evidence.
- Authentication establishes identity; authorization independently decides whether that identity may act in trusted server-selected scope.
- Repository operations remain scoped and database uniqueness/foreign-key constraints enforce the correct application boundary.
- Public IDs and external provider subjects are locators/identities in their defined namespace, not encoded ownership authority.
- Cross-application negative tests are required for product slices that introduce new identity/credential state.
- Deletion, retention, backup/restore, import/export and migration must preserve scope.

## 9. Proposed Phase 2 trust decisions

ADRs 0004–0006 are **proposed** and require explicit Human maintainer ratification before an implementation may treat them as accepted architecture.

Future Phase 2 implementation must read the applicable ADR rather than inventing policy locally:

- `docs/adr/0004-phase2-identity-linking-external-trust.md` — external/provider subject ownership, no email-equality auto-link, authenticated explicit link/unlink, conflict/last-method rules, primary identifiers, phone and passkey ownership;
- `docs/adr/0005-phase2-authentication-assurance-recovery.md` — primary proof versus full assurance, MFA downgrade resistance, pending authentication, reverification freshness and recovery;
- `docs/adr/0006-phase2-device-privacy-hosted-auth.md` — device metadata minimization/retention and application-scoped hosted redirect/state binding.

While those ADRs remain proposed, accepted ADRs 0001–0003 continue to govern existing behavior. In particular ADR 0002's prohibition on email-equality account linking remains accepted and binding. No runtime mitigation described only in a proposed ADR may be claimed as implemented.

## 10. Decisions still intentionally open

This baseline does not decide:

- acceptance of ADRs 0004–0006;
- any account-merge lifecycle beyond the proposed explicit-link model;
- concrete OAuth/OIDC provider adapter or token-storage lifecycle;
- concrete WebAuthn, MFA, recovery-code or pending-auth transaction representation;
- concrete device PII retention because new device PII storage is deferred by default;
- data ownership between future extracted services;
- Clerk API compatibility;
- concrete cursor/idempotency/audit infrastructure.

## 11. Review checklist for future contract PRs

A future public/product PR touching these conventions should demonstrate:

- explicit application and applicable organization scope;
- stable/opaque identifiers without encoded authority;
- BeeBox-owned safe/anti-enumerating errors;
- bounded deterministic pagination when listing;
- idempotency/retry/concurrency semantics for mutations;
- UTC/versioned time semantics;
- explicit API/event compatibility impact;
- required audit evidence;
- negative authorization/cross-tenant tests;
- for Phase 2 identity/security work, traceability to the applicable **accepted** trust ADR and no reliance on a merely proposed decision;
- no vendor-model leakage or implicit trust-boundary expansion.