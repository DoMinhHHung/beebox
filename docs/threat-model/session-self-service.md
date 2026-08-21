# P2.9 session self-service threat-model delta

Status: Phase 2 implementation contract for current-user session inventory and revocation.

This document extends `initial.md` and ADR 0006. It does not introduce device intelligence, persistent fingerprinting, organization/admin session management, or a second step-up mechanism.

## Assets and authorities

- The publishable key selects one application only; it is not user authority.
- The ordinary bearer resolves the exact current BeeBox session, application, and user from server state.
- A `ses_` public ID is an opaque resource locator only. Knowing it never grants read or mutation authority.
- P2.8 is the only step-up authority for sensitive session mutations. Grants are one-time and bound to the exact application, user, target bearer session, and purpose.
- `sessions.revoked_at` remains the authoritative online revocation state. Refresh credentials are verifier-only and become unusable when their session is revoked.

## Threats and controls

### IDOR/BOLA through session IDs

**Threat:** a caller supplies another user's or another application's opaque session ID to inspect or revoke it.

**Control:** list scope is derived only from the server-resolved current session. Selected revocation applies the application-and-user ownership predicate inside the same PostgreSQL transaction as the mutation. Cross-owner and absent valid locators converge to the same externally safe idempotent behavior. Backend secret-key endpoints remain a separate authority surface.

### Cross-application principal confusion

**Threat:** equal-looking users or a stolen session locator is reused across application instances.

**Control:** every list and revoke predicate contains both `application_instance_id` and `user_id`. The current actor session is reloaded and checked against those values inside the mutation transaction.

### Stolen current session

**Threat:** a stolen ordinary bearer attempts destructive session management.

**Control:** list remains ordinary authenticated self-service, but revoke-one, revoke-others, and sign-out-everywhere require a consumed P2.8 grant with exact purposes `session_revoke`, `session_revoke_others`, or `sign_out_everywhere`. Target-session age, refresh rotation, and client timestamps are not step-up authority.

### Reverification theft, wrong purpose, and replay

**Threat:** a valid grant is copied, replayed, or substituted across operations or sessions.

**Control:** P2.8 hashes the grant at rest, binds it to the exact target session and purpose, caps its lifetime, atomically consumes it once, and rechecks target/proof authority. P2.9 additionally calls `RequireReverification` at the application boundary, so direct service callers cannot bypass the HTTP gate.

### Bulk revocation partial failure

**Threat:** only some sessions are revoked, or revocation commits while audit evidence fails.

**Control:** bulk update and one bounded operation audit event run in one PostgreSQL transaction. Audit failure rolls back the revocation. There is no application loop that commits individual sessions separately.

### Concurrent revoke

**Threat:** revoke-one, revoke-others, and sign-out-everywhere race and leave an unexpected active foreign session or inconsistent audit state.

**Control:** current-user mutations serialize through the scoped user row, then revalidate the current actor session. SQL updates are idempotent (`revoked_at` is written only when NULL), repeat operations converge, and every update remains scoped to the exact application and user.

### Current-versus-other ambiguity

**Threat:** a bulk action accidentally revokes or preserves the current session contrary to the public contract.

**Control:** revoke-others explicitly excludes the server-resolved current `ses_` ID; sign-out-everywhere deliberately includes it. Current marking in the list is derived by comparing returned rows with the server-resolved current session, never a client field.

### Refresh credential survival

**Threat:** a refresh credential remains usable after self-service revocation.

**Control:** refresh rotation joins the owning session and rejects `revoked_at IS NOT NULL`. P2.9 reuses this source of truth and adds no cache or Redis dependency.

### Offline JWT revocation gap

**Threat:** a relying party that verifies only the Ed25519 JWT signature assumes self-service revocation is globally instantaneous.

**Control:** BeeBox endpoints that resolve persisted session state observe revocation immediately. Offline consumers cannot observe database revocation and may accept an already-issued access JWT until its short five-minute lifetime (subject to existing clock-skew verification rules). Documentation must state this limitation explicitly; P2.9 does not claim a global JWT denylist.

### Privacy expansion through a "device" UI

**Threat:** session inventory becomes justification for collecting precise location, raw user-agent, IP history, permanent fingerprint, or behavioral identifiers.

**Control:** P2.9 returns only already-persisted lifecycle facts: opaque session ID, creation/last-active/idle/absolute expiry, revoked state, and current marker. No device, IP, user-agent, location, hardware, MFA provenance, or fingerprint columns are added.

### Audit data leakage or unbounded telemetry

**Threat:** identifiers/tokens become metric labels or audit data grows per revoked child session.

**Control:** bulk actions use one operation-level audit event. Audit vocabulary and metric dimensions are fixed; reverification/access/refresh secrets and verifier hashes are never audit or metric values. Single-session audit may include the bounded opaque selected session resource reference for investigation.

### Enumeration through error differences

**Threat:** response differences reveal whether a supplied session exists or belongs to another user/application.

**Control:** a syntactically valid selected locator that is absent or outside ownership produces the same idempotent public success class. Malformed locators fail request validation without querying ownership.

### Unbounded inventory/resource exhaustion

**Threat:** session listing forces unbounded result allocation or table scans.

**Control:** default page size is 20, maximum 100, cursor size is bounded, ordering is deterministic by `(created_at DESC, public_id DESC)`, and migration `00022` adds the exact `(application_instance_id, user_id, created_at DESC, public_id DESC)` index used by the list access pattern.

## Security invariants

1. Application/user scope is always server-derived from current authority.
2. Public session IDs are locators, never authority.
3. Sensitive mutations require one exact P2.8 grant; ordinary current-session sign-out remains unchanged.
4. Selected/bulk mutation and audit commit atomically.
5. Revoked sessions cannot refresh.
6. No new device/privacy data is persisted or returned.
7. Offline JWT verification has a documented bounded revocation lag; online BeeBox session resolution is authoritative.
