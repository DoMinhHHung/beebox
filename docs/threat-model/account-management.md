# P2.10 account-management threat-model delta

This document records the security boundary added by Phase 2 account/profile self-service. It supplements the repository-wide threat model and the P2.8 reverification model; it does not create a second identity or authorization model.

## Assets and authority

- `application_instance_id`, authenticated BeeBox user identity and the active target session are authoritative scope.
- Public identifier IDs (`eml_*`, `phn_*`) are opaque locators only. Possessing or guessing one never grants access to that identifier.
- Email/phone equality is not account-linking authority. P2.10 never merges, adopts or transfers principals because two identifiers compare equal.
- PostgreSQL is the final concurrency/uniqueness arbiter. Redis or process memory is not required for correctness.

## Sensitive mutations

Identifier add/remove and explicit primary changes use accepted P2.8 purpose-bound reverification. Primary switching uses the dedicated `identifier_primary` purpose and must target an already verified identifier owned by the same exact application/user. The grant is server-recorded, one-time, target-session-bound and independently revalidated; `sessions.created_at`, refresh rotation or client timestamps are not substitutes for proof freshness.

Required success audit facts are written in the same correctness transaction as the identifier mutation. A failed audit write rolls the mutation back. Audit records contain public locators and bounded action metadata, never OTPs, raw secrets, tokens or gratuitous device/location fingerprints.

## Identifier ownership and last-method safety

Email and phone rows remain explicitly application/user scoped. Removal serializes the user's usable authentication-method inventory so concurrent removals cannot strand the user without an accepted login method. When a removed primary identifier has a verified alternative of the same kind, promotion is deterministic; an explicit primary switch never promotes an unverified or foreign identifier.

For phone identifiers, unverified same-number claims do not reserve a number application-wide. The database enforces at most one **verified** owner for `(application_instance_id, phone_e164)` while still allowing the same number in another application. Concurrent verification therefore converges to at most one verified owner without turning an unverified claim into account-linking authority.

## Possession challenges

Email/phone verification challenges are purpose separated from primary authentication. Challenge state is scoped to the exact application and identifier, has a bounded lifetime and failure budget, uses server-side admission/cooldown controls, and is replay-safe. Provider delivery failure is surfaced through BeeBox-owned safe errors and does not authorize or partially verify an identifier.

Phone verification stores verifier material rather than plaintext code authority. Verification and ownership changes are transactionally arbitrated so a failed/rolled-back confirmation does not partially consume challenge state or create a second verified owner.

## Pagination and profile minimization

Identifier lists default to 20 and reject limits above 100. Cursors are opaque, deterministic and kind-scoped; a cursor from one identifier kind cannot be used as authority for another. The `limit+1` pattern keeps records beyond the first 100 reachable without returning an unbounded inventory.

Profile self-service is intentionally limited to `display_name`, `given_name`, `family_name` and `locale`. Names are NFC-normalized and bounded; locale is parsed/canonicalized and bounded. P2.10 does not collect behavioral, IP, user-agent, location, hardware or remembered-device trust data.

## Primary threats and controls

| Threat | Control/evidence |
| --- | --- |
| IDOR through a public identifier ID | Every lookup/mutation predicates exact application and authenticated user; `TestAccountIdentifierMutationIsTenantScopedAndNonEnumerating`. |
| Concurrent removal strands the account | User/method inventory is serialized; `TestAccountIdentifierConcurrentRemovalCannotStrandUser`. |
| Audit succeeds independently of mutation | Same transaction; `TestAccountIdentifierRemovalAuditFailureRollsBackMutation`. |
| Concurrent verified-phone takeover | Verified-only application-wide PostgreSQL uniqueness plus exact owner predicates; migration 00023 integration coverage. |
| Unverified phone claim blocks legitimate ownership | No unconditional application-wide phone uniqueness; only same-user duplicate and verified-owner invariants are enforced. |
| Cursor leaks/cross-kind substitution | Bounded opaque cursor validation and kind binding in account-management unit tests. |
| Profile becomes arbitrary metadata/PII sink | Closed four-field model with normalization and database length constraints. |
| Identifier equality implicitly links accounts | No merge/adoption/transfer path exists in P2.10; application/user scope remains authoritative. |

## Non-goals

P2.10 does not add principal merge, tenant transfer, cross-application identity portability, trusted-device scoring, arbitrary profile schemas or Redis-backed authorization. Any future change to those boundaries requires a separately reviewed architecture/security decision.
