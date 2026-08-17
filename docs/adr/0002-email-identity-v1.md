# ADR 0002: application-scoped email identity v1

- Status: accepted
- Authority: Human-ratified architecture decision
- Scope: BeeBox Phase 1 v1 email identifiers

## Context

BeeBox now has an `application_instance` root isolation resource and application-scoped internal user persistence. The first email-identifier slice needs explicit normalization, uniqueness, ownership, verification-state, and account-linking semantics before email PII can be persisted safely.

These choices are identity semantics, not merely database details. They therefore require an explicit repository-owned decision rather than being inferred from an implementation.

## Decision

### Application scope and uniqueness

- Email identifiers are scoped to `application_instance`.
- Email is not globally unique across BeeBox.
- The same normalized email may belong to independent users in different application instances.
- Within one application instance, one normalized email may belong to exactly one user.
- PostgreSQL enforces that invariant with uniqueness on `(application_instance_id, normalized_email)`.
- Each email identifier references a user in the same application instance through database-enforced scoped referential integrity.
- Organization is not introduced by this decision and remains additional only where organization ownership is actually applicable.

### No automatic account linking

- Matching normalized email text never automatically links, merges, collapses, or reassigns users.
- Creating an already-existing normalized email inside the same application conflicts, regardless of whether the attempted owner is the same user or a different user.
- A duplicate create does not adopt or return the existing user as an implicit account-link operation.
- An unverified email claim can never cause account linking.
- Any future explicit account-linking or account-merge lifecycle requires a separate reviewed decision and complete security design.

### Verification state

- A newly created email identifier starts unverified.
- BeeBox persists this explicitly as a nullable `verified_at`; `NULL` means unverified.
- This slice defines no transition to verified state.
- A later verification slice owns OTP/link generation, expiry, attempts, replay prevention, delivery, transaction behavior, authorization where applicable, and required audit evidence.

### BeeBox v1 normalization

BeeBox v1 supports ASCII mailbox addresses only.

For accepted input:

1. surrounding ASCII space is removed before storage/comparison;
2. the trimmed mailbox spelling is stored case-preserving for future delivery/display use;
3. the comparison key is the lowercase form of the entire trimmed ASCII mailbox;
4. dots are preserved;
5. `+tag` suffixes are preserved;
6. no provider aliases are mapped;
7. Gmail/Google Workspace, Outlook/Hotmail, Yahoo, or another provider receives no special handling.

Full-mailbox lowercase is BeeBox's v1 comparison policy. It is not a claim that SMTP local parts are universally case-insensitive.

SMTPUTF8 and internationalized mailbox addresses are deferred. BeeBox does not claim complete RFC 5322 compatibility; validation intentionally accepts a bounded mailbox-only subset suitable for this v1 persistence policy.

### Public compatibility remains open

- Email-identifier and user database IDs remain storage-internal.
- This ADR does not ratify UUID, ULID, integer, prefixed, Clerk-compatible, or any other permanent public identifier encoding.
- No public email lookup, signup, signin, or user-management API is introduced.
- Primary-email semantics, multiple-email UX/lifecycle, switching/removal, and public contract representation remain separate future decisions.

## Consequences

- The persistence layer can deterministically normalize email and rely on PostgreSQL for same-application uniqueness under concurrency.
- The same normalized address can coexist across independent application roots without collision.
- Application code must not use email equality as account-link authority.
- Email is now persisted PII and must not be copied into stable errors, logs, metric labels, traces, or fixtures unnecessarily.
- Backup/restore now carries email PII and must preserve application/user/email relationships.
- Deletion, anonymization, export, retention, backup handling, and downstream cleanup must be designed with the first reachable lifecycle that needs them.
- Future authentication/identifier lookup must map internal not-found/conflict state to anti-enumerating public behavior; this ADR does not define a public error contract.

## Deferred work

- email verification/OTP/link lifecycle;
- email delivery/provider integration;
- password signup/signin and authentication;
- explicit account linking/merging;
- primary email and multiple-email management;
- public user/email identifiers and APIs;
- deletion/anonymization/export/retention lifecycle;
- audit implementation for reachable security/admin actions.
