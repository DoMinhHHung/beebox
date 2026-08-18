# ADR 0005 — Phase 2 authentication assurance, reverification and recovery

Status: **proposed**

Date: 2026-08-18

Decision owner: Human maintainer

Authority: This ADR is not accepted architecture until the Human maintainer explicitly ratifies it. It defines no runtime API or persistence by itself.

## Context

Phase 2 introduces additional authentication methods, MFA, recovery and sensitive account mutations. A valid primary proof is not always equivalent to a fully authenticated session, and an old valid session must not automatically authorize sensitive credential changes.

This ADR defines the minimum assurance model needed by concrete Phase 2 work without introducing a generic policy engine.

## Proposed decision

### Three distinct states

Future implementation must distinguish:

1. **primary method proven** — one allowed authentication method succeeded;
2. **fully authenticated** — all assurance requirements currently configured for that user/application are satisfied;
3. **recently reverified for a sensitive operation** — trusted server-side evidence shows sufficiently fresh identity proof for the requested mutation.

A fully privileged authenticated session must not be issued until required additional assurance is complete.

### Pending authentication lifecycle

Conceptually:

`primary proof accepted -> required additional assurance pending -> required factors satisfied -> fully authenticated session`

The implementation may later use a short-lived transaction/challenge object, but its schema and wire model are not ratified by this ADR.

Pending state must be application-scoped, replay-resistant, bounded in lifetime and unable to act as a fully authenticated session.

### MFA consistency and downgrade resistance

Configured MFA requirements apply regardless of which allowed primary method starts sign-in. A user who requires MFA must not bypass it by switching among password, email OTP, phone OTP, social authentication or another primary method.

Two sequential checks are not automatically independent MFA factors. Factor independence and security properties must be evaluated for each implemented factor set.

A passkey is not automatically counted as an additional factor merely because it uses WebAuthn. Later implementation must follow the ratified assurance semantics and the actual authenticator/user-verification guarantees.

Alternative authentication, recovery or enrollment paths may not silently weaken an already configured requirement.

### Sensitive-operation reverification

At minimum, the following require recent identity proof before commit:

- password change;
- primary email or phone change;
- social link or unlink;
- passkey registration or removal;
- MFA enrollment, removal or reset;
- recovery-code regeneration;
- account deletion when introduced.

Trusted server-side representation may include authentication time, last successful reverification time and methods/assurance satisfied where relevant. Client timestamps or client-declared assurance are never authority.

The proof used for reverification must itself satisfy the operation's security requirements; a weaker recovery or alternate method cannot be used merely to downgrade protection.

### Proposed freshness default

Pending Human approval, the proposed simple v1 freshness window is **10 minutes from the most recent successful server-recorded reverification** for the sensitive mutations listed above.

The concrete implementation must fail closed when the freshness evidence is absent, expired, belongs to another application/user/session, or does not satisfy the required method/assurance semantics. This duration is a proposed default, not accepted architecture until Human ratification.

### Enrollment, change and reset

Credential/factor enrollment or replacement is a sensitive state transition. Later implementations must define validation, ownership, uniqueness, retry/replay, concurrency and transaction behavior and must append audit evidence inside the committed mutation boundary.

A reset lifecycle must not silently become an unlink/remove operation that leaves the user below required assurance or without a usable authentication/recovery method.

### Recovery

Recovery is purpose-specific and must not become a permanent weaker password.

- recovery credentials are scoped to their intended recovery lifecycle;
- recovery codes are one-time;
- replay/reuse fails closed;
- successful recovery does not erase configured MFA/security state unless a separately authorized reset lifecycle explicitly does so;
- credential/factor reset is separately audited;
- recovery paths must preserve alternate-method downgrade resistance;
- public failure behavior must avoid unnecessary account enumeration.

Exact recovery-code generation, hashing, count, storage and presentation remain for the recovery implementation slice.

### Last-method and assurance interaction

A credential/factor removal may proceed only when the account retains a usable path consistent with configured assurance requirements. Disabled, revoked, expired or otherwise unusable methods do not count. An operation that would strand the account or silently reduce required assurance is rejected.

### Audit requirements

Future Phase 2 audit vocabulary should cover security-relevant attempted/succeeded/denied events as required by the threat model, including factor enrollment/removal/reset, passkey registration/revocation, recovery credential regeneration/use and reverification success/denial.

Audit facts follow BeeBox conventions: explicit application scope, actor/subject, resource category/reference, outcome, correlation/operation identifier, occurrence time and minimized safe source context. They must not contain passwords, OTPs, recovery codes, provider tokens, credential material or arbitrary raw provider errors.

### Observability

This ADR adds no runtime metrics. Future metrics use fixed bounded operation/outcome vocabularies only. Metric labels must not include email, phone, user ID, application ID, provider subject, credential ID, session ID, IP address, token/code or raw error.

## Human decision required

Decision 2 — ratify or change the proposed reverification/assurance baseline:

- valid primary proof is distinct from full required assurance;
- MFA requirements apply consistently across alternate primary methods;
- sensitive mutations require fresh server-trusted proof;
- proposed v1 freshness default: 10 minutes.

## Consequences

Later sign-in work must support a pending assurance state when needed and may not issue full privilege after only a primary proof. Sensitive account changes become explicitly freshness-bound instead of relying on arbitrary session age.

## Non-goals

No generic policy engine, MFA/TOTP runtime, OTP runtime, passkey runtime, recovery-code implementation, step-up middleware, session schema, migration, OpenAPI route or SDK method is introduced here.