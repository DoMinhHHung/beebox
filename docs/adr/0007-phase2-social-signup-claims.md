# ADR 0007: Phase 2 social signup claims and principal creation

- Status: accepted
- Date: 2026-08-18
- Human authority: ratified before P2.3 implementation
- Human amendment: 2026-08-19 — expand the fixed P2.3 provider vocabulary from ten to eleven by adding `slack`; `facebook` remains in scope. This amendment changes provider breadth only and does not alter identity ownership, provider-email non-authority, token handling, account-linking, or P2.4 boundaries below.

## Context

P2.3 adds browser social authentication for a fixed provider set. ADR 0004 already establishes `(application, provider, provider_subject)` as the ownership authority for an external identity and explicitly rejects provider-email equality as account-link authority. ADR 0005 defines social proof as primary authentication without pre-deciding future MFA or step-up policy. ADR 0006 defines the exact application-scoped redirect and state-binding requirements.

P2.3 still required a Human product/trust decision for the case where a successfully verified provider subject has never been linked in the current BeeBox application.

## Decision

For P2.3, when a verified `(application, provider, provider_subject)` does not already exist, BeeBox may create a new application-scoped BeeBox user and attach exactly that verified external identity to the new user. This is normal social signup and uses the same provider-proof lifecycle as social sign-in.

Provider email is non-authoritative in P2.3:

- provider email is not account-link authority;
- P2.3 does not create an `email_identifiers` row from a provider email claim;
- P2.3 does not mark a BeeBox email verified from a provider email claim;
- P2.3 does not update or transfer an existing BeeBox email identifier;
- P2.3 does not persist provider email for profile convenience;
- equality between a provider email and an existing BeeBox email does not attach, merge, adopt, or transfer either principal.

Therefore a new verified provider subject creates a separate BeeBox principal even when the provider returns an email equal to an email identifier already owned in that application.

If `(application, provider, provider_subject)` already exists, BeeBox resolves exactly the existing external-identity owner. It does not create another principal and does not mutate email identity.

P2.4 explicit authenticated linking is the only future path authorized for attaching a new external identity to an existing BeeBox user. P2.3 does not implement that path.

## Provider set

The P2.3 public provider vocabulary is exactly:

- `google`
- `apple`
- `microsoft`
- `github`
- `gitlab`
- `facebook`
- `slack`
- `discord`
- `linkedin`
- `x`
- `tiktok`

These are protocol adapters behind one BeeBox-owned social-auth lifecycle. This ADR does not authorize provider-specific account models, provider-specific persistence ownership, custom OIDC, enterprise SSO, or additional providers. Adding Slack does not replace Facebook and does not resolve or weaken any provider-specific protocol evidence gate.

## Security consequences

- A provider subject is authoritative only after the configured provider protocol proof succeeds.
- Provider email, name, avatar, and other profile claims are discarded unless a protocol needs a claim transiently for proof correctness.
- Provider access, refresh, and ID tokens are not BeeBox public/session credentials and are not persisted or exposed to the application.
- Ownership uniqueness remains database-enforced per `(application, provider, provider_subject)` and concurrent first-use callbacks must converge without orphan principals.
- Completion of a provider callback does not directly issue a BeeBox session to a browser redirect. A short-lived one-time BeeBox completion grant bound to client S256 PKCE must be exchanged before ordinary session issuance.
- ADR 0004, ADR 0005, and ADR 0006 remain authoritative and are not weakened by this record.
