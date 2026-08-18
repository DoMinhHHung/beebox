# ADR 0004 — Phase 2 identity linking and external identity trust

Status: **proposed**

Date: 2026-08-18

Decision owner: Human maintainer

Authority: This ADR is not accepted architecture until the Human maintainer explicitly ratifies it. It preserves accepted ADRs 0001–0003 and does not itself create runtime behavior.

## Context

Phase 1 deliberately excludes social authentication, phone identity, passkeys and account linking. ADR 0002 already establishes that normalized email equality never authorizes account linking or merging. Phase 2 must define identity ownership before provider, phone, passkey or multi-identifier implementation can safely proceed.

`application_instance` remains the root isolation resource. Organization scope is additional only where applicable.

## Proposed decision

### Application-scoped external identity

Every Phase 2 identity and credential belongs to an explicit `application_instance`. The same external identity may independently exist in different applications. An identifier belonging to application A must never select, mutate, link or authenticate a BeeBox user in application B.

### Social provider identity

For social sign-in, `(application_instance, provider, provider_subject)` is the stable provider-account identity. Provider email is an attribute or claim, not the provider-account primary key and not account-link authority.

- an already-linked provider subject may resolve its existing BeeBox user;
- a new provider subject whose email matches an existing BeeBox email must not silently attach to that user;
- provider email changes must not transfer ownership;
- loss of an email claim or `email_verified=true` must not orphan, reassign or silently relink a provider subject;
- provider claims may enrich BeeBox profile/identifier state only through the separately defined verified-identifier lifecycle;
- OAuth access/refresh tokens are not retained merely because the provider returns them. Any future token retention requires a separately reviewed secret-storage lifecycle.

Public conflict behavior must preserve anti-enumeration and must not reveal another user's unnecessary identity details.

### Explicit authenticated linking

The proposed v1 linking flow is:

1. resolve the target user from trusted authenticated session state;
2. require recent reverification under ADR 0005;
3. begin provider or credential proof;
4. validate the proof inside the current application scope;
5. verify the external subject/credential is not owned by another user in that application;
6. atomically attach it to the current user;
7. append required audit evidence in the same correctness boundary.

A client-supplied user ID is never linking authority. Unauthenticated account-link mutation is forbidden. An unauthenticated social sign-in may authenticate an already-linked provider subject but may not attach that subject to an unrelated existing account.

### Deterministic conflicts and concurrency

Future implementations must define and enforce deterministic behavior for:

- provider subject already linked to the current user: idempotent logical success/no duplicate ownership;
- provider subject owned by another user: deny without merging principals or exposing unnecessary information;
- provider verified email equal to an existing BeeBox identifier: require explicit authenticated linking; do not auto-associate;
- two BeeBox users claiming related provider/email state: no implicit merge;
- concurrent claims for one provider subject: one owner at most, enforced by PostgreSQL uniqueness in the application scope rather than by application pre-check only.

No path in this ADR permits principal merge. A future account-merge capability would require its own Human-ratified trust decision.

### Unlink and last-method protection

Removing a login-capable method is a sensitive mutation. It must:

- act only on the authenticated current user in the current application;
- require recent reverification;
- verify the target credential belongs to that user/application;
- reject removal of the last currently usable authentication/recovery path;
- count only methods that are actually usable, not disabled, revoked, expired or otherwise unusable methods;
- preserve configured MFA/assurance requirements so removal cannot create an impossible or silently downgraded state;
- execute atomically and append audit evidence.

### Provider-first account adding a password

Adding a password to a social-first account is authenticated credential enrollment. It requires recent proof under ADR 0005 and uses the existing BeeBox public password policy from ADR 0003. Email lookup may not discover or adopt another account.

### Primary identifiers

Provider profile changes do not automatically change BeeBox primary email or phone. A primary-identifier change must:

- target an identifier belonging to the same application-scoped user;
- complete the identifier-specific verification lifecycle;
- satisfy deterministic uniqueness/conflict rules;
- require recent reverification when sensitive;
- append audit evidence.

### Phone identity

Phone identifiers are application-scoped and must use one reviewed canonical telephone representation suitable for a later E.164-based implementation. Verified and unverified state is explicit.

- phone equality never merges accounts;
- an unverified phone claim never links identities;
- verified-phone uniqueness within an application is deterministic and later database-enforced;
- add/remove/change follows recent-reverification and last-method rules when phone is authentication-capable;
- SMS provider/vendor models never become BeeBox public models.

### Passkey ownership

A passkey is a user-owned authentication credential scoped to the applicable BeeBox application/RP boundary.

- BeeBox stores public credential material only; no private key reaches BeeBox;
- a credential ID cannot belong to multiple users within the same security scope;
- ownership is not transferred by email/provider changes;
- registration/removal requires authenticated and recently reverified account state according to ADR 0005;
- cross-application/RP reuse is not implicitly accepted.

WebAuthn protocol details remain deferred to the passkey implementation slice.

### Audit requirements

Future Phase 2 security mutations must preserve current audit semantics: explicit application scope, actor/subject, resource category/reference, outcome, correlation/operation identifier, occurrence time and minimized safe source context.

Security-relevant linking/unlinking attempts, primary-identifier changes, passkey registration/revocation and equivalent credential ownership changes require audit evidence where the concrete threat model requires attempted/denied/succeeded facts.

Audit/log/metric data must never contain provider tokens, OTPs, recovery codes, password material, passkey private material, arbitrary provider errors, or unnecessary raw email/phone/provider-subject PII.

## Required persistence invariants for later implementation

No schema is added by this ADR. Later storage must enforce at least:

- application-scoped ownership of external identities and credentials;
- provider-subject uniqueness within the application/provider namespace;
- deterministic verified-identifier uniqueness according to the ratified identifier policy;
- passkey credential ownership uniqueness in the applicable security scope;
- concurrency-safe attach/detach transitions.

## Human decision required

Decision 1 — ratify or reject this identity-linking baseline:

- no email-based automatic account linking;
- provider subject is the stable social identity authority;
- linking requires an authenticated current user plus recent reverification;
- conflicts never merge principals implicitly.

## Consequences

Later social, phone, passkey and account-linking PRs cannot infer ownership from mutable claims or client-selected user IDs. Application isolation remains explicit. This conservative model may require an extra user proof in ambiguous same-email cases, trading convenience for takeover resistance.

## Non-goals

This ADR adds no provider adapter, OAuth/OIDC endpoint, account-link code, phone persistence, SMS contract, passkey/WebAuthn runtime, migration, OpenAPI operation, SDK method, account merge, organization behavior or provider-token storage.