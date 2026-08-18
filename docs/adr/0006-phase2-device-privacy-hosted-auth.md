# ADR 0006 — Phase 2 device privacy and hosted authentication trust

Status: **proposed**

Date: 2026-08-18

Decision owner: Human maintainer

Authority: This ADR is not accepted architecture until the Human maintainer explicitly ratifies it. It introduces no hosted UI, database column or runtime redirect endpoint.

## Context

Phase 2 plans device/session UX and hosted authentication. Both can quietly expand the privacy and phishing trust boundary if metadata or redirect semantics are left to feature implementation. BeeBox therefore needs a conservative contract before those features exist.

## Proposed decision

### Device/session metadata minimization

BeeBox does not collect metadata merely for decorative UI. Any persisted device/session metadata must have a documented security or user-facing purpose and an explicit lifecycle.

Conservative baseline:

- no precise location tracking;
- no permanent cross-session fingerprint;
- no third-party fingerprinting infrastructure;
- no collection of new PII without a defined purpose;
- IP address and user-agent, if later persisted, are bounded in use/retention and redacted from inappropriate telemetry;
- a derived device label must come from bounded/minimized metadata and must not become a stable tracking identifier;
- approximate geographic enrichment is deferred unless a later reviewed feature justifies it;
- user-visible metadata must not imply more certainty than the underlying signal provides.

Security timestamps may be retained where needed for session/revocation/investigation semantics, but retention must remain tied to the applicable session/security lifecycle rather than indefinite collection.

No new database columns are authorized by this ADR.

### Device privacy and observability

Logs, traces, audit and metrics must minimize identity metadata. Metric labels must never include IP address, user ID, application ID, session ID or arbitrary device identifier. Raw user-agent strings and IP addresses are not stable metric dimensions.

Audit may include minimized safe source context only when required for investigation and consistent with the retention policy; it must not become a general device-tracking store.

### Hosted authentication redirect boundary

Any future hosted-auth flow must validate redirects server-side against the current application's configured redirect allowlist/boundary.

Required semantics:

- the redirect belongs to the current trusted `application_instance` configuration;
- production redirects use HTTPS;
- explicit localhost HTTP may be allowed only as an isolated development exception;
- matching is exact according to the future reviewed canonical redirect representation, never arbitrary substring/suffix matching;
- wildcards that permit open redirects are forbidden;
- userinfo, fragments and malformed origins/URLs are rejected where applicable;
- browser-supplied redirect/callback values are untrusted input to validate, never authority;
- error redirects use the same validation boundary as success redirects;
- one application's flow cannot substitute another application's redirect target.

Existing ADR 0003 exact-origin semantics remain the browser-origin baseline; a future redirect-url contract may add path-level exact values but may not weaken the application isolation or open-redirect protections above.

### State binding

Generic hosted/social sign-in and explicit authenticated account linking do not have identical state requirements. Both require server-validated flow binding, but account linking additionally carries an already-authenticated BeeBox principal across an external round-trip and therefore must prevent principal/session substitution.

Every future hosted/social authentication attempt must bind state to at least:

- the authentication/provider attempt;
- the trusted application scope;
- the intended validated redirect where applicable;
- the relevant flow/purpose so one flow cannot be substituted for another.

For an **explicit account-link** operation, the state/transaction must additionally bind or securely reference:

- the initiating BeeBox principal/user resolved from trusted authenticated state;
- the initiating authenticated session, or an explicitly equivalent non-substitutable authenticated context;
- purpose = account linking;
- the external/provider proof attempt initiated for that link;
- the required recent-reverification context/evidence from ADR 0005;
- the trusted application scope and validated redirect where applicable.

Raw user IDs, session IDs or other identifiers carried by the client are never link authority merely because they appear in state or callback input. The later concrete representation may be server-stored, signed/integrity-protected or otherwise safely represented; this ADR does not ratify one schema or protocol mechanism.

State/transaction representation must be unpredictable or integrity-protected as appropriate, bounded in lifetime, replay-bounded or one-time where the flow requires it, and validated server-side before security mutation.

For explicit linking, callback/commit must validate the complete initiation binding before attaching any external credential. If the initiating authenticated context has been revoked, expired, substituted, switched to a different principal, moved across applications or otherwise no longer satisfies the link requirements, BeeBox must fail closed. The operation must not continue merely by using a replacement browser session; it must create no link mutation and require a fresh/restarted link flow when appropriate.

Client-declared application identity, redirect, principal, session or assurance never replaces trusted server-side binding.

The exact state schema, persistence, signing/encryption choice and OAuth/OIDC protocol details are deferred to the implementing slice.

### Phishing/open-redirect and link-CSRF defenses

Future hosted-auth UI must not create a generic arbitrary redirector. Invalid, cross-application or non-allowlisted redirects fail safely. Failure handling must not leak provider tokens/codes, session secrets or unnecessary identity details into URLs, logs, audit or telemetry.

An explicit-link callback must also reject account-link CSRF/session-switch substitution: a provider proof initiated while authenticated as principal A cannot be redeemed as authority to attach that provider credential to principal B merely because B is the browser's current authenticated user when the callback arrives. Cross-application substitution fails identically.

### Retention proposal

No new device PII persistence should be introduced until a concrete P2.9 feature defines its purpose and retention. This ADR therefore proposes **defer-by-default** for IP/user-agent/location storage rather than inventing an indefinite retention period.

When later persistence is justified, that PR must define deletion/retention/user visibility and demonstrate that incident/audit needs cannot be met with less data.

## Human decision required

Decision 3 — ratify or change the device metadata/hosted-auth baseline:

- minimal collection only for defined security/user purpose;
- no precise location or fingerprinting by default;
- defer new IP/user-agent/location persistence until a concrete bounded retention lifecycle is reviewed;
- hosted redirects are exact application-scoped allowlisted destinations with the same boundary for success and error flows;
- explicit account-link state remains bound to its initiating principal/session-equivalent and reverification context across the provider round-trip.

## Consequences

Later device/session UX cannot silently create a fingerprinting system, hosted authentication cannot delegate redirect authority to browser input, and explicit linking cannot silently switch its target principal at callback time. Future features may add narrowly justified metadata or redirect/state representations only through explicit reviewed contracts.

## Non-goals

No hosted frontend, OAuth/OIDC provider flow, redirect endpoint, account-link runtime, device-management API, session UI, location service, fingerprinting provider, migration, OpenAPI operation, SDK method or concrete OAuth state schema is introduced here.