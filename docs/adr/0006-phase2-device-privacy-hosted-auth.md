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

A future hosted/social authentication attempt must bind state to at least:

- the authentication attempt;
- the trusted application scope;
- the intended validated redirect;
- the relevant flow/purpose so one flow cannot be substituted for another.

State must be unpredictable or integrity-protected according to the later implementation and must be bounded in lifetime/replay. Client-declared application identity, redirect or assurance does not replace trusted server-side binding.

The exact state schema, persistence, signing/encryption choice and OAuth/OIDC protocol details are deferred to the implementing slice.

### Phishing/open-redirect defenses

Future hosted-auth UI must not create a generic arbitrary redirector. Invalid, cross-application or non-allowlisted redirects fail safely. Failure handling must not leak provider tokens/codes, session secrets or unnecessary identity details into URLs, logs, audit or telemetry.

### Retention proposal

No new device PII persistence should be introduced until a concrete P2.9 feature defines its purpose and retention. This ADR therefore proposes **defer-by-default** for IP/user-agent/location storage rather than inventing an indefinite retention period.

When later persistence is justified, that PR must define deletion/retention/user visibility and demonstrate that incident/audit needs cannot be met with less data.

## Human decision required

Decision 3 — ratify or change the device metadata baseline:

- minimal collection only for defined security/user purpose;
- no precise location or fingerprinting by default;
- defer new IP/user-agent/location persistence until a concrete bounded retention lifecycle is reviewed;
- hosted redirects are exact application-scoped allowlisted destinations with the same boundary for success and error flows.

## Consequences

Later device/session UX cannot silently create a fingerprinting system, and hosted authentication cannot delegate redirect authority to browser input. Future features may add narrowly justified metadata or redirect forms only through explicit reviewed contracts.

## Non-goals

No hosted frontend, OAuth/OIDC provider flow, redirect endpoint, device-management API, session UI, location service, fingerprinting provider, migration, OpenAPI operation or SDK method is introduced here.