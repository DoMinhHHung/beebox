# Microservice boundary threat-model delta

Status: required security delta for ADR 0008. Existing Phase 1/2 threat models remain authoritative for identity behavior.

## New trust boundary

Public traffic terminates at BeeBox Gateway and is proxied over bounded HTTP to BeeBox Identity Service. Identity remains the authority for application scope, authentication, authorization, Origin/CSRF/redirect checks and security-state mutation. Gateway is not an authorization oracle.

## Threats and controls

| Threat | Control / required evidence |
| --- | --- |
| Direct public Identity exposure bypasses edge controls | Identity binds to loopback/private interface by default; reference Compose does not publish its port; deployment must restrict public access. Identity still enforces all authn/authz/tenant controls itself. |
| Spoofed forwarding headers | Gateway removes/reconstructs client `Forwarded`/`X-Forwarded-*` metadata and does not treat it as application authority. |
| Request smuggling / hop-by-hop confusion | Go `net/http` parsing is used at both boundaries; Gateway strips hop-by-hop connection metadata and does not synthesize a second business protocol. Conflicting/invalid transport input fails closed. |
| Correlation-ID injection or cardinality abuse | Gateway accepts only bounded valid request IDs and otherwise generates its own. IDs are not authorization data and are bounded labels/log fields. |
| Slow or unavailable Identity upstream | Connect, response-header, whole-request and idle transport lifetimes are bounded; request cancellation propagates; Gateway readiness fails when required upstream readiness fails. |
| Ambiguous mutation replay | Gateway does not automatically retry ambiguous state-changing requests. Existing endpoint idempotency/replay semantics remain authoritative. |
| Credential/cookie/header leakage | Gateway does not log request/response bodies, Authorization values or Cookie/Set-Cookie values. Browser refresh cookies pass through unchanged and are tested for `__Host-`, Secure, HttpOnly, Path=/, no Domain and SameSite=Strict semantics. |
| OAuth/email-link query leakage | Access logs intentionally omit query strings. OAuth code/state and similar one-time material must not become log or metric labels. |
| Gateway outage | Public traffic is unavailable even if Identity is healthy. Operators restore/replace Gateway; they do not expose Identity publicly as a bypass. |
| Identity/PostgreSQL outage | Gateway readiness becomes false and upstream calls fail safely. Identity readiness remains database-aware. No edge cache becomes correctness authority. |
| Network position treated as tenant authority | Identity resolves trusted application credentials, sessions, membership/authorization state itself. Source address/forwarding metadata never grants tenant or user authority. |
| Oversized request / resource exhaustion | Gateway enforces a bounded request-body limit and HTTP server/transport timeouts; Identity retains its own decode/body and provider bounds. |
| Secret propagation through observability | Passwords, OTPs, recovery codes, access/refresh tokens, provider codes/tokens, signing/encryption keys and unnecessary PII are prohibited from logs, traces and metric labels. |

## Residual risks

The reference topology relies on operator-controlled private networking between Gateway and Identity. This PR does not introduce service mesh or mandatory mTLS. Deployments that route internal traffic across an untrusted network must add an appropriate authenticated transport design before exposure.

A Gateway is an additional availability hop. Readiness, bounded failures, correlation and rollback reduce operational risk but do not remove it.

## Regression requirements

Gateway integration evidence must preserve Phase 1/2 semantics including application isolation, backend cross-tenant denial, session/JWT/JWKS, browser cookie transport, a passwordless flow and self-service routes. Existing Phase 1/2 negative/security/PostgreSQL suites remain required and must not be removed because the HTTP edge moved.
