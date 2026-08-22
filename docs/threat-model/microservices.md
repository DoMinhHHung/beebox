# Microservice boundary threat-model delta

Status: required security delta for ADR 0008. Existing Phase 1/2 threat models remain authoritative for identity behavior.

## New trust boundary

Public traffic terminates at BeeBox Gateway and is proxied over bounded HTTP to BeeBox Identity Service. Identity remains the authority for application scope, authentication, authorization, Origin/CSRF/redirect checks and security-state mutation. Gateway is not an authorization oracle.

Gateway also establishes the public request-correlation boundary. The public request ID is observability metadata only: it conveys no user, application, tenant or authorization authority.

## Threats and controls

| Threat | Control / required evidence |
| --- | --- |
| Direct public Identity exposure bypasses edge controls | Identity binds to loopback/private interface by default; reference Compose does not publish its port; deployment must restrict public access. Identity still enforces all authn/authz/tenant controls itself. |
| Spoofed forwarding headers | Gateway removes/reconstructs client `Forwarded`/`X-Forwarded-*` metadata and does not treat it as application authority. |
| Request smuggling / hop-by-hop confusion | Go `net/http` parsing is used at both boundaries; Gateway strips hop-by-hop connection metadata and does not synthesize a second business protocol. Conflicting/invalid transport input fails closed. |
| Client-selected request/audit correlation | Gateway ignores inbound `X-Request-ID`, generates a fresh cryptographically random 16-byte / 32-hex public ID and emits exactly one value. A direct Identity caller cannot select audit correlation by supplying a valid-looking public ID. |
| Injection of internal correlation metadata | Gateway strips client copies of `X-BeeBox-Internal-Correlation` and its signature header, signs only its freshly generated ID with HMAC-SHA256 and a dedicated key, and Identity accepts the supplied correlation only after constant-time MAC verification. Missing/invalid proof falls back to a new Identity correlation. |
| Internal correlation-key misuse | `BEEBOX_INTERNAL_CORRELATION_KEY` is a dedicated high-entropy raw 32-byte base64url key. It is not reused for JWT, TOTP, OAuth state, application credentials or database access. Possession of the key authenticates only tracing metadata and cannot bypass application/session/MFA/Origin/CSRF/tenant/authz checks. Key/signature values are never logged or returned. |
| Correlation-ID cardinality abuse | IDs are fixed-size random 32-hex values generated at the receiving trust boundary. Correlation is not accepted from arbitrary client input and remains bounded in logs/metrics. |
| Slow or unavailable Identity upstream | Connect, response-header, whole-request and idle transport lifetimes are bounded; request cancellation propagates; Gateway readiness fails when required upstream readiness fails. Gateway server config rejects deadline ordering where the socket write deadline could pre-empt the documented whole-request timeout response. |
| Gateway timeout mistaken for rollback | A 504 after dispatch does not prove Identity failed to commit. For POST/PUT/PATCH/DELETE the outcome may be unknown. Gateway never auto-retries; clients reuse the same idempotency key when the endpoint supports one, otherwise reconcile authoritative state before deciding to retry. |
| Ambiguous mutation replay | Gateway does not automatically retry ambiguous state-changing requests. Existing endpoint idempotency/replay semantics remain authoritative. |
| Oversized known-length request / resource exhaustion | Gateway can reject a declared Content-Length above the configured limit before reading or dispatching the body. |
| Oversized unknown/chunked request partially mutates upstream | Current Phase 1/2 API bodies are buffered before dispatch using at most `MaxBodyBytes + 1`. Over-limit bodies are closed and rejected with canonical 413 before Identity is invoked. Exact-limit bodies are preserved byte-for-byte. Future true streaming/upload APIs require a separate design instead of bypassing this property. |
| Pre-read cancellation/resource leak | Bounded body pre-read uses the request context and closes the incoming body. Tests require prompt cancellation and no unbounded goroutine/resource behavior. |
| Competing/duplicate public request-ID headers | Identity emits the established request correlation and Gateway normalizes the proxied response with `Header.Set`, so representative Phase 1/2 routes expose exactly one public `X-Request-ID`. Error-body `request_id` must match the header. |
| Credential/cookie/header leakage | Gateway does not log request/response bodies, Authorization values or Cookie/Set-Cookie values. Browser refresh cookies pass through unchanged and are tested for `__Host-`, Secure, HttpOnly, Path=/, no Domain and SameSite=Strict semantics. |
| Canonical error-contract split | Gateway-generated `/v1` 413/502/504 responses use the same nested BeeBox error envelope as Identity with stable codes `request_too_large`, `upstream_unavailable`, `upstream_timeout`; safe messages omit internal hosts, URLs, network errors, credentials and implementation detail. OpenAPI and SDK tests lock the wire shape. |
| OAuth/email-link query leakage | Access logs intentionally omit query strings. OAuth code/state and similar one-time material must not become log or metric labels. |
| Gateway outage | Public traffic is unavailable even if Identity is healthy. Operators restore/replace Gateway; they do not expose Identity publicly as a bypass. |
| Identity/PostgreSQL outage | Gateway readiness becomes false and upstream calls fail safely. Identity readiness remains database-aware. No edge cache becomes correctness authority. |
| Network position treated as tenant authority | Identity resolves trusted application credentials, sessions, membership/authorization state itself. Source address/forwarding metadata and correlation provenance never grant tenant or user authority. |
| Secret propagation through observability | Passwords, OTPs, recovery codes, access/refresh tokens, provider codes/tokens, signing/encryption/correlation keys, correlation signatures and unnecessary PII are prohibited from logs, traces and metric labels. |

## Internal-correlation key rotation

The reference mechanism intentionally uses one dedicated shared key rather than introducing PKI or a service mesh. Rotation must coordinate Gateway and Identity so both sides converge on the same new key. During any mismatch, Identity must reject the supplied proof and mint a fresh local correlation; it must never accept an unverified Gateway claim merely to preserve trace continuity.

A compromised correlation key should be rotated promptly, but compromise does not itself grant BeeBox product authority. The key authenticates only the correlation metadata described above. A deployment where the Gateway -> Identity network is not trusted still needs an appropriate transport confidentiality/authentication design; this HMAC is not a replacement for TLS/mTLS where those are required.

## Residual risks

The reference topology relies on operator-controlled private networking between Gateway and Identity. This PR does not introduce service mesh or mandatory mTLS. Deployments that route internal traffic across an untrusted network must add an appropriate authenticated transport design before exposure.

A Gateway is an additional availability hop. Readiness, bounded failures, canonical errors, authenticated correlation and rollback reduce operational risk but do not remove it.

Bounded pre-dispatch buffering intentionally consumes up to the configured API-body bound per in-flight request. The configured limit and concurrency therefore remain resource-admission controls and must not be increased casually.

## Regression requirements

Gateway integration evidence must preserve Phase 1/2 semantics including application isolation, backend cross-tenant denial, session/JWT/JWKS, browser cookie transport, a passwordless flow and self-service routes. Existing Phase 1/2 negative/security/PostgreSQL suites remain required and must not be removed because the HTTP edge moved.

Corrective boundary evidence additionally requires client request-ID/internal-header spoof rejection, authenticated Gateway -> Identity audit correlation, direct-Identity spoof rejection, exactly-one public request-ID on representative password/email OTP/session-account/passkey/TOTP/recovery/social paths, canonical 413/502/504 error-body/header equality, actual-server timeout behavior, late committed-mutation ambiguity without retry, and unknown-length/chunked body-limit cancellation/cleanup cases.
