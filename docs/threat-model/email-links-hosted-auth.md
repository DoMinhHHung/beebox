# P2.11 secure email links and hosted-auth threat-model delta

This document covers the Phase 2 secure email-link primary authentication flow and the minimal hosted authentication surface served by the same BeeBox Go process. Headless APIs remain the canonical product contract; hosted auth is a first-party client of those boundaries rather than a second identity implementation.

## Email-link authority

Each sign-in link contains a random 32-byte one-time secret. PostgreSQL stores only a domain-separated SHA-256 verifier bound to the exact application, challenge public ID and accepted completion URL. The challenge expires after 10 minutes, has a maximum five failed proofs, a one-minute resend cooldown and at most three issues in a 15-minute window.

Request behavior is anti-enumerating for syntactically valid email input. Unknown/unverified identifiers, cooldown/window suppression and other account-dependent issue states do not become an account inventory oracle. Provider delivery failures map to BeeBox-owned errors and never expose provider response bodies, credentials or the challenge secret.

Successful confirmation is one-time. Concurrent proof attempts converge to at most one consumed challenge/session outcome. Required audit evidence commits in the same transaction as challenge consumption and session or pending-MFA creation; audit failure rolls back all success-side state.

When active TOTP is configured, email-link proof creates only pending-MFA authority. It does not create an ordinary access token, refresh credential or session before the required factor is completed.

## Scanner-safe link layout

The emailed URL places only the public challenge locator and publishable application key in the query string. The one-time secret is placed in the URL fragment. Browsers do not send the fragment in the HTTP request, so an automated mail scanner performing a normal GET cannot redeem the secret server-side.

`GET /auth/email-link` only renders the hosted client. JavaScript reads the fragment locally, removes it from browser history with `history.replaceState`, and then performs the explicit POST confirmation. The server never accepts the email-link secret from a GET/query parameter.

## Hosted mutation boundary

Hosted mutation requests require:

- exact configured hosted `Origin`;
- synchronizer CSRF token equality between a Secure HttpOnly `__Host-` cookie and request header;
- mutation methods only;
- the normal canonical BeeBox application/session/reverification checks underneath the hosted proxy.

Hosted cookies use the `__Host-` prefix with `Secure`, no `Domain`, and `Path=/`. Pending MFA and hosted social context are HttpOnly and are not exposed as JSON authority. The page does not persist tokens in `localStorage` or `sessionStorage`.

Security headers include `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, restrictive `Permissions-Policy`, and a CSP that restricts scripts/styles/connect/form actions to self while disabling objects, framing, base-URI changes, remote images and fonts. Hosted customization is limited to built-in language/theme choices (`en`/`vi`, `system|light|dark`); arbitrary HTML/CSS/JS, remote logo/image URLs and user-supplied translation templates are not accepted.

## Redirect/open-redirect control

Completion destinations are canonicalized and checked against the application's existing exact redirect allowlist before issue and again before hosted completion. Query/fragment-bearing or otherwise non-canonical destinations do not become trusted merely because they were supplied by the browser.

The hosted social flow uses the hosted callback as the provider/client redirect while preserving the application's final allowlisted completion URL inside server-protected context. That context contains the exact application identity, PKCE verifier, final completion URL and bounded timestamps. It is AES-GCM protected with purpose-separated AAD and expires no later than the existing social-attempt TTL. Tampering, expiry or cross-application substitution fails closed before social completion exchange.

Provider callback GET remains scanner/idempotency safe: it renders/returns the provider completion code to the hosted client but does not perform the final one-time BeeBox completion exchange. The hosted client removes callback query authority from history and performs an explicit POST exchange; only then may ordinary BeeBox session authority be returned.

## Provider and retry behavior

Email delivery and social provider I/O inherit the repository's explicit context deadlines/body bounds and safe error mapping. One-time callback/completion/linking/mutation operations are not automatically retried after ambiguous failure. Only the already-reviewed bounded retry behavior for idempotent discovery/JWKS GETs is permitted.

## Primary threats and controls

| Threat | Control/evidence |
| --- | --- |
| Mail scanner consumes sign-in link | Secret is fragment-only; GET never confirms; hosted test `TestHostedEmailLinkGETNeverConsumesSecretAndAssetRemovesFragment`. |
| Stolen database row reveals live link secret | Only domain-separated 32-byte verifier is stored; raw secret is delivery-only. |
| Replay/concurrent confirmation creates multiple sessions | Transactional one-time consumption; `TestEmailLinkConcurrentConsumeCreatesAtMostOneSession`. |
| Audit failure leaves consumed challenge/session | Same transaction; `TestEmailLinkAuditFailureRollsBackConsumptionAndSession`. |
| Cross-application challenge use | Composite scope predicates/FKs and generic failure; `TestEmailLinkFailureBudgetAndCrossApplicationIsolation`. |
| Email link bypasses TOTP | Pending-MFA only with active TOTP; `TestEmailLinkWithActiveTOTPCreatesPendingMFAWithoutSession`. |
| Hosted CSRF/cross-origin mutation | Exact Origin + synchronizer CSRF cookie/header; hosted HTTP tests. |
| Host-cookie prefix silently rejected by browsers | Every `__Host-` cookie uses `Secure`, `Path=/`, no `Domain`; hosted cookie tests. |
| Open redirect after proof | Exact application redirect allowlist is checked at issue and completion. |
| Hosted social PKCE verifier lost or client-tampered | Verifier/final destination live inside short-lived AES-GCM hosted context; tamper/round-trip tests. |
| XSS/customization expands trust surface | Static assets, restrictive CSP, built-in locales/themes only, no arbitrary remote/custom executable content. |

## Non-goals

P2.11 is not a generic page-builder, tenant-supplied JavaScript runtime, CAPTCHA integration, Redis correctness layer or OAuth authorization server. It does not change account-linking semantics, principal ownership or the application-instance trust root.
