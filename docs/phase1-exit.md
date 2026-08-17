# BeeBox Phase 1 — B2C Exit Evidence

Status: Checkpoint 5 exit candidate. This document records code/test evidence on the checkpoint branch. Phase 1 is not declared complete until this checkpoint is Human squash-merged and exact `main` post-merge CI is green.

## Exit matrix

| # | Criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Application/instance isolation | PASS | `docs/adr/0001-application-instance-root.md`; application-scoped FKs/queries; cross-app tests in `internal/applicationinstance/postgres`, `internal/authentication/postgres`, `internal/session/postgres/management_integration_test.go`, and `internal/httpapi/e2e_integration_test.go`. |
| 2 | Application credentials: publishable + secret, rotation, revoke, scoped verification | PASS | `internal/applicationinstance/integration.go`, `internal/applicationinstance/postgres/integration_store.go`, operator CLI tests and application PostgreSQL integration tests. Secret plaintext is one-time output; verifier only is persisted. |
| 3 | Users + verified email identifiers | PASS | `internal/identity`, migrations 00003/00004/00007, identity PostgreSQL integration tests and email-verification integration tests. |
| 4 | Reachable email/password signup: password policy + idempotency | PASS | `internal/httpapi/httpapi.go`, `internal/authentication/public_signup.go`, `internal/authentication/postgres/public_signup_*`, and `internal/httpapi/e2e_integration_test.go`. |
| 5 | Reachable email OTP verification: delivery, replay, expiry, attempts | PASS | `internal/authentication/email_verification.go`, PostgreSQL verification tests, SMTP adapter, public verification adapter and Phase 1 HTTP E2E test. |
| 6 | Email/password signin: anti-enumeration, rate limit, verified identifier | PASS | `internal/session/service.go`, `internal/session/postgres/store.go`, session integration tests and public session HTTP tests. Unknown identifiers take dummy password-verifier work. |
| 7 | Password reset lifecycle + session revocation | PASS | `internal/authentication/password_reset.go`, `internal/authentication/postgres/password_reset_store.go`, reset integration tests, public reset adapter and Phase 1 HTTP E2E reset path. |
| 8 | Sessions: create, inactivity/absolute expiry, current, refresh, revoke, signout | PASS | `internal/session`, `internal/session/postgres`, `internal/session/management.go`, `internal/httpapi/session_management.go`, scoped management integration tests and HTTP E2E. |
| 9 | Secure cookie + bearer transport | PASS | `internal/httpapi/session.go` tests exact `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, application-specific `__Host-` cookie behavior; bearer access is used for current/signout. Tokens are not accepted in query parameters. |
| 10 | JWT/JWKS: strict validation, rotation model, offline revocation limitation | PASS | `internal/session/token.go` and tests; `sdk/go/verifier.go`/tests enforce EdDSA, `kid`, issuer, audience, signature and time claims with bounded JWKS cache/refresh. README/threat model document offline revocation lag. |
| 11 | Minimal Go SDK | PASS | `sdk/go/client.go` and tests cover signup, verification, signin, current session, refresh, signout, reset, backend get/revoke; `sdk/go/verifier.go` provides bounded offline access-token verification without blind refresh-token retries. |
| 12 | OpenAPI 3.1 | PASS | `api/openapi/v1.yaml` covers all reachable Phase 1 routes and auth schemes without internal BIGINT/database models; `api/openapi/openapi_test.go` is an explicit CI contract gate. |
| 13 | Negative/security tests | PASS | Existing unit/integration suites plus HTTP E2E cover duplicate/no-auto-link, cross-app scope, OTP/reset replay/attempts, JWT validation, refresh replay, password reset session revocation and safe public errors. |
| 14 | Audit events | PASS | `internal/audit`, registration/verification/session/reset transactional stores and integration assertions. Required security-state mutations commit their audit facts in the same correctness transaction; no secret/PII payload is introduced. |
| 15 | Operational metrics | PASS | `internal/metrics`, `internal/httpapi/metrics.go`, `internal/authentication/metricsdelivery`: bounded operation/outcome counters, SMTP outcome, and database pool occupancy gauges. Email, user/session/app IDs, token/JTI, credential IDs and raw errors are rejected as labels. |
| 16 | Documented local setup | PASS | `compose.yaml` provides synthetic PostgreSQL 17 and Mailpit dependencies; README quickstart documents migrate, key generation, application bootstrap, local SMTP/issuer configuration and Phase 1 lifecycle. |
| 17 | No cross-tenant access | PASS | Root scope remains `application_instance`; composite/scoped FKs and query predicates plus adversarial tests prevent cross-application email, challenge, session, secret-key and reset access. |

## CI exit gate

The checkpoint is acceptable only when the exact PR head passes all repository gates:

- `gofmt -l .` returns no files;
- `go vet ./...`;
- `go test ./api/openapi`;
- `go test ./sdk/go`;
- `go test ./...`;
- PostgreSQL integration suite including `./internal/httpapi`;
- `go test -race ./...`.

The final Human merge must then be followed by a successful exact-main CI run before Phase 1 may be called complete.

## Security boundaries that remain Phase 2+

Phase 1 does not claim social auth, MFA, passkeys, account linking, organizations, machine authentication, webhooks, billing, OAuth/OIDC authorization-server behavior, a global JWT denylist, tamper-proof/compliance-grade audit storage, or compliance certification.
