# Initial BeeBox Threat Model

> Status: repository-owned threat model for the Phase 1 B2C exit candidate.
> Governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, and accepted ADRs 0001–0003.
> Phase 1 is not declared complete until Checkpoint 5 is Human squash-merged and exact `main` post-merge CI is green.

## 1. Scope and trust model

BeeBox is one Go modular monolith with PostgreSQL as the correctness source of truth. `application_instance` is the root isolation boundary. Email identity is application-scoped and equal email values never authorize account linking or merging. BeeBox Phase 1 is not an OAuth/OIDC authorization server.

The reachable Phase 1 surface covers email/password signup, email ownership verification, verified-email/password signin, session creation/current-state/refresh/revoke/signout, Ed25519 access JWT/JWKS, password reset, backend secret-key session management, and bounded operational metrics. The minimal Go SDK consumes this BeeBox-owned surface and can verify access tokens offline from JWKS.

No Redis, queue, outbox, distributed transaction, service extraction, hosted mutation or global JWT denylist is required for Phase 1 correctness.

## 2. Assets and secret/PII handling

| Asset | Requirement |
| --- | --- |
| Application scope | Selected from verified publishable/secret integration context and included in every identity/session/reset lookup or mutation. |
| Email | PII; excluded from audit facts, stable errors, logs and metrics labels introduced by these flows. |
| Password | Raw input transient only; shared public policy runs before Argon2id hashing. |
| Password/OTP/reset verifiers | Sensitive verifier material; never returned or logged. |
| Application secret | Random high-entropy plaintext returned once; verifier only persisted. |
| Refresh credential | Random secret stored only as verifier hash; one-time rotation. |
| Access JWT | Short-lived bearer credential; never logged/audited/used as a metric label. |
| Signing private key | Configuration secret only; never stored in PostgreSQL or published in JWKS. |
| Audit facts | Required security-state facts commit inside the mutation correctness transaction. |
| PostgreSQL/backups | Privileged boundary containing PII and credential-derived verifier material. |

## 3. Public application trust and tenancy

Publishable keys are intentionally non-secret and establish application integration context only. They grant no user/backend/admin authority. Secret keys establish backend application authority only after verifier comparison and revocation checks. Public IDs (`app_`, `usr_`, `ses_`, `cred_`) are opaque locators; parsing or possessing one is not authorization.

Frontend/backend routes and persistence always combine the trusted application with the target resource. Backend session lookup/revoke uses secret-key-derived application scope plus session public ID. Cross-application tests prove app B cannot inspect/revoke app A session state.

Exact configured origins remain the browser/CORS boundary. Credentialed browser flows never use wildcard Origin authority. Refresh cookies are application-specific `__Host-` cookies with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain attribute.

## 4. Password, signup and email verification

Public password establishment/reset uses one shared policy: NFC normalization, 15–128 Unicode code points, safe internal byte bound, no silent trim, no composition requirement and repository-owned common/expected-password blocking. Low-level Argon2id remains a separate internal primitive.

Signup is application-scoped, idempotent and anti-enumerating for duplicate account state. Duplicate normalized email never auto-links, adopts or merges another account.

Email verification proves control of the mailbox only. It is not authentication, MFA, session establishment or account-link authorization. Verification uses six random ASCII decimal digits, verifier-only persistence, 10-minute expiry, five failed attempts, 15-minute issue window, three issues per window, 60-second cooldown, generation rotation and single-use consumption. Success atomically sets `verified_at`, consumes the challenge and appends audit evidence.

SMTP delivery happens after challenge/audit commit. Ambiguous provider failure does not erase the security fact; no automatic retry/outbox is introduced.

## 5. Signin and online abuse

Signin lookup is application + normalized email scoped and requires verified email state. Unknown identifiers execute dummy Argon2 work so the obvious no-user path does not skip verifier cost. Public invalid-credential behavior does not distinguish unknown account, unverified identifier, missing credential or wrong password.

PostgreSQL-backed application/identifier attempt limits bound obvious online abuse without storing raw email solely for rate limiting. Argon2 remains intentionally expensive, so reachable deployments still need capacity planning and external volumetric protection; Phase 1 does not claim DDoS immunity.

Password credential generation is rechecked when creating a session. A concurrent password reset therefore cannot create a surviving session from a stale password snapshot: reset-first causes generation mismatch; signin-first creates a session that the reset transaction subsequently revokes.

## 6. Sessions, refresh and backend session management

Sessions have 30-day absolute and seven-day inactivity lifetimes. Refresh credentials are one-time random secrets stored by verifier hash. Successful refresh consumes the old credential, creates a replacement, updates activity and audits atomically. Reuse of an already-consumed refresh credential revokes the owning session and records replay/revocation evidence.

Ambiguous refresh network failure is not hidden by automatic retry. Clients may need reauthentication instead of replaying a potentially consumed credential.

`GET /v1/sessions/current` validates both the access JWT and persisted session state, so BeeBox observes revocation immediately. Current-session signout and backend secret-key revoke update persisted session state and append audit evidence. Backend secret-key operations cannot cross application scope.

## 7. JWT/JWKS and offline verification

Access tokens are five-minute Ed25519/JOSE EdDSA JWTs. Validation fails closed for wrong algorithm, missing/unknown `kid`, bad signature, wrong issuer/audience, invalid typed user/session IDs, expiry or premature use, with at most 30 seconds of clock skew. JWTs contain no Phase 1 role/permission/org claims.

JWKS publishes active and retiring public Ed25519 material only; private `d` material is rejected. Signing private material is configuration-only. Retiring public keys remain an operational rotation responsibility for at least access-token lifetime plus skew after signing stops.

The Go SDK verifier uses a bounded HTTP client, concurrency-safe JWKS cache and at most one controlled refresh for an unknown key ID before failing. It never changes the token algorithm allowlist based on server input.

Offline verifiers cannot observe immediate database revocation. Five-minute access-token lifetime bounds the stale-auth window; BeeBox makes no global denylist claim.

## 8. Password reset/recovery

Reset request is anti-enumerating whether email is unknown, unverified, ineligible, suppressed, rate-limited or affected by delivery ambiguity. Eligible reset codes are dedicated eight-digit random decimal secrets with verifier-only persistence, 10-minute TTL, five attempts, 15-minute issue window, three issues per window and 60-second cooldown.

Final confirmation verifies code/new-password work outside the long transaction, then rechecks application scope, verified email, challenge generation/state, expiry, attempt budget and password credential generation under the final correctness transaction.

Wrong code commits failed-attempt increment and denied audit together. Success atomically replaces the password verifier, increments credential generation, consumes/clears the reset challenge, revokes all current sessions and appends reset-success audit. Reset replay/stale generation cannot repeat the transition.

Already-issued stateless access JWTs may remain cryptographically valid for offline consumers until short expiry even after reset; BeeBox current-state endpoints see revocation immediately.

## 9. Audit and privacy

Security mutations keep required audit evidence inside their transaction: registration, verification issue/deny/success, signin/session creation, refresh/replay, session revoke/signout and password reset issue/deny/success.

Audit facts retain application scope, actor meaning, subject where known, action, resource category, outcome, correlation, occurrence time and safe source. They contain no email, password/hash, OTP/reset code/verifier, application secret, refresh credential, access JWT or signing private key. Storage is append-oriented at application semantics; tamper-proof/compliance-grade storage is not claimed.

## 10. Operational metrics and observability

`GET /metrics` exposes fixed-vocabulary operation/outcome counters, SMTP delivery outcome, and bounded PostgreSQL pool acquired/idle/total/max connection gauges. It does not label by email, user/session/application ID, token/JTI, credential ID or raw error. Deployment operators must protect the metrics endpoint at the network/ingress boundary appropriate to their environment.

Metrics are observability only and never a correctness dependency.

## 11. Reproducible local boundary

`compose.yaml` supplies synthetic PostgreSQL 17 and Mailpit dependencies. Operator commands explicitly migrate, generate Ed25519 configuration and bootstrap application credentials/origins. No production credential is required for repository verification. Serve mode never auto-migrates and repository work does not mutate hosted infrastructure.

## 12. Residual threat table

| Threat | Current control / residual risk |
| --- | --- |
| Database/backup compromise | Password/OTP/reset/refresh/application-secret verifiers remain sensitive offline targets; backups require privileged protection. |
| Online password/Argon2 exhaustion | Request limits and dummy-work consistency reduce obvious abuse/timing signals; volumetric protection/capacity remain operational concerns. |
| Signup/signin/reset enumeration | Public responses collapse account-sensitive distinctions; timing side channels require continued regression testing. |
| Email/SMTP compromise | Verification/reset prove mailbox control only; provider compromise can expose delivered codes. |
| OTP/reset guessing | Short TTL, bounded attempts/issues/cooldowns and verifier-only storage. |
| Reset/signin race | Credential-generation recheck plus all-session reset revocation. |
| Refresh theft/replay | One-time rotation and replay-triggered session revoke; ambiguous successful response loss can force reauthentication. |
| Access-token theft | Short-lived bearer token remains usable until expiry for offline consumers; no global denylist. |
| XSS/CSRF | HttpOnly refresh cookie, SameSite=Strict and exact Origin reduce cookie abuse; XSS can still act with page authority. |
| Signing-key compromise | Requires secure configuration distribution and rotation; private material is absent from DB/JWKS. |
| Metrics exposure | No PII/secret labels, but endpoint still reveals operational state and should be network-protected. |

## 13. Phase 2+ exclusions

Phase 1 does not claim social auth, MFA/passkeys, organizations, account linking, machine authentication, generic account recovery beyond email/password, webhooks, billing, OAuth/OIDC authorization-server behavior, a global JWT denylist, distributed infrastructure, compliance certification or tamper-proof audit storage.

## 14. Evidence map

- `docs/phase1-exit.md` — 17-criterion exit matrix.
- `api/openapi/v1.yaml` and `api/openapi/openapi_test.go` — complete public Phase 1 contract and deterministic CI gate.
- `sdk/go` — minimal client and strict offline access-token verifier tests.
- `internal/httpapi/e2e_integration_test.go` — actual HTTP + PostgreSQL lifecycle: signup → verification → signin → current → refresh → signout and password reset → credential replacement.
- `internal/session/management.go`, `internal/session/postgres/management.go`, and scoped tests — current/backend session state and revoke behavior.
- `internal/metrics` and `internal/authentication/metricsdelivery` — bounded operational metrics without identity/secret labels.
- `compose.yaml` and `README.md` — reproducible local dependencies and lifecycle instructions.
- `.github/workflows/ci.yml` — format, vet, OpenAPI, SDK, unit, PostgreSQL HTTP/E2E integration and race gates.
