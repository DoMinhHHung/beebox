# BeeBox Phase 2 — B2C Exit Evidence

Status: Phase 2 exit candidate on the integration branch. This document records implementation and test evidence. Phase 2 is considered implementation-complete only when the Draft PR body records a successful CI run for the exact final PR head. Merge/Ready decisions remain outside this document and outside the Implementer role.

## Exit matrix

| # | Criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Application/tenant isolation remains the root authorization boundary | PASS | ADR 0001/0004; composite/scoped database predicates and FKs; social, passkey, reverification, session self-service, account-management and email-link cross-application tests. Public locators never become authority. |
| 2 | Passwordless email OTP is purpose-separated, anti-enumerating and replay-safe | PASS | `internal/authentication/email_otp.go`, PostgreSQL email-OTP integration coverage, HTTP contract tests and migration 00012/00013 evolution. |
| 3 | Phone-first signup and verified-phone OTP preserve no-account-before-proof and verified ownership | PASS | phone service/store integration tests, provider adapters, strict E.164 validation and migration 00014 constraints. |
| 4 | Social OAuth/OIDC supports the reviewed eleven providers without importing provider profile authority | PASS | `internal/authentication/social.go`, provider contract suite (including repeated/focused JWKS tests), social PostgreSQL/HTTP integration tests and ADR 0007. |
| 5 | Explicit social linking/unlinking does not merge/adopt/transfer principals | PASS | P2.4A/P2.4B service/store tests, provider-subject/application uniqueness, exact initiating-session binding, last-method checks and audit rollback evidence. |
| 6 | Passkeys/WebAuthn are application/Origin/RP/user scoped and MFA-aware | PASS | `docs/threat-model/passkeys.md`, passkey unit/HTTP/PostgreSQL tests and migration 00018 exact-upgrade/security coverage. |
| 7 | Active TOTP gates every implemented primary method before ordinary session authority | PASS | pending-MFA tagged result, TOTP completion stores/tests, `TestPendingMFAResultContainsNoSessionAuthority`, email-link active-TOTP integration test and migration 00019. |
| 8 | Recovery codes are one-time, bounded and cannot silently remove active TOTP | PASS | `docs/threat-model/recovery-codes.md`, recovery concurrency/replay/audit tests and exact-predecessor migration 00020 coverage. |
| 9 | Generic reverification is independent, purpose/target/session bound and replay-safe | PASS | `docs/threat-model/reverification.md`, PostgreSQL cross-user/cross-app/replay/concurrency/audit tests and exact 00020 -> 00021 migration evidence. |
| 10 | Session self-service is minimized, paginated, tenant scoped and immediately persists revocation | PASS | `docs/session-self-service.md`, `docs/threat-model/session-self-service.md`, session self-service integration tests and migration 00022 exact-upgrade coverage. |
| 11 | Identifier/profile self-service prevents IDOR, implicit account linking and last-method races | PASS | `docs/threat-model/account-management.md`, account-management unit/HTTP/PostgreSQL tests and migration 00023 upgrade/ownership/constraint coverage. |
| 12 | Verified-phone ownership converges correctly under concurrency | PASS | migration 00023 preserves verified-only application-wide uniqueness while allowing unverified cross-user claims and cross-application reuse; account-management store uses scoped ownership predicates. |
| 13 | Identifier pagination and profile data are bounded/minimized | PASS | default 20/max 100 kind-bound opaque cursors; four-field profile model (`display_name`, `given_name`, `family_name`, `locale`) with normalization and database length constraints. |
| 14 | Secure email links are anti-enumerating, short-lived, one-time and MFA-aware | PASS | `internal/authentication/email_link.go`, PostgreSQL concurrent-consume/failure-budget/audit/TOTP tests, migration 00024 and `docs/threat-model/email-links-hosted-auth.md`. |
| 15 | Email-link scanners cannot consume authority through GET | PASS | link secret is fragment-only; GET only renders; explicit POST confirms; `TestHostedEmailLinkGETNeverConsumesSecretAndAssetRemovesFragment`. |
| 16 | Hosted auth is same-process, headless-canonical and hardened against CSRF/XSS/open redirect | PASS | `internal/httpapi/hosted.go`, static hosted assets/tests, exact Origin + synchronizer CSRF, restrictive CSP, `__Host-` cookie invariants, exact application redirect policy, built-in locales/themes only. |
| 17 | Hosted social preserves PKCE/final destination across provider round-trip without browser storage authority | PASS | `internal/authentication/social_hosted_state.go` AES-GCM purpose-separated context; hosted round-trip/tamper tests; callback GET does not perform final one-time exchange. |
| 18 | Provider/network failure paths are bounded and fail closed | PASS | SMTP/SMS/social adapters use context deadlines/body limits/safe BeeBox errors; one-time mutations/callback/exchanges are not blindly retried; focused OIDC/JWKS tests exercise the accepted bounded discovery/JWKS behavior. |
| 19 | Security-state cleanup is bounded and not a correctness dependency | PASS | `internal/platform/maintenance/cleanup.go` caps each category; integration tests cover batching/cancellation, passkeys, recovery/social link and email-link cleanup; proof paths independently enforce expiry/consumption. |
| 20 | Required security audit writes share the correctness transaction | PASS | passkey, TOTP, recovery, reverification, session self-service, account-management, email-link and social integration tests inject audit failures and verify rollback. |
| 21 | Clean install and exact predecessor migrations are covered | PASS | ordered migrations through 00024, clean/idempotent/concurrent migration tests plus exact upgrade tests for P2.5–P2.11 migrations. |
| 22 | OpenAPI and Go SDK track the public headless surface | PASS | `api/openapi/openapi_test.go`, feature-specific OpenAPI tests, `sdk/go` feature clients/tests, and CI contract gates. Hosted HTML is intentionally not a second OpenAPI contract. |
| 23 | Privacy boundary excludes device/location/fingerprint trust | PASS | ADR 0006, session/account models and threat-model deltas; no IP/user-agent/location/hardware/remembered-device authority introduced by Phase 2. |
| 24 | PostgreSQL remains correctness source; Redis/CAPTCHA are not required | PASS | all replay/uniqueness/admission/transaction invariants are database-backed; Phase 2 adds no Redis correctness dependency or CAPTCHA vendor trust boundary. |

## Final exact-head CI gate

The Phase 2 implementation checkpoint is valid only when the exact final Draft PR head passes every substantive repository gate with no required step skipped:

- `gofmt -l .` returns no files;
- `go vet ./...`;
- `govulncheck ./...`;
- `go test ./api/openapi`;
- `go test ./sdk/go`;
- `go test ./internal/authentication/socialprovider -count=1`;
- `go test ./internal/authentication/socialprovider -count=20`;
- focused OIDC/JWKS rotation repetitions and social-provider race coverage required by CI;
- `go test ./...`;
- PostgreSQL 17 integration suite, including the exact P2.8 reverification predecessor probe and all migration/authentication/session/HTTP/maintenance packages selected by CI;
- `go test -race ./...`.

The Draft PR body is the external checkpoint ledger for the exact head SHA and CI run ID so this tracked file does not need to be mutated after CI and invalidate its own evidence.

## Rollout and rollback

BeeBox serve mode does not auto-migrate. Apply reviewed migrations explicitly before deploying code that depends on them. Migrations are forward-only; do not edit already-merged migrations or attempt destructive automatic rollback. If application rollout must be reverted after a compatible additive migration, roll back the application binary/configuration while retaining the forward-compatible schema, then correct schema issues with a new reviewed roll-forward migration.

Hosted auth is enabled only with a configured canonical hosted origin. Social/provider capabilities remain optional and fail startup closed when explicitly configured with invalid required trust material. Existing non-social/non-hosted flows remain available when those optional capabilities are not configured.

## Explicit non-goals after Phase 2

Phase 2 does not claim principal/account merge, cross-application identity transfer, provider-side consent/token revocation for unlink, OAuth/OIDC authorization-server behavior, organizations/enterprise federation, billing, arbitrary hosted-page JavaScript/CSS/templates, trusted-device scoring, global JWT denylisting, tamper-proof/compliance-grade audit storage or compliance certification.

These are future product/architecture decisions and must not be inferred from the Phase 2 implementation.
