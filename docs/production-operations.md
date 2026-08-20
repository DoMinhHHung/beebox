# BeeBox production operations runbook

This runbook describes production responsibilities that repository code cannot safely choose for every deployment. It does not perform deployment, hosted migration, IAM, secret-manager, backup, or network changes.

## PostgreSQL

Production PostgreSQL must not reuse `compose.yaml` development credentials. Use a separately managed production role model and TLS appropriate to the deployment environment. BeeBox serve mode never auto-migrates; reviewed schema changes are applied explicitly with `beebox migrate` before code that depends on them.

Backups are an operator responsibility. Production plans should include encrypted backups, point-in-time recovery where supported, an explicit retention owner, and periodic restore drills. RPO and RTO are deployment/business decisions and are intentionally not invented by BeeBox. Forward-only migrations remain the repository policy: after production data depends on a schema, corrections use reviewed roll-forward migrations rather than destructive automatic rollback.

## Ed25519 signing keys

Signing private keys must not live in the repository, database merely for convenience, images, or logs. Production deployments should source active private material from an appropriate secret manager and separately configure retiring public verification keys.

BeeBox access tokens have a five-minute lifetime and allow at most 30 seconds of clock skew. When rotating keys, stop signing with the old key only after the new active key is deployed, and keep the old public verification key configured for at least the maximum access-token lifetime plus accepted skew after signing stops. JWKS is intentionally public; do not place application authentication in front of `/.well-known/jwks.json`, because offline JWT verification requires public verification material.

If a signing private key is suspected compromised: remove it from active signing, introduce a new active key, preserve non-compromised verification overlap as needed, assess whether sessions must be revoked/reauthenticated, and preserve security audit evidence. Already-issued tokens signed by a compromised key may require a stronger operational response than normal rotation.

## Application credential compromise

Publishable keys are non-secret application context selectors. Secret application credentials establish backend application scope and must be protected as secrets. A suspected secret-key compromise should use the existing trusted operator credential rotation/revocation path. Determine whether affected user sessions also require revocation based on what the credential could access; do not infer user authorization merely from a credential identifier.

New secret values and generated signing private material are intentional one-time command output. Do not capture them in structured application logs.

## TOTP secret-encryption keys

TOTP setup secrets are encrypted with the bounded keyring configured by `BEEBOX_SECRET_ENCRYPTION_KEYS` and `BEEBOX_SECRET_ENCRYPTION_ACTIVE_KEY_ID`. Each key entry is `key-id:base64url-raw-32-byte-key`; entries are comma separated, key IDs are unique and the total keyring is limited to eight keys. Store root keys in an appropriate secret manager, never in the repository, image, database, command output capture or application logs.

Rotation is additive:

1. generate a new independent 32-byte root key and add it to every instance's keyring while retaining all historical keys;
2. deploy and verify that every instance can start with the expanded keyring;
3. change the active key ID to the new key on every instance; new enrollments now use it;
4. retain an old key while any `totp_credentials` or unconsumed `totp_enrollments` envelope references it;
5. re-encrypt or replace all remaining referenced credentials under a separately reviewed operation before removing the old key;
6. remove the historical key only after the persisted reference inventory is empty on every environment and backup/restore requirements have been addressed.

BeeBox startup reads the persisted version/key-ID inventory and fails closed when ciphertext references a missing key or unsupported version. This intentionally makes premature key removal an availability failure instead of silently losing or bypassing MFA. An invalid keyring also fails startup. Never "fix" readiness by deleting TOTP rows, disabling MFA or editing ciphertext in a hosted database.

If a root key may be compromised, stop treating ordinary overlap as sufficient: introduce a new active key, assess exposure of encrypted seeds and backups, require affected users to replace TOTP credentials through the authorized recovery lifecycle, preserve audit evidence and follow the deployment's incident process. Removing the compromised key before referenced credentials are safely replaced only locks users out; it does not revoke knowledge already obtained by an attacker.

## KDF resource admission

Argon2id remains the verifier primitive for passwords and the current short-lived email/reset challenge verifiers. Each operation uses 64 MiB of Argon2 memory with the Phase 1 parameters. BeeBox therefore has a separate process resource-admission boundary in addition to PostgreSQL abuse rate limits.

`BEEBOX_KDF_CONCURRENCY` controls the maximum concurrently running expensive KDF operations. The default is `2`, corresponding to about 128 MiB of Argon2 working memory before ordinary process/runtime overhead. This is a conservative default, not a universal production sizing recommendation. Operators must choose a bounded value from observed CPU/memory limits; configuration outside `1..64` is rejected. The implementation also bounds waiting admission rather than permitting an unbounded process queue.

PostgreSQL rate limits are still the distributed abuse-control authority. Process KDF admission only protects one BeeBox process and must not be treated as tenant/authentication correctness state.

## Security-state cleanup

Run bounded cleanup explicitly when appropriate:

```sh
go run ./cmd/beebox cleanup-security-state
```

Each invocation deletes at most 500 rows from each eligible category:

- expired `public_auth_rate_limits` rows;
- expired `public_auth_idempotency` rows;
- expired or consumed email-verification challenges;
- expired or consumed password-reset challenges;
- expired or consumed TOTP enrollments;
- expired or consumed pending-MFA authentication transactions;
- invalidated recovery-code sets that are no longer referenced by a pending TOTP replacement;
- expired TOTP-enrollment/recovery-regeneration admission windows.

Execution is repeatable, bounded per category and cancellation-aware. Live challenge/idempotency/rate-limit rows, active recovery sets and live admission windows are not eligible. Correctness never depends on cleanup: proof paths independently enforce expiry, invalidation and consumption. `audit_events` are never pruned by this command.

### OPEN SECURITY DECISION — session/refresh retention

This command deliberately does **not** delete sessions or `session_refresh_credentials`. Phase 1 requires reuse of a consumed refresh credential to revoke the session, but the current public/security contract does not ratify a minimum replay-detection retention interval. Deleting consumed refresh credentials could turn a detectable replay into an ordinary unknown-token failure. Define that retention window explicitly before adding session/refresh pruning.

### OPEN SECURITY DECISION — short-lived code verifier

Email verification uses six decimal digits and password reset uses eight decimal digits, with short TTLs, bounded attempts and request admission. Their verifier material currently uses the same reviewed Argon2id envelope as password-derived verifier material. Keeping Argon2id preserves additional resistance after database/backup compromise, and the new pre-KDF/process admission controls bound its online resource cost.

Do not replace this with plain SHA-256, plaintext, reversible encryption, or a keyed construction without separately reviewing offline-attack consequences and, for a keyed verifier, the new server-key/pepper lifecycle and compatibility of outstanding challenges.

## Metrics

`GET /metrics` intentionally exposes operational information and remains PII/secret-free. Production deployments should restrict scrape access at an appropriate network, proxy, or service boundary rather than adding application authentication that would distort the public product trust model.

Never add email, user/session/application identifiers, credentials, tokens/JTI, IP addresses, or arbitrary error strings as metric labels. Use only bounded operation/outcome vocabulary.

## Branch protection — MANUAL PRODUCTION GATE

During this hardening campaign the connected GitHub App received `403 Resource not accessible by integration` from the `main` branch-protection endpoint, so repository settings were not changed or guessed in code.

Before treating the repository as production-governed, a repository administrator should verify/configure at minimum:

- PR-based changes to `main`; no accidental direct feature pushes;
- BeeBox CI required before merge;
- required-check/branch-update behavior consistent with the Human-controlled squash workflow;
- force-push and branch deletion disabled for `main` unless an explicit recovery procedure requires otherwise;
- final merge remains Human-controlled.

These are repository settings, not application-code substitutes.

## `/metrics` and JWKS are different trust surfaces

`/metrics` is operational and should normally be network-gated. JWKS is intentionally public standards material and must remain publicly readable for offline access-token verification. Do not apply the `/metrics` hardening recommendation to JWKS.

## OpenSQLDB adapter usage

BeeBox currently creates short-lived `database/sql` adapters backed by the process-owned pgx pool; closing those adapters does not close the underlying process pool. This campaign does not classify that pattern as a correctness bug. No production refactor should be made without benchmark evidence showing material allocation/latency impact versus a safely reused adapter.
