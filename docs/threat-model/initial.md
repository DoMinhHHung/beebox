# Initial BeeBox Threat Model

> Status: repository-owned threat model for the architecture represented by this checkpoint.
> Current governance baseline: `Instruction.md`, `docs/contracts/conventions.md`, accepted ADRs 0001/0002, and proposed `docs/adr/0003-phase1-public-auth-contract.md`.
> Scope: current Go runtime, PostgreSQL lifecycle, explicit migration/operator modes, application-scoped identity persistence, transactional registration, internal email OTP ownership verification, typed public locators, application integration credentials, exact allowed origins, and local signing-key generation.

## 1. Purpose and decision state

This document distinguishes controls actually implemented by the repository from controls still required before Phase 1 authentication becomes publicly reachable.

ADR 0001 keeps `application_instance` as the root isolation resource. ADR 0002 keeps email application-scoped and forbids automatic account linking from email equality. Email verification proves control of one stored address only; it is not authentication, MFA, session establishment, authorization, account linking, or account merging.

ADR 0003 is **proposed while Checkpoint 1 is open**. Human squash-merge of the checkpoint constitutes acceptance. Until that acceptance is on `main`, BeeBox exposes no public product-authentication route that relies on the proposed public-ID, application-key, password, JWT, key-ring, refresh, or cookie semantics.

BeeBox remains one Go deployable modular monolith. PostgreSQL remains the correctness source of truth. No Redis, queue, outbox, distributed transaction, service extraction, OAuth/OIDC authorization server, or public product API is introduced by this checkpoint.

## 2. Implemented architecture and persistence

Embedded forward migrations now contain:

1. runtime baseline;
2. `application_instances`;
3. application-scoped `users`;
4. scoped `email_identifiers`;
5. scoped `password_credentials`;
6. scoped `audit_events`;
7. scoped `email_verification_challenges`;
8. typed application/user public IDs plus application integration credentials and exact allowed origins.

Migration 00008 is additive. Existing application/user rows receive random UUIDv4-based public IDs and the columns become `NOT NULL`, unique, and format constrained. Defaults preserve compatibility with existing internal inserts. Internal BIGINT primary keys remain internal persistence identities.

Current internal identity/authentication behavior retains:

- scoped user/email/password persistence;
- no-auto-link email semantics;
- transactional email/password registration with required success audit;
- six-digit cryptographically random email-verification codes stored only as dedicated Argon2id verifier hashes;
- bounded verification challenge expiry, attempts, issue window/count, cooldown, generation rotation, consumption, replay protection, and resend-generation race protection;
- challenge issuance audit committed before delivery;
- verification denied/success audit inside the corresponding state transaction;
- no concrete production email provider.

Checkpoint 1 additionally implements:

- `app_<uuidv4>` application public locators;
- `usr_<uuidv4>` user public locators;
- `cred_<uuidv4>` application credential record locators;
- non-secret `bb_pk_<uuidv4>` publishable application keys;
- backend secret keys formatted `bb_sk_<credential-uuidv4>.<32-byte-base64url-secret>`;
- SHA-256 verifier-at-rest for uniformly random 256-bit application secrets;
- constant-time secret comparison followed by current persisted credential-state recheck;
- scoped, atomic credential rotation and scoped revocation;
- exact application allowed origins;
- trusted operator commands for application bootstrap, origin addition, credential rotation/revocation, and local Ed25519 key generation;
- proposed ADR 0003 covering later Phase 1 public password/token/session/cookie contracts.

Serve mode still exposes only health endpoints.

## 3. Assets

| Asset | Required security property |
| --- | --- |
| Application root | Every product/resource lookup remains tied to explicit trusted application scope. |
| Public application/user/credential IDs | Stable opaque locators only; no tenant, role, permission, ownership, or authority encoding. |
| Publishable key | Non-secret application-context selector only; must never imply backend/user/admin authority. |
| Application secret | 32 random bytes, one-time plaintext output only, never persisted/logged/audited/traced/metered. |
| Application secret verifier | SHA-256 digest of high-entropy random material; sensitive credential verifier state. |
| Credential revocation/rotation state | Current persisted state must win over stale verification snapshots. |
| Allowed origins | Exact application-scoped browser-origin allowlist; no wildcard authority. |
| Signing private key | Local/configuration secret only; never stored in source or PostgreSQL for convenience. |
| Email PII | Excluded from stable errors/audit/telemetry added here. |
| Password/OTP material | Existing secret-handling guarantees remain unchanged. |
| Audit facts | Append-oriented scoped evidence committed with security-sensitive credential/origin mutations. |
| PostgreSQL/backups | Sensitive boundary containing PII and verifier material; operator access is privileged. |

## 4. Actors and trust boundaries

| Actor | Trust meaning |
| --- | --- |
| Unauthenticated network client | Can reach health endpoints only; no public product-auth route exists. |
| Publishable-key holder | Future application integration context only; not a backend or user principal. |
| Backend secret-key holder | After verification, establishes backend application scope only; not a user identity. |
| Trusted operator | May explicitly bootstrap applications, rotate/revoke credentials, configure origins, and generate local signing material. |
| Anonymous registration/email-verification actors | Existing internal audit identities only; not authenticated users. |
| PostgreSQL | Source of truth for application scope, credential verifier/revocation state, origins, identity state, and audit facts. |
| CI | Runs synthetic tests and real PostgreSQL integration tests. |

### Operator process -> PostgreSQL

Operator database commands load the existing migration-mode database configuration and execute under a bounded context. They never run migrations implicitly. The operator must apply reviewed migrations explicitly before using commands that depend on migration 00008.

Application bootstrap creates a root and then initial credentials/origins using trusted process authority. Generated application secrets are written only to the explicit command output stream. Structured logs and stable errors do not include them.

### Publishable key -> application context

A publishable key is stored directly because it is intentionally non-secret. Resolution joins the credential to its owning application and requires an unrevoked publishable credential. The result establishes only integration context. The key cannot be parsed or reused as a backend secret.

### Backend secret -> application scope

A backend secret key contains a credential UUID locator plus 32 random secret bytes. Verification:

1. validates the BeeBox-owned format;
2. loads verifier material by credential locator;
3. hashes the candidate secret with SHA-256;
4. executes constant-time comparison, including a fixed-size dummy comparison path for load failure;
5. rejects already-revoked state;
6. performs a database-authoritative finalize step that requires the same verifier and `revoked_at IS NULL` before recording `last_used_at`;
7. only then returns the owning internal application scope.

A revoke that races after the snapshot but before finalization prevents successful authentication. Credential locator possession alone is not authority.

### Credential rotation/revocation -> PostgreSQL

Rotation is explicitly scoped by trusted application ID + credential public ID + credential kind. One transaction locks the old scoped credential, rejects missing/revoked/wrong-scope state, inserts the new credential, appends its create audit, revokes the old credential, appends its revoke audit, then commits. Separate audit correlation IDs are used because current audit correlation IDs are unique per fact.

Direct revocation is also application-scoped and row-locked. Cross-application rotation/revocation cannot select the foreign credential.

### Allowed origin -> future browser trust

Allowed origins are application-scoped exact HTTP/HTTPS origins. Canonicalization rejects userinfo, path other than `/`, query, fragment, unsupported schemes, surrounding whitespace, and wildcards. Host/scheme casing is canonicalized and explicit ports are retained. PostgreSQL enforces per-application uniqueness.

No current HTTP handler trusts or consumes these origins yet. Later browser/CORS/CSRF work must use the exact stored application origins rather than treating Origin parsing as authorization.

## 5. Public-ID security properties

Public IDs are random UUIDv4 bodies with BeeBox-owned type prefixes. Migration constraints enforce application/user format and uniqueness; runtime generators use `crypto/rand` and set UUIDv4 version/variant bits.

Security invariant:

- `app_`, `usr_`, `cred_`, and future `ses_` prefixes communicate resource category only;
- IDs do not encode tenant, role, permission, organization, ownership, shard, or other authority;
- parsing success never authenticates or authorizes;
- internal persistence still scopes queries by trusted application context where applicable;
- no public API currently returns these IDs.

The migration integration suite proves pre-00008 application/user rows receive valid IDs and those IDs remain unchanged on migration rerun.

## 6. Application credential controls

Implemented:

- publishable vs secret kinds constrained in PostgreSQL;
- publishable rows cannot contain secret verifier material;
- secret rows cannot contain publishable-key values and require exactly a 32-byte verifier digest;
- secret plaintext is absent from PostgreSQL;
- generated secrets use `crypto/rand` for 32 bytes;
- SHA-256 is used only for already-uniform 256-bit application secrets, not passwords/OTP/reset codes;
- constant-time verifier comparison;
- current-state finalization prevents concurrent revoke from being ignored;
- successful secret verification records `last_used_at`;
- rotation/revocation is application scoped;
- publishable credentials cannot authenticate through the backend-secret path;
- credential create/revoke facts are transactionally audited without key material;
- no credential mutation HTTP API exists.

Residual risk: compromise of a plaintext backend secret grants its application-level backend authority until revocation. Future reachable backend APIs must enforce least-privilege route semantics and must never treat a secret key as a user principal.

## 7. Signing-key preparation

Checkpoint 1 includes only a safe local Ed25519 key generator. It uses Go's standard Ed25519 implementation and cryptographic randomness, emitting a unique key ID plus base64url public/private material as explicit operator output.

No JWT is issued or validated yet. No JWKS endpoint exists. No signing private key is persisted to PostgreSQL or source. Proposed ADR 0003 requires one active signer, retiring public verification keys, strict EdDSA, mandatory `kid`, bounded key-retention overlap, and startup failure for malformed token configuration when token capability is later enabled.

## 8. Existing email-verification controls retained

The internal verification lifecycle remains unchanged by this checkpoint:

- exactly six ASCII decimal digits from unbiased `crypto/rand` generation;
- dedicated Argon2id verification-code hash;
- 10-minute TTL;
- five failed attempts per active issue window;
- 15-minute issue window;
- three issues per window;
- 60-second resend cooldown;
- generation rotation invalidates prior code state;
- resend inside the same window does not reset failed attempts;
- success atomically sets `verified_at`, consumes the challenge, clears verifier material, and appends success audit;
- concurrent successful verification has one winner;
- stale generation after resend cannot verify;
- every lookup carries explicit application scope.

Email verification remains identity evidence only and creates no authenticated principal/session/token.

## 9. Audit and privacy

Checkpoint 1 security-sensitive application-integration mutations use append-oriented audit facts:

- `application.credential.created`;
- `application.credential.revoked`;
- `application.allowed_origin.added`.

Actor is the trusted operator; source is the trusted operator CLI; resource category is credential or allowed origin; application scope and cryptographically random correlation remain mandatory.

Audit rows contain no publishable/secret key value, secret verifier, allowed-origin string payload, signing private key, email, password, OTP, or token. Existing audit storage is not claimed to be tamper-proof or compliance-certified.

Stable application-integration errors do not include SQL, SQLSTATE, constraint names, provider/database topology, credentials, or secret material. Context cancellation/deadline remains causal where applicable.

## 10. Migration and concurrency controls

Migration 00008 is forward-only and does not modify migrations 00001–00007. Normal applied versions are now 1 through 8. Synthetic transactional failure evidence moves to version 9.

The existing migration guarantees remain required and tested:

- embedded ordered sources;
- first apply;
- rerun idempotency;
- concurrent runner convergence under the same-session advisory lock;
- cancellation while waiting for the migration lock;
- transactional rollback;
- failed synthetic version is not recorded;
- serve mode never auto-migrates.

Credential correctness uses PostgreSQL row locks/transactions and constraints rather than Redis or process mutexes. Cross-application credential tests prove app A cannot rotate/revoke an app B credential.

## 11. Reachability boundary and deferred Phase 1 work

Current HTTP surface remains health-only. Checkpoint 1 does **not** implement:

- `/v1` product routes;
- public signup or email-verification endpoints;
- request idempotency/rate limits;
- production SMTP delivery;
- public password policy enforcement;
- signin;
- session persistence;
- JWT issuance/validation;
- JWKS;
- refresh tokens;
- browser auth cookies/CORS credential flow;
- password reset/recovery;
- OpenAPI public auth contract;
- Go SDK;
- auth metrics or final E2E setup.

Those capabilities must be introduced by later Phase 1 checkpoints after ADR 0003 is Human-accepted on `main`.

## 12. Residual threats and future controls

| Threat | Current state | Required later control |
| --- | --- | --- |
| Public-ID guessing/confusion | IDs are random/typed and carry no authority; no product API exposes them yet. | Every public lookup must still derive trusted application scope and perform authorization. |
| Publishable-key theft | Key is intentionally non-secret and grants context only. | Public endpoints must constrain operations and add request abuse/idempotency controls. |
| Backend secret theft | High-entropy secret with hash-at-rest and revocation. | Secret storage/rotation operational guidance and least-privilege backend APIs. |
| Stale secret auth during revoke | Final database recheck fails a concurrent revoke. | Preserve the same state-authoritative pattern in future backend middleware. |
| Cross-app credential mutation | Scoped row selection rejects foreign credential. | All future management/backend operations must retain application scope. |
| Origin confusion | Canonical exact origins are stored; no browser auth exists yet. | Exact CORS/CSRF validation for credentialed cookie requests. |
| Private signing-key exposure | Only explicit local generation exists; no DB/source persistence. | Secure runtime secret/config distribution and key-ring validation. |
| JWT revocation gap | JWT not implemented. | Proposed 5-minute lifetime, max 30-second skew, DB session check for BeeBox immediate revoke paths, explicit offline limitation. |
| Refresh theft/replay | Refresh not implemented. | One-time rotation; consumed-token reuse revokes session; no blind retry. |
| Signup/signin enumeration | Not publicly reachable. | Anti-enumerating public errors, dummy password verification, rate limits. |
| OTP/provider abuse | Verification is internal; no production provider. | Request-level limits, exact application scope/origin, bounded SMTP adapter. |

## 13. Review triggers

Review this model whenever a change introduces or changes:

- ADR 0003 acceptance or amendment;
- public `/v1` reachability;
- publishable/secret credential trust semantics;
- application/user/session public ID format;
- password policy;
- SMTP/provider delivery;
- signin/password verification;
- sessions/refresh/cookies;
- JWT/JWKS/signing-key configuration;
- password reset/recovery;
- account linking/merging;
- authorization/organizations;
- audit query/export/retention;
- telemetry containing identity/security metadata;
- migration/schema ownership or service boundaries.

## 14. Evidence map

- `docs/adr/0001-application-instance-root.md` — root scope.
- `docs/adr/0002-email-identity-v1.md` — app-scoped email/no-auto-link.
- `docs/adr/0003-phase1-public-auth-contract.md` — proposed public trust/token/password/session contract.
- `internal/platform/publicid/*` — typed cryptographically random UUIDv4 generation/validation.
- `internal/platform/migration/sql/00008_phase1_public_integration.sql` — backfill/defaults/constraints, credential/origin tables.
- `internal/platform/migration/public_integration_migration_test.go` — preexisting-row public-ID backfill and stability evidence.
- `internal/applicationinstance/integration.go` — credential/origin semantics and secret verification orchestration.
- `internal/applicationinstance/postgres/integration_store.go` — scoped transactional credential/origin persistence and audit.
- `internal/applicationinstance/postgres/integration_store_integration_test.go` — secret-at-rest, publishable authority separation, rotation/revoke, cross-app and audit evidence.
- `internal/platform/signingkey/*` — local Ed25519 generation/validation.
- `cmd/beebox/operator.go` — trusted bounded operator entry points.
- `internal/authentication/*` — retained registration/email-verification security lifecycle.
- `.github/workflows/ci.yml` — formatting, vet, unit, real PostgreSQL integration and race gates.
