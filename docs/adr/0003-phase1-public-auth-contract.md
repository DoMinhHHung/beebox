# ADR 0003 — Phase 1 public authentication contract

Status: **proposed**

Date: 2026-08-17

Decision owner: Human maintainer

Acceptance rule: **Human squash-merge of the Checkpoint 1 pull request containing this ADR constitutes acceptance of this decision.** No public product authentication route may rely on these semantics before that merge is present on `main`.

## Context

BeeBox has an application-scoped identity persistence foundation, transactional email/password registration, and an internal email-ownership verification lifecycle. It still exposes no public product authentication API. Phase 1 needs a stable trust and wire-contract baseline before reachable signup, signin, sessions, tokens, password reset, SDKs, or browser credential transport are introduced.

This decision preserves ADR 0001 (`application_instance` is the root isolation resource) and ADR 0002 (email equality never auto-links or merges accounts). BeeBox remains a Go modular monolith with PostgreSQL as the correctness source of truth. This ADR defines BeeBox-owned contracts; Clerk remains a public capability benchmark only.

## Decision

### Public resource identifiers

Phase 1 public resource identifiers are opaque, type-prefixed random UUIDv4 values:

- application: `app_<uuidv4>`;
- user: `usr_<uuidv4>`;
- session: `ses_<uuidv4>`;
- credential record: `cred_<uuidv4>`.

They are stable for a resource lifetime and globally unique in BeeBox persistence. The UUID body is random. The prefix identifies only the resource category. Public identifiers never encode application scope, organization, role, permission, ownership, entitlement, or other authority.

Parsing or possessing a public ID is never authorization. Repository lookups remain explicitly scoped by trusted application context where applicable. Internal BIGINT primary keys remain internal persistence identities and are never public API models.

PostgreSQL's built-in random UUID generation may be used for additive migration backfill. Runtime-created resources may generate UUIDv4 identifiers with cryptographically secure randomness before persistence.

### Application integration credentials

A publishable key has format `bb_pk_<uuidv4>`. It is intentionally non-secret and identifies only an application integration context. It can be rotated and revoked. Possession grants no user, session, administrative, backend, role, permission, or account-link authority.

A backend secret key has format `bb_sk_<credential-uuidv4>.<secret>`, where `<secret>` is exactly 32 cryptographically random bytes encoded with unpadded base64url. The credential UUID is a locator only. Only a SHA-256 digest of the uniformly random 256-bit secret component is persisted. Verification uses constant-time comparison. Plaintext is returned only at the explicit one-time operator boundary and is never logged, audited, traced, measured, or persisted.

Secret-key verification establishes trusted backend application scope only. It does not establish a user identity.

Credential records are application-scoped, revocable, rotatable, and have BeeBox-owned public credential IDs. Database constraints prevent publishable credentials from carrying secret verifier material and secret credentials from carrying publishable-key material.

### Allowed origins and browser integration

Allowed origins are stored per application as exact canonical HTTP/HTTPS origins. Wildcards are forbidden. Paths, queries, fragments, and userinfo are forbidden. Host casing is canonicalized; explicit ports are retained. Production applications are expected to use HTTPS. Explicit localhost HTTP may be configured for local development.

Future credentialed browser CORS and cookie-authenticated unsafe requests must validate the exact stored Origin. No wildcard credentialed CORS is permitted.

### Public password policy

Every public Phase 1 password establishment/change/reset path will use one shared policy component:

- minimum 15 Unicode code points;
- maximum 128 Unicode code points;
- must also remain within the existing safe low-level byte bound;
- accepted Unicode input is normalized to NFC before hashing;
- spaces and ordinary Unicode are permitted;
- no required uppercase/lowercase/digit/symbol composition rule;
- no silent trimming;
- repository-owned common/expected/compromised blocklist including BeeBox/context-specific obvious passwords.

The built-in list is not represented as a comprehensive breach corpus. The existing low-level Argon2id `HashPassword` primitive remains a primitive and does not silently become the public policy implementation.

### Access-token trust

Phase 1 access tokens will be JWT/JWS signed with Ed25519 using JOSE `EdDSA` only. Validation uses an exact algorithm allowlist. `kid` is mandatory.

Required claims:

- `iss`: configured BeeBox absolute HTTPS issuer URL;
- `sub`: BeeBox user public ID;
- `aud`: BeeBox application public ID;
- `sid`: BeeBox session public ID;
- `exp`;
- `nbf`;
- `iat`;
- `jti`.

No role, permission, organization, or entitlement claim is included in Phase 1.

Access-token lifetime is 5 minutes. Accepted clock skew is at most 30 seconds. Wrong algorithm, missing/unknown key ID, invalid signature, wrong issuer/audience, expiry, premature not-before, invalid public-ID syntax, or malformed mandatory claims fail closed.

An offline verifier cannot observe immediate session revocation. The 5-minute access-token lifetime bounds that stale-auth window. BeeBox's own authenticated endpoints may additionally check current session state in PostgreSQL when immediate revocation is required. Documentation and SDK behavior must state this limitation.

BeeBox Phase 1 is not an OAuth or OpenID Connect authorization server and makes no OAuth/OIDC compliance claim.

### Signing-key ring

Signing private keys are configuration material, not database convenience state and not source-controlled secrets. Configuration supports one active Ed25519 signing key plus additional retiring public verification keys.

Every key has a distinct `kid`. The active signer must include valid private material. JWKS publishes public Ed25519 material only. A retiring public key must remain configured for at least the maximum access-token lifetime plus accepted clock skew after it stops signing. Malformed, duplicate, or missing active configuration fails startup when token capability is enabled.

BeeBox provides a local operator key-generation command. It prints generated private material only as explicit one-time command output; normal structured logging never includes it.

### Session and refresh defaults

Phase 1 session defaults are:

- absolute lifetime: 30 days;
- inactivity lifetime: 7 days;
- access JWT lifetime: 5 minutes;
- opaque refresh secret: 32 random bytes.

Only refresh-token verifier material is persisted. A refresh credential rotates on every successful refresh. Reuse of an already-consumed refresh credential revokes the session. There is no transparent automatic retry that masks ambiguous refresh rotation. If a successful refresh response is lost, a client may need to reauthenticate instead of replaying a credential that might already be consumed.

### Cookie and bearer transport

Browser refresh-cookie mode will use an application-specific `__Host-` cookie with:

- `Secure`;
- `HttpOnly`;
- `SameSite=Strict`;
- `Path=/`;
- no `Domain` attribute.

Production never disables `Secure`. Cookie-authenticated unsafe requests require exact allowed-Origin validation. Missing/invalid browser Origin fails safely. Credentialed CORS never uses wildcard Origin.

Bearer access tokens use `Authorization: Bearer <token>`. Refresh credentials use their separately defined transport and are never placed in URLs. Authentication tokens are never emitted in query parameters, server-generated HTML, logs, audit facts, metrics, or traces.

### Audit and secret handling

Every security-sensitive committed mutation introduced by Phase 1 keeps its required audit fact in the same correctness boundary. Audit is append-oriented at application semantics; this ADR does not claim tamper-proof storage or compliance certification.

Audit, stable errors, logs, metrics, traces, and provider errors must never contain raw password, OTP, reset code, application secret, refresh token, access token, signing private key, or unnecessary email PII.

## Consequences

Checkpoint 1 may add public IDs, application credentials, exact allowed origins, operator bootstrap/rotation/revocation commands, local Ed25519 key generation, schema constraints, and internal persistence/audit behavior. It must expose no public authentication route.

After Human acceptance, later Phase 1 checkpoints may build versioned `/v1` APIs, SMTP delivery, public password policy, signup/verification, signin/session/JWT/JWKS/refresh, password reset, OpenAPI, SDK, metrics, and local end-to-end setup according to this contract.

Any later incompatible public-contract change requires an explicit version/migration path and, where it changes a trust boundary, new Human authority.
