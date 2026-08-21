# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go. Clerk's public product capabilities are a benchmark only; BeeBox owns its public contracts, identifiers, persistence model, security boundaries and implementation.

The repository is a Go-first modular monolith with PostgreSQL as the initial correctness source. Domain/application code does not depend on HTTP, SQL or provider SDK models, and public identifiers never substitute for authorization scope.

## Current B2C capability

The merged Phase 1 foundation provides application-scoped email/password signup and verification, sign-in, rotating sessions/refresh credentials, Ed25519 access JWTs/JWKS, password reset, backend session management, OpenAPI, a Go SDK, operational metrics and reproducible local dependencies.

Phase 2 adds the following application-scoped capabilities:

- P2.0 — trust/contract baseline and tenant/application invariants;
- P2.1 — passwordless email OTP primary authentication;
- P2.2 — phone-first signup and verified-phone SMS OTP authentication;
- P2.3 — social OAuth/OIDC for Google, Apple, Microsoft, GitHub, GitLab, Facebook, Slack, Discord, LinkedIn, X and TikTok;
- P2.4A — explicit authenticated social account linking;
- P2.4B — linked social-account listing and unlink with last-method protection;
- P2.5 — Passkeys/WebAuthn registration, authentication, list and removal;
- P2.6 — TOTP MFA with pending-MFA continuation across every implemented primary method;
- P2.7 — recovery codes and protected TOTP replacement;
- P2.8 — one-time, purpose/session-bound reverification for sensitive mutations;
- P2.9 — current-user session inventory/revocation self-service with bounded opaque pagination;
- P2.10 — email/phone identifier and four-field profile self-service with explicit primary selection, ownership verification, tenant isolation and last-method safety;
- P2.11 — secure email sign-in links plus a minimal same-process hosted-auth surface with CSRF/CSP/open-redirect/cookie hardening and scanner-safe link consumption.

`docs/phase2-exit.md` records the Phase 2 exit matrix and required exact-head CI gate. The Draft PR ledger is the source for the final tested commit SHA/run; documentation does not imply Human merge approval.

BeeBox still does **not** claim principal/account merge, cross-application identity transfer, provider-side OAuth consent/token revocation on unlink, organizations/enterprise federation, OAuth/OIDC authorization-server behavior, billing, arbitrary hosted-page JavaScript/CSS/templates, remembered-device risk scoring, a global JWT denylist or compliance certification.

## Security and architecture invariants

- `application_instance` is the root tenant boundary. Application/user/session scope is authoritative; opaque public IDs are locators only.
- Authentication does not replace authorization. Cross-application/cross-user identifiers, sessions, factors and provider subjects fail closed.
- Identifier equality never implicitly links, merges, adopts or transfers accounts.
- PostgreSQL constraints/transactions are the final arbiter for uniqueness, replay, admission, concurrency and security-state mutation. Redis is not required for Phase 2 correctness.
- Active TOTP prevents ordinary session/access/refresh issuance until MFA completes, regardless of the primary authentication method.
- Sensitive mutations use explicit P2.8 reverification where required; target-session creation time or token refresh is not fresh-auth authority.
- Secrets/codes/tokens are never intentionally persisted or logged as plaintext outside their allowed lifecycle. Audit/metrics minimize identifiers and reject unbounded PII/secret labels.
- One-time callbacks/completions/mutations are not blindly retried after ambiguous outcomes. Provider I/O is bounded by context deadlines/body limits and BeeBox-owned safe errors.
- Hosted auth is a first-party client of the canonical headless behavior, not an independent identity implementation.

## Project documentation

- [Repository instructions](Instruction.md)
- [Contract and tenancy conventions](docs/contracts/conventions.md)
- [ADR 0001: application_instance root](docs/adr/0001-application-instance-root.md)
- [ADR 0002: email identity v1](docs/adr/0002-email-identity-v1.md)
- [ADR 0003: Phase 1 public auth contract](docs/adr/0003-phase1-public-auth-contract.md)
- [ADR 0004: Phase 2 identity linking and external trust](docs/adr/0004-phase2-identity-linking-external-trust.md)
- [ADR 0005: Phase 2 authentication assurance and recovery](docs/adr/0005-phase2-authentication-assurance-recovery.md)
- [ADR 0006: Phase 2 device privacy and hosted-auth trust](docs/adr/0006-phase2-device-privacy-hosted-auth.md)
- [ADR 0007: Phase 2 social signup claims and principal creation](docs/adr/0007-phase2-social-signup-claims.md)
- [Initial threat model](docs/threat-model/initial.md)
- [P2.5 passkey threat-model delta](docs/threat-model/passkeys.md)
- [P2.6 TOTP MFA threat model](docs/threat-model/totp-mfa.md)
- [P2.7 recovery-code threat model](docs/threat-model/recovery-codes.md)
- [P2.8 reverification threat model](docs/threat-model/reverification.md)
- [P2.9 session self-service threat model](docs/threat-model/session-self-service.md)
- [P2.10 account-management threat model](docs/threat-model/account-management.md)
- [P2.11 email-link/hosted-auth threat model](docs/threat-model/email-links-hosted-auth.md)
- [Phase 1 exit evidence](docs/phase1-exit.md)
- [Phase 2 exit evidence](docs/phase2-exit.md)
- [Production operations](docs/production-operations.md)
- [OpenAPI v1](api/openapi/v1.yaml)
- [Go SDK](sdk/go)

## Prerequisites

- Go 1.26.x
- Git
- Docker with Compose for local PostgreSQL 17 and Mailpit

## Local quickstart

Start local dependencies:

```sh
docker compose up -d
```

Use the local database only; repository commands do not mutate a hosted database automatically:

```sh
export BEEBOX_DATABASE_URL='postgres://beebox:beebox_local@127.0.0.1:5432/beebox?sslmode=disable'
go run ./cmd/beebox migrate
```

Generate Ed25519 signing material. Private material is intentional one-time output; do not commit or log it:

```sh
go run ./cmd/beebox generate-signing-key
```

Configure the returned values and an issuer:

```sh
export BEEBOX_ISSUER='https://auth.example.test'
export BEEBOX_SIGNING_KID='<kid>'
export BEEBOX_SIGNING_PRIVATE_KEY='<private_key>'
export BEEBOX_SIGNING_PUBLIC_KEY='<public_key>'
```

Bootstrap an application and browser origin:

```sh
go run ./cmd/beebox bootstrap-application http://localhost:3000
```

Save the emitted `application_id`, `publishable_key` and `secret_key` outside source control. Configure local SMTP capture and start BeeBox:

```sh
export BEEBOX_SMTP_ADDR='127.0.0.1:1025'
export BEEBOX_SMTP_FROM='beebox@example.test'
export BEEBOX_SMTP_TLS_MODE='insecure_localhost'
export BEEBOX_HTTP_ADDR=':8080'
go run ./cmd/beebox
```

Mailpit is available locally on port `8025`. BeeBox serve mode never auto-migrates.

## Primary authentication

The canonical headless API supports these primary proofs:

- verified email + password: `POST /v1/sign-ins`;
- email OTP: `POST /v1/sign-ins/email-otp` then `/confirm`;
- verified-phone OTP: `POST /v1/sign-ins/phone-otp` then `/confirm`;
- social OAuth/OIDC: create a social attempt, complete the provider callback, then exchange the one-time BeeBox completion code with the client PKCE verifier;
- Passkeys/WebAuthn: create and complete a discoverable authentication ceremony;
- secure email sign-in link: request the link and confirm the one-time fragment secret through the hosted POST flow.

Every primary method returns the same security meaning: if the user has active TOTP, successful primary proof returns only pending-MFA authority. Ordinary session/access/refresh authority is produced only after TOTP or an accepted recovery-code completion.

Phone input is strict international E.164 (`+` followed by 2–15 decimal digits, first digit non-zero). BeeBox does not infer a default region. Email/phone equality is never account-linking authority.

## Sessions, reverification and account self-service

Access tokens are short-lived Ed25519 JWTs. Refresh credentials rotate and remain application/session scoped. Current-user session inventory is bounded and omits IP, user-agent, location, hardware fingerprint and remembered-device trust data. Session revocation is persisted immediately; already-issued offline JWT verification remains bounded by the documented access-token lifetime.

Sensitive operations use a one-time P2.8 reverification grant bound to the exact application, user, target session and purpose. A separately authenticated proof session establishes freshness; `sessions.created_at` and token refresh do not.

P2.10 account self-service exposes only:

- bounded email/phone identifier lists and add/verify/remove/primary operations;
- verified-only application-wide phone ownership arbitration in PostgreSQL while allowing unverified same-number claims and cross-application reuse;
- profile fields `display_name`, `given_name`, `family_name` and `locale`.

Last-method checks and required audit facts share the same correctness transaction with destructive identifier/social/passkey mutations.

## Secure email links and hosted authentication

Configure hosted authentication only with an exact canonical origin:

```sh
export BEEBOX_HOSTED_AUTH_ORIGIN='https://auth.example.test'
```

A sign-in link contains a random 32-byte one-time secret, expires after ten minutes, has a one-minute resend cooldown and a maximum of three issues per 15-minute window. The secret is delivered in the URL fragment, so a normal mail-scanner GET does not transmit it to the BeeBox server. Hosted JavaScript removes the fragment from history and performs the explicit POST confirmation.

Hosted mutations require exact Origin plus a synchronizer CSRF token. Static pages send a restrictive CSP and no-store/no-referrer headers. Hosted `__Host-` cookies are Secure, HttpOnly where authority is stored, use `Path=/` and no `Domain`. Built-in UI customization is limited to `en`/`vi` and `system|light|dark`; BeeBox does not accept arbitrary tenant HTML/CSS/JavaScript, remote logos or translation templates.

Hosted social continuation keeps the PKCE verifier and exact final allowlisted completion URL in a short-lived AES-GCM-protected server-issued context. Provider callback GET does not perform the final BeeBox completion exchange; the hosted client removes callback query state from browser history and explicitly POSTs the one-time exchange.

## Optional providers

SMS is disabled by default and selects exactly one process-wide transport:

```sh
export BEEBOX_SMS_MODE='disabled' # or twilio|vonage|plivo|telnyx
```

Provider-specific SMS credentials are process secrets. An unknown mode or incomplete selected-provider configuration fails startup rather than silently falling back. BeeBox performs no cross-provider failover/retry for an ambiguous SMS send.

Social connections are configured statically per application through the strict `BEEBOX_SOCIAL_CONNECTIONS` JSON configuration. Provider endpoints are fixed in code. When provider-side/hosted state protection is required, configure an independent random 32-byte key as unpadded base64url:

```sh
export BEEBOX_SOCIAL_STATE_KEY='<base64url-raw-32-byte-key>'
```

Provider access/refresh/ID tokens remain adapter-local transient material and are not exposed as BeeBox credentials. Verified provider email/profile claims do not create or verify BeeBox email identifiers and do not link principals.

See [production operations](docs/production-operations.md) for key lifecycle, provider/hosted boundary, cleanup and deployment responsibilities.

## TOTP keyring

TOTP seed material is encrypted at rest. Configure a bounded encryption keyring outside source control:

```sh
export BEEBOX_SECRET_ENCRYPTION_KEYS='<key-id>:<base64url-raw-32-byte-key>'
export BEEBOX_SECRET_ENCRYPTION_ACTIVE_KEY_ID='<key-id>'
```

Rotation is additive: deploy the expanded keyring before switching the active key and retain historical keys while persisted ciphertext references them. Missing referenced keys fail startup closed rather than silently disabling MFA.

## Security-state maintenance

Run bounded cleanup explicitly when appropriate:

```sh
go run ./cmd/beebox cleanup-security-state
```

The command removes only expired/consumed operational security state in bounded batches. It never prunes audit events, users, identifiers, external identities, passkey/TOTP credentials, sessions or refresh credentials, and correctness never depends on cleanup.

## Public contracts and verification

OpenAPI is validated in CI:

```sh
go test ./api/openapi
```

The Go SDK is tested independently:

```sh
go test ./sdk/go
```

Repository CI also runs formatting, `go vet`, `govulncheck`, repeated/focused social-provider contract checks, normal Go tests, PostgreSQL 17 integration coverage and the full race detector. Phase 2 exit requires all substantive gates to pass on the exact final Draft PR head; see [Phase 2 exit evidence](docs/phase2-exit.md).
