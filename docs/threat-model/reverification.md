# Reverification threat model

This document covers the P2.8 generic reverification boundary for sensitive self-service mutations. Reverification is not ordinary session freshness and it is not authority created by refreshing an access or refresh token. A caller starts with an existing target session, proves the same BeeBox principal again through an independently authenticated proof session, mints one short-lived purpose-specific grant, and consumes that grant exactly once on the intended mutation.

## Assets

- **Target session authority** selects the exact existing BeeBox session whose sensitive mutation is being authorized.
- **Proof session authority** represents the fresh server-trusted authentication evidence used to step up the target session. The proof session may differ from the target session.
- **Reverification grant secret** is the bearer value returned once to the client and presented once through `X-BeeBox-Reverification`.
- **Verifier hash** is the only persisted verifier for the grant secret. The plaintext secret is never persisted.
- **MFA provenance** records whether the proof session was completed with TOTP or a recovery code when additional assurance is configured.
- **Audit evidence** records successful grant issuance and consumption without recording the grant secret, proof token or sensitive factor material.

## Trust boundaries

The browser or headless client is untrusted input. `X-BeeBox-Publishable-Key` selects application context and an exact allowlisted `Origin` is required for the browser-facing lifecycle; neither is user authority.

The `Authorization` bearer is resolved to the persisted **target session**. `proof_access_token` is independently resolved to the persisted **proof session**. BeeBox requires both sessions to be active and requires their application and user to match exactly. The proof session is not required to have the target session's public ID.

The proof session's server-recorded authentication time is accepted only inside the ten-minute P2.8 window. This timestamp is evidence about the fresh proof; the target session's creation time is not sensitive-mutation authority.

A successful proof creates a grant bound to application, user, target-session public ID, proof-session public ID, operation purpose and expiry. Consumption must match the exact target session and purpose before the application service receives a trusted `RequireReverification` authorization context.

## Threats and controls

| Threat | Control |
| --- | --- |
| Stolen old target session is used directly for a sensitive mutation | Sensitive application services require a trusted P2.8 authorization. Possession, age or refresh of the target session alone does not satisfy it. |
| Attacker proves a different user | Target and proof are independently resolved and must have the same exact application and user; persistence revalidates both bindings. |
| Cross-application proof/session substitution | Application/user/session scope is checked by the service and enforced again by PostgreSQL composite foreign keys on the grant. |
| Wrong target session receives a valid grant | The verifier hash and persisted grant both bind the target session; consumption recomputes/verifies that exact binding. |
| Grant is used for another operation | Purpose is part of the verifier binding and stored grant. Wrong-purpose consumption fails closed and counts toward the bounded failed-attempt limit. |
| Proof is stale | Server-recorded proof authentication time must be in the past and within the accepted ten-minute window at issue and consumption. Client timestamps are never authority. |
| Target or proof is revoked/expired after grant issue | Consumption transactionally reloads both sessions and requires them to remain active. Revocation or expiry invalidates the outstanding grant. |
| Grant secret is stolen | The grant is short-lived, exact target/purpose bound and one-time. Theft does not provide a generic session or reusable factor-management credential. |
| Replay or synchronized concurrent consumption | The grant row is locked for consumption and `consumed_at` is committed atomically; at most one consumer receives trusted authorization. |
| Guessing or malformed token attempts | Secrets contain 32 random bytes; only a 32-byte domain-separated SHA-256 verifier is persisted. Malformed public IDs/secrets and verifier mismatches fail closed. Failed uses are bounded to five. |
| Recovery code downgrades generic step-up while TOTP remains configured | When TOTP is configured, the proof session must carry fresh `totp` MFA provenance. `recovery_code` provenance is explicitly rejected for generic reverification. Recovery remains limited to pending-MFA completion and the dedicated TOTP replacement lifecycle. |
| Missing or forged MFA provenance | Provenance comes from BeeBox session creation after factor completion, not from client input. Missing/unknown provenance fails closed when TOTP is required. |
| Audit write fails after authority mutation | Grant issue/consume state and required success audit evidence share the same database transaction. Induced audit failure rolls authority mutation back. |
| Grant/proof secret leaks through telemetry | Reverification tokens, proof access tokens, verifier hashes and factor material are excluded from logs, audit facts and metric labels. Public errors are stable and do not reveal protected account/security inventory. |
| Clock manipulation extends authority | PostgreSQL/server time and server-recorded session times bound validity. Grants are capped to ten minutes and also to target/proof idle and absolute expiry. Client clocks do not extend the window. |

## Issue and consume lifecycle

1. The caller retains the original target-session bearer.
2. The caller performs fresh primary authentication and, when TOTP is configured, completes TOTP to obtain an eligible proof-session bearer.
3. The caller sends `POST /v1/reverifications` with the target bearer in `Authorization`, the proof bearer in `proof_access_token`, and exactly one supported purpose.
4. BeeBox validates application/origin, both active sessions, same application/user, proof freshness and required MFA provenance, then returns an opaque `reverification_token` with `Cache-Control: no-store`.
5. The caller sends that token once in `X-BeeBox-Reverification` on the matching sensitive mutation while continuing to use the original target bearer.
6. BeeBox transactionally revalidates target and proof, consumes the grant, records audit evidence, and injects trusted exact-scope authorization for the application service.

Expired, replayed, wrong-purpose, wrong-target, revoked-session and invalid-provenance grants are not refreshed or reused. The client must obtain fresh authentication evidence and mint a new grant instead of blindly retrying a spent one-time grant after an ambiguous mutation result.

## Residual risk

A party that simultaneously controls an active target session, an eligible fresh proof session for the same user/application, and the short-lived grant can authorize the bound mutation. P2.8 reduces the value of a stolen older session by requiring independent recent proof; it does not defend a user whose current primary authentication and required TOTP factor are both compromised. Client storage and transport remain responsible for protecting bearer values in memory and transit.