# TOTP MFA threat model

This document extends the BeeBox threat model for the P2.6 TOTP implementation. It covers TOTP enrollment, authentication continuation, removal, secret encryption and operational key rotation. Recovery codes and generic reverification are separate later checkpoints and are not claimed here.

## Security boundary

TOTP is an additional factor after any implemented primary proof: password, verified-email OTP, verified-phone OTP, social provider proof or passkey. A primary proof for a user with active TOTP creates only a five-minute pending-authentication transaction. It creates no session, access token or refresh credential. The public authentication result is a `status`-discriminated union so clients cannot mistake pending authentication for authenticated authority.

Pending tokens contain an opaque `mfp_` public identifier and 32 random secret bytes. PostgreSQL stores only a SHA-256 verifier over the purpose-separated input `beebox:v1:pending-mfa-token\0 || secret`, together with the exact application, user, primary method and bounded primary-proof context. A transaction expires after five minutes, accepts no more than five failed proofs and is consumed in the same transaction that advances the credential timestep, creates session/refresh state and appends audit evidence.

## TOTP profile

- HMAC-SHA1, six decimal digits and a 30-second timestep;
- accepted clock window is exactly previous, current and next timestep;
- one active logical credential per application/user;
- the persisted last accepted timestep is locked and advanced transactionally;
- an accepted timestep may authorize at most one completion, including across concurrent pending transactions;
- passkeys and alternative primary methods do not bypass active TOTP;
- BeeBox has no trusted-device or remembered-device bypass.

## Secret confidentiality and integrity

The Base32 setup secret is returned only by the enrollment-start response and is never stored in plaintext. Persistence uses an envelope containing a bounded key ID, version 1, a random 96-bit nonce and AES-256-GCM ciphertext. The AES key is derived from the selected 32-byte root key using HKDF-SHA256 with the fixed TOTP purpose. AEAD associated data binds the envelope version, purpose, exact application, user and credential.

Startup inventories every persisted TOTP credential and unconsumed enrollment. It fails closed if ciphertext exists while encryption is disabled, a referenced key ID is missing or an envelope version is unsupported. Decryption also fails closed for a missing key, unknown key ID, malformed nonce/envelope or authentication failure. Setup secrets and decrypted Base32 values are forbidden from logs, metrics and audit facts.

## Threats and controls

| Threat | Control and evidence |
| --- | --- |
| MFA downgrade through another primary method | Every implemented primary finalizer calls the same PostgreSQL assurance boundary. Active TOTP returns only `mfa_required`. |
| Authority issued before the second factor | Pending results omit session/access/refresh authority; session creation occurs only inside successful pending-MFA finalization. |
| Pending-token database disclosure | Only a domain-separated SHA-256 verifier is persisted; the 32-byte secret is returned once. |
| Pending-token guessing or brute force | 256-bit random secret, five-minute TTL and at most five failed completions. |
| TOTP replay or concurrent same-step use | Credential row is locked; the last accepted timestep must increase; pending consume, session issuance and audit are atomic. |
| Cross-tenant or cross-user substitution | Token lookup and finalization verify the exact application/user/primary-proof snapshot and active credential context. |
| Audit failure leaving authority | Audit insertion shares the authority transaction; failure rolls back pending consume, timestep advance and session/refresh creation. |
| Ciphertext moved between principals | AES-GCM AAD binds purpose/application/user/credential, causing authentication failure. |
| Unknown or prematurely removed key | Startup reference inventory and decrypt both fail closed. Operators retain historical keys until all references are gone. |
| Secret leakage through observability | Metrics use bounded outcomes only; audit references the BeeBox credential ID; no plaintext or code is emitted. |

## Residual and operational risks

TOTP depends on approximate server/authenticator clock agreement; the three-step acceptance window is deliberate and replay protection remains authoritative. Compromise of both a primary factor and the user's TOTP seed defeats this factor combination. Root-key compromise requires an incident response and credential replacement plan; normal additive key rotation does not by itself rewrite existing ciphertext. Offline access JWT revocation retains the documented five-minute maximum lag and is independent of pending-MFA issuance controls.
