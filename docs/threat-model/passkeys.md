# P2.5 passkey / WebAuthn threat-model delta

This document extends the initial BeeBox threat model for the P2.5 passkey implementation. It does not define TOTP/MFA behavior; TOTP remains P2.6.

## Trust and key boundary

BeeBox uses WebAuthn as a primary authentication method. The authenticator owns the credential private key; BeeBox never receives, stores, reconstructs or logs that private key. BeeBox stores the public WebAuthn credential representation required to verify assertions, the opaque credential ID, RP ID, application/user ownership, and bounded ceremony state. Browser WebAuthn request/response objects cross the public BeeBox API as opaque JSON; go-webauthn types are an internal adapter detail and are not a public contract.

The application is resolved from the BeeBox publishable key. Every passkey browser request requires one exact canonical Origin already allowed for that application. The RP ID is derived server-side from that trusted Origin and stored ceremony state; callers cannot choose a different RP ID at completion. Registration, listing and removal additionally derive the exact current user/session from a BeeBox bearer access token rather than accepting user/session IDs from the request.

## Ceremony replay, expiry and substitution

Registration and authentication starts create opaque `pka_` ceremony locators with a maximum five-minute lifetime. The database stores a SHA-256 challenge hash, not a raw challenge column, plus the minimum WebAuthn session data needed by the maintained verifier. Completion resolves the exact application, purpose, Origin and ceremony locator, rejects expired state and atomically marks the ceremony consumed before proof can be reused. A consumed, expired, wrong-purpose, wrong-Origin or wrong-application attempt fails closed; cleanup is not required for correctness.

The WebAuthn adapter rechecks the ceremony RP ID against the trusted current RP ID and delegates challenge, client-data Origin, RP-ID hash, authenticator-data/signature, user-presence/user-verification and credential parsing to the maintained go-webauthn verifier. Malformed client data, authenticator data, signatures or stored credential JSON are mapped to BeeBox-owned proof failures rather than returned verbatim.

Authentication is discoverable/resident-credential based and requires user verification. The asserted credential ID and user handle are resolved only inside the exact application and RP ID. A credential owned by a different BeeBox application or principal cannot be substituted even when its opaque credential bytes are known. Public `pky_` and `pka_` IDs are locators, never authorization.

## Credential state and cloned-authenticator signals

BeeBox persists the verifier-owned WebAuthn credential JSON because authenticator state such as the signature counter may change after a valid assertion. Authentication locks the exact stored credential and, in one database transaction, updates that verifier state, creates the ordinary BeeBox session/refresh verifier and appends the security audit event. BeeBox does not invent a second counter policy outside the maintained library; counter/cloned-authenticator semantics follow the selected go-webauthn behavior and are fail-closed when the verifier rejects the assertion.

Concurrent/replayed authentication cannot use the same ceremony twice. Credential state is locked while the successful assertion is finalized so concurrent state updates cannot silently overwrite one another.

## Enrollment and removal authority

Passkey registration and removal are sensitive account mutations. They require the persisted initiating/current session itself to be inside the accepted recent-authentication window; merely refreshing an access token for an old session does not renew that evidence. Registration is bound to that exact application/user/session. Removal resolves ownership from the current application/user and an opaque `pky_` locator.

A passkey participates in last-usable-authentication-method protection only when it is a stored credential for the exact current application/user under the implemented passkey contract. Cross-application credentials never count. Removing the sole usable passkey is denied. Removal is allowed when another usable passkey or another currently usable BeeBox primary/recovery path remains, using the same application-scoped availability rules as social unlink. P2.5 does not classify passkeys as TOTP/MFA and does not bypass future configured TOTP requirements.

Social-account unlink likewise counts a same-application/user passkey as a usable remaining primary authentication path. This prevents P2.4B from incorrectly stranding a passkey-capable account while preserving the previous behavior when no passkey exists.

## Transaction and audit integrity

Successful registration persists the credential and its passkey-registration audit fact in the same transaction. Successful authentication persists updated credential state, ordinary session/refresh state and its authentication audit fact coherently in one transaction. Successful removal deletes the credential and writes its removal audit fact in one transaction. Induced audit-insert failure must roll back the corresponding credential/session mutation.

Audit data contains BeeBox-owned action/outcome/application/user context and an opaque `passkey:<pky_...>` resource reference where a credential resource exists. Raw WebAuthn browser responses, challenges, credential public-key blobs, credential IDs and authenticator-private material are not audit payloads.

## Retention and denial of service

Expired and consumed `passkey_attempts` are operational security state, not durable identity data. The existing BeeBox maintenance primitive removes them in bounded batches using expiry/consumption indexes. Live ceremonies and `passkey_credentials` are outside that cleanup. Proof paths always enforce expiry and consumption before cleanup, so delayed maintenance cannot make stale state usable.

Large or malformed browser payloads remain subject to the HTTP JSON-body limit and WebAuthn parser validation. Credential IDs and names have database bounds, passkey lists are bounded, and RP/origin strings are constrained. Authentication failures expose stable BeeBox error categories rather than credential ownership, raw verifier errors or internal database details.
