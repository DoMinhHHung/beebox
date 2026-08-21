# P2.9 session self-service

P2.9 adds current-user session inventory and revocation without adding device fingerprinting, location, raw user-agent, or IP-history data.

## Authority model

All user routes require the application publishable key and an ordinary bearer access token. BeeBox derives the exact application and user from that trusted current session; callers never submit `application_id` or `user_id` as authority.

`GET /v1/sessions` is ordinary authenticated self-service. The three destructive operations additionally require a one-time P2.8 `X-BeeBox-Reverification` grant minted for the same target bearer session:

- selected session revoke: `session_revoke`;
- revoke every other session: `session_revoke_others`;
- sign out everywhere: `sign_out_everywhere`.

The existing `POST /v1/sessions/sign-out` remains simple current-session sign-out and does not require reverification.

## List sessions

```text
GET /v1/sessions?limit=20&cursor=<opaque-when-present>
X-BeeBox-Publishable-Key: <publishable-key>
Authorization: Bearer <current-access-token>
Origin: https://app.example.test
```

The default limit is 20 and the maximum is 100. Pages are newest-first. `next_cursor` is opaque and conveys no authority.

Each item contains only:

- opaque `id`;
- `created_at`;
- `last_seen_at`;
- `idle_expires_at`;
- `expires_at`;
- `revoked`;
- `current`.

BeeBox does not expose internal IDs, MFA provenance, refresh state, raw IP/user-agent, location, or device fingerprint data on this surface.

## Revoke one owned session

Mint a P2.8 grant for `session_revoke`, then call:

```text
POST /v1/sessions/<session-id>/revoke
X-BeeBox-Publishable-Key: <publishable-key>
Authorization: Bearer <current-access-token>
X-BeeBox-Reverification: <one-time-session_revoke-grant>
Origin: https://app.example.test
```

The path ID is only a locator. BeeBox checks ownership using the current application and user inside the revocation transaction. An absent/already-revoked/out-of-scope syntactically valid locator does not reveal ownership. Revoking the current session is allowed; browser refresh-cookie authority is cleared after commit.

## Revoke every other session

Mint a P2.8 grant for `session_revoke_others`, then call:

```text
POST /v1/sessions/revoke-others
X-BeeBox-Publishable-Key: <publishable-key>
Authorization: Bearer <current-access-token>
X-BeeBox-Reverification: <one-time-session_revoke_others-grant>
Origin: https://app.example.test
```

BeeBox atomically revokes every currently revocable session for the exact application/user except the server-resolved current target session. The current session remains active.

## Sign out everywhere

Mint a P2.8 grant for `sign_out_everywhere`, then call:

```text
POST /v1/sessions/sign-out-everywhere
X-BeeBox-Publishable-Key: <publishable-key>
Authorization: Bearer <current-access-token>
X-BeeBox-Reverification: <one-time-sign_out_everywhere-grant>
Origin: https://app.example.test
```

BeeBox atomically revokes all currently revocable sessions for the exact application/user, including the current target session, and clears current browser refresh-cookie authority after commit.

## Revocation semantics

`sessions.revoked_at` remains BeeBox's revocation source of truth. Refresh rotation checks this persisted state, so a refresh credential attached to a revoked session is unusable. BeeBox endpoints such as `GET /v1/sessions/current` also resolve persisted session state and therefore observe revocation immediately.

BeeBox access JWTs are short-lived Ed25519 tokens with a five-minute lifetime. A third-party/offline consumer that validates only the JWT signature and claims does not query BeeBox's session table and therefore cannot learn that a still-unexpired token was revoked. Such an offline verifier may continue accepting the already-issued token until its short expiry (subject to the verifier's existing clock-skew rules). P2.9 does not introduce Redis or a global JWT denylist and does not claim instantaneous offline revocation.

## Transaction and audit behavior

Selected and bulk revocation are scoped and committed in PostgreSQL with their security audit event. Audit insertion failure rolls back revocation. Repeat/concurrent revocation converges on the same final `revoked_at` state, while no session outside the exact application/user scope is touched.
