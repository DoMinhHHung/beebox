package beebox

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type PasskeyAttempt struct {
	AttemptID string          `json:"attempt_id"`
	PublicKey json.RawMessage `json:"public_key"`
	ExpiresIn int64           `json:"expires_in"`
}

type PasskeyRegistrationCompleteRequest struct {
	AttemptID  string          `json:"attempt_id"`
	Name       string          `json:"name,omitempty"`
	Credential json.RawMessage `json:"credential"`
}

type PasskeyAuthenticationCompleteRequest struct {
	AttemptID  string          `json:"attempt_id"`
	Credential json.RawMessage `json:"credential"`
}

type Passkey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type PasskeyList struct {
	Items []Passkey `json:"items"`
}

// BeginPasskeyRegistration returns WebAuthn creation options for the current
// authenticated target session after the caller has supplied a one-time
// passkey_register reverification grant. The SDK transports opaque browser
// WebAuthn JSON and never interprets authenticator protocol structures.
func (c *Client) BeginPasskeyRegistration(ctx context.Context, accessToken, origin, reverificationToken string) (PasskeyAttempt, error) {
	var out PasskeyAttempt
	err := c.doJSON(ctx, "POST", "/v1/passkeys/registration/attempts", struct{}{}, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
	return out, err
}

func (c *Client) CompletePasskeyRegistration(ctx context.Context, accessToken, origin string, input PasskeyRegistrationCompleteRequest) (Passkey, error) {
	var out Passkey
	err := c.doJSON(ctx, "POST", "/v1/passkeys/registration/complete", input, &out, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Origin":        origin,
	}, false)
	return out, err
}

func (c *Client) BeginPasskeyAuthentication(ctx context.Context, origin string) (PasskeyAttempt, error) {
	var out PasskeyAttempt
	err := c.doJSON(ctx, "POST", "/v1/passkeys/authentication/attempts", struct{}{}, &out, map[string]string{"Origin": origin}, false)
	return out, err
}

func (c *Client) CompletePasskeyAuthentication(ctx context.Context, origin string, input PasskeyAuthenticationCompleteRequest) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, "POST", "/v1/passkeys/authentication/complete", input, &out, map[string]string{"Origin": origin}, false)
	return out, err
}

func (c *Client) ListPasskeys(ctx context.Context, accessToken, origin string) (PasskeyList, error) {
	var out PasskeyList
	err := c.doJSON(ctx, "GET", "/v1/passkeys", nil, &out, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Origin":        origin,
	}, false)
	return out, err
}

func (c *Client) RemovePasskey(ctx context.Context, accessToken, origin, reverificationToken, passkeyID string) error {
	return c.doJSON(ctx, "DELETE", "/v1/passkeys/"+url.PathEscape(passkeyID), nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}
