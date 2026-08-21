package beebox

import (
	"context"
	"net/http"
)

// RequestEmailLink asks BeeBox to send a one-time passwordless sign-in link.
// The response is deliberately generic and does not reveal account eligibility.
func (c *Client) RequestEmailLink(ctx context.Context, email, completionURL string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins/email-link", map[string]string{
		"email":          email,
		"completion_url": completionURL,
	}, &out, nil, false)
	return out, err
}

// ConfirmEmailLink redeems a one-time email-link secret. It is never retried
// automatically because a successful but ambiguous response may have consumed
// the challenge and created either a session or a pending-MFA transaction.
func (c *Client) ConfirmEmailLink(ctx context.Context, challengeID, secret string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins/email-link/confirm", map[string]string{
		"challenge_id": challengeID,
		"secret":       secret,
	}, &out, nil, false)
	return out, err
}
