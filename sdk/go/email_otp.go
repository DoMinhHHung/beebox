package beebox

import (
	"context"
	"net/http"
)

// RequestEmailOTP asks BeeBox to send a passwordless sign-in code. The returned
// status is deliberately generic and does not reveal account eligibility.
func (c *Client) RequestEmailOTP(ctx context.Context, email string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins/email-otp", map[string]string{"email": email}, &out, nil, false)
	return out, err
}

// ConfirmEmailOTP redeems a passwordless sign-in code exactly once. This method
// does not automatically retry because an ambiguous successful response may
// have consumed the challenge and created a session.
func (c *Client) ConfirmEmailOTP(ctx context.Context, email, code string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins/email-otp/confirm", map[string]string{"email": email, "code": code}, &out, nil, false)
	return out, err
}
