package beebox

import (
	"context"
	"net/http"
)

type TOTPEnrollment struct {
	EnrollmentID string `json:"enrollment_id"`
	Secret       string `json:"secret"`
	OTPAuthURI   string `json:"otpauth_uri"`
	ExpiresIn    int64  `json:"expires_in"`
}

type TOTPCredential struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

type TOTPState struct {
	Enabled      bool   `json:"enabled"`
	CredentialID string `json:"credential_id,omitempty"`
}

func (c *Client) StartTOTPEnrollment(ctx context.Context, origin, accessToken string) (TOTPEnrollment, error) {
	var out TOTPEnrollment
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/totp/enrollments", nil, &out, totpSessionHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) ConfirmTOTPEnrollment(ctx context.Context, origin, accessToken, enrollmentID, code string) (TOTPCredential, error) {
	var out TOTPCredential
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/totp/enrollments/confirm", map[string]string{
		"enrollment_id": enrollmentID,
		"code":          code,
	}, &out, totpSessionHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) TOTPState(ctx context.Context, origin, accessToken string) (TOTPState, error) {
	var out TOTPState
	err := c.doJSON(ctx, http.MethodGet, "/v1/mfa/totp", nil, &out, totpSessionHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) CompleteTOTPAuthentication(ctx context.Context, origin, pendingMFAToken, code string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/totp/complete", map[string]string{
		"pending_mfa_token": pendingMFAToken,
		"code":              code,
	}, &out, map[string]string{"Origin": origin}, false)
	return out, err
}

func (c *Client) RemoveTOTP(ctx context.Context, origin, accessToken string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/mfa/totp", nil, nil, totpSessionHeaders(origin, accessToken), false)
}

func totpSessionHeaders(origin, accessToken string) map[string]string {
	return map[string]string{
		"Origin":        origin,
		"Authorization": "Bearer " + accessToken,
	}
}
