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
	ID            string   `json:"id"`
	CreatedAt     string   `json:"created_at"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

type RecoveryCodeState struct {
	Available bool `json:"available"`
	Remaining int  `json:"remaining"`
}

type RecoveryCodeSet struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

type TOTPState struct {
	Enabled      bool   `json:"enabled"`
	CredentialID string `json:"credential_id,omitempty"`
}

func (c *Client) StartTOTPEnrollment(ctx context.Context, origin, accessToken, reverificationToken string) (TOTPEnrollment, error) {
	var out TOTPEnrollment
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/totp/enrollments", nil, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
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

func (c *Client) CompleteRecoveryCodeAuthentication(ctx context.Context, origin, pendingMFAToken, code string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/recovery-codes/complete", map[string]string{
		"pending_mfa_token": pendingMFAToken,
		"code":              code,
	}, &out, map[string]string{"Origin": origin}, false)
	return out, err
}

func (c *Client) RecoveryCodeState(ctx context.Context, origin, accessToken string) (RecoveryCodeState, error) {
	var out RecoveryCodeState
	err := c.doJSON(ctx, http.MethodGet, "/v1/mfa/recovery-codes", nil, &out, totpSessionHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) RegenerateRecoveryCodes(ctx context.Context, origin, accessToken, reverificationToken string) (RecoveryCodeSet, error) {
	var out RecoveryCodeSet
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/recovery-codes/regenerate", nil, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
	return out, err
}

func (c *Client) RemoveTOTP(ctx context.Context, origin, accessToken, reverificationToken string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/mfa/totp", nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) StartTOTPReplacement(ctx context.Context, origin, accessToken, reverificationToken, recoveryCode string) (TOTPEnrollment, error) {
	var out TOTPEnrollment
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/totp/replacements", map[string]string{"recovery_code": recoveryCode}, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
	return out, err
}

func (c *Client) ConfirmTOTPReplacement(ctx context.Context, origin, accessToken, enrollmentID, code string) (TOTPCredential, error) {
	var out TOTPCredential
	err := c.doJSON(ctx, http.MethodPost, "/v1/mfa/totp/replacements/confirm", map[string]string{
		"enrollment_id": enrollmentID,
		"code":          code,
	}, &out, totpSessionHeaders(origin, accessToken), false)
	return out, err
}

func totpSessionHeaders(origin, accessToken string) map[string]string {
	return map[string]string{
		"Origin":        origin,
		"Authorization": "Bearer " + accessToken,
	}
}
