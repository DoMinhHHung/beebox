package beebox

import (
	"context"
	"net/http"
)

// RequestPhoneSignUpOTP requests the generic phone-first signup SMS challenge.
// It does not create a user until ConfirmPhoneSignUpOTP proves possession.
func (c *Client) RequestPhoneSignUpOTP(ctx context.Context, phone string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ups/phone", map[string]string{"phone": phone}, &out, nil, false)
	return out, err
}

// ConfirmPhoneSignUpOTP is intentionally one-time and is never automatically
// retried because an ambiguous successful response may already have committed
// the user and session.
func (c *Client) ConfirmPhoneSignUpOTP(ctx context.Context, phone, code string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ups/phone/confirm", map[string]string{"phone": phone, "code": code}, &out, nil, false)
	return out, err
}

// RequestPhoneOTPSignIn asks BeeBox to send a primary-authentication SMS code
// for an existing verified phone. The response is deliberately generic.
func (c *Client) RequestPhoneOTPSignIn(ctx context.Context, phone string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins/phone-otp", map[string]string{"phone": phone}, &out, nil, false)
	return out, err
}

// ConfirmPhoneOTPSignIn redeems a phone sign-in challenge exactly once and does
// not automatically retry an ambiguous confirmation.
func (c *Client) ConfirmPhoneOTPSignIn(ctx context.Context, phone, code string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins/phone-otp/confirm", map[string]string{"phone": phone, "code": code}, &out, nil, false)
	return out, err
}
