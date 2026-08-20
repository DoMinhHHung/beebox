package beebox

import (
	"context"
	"net/http"
	"time"
)

const ReverificationHeader = "X-BeeBox-Reverification"

type ReverificationPurpose string

const (
	ReverificationPurposeTOTPEnroll          ReverificationPurpose = "totp_enroll"
	ReverificationPurposeTOTPRemove          ReverificationPurpose = "totp_remove"
	ReverificationPurposeTOTPReplace         ReverificationPurpose = "totp_replace"
	ReverificationPurposeRecoveryRegenerate  ReverificationPurpose = "recovery_regenerate"
	ReverificationPurposePasskeyRegister     ReverificationPurpose = "passkey_register"
	ReverificationPurposePasskeyRemove       ReverificationPurpose = "passkey_remove"
	ReverificationPurposeSocialLink          ReverificationPurpose = "social_link"
	ReverificationPurposeSocialUnlink        ReverificationPurpose = "social_unlink"
	ReverificationPurposeSessionRevoke       ReverificationPurpose = "session_revoke"
	ReverificationPurposeSessionRevokeOthers ReverificationPurpose = "session_revoke_others"
	ReverificationPurposeSignOutEverywhere   ReverificationPurpose = "sign_out_everywhere"
	ReverificationPurposeIdentifierAdd       ReverificationPurpose = "identifier_add"
	ReverificationPurposeIdentifierRemove    ReverificationPurpose = "identifier_remove"
	ReverificationPurposeIdentifierPrimary   ReverificationPurpose = "identifier_primary"
)

type ReverificationGrant struct {
	Token     string    `json:"reverification_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) CreateReverification(ctx context.Context, origin, accessToken, proofAccessToken string, purpose ReverificationPurpose) (ReverificationGrant, error) {
	var out ReverificationGrant
	err := c.doJSON(ctx, http.MethodPost, "/v1/reverifications", map[string]any{
		"purpose":            purpose,
		"proof_access_token": proofAccessToken,
	}, &out, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Origin":        origin,
	}, false)
	return out, err
}

func reverificationHeaders(origin, accessToken, reverificationToken string) map[string]string {
	return map[string]string{
		"Authorization":         "Bearer " + accessToken,
		"Origin":                origin,
		ReverificationHeader: reverificationToken,
	}
}
