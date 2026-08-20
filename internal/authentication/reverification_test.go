package authentication

import (
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func TestReverificationPurposeAllowlist(t *testing.T) {
	for _, purpose := range []string{
		ReverificationPurposeTOTPEnroll,
		ReverificationPurposeTOTPRemove,
		ReverificationPurposeTOTPReplace,
		ReverificationPurposeRecoveryRegenerate,
		ReverificationPurposePasskeyRegister,
		ReverificationPurposePasskeyRemove,
		ReverificationPurposeSocialLink,
		ReverificationPurposeSocialUnlink,
		ReverificationPurposeSessionRevoke,
		ReverificationPurposeSessionRevokeOthers,
		ReverificationPurposeSignOutEverywhere,
		ReverificationPurposeIdentifierAdd,
		ReverificationPurposeIdentifierRemove,
		ReverificationPurposeIdentifierPrimary,
	} {
		if !ValidReverificationPurpose(purpose) {
			t.Fatalf("purpose %q rejected", purpose)
		}
	}
	for _, purpose := range []string{"", "profile_patch", "recovery_code", "admin"} {
		if ValidReverificationPurpose(purpose) {
			t.Fatalf("unexpected purpose %q accepted", purpose)
		}
	}
}

func TestReverificationHashIsPurposeAndSessionBound(t *testing.T) {
	secret := make([]byte, ReverificationSecretSize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	appID := applicationinstance.InternalID(7)
	userID := identity.InternalID(11)
	base := reverificationHash(secret, appID, userID, "ses_a", ReverificationPurposeTOTPEnroll)
	if base == reverificationHash(secret, appID, userID, "ses_b", ReverificationPurposeTOTPEnroll) {
		t.Fatal("hash is not session-bound")
	}
	if base == reverificationHash(secret, appID, userID, "ses_a", ReverificationPurposeTOTPRemove) {
		t.Fatal("hash is not purpose-bound")
	}
	if base == reverificationHash(secret, appID, identity.InternalID(12), "ses_a", ReverificationPurposeTOTPEnroll) {
		t.Fatal("hash is not user-bound")
	}
}
