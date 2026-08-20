package authentication

import (
	"context"
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

func TestRequireReverificationRequiresExactTrustedScope(t *testing.T) {
	appID := applicationinstance.InternalID(7)
	userID := identity.InternalID(11)
	sessionID := "ses_123e4567-e89b-42d3-a456-426614174000"
	purpose := ReverificationPurposePasskeyRegister

	if err := RequireReverification(context.Background(), appID, userID, sessionID, purpose); err != ErrReverificationInvalid {
		t.Fatalf("absent authorization error=%v", err)
	}

	tests := []struct {
		name      string
		authApp   applicationinstance.InternalID
		authUser  identity.InternalID
		authSes   string
		authPurp  string
		checkApp  applicationinstance.InternalID
		checkUser identity.InternalID
		checkSes  string
		checkPurp string
	}{
		{name: "application", authApp: appID + 1, authUser: userID, authSes: sessionID, authPurp: purpose, checkApp: appID, checkUser: userID, checkSes: sessionID, checkPurp: purpose},
		{name: "user", authApp: appID, authUser: userID + 1, authSes: sessionID, authPurp: purpose, checkApp: appID, checkUser: userID, checkSes: sessionID, checkPurp: purpose},
		{name: "target session", authApp: appID, authUser: userID, authSes: sessionID + "-other", authPurp: purpose, checkApp: appID, checkUser: userID, checkSes: sessionID, checkPurp: purpose},
		{name: "purpose", authApp: appID, authUser: userID, authSes: sessionID, authPurp: ReverificationPurposePasskeyRemove, checkApp: appID, checkUser: userID, checkSes: sessionID, checkPurp: purpose},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := withReverificationAuthorization(context.Background(), tt.authApp, tt.authUser, tt.authSes, tt.authPurp)
			if err := RequireReverification(ctx, tt.checkApp, tt.checkUser, tt.checkSes, tt.checkPurp); err != ErrReverificationInvalid {
				t.Fatalf("mismatched scope error=%v", err)
			}
		})
	}

	ctx := testReverificationContext(appID, userID, sessionID, purpose)
	if err := RequireReverification(ctx, appID, userID, sessionID, purpose); err != nil {
		t.Fatalf("exact authorization error=%v", err)
	}
}

func testReverificationContext(appID applicationinstance.InternalID, userID identity.InternalID, sessionID, purpose string) context.Context {
	return withReverificationAuthorization(context.Background(), appID, userID, sessionID, purpose)
}
