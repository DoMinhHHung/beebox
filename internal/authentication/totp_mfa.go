package authentication

import (
	"context"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

type PendingTOTPAuthenticationSnapshot struct {
	PendingPublicID       string
	TokenHash             [32]byte
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	PrimaryMethod         string
	PrimaryContext        string
	CredentialID          string
	Envelope              TOTPSecretEnvelope
	LastAcceptedTimestep  *int64
	FailedAttempts        int
	ExpiresAt             time.Time
}

type TOTPAuthenticationFinalize struct {
	PendingPublicID string
	TokenHash       [32]byte
	Snapshot        PendingTOTPAuthenticationSnapshot
	Timestep        int64
	SessionPublicID string
	RefreshVerifier [32]byte
	IdleExpiresAt   time.Time
	ExpiresAt       time.Time
	CorrelationID   audit.CorrelationID
}

type TOTPAuthenticationResult struct {
	UserPublicID        identity.PublicID
	ApplicationPublicID applicationinstance.PublicID
	PrimaryMethod       string
	PrimaryContext      string
}

type TOTPAuthenticationPersistence interface {
	LoadPendingTOTPAuthentication(context.Context, string, [32]byte) (PendingTOTPAuthenticationSnapshot, error)
	RecordPendingTOTPFailure(context.Context, string, [32]byte) error
	FinalizePendingTOTPAuthentication(context.Context, TOTPAuthenticationFinalize) (TOTPAuthenticationResult, error)
}

func (s *TOTPService) CompletePendingAuthentication(
	ctx context.Context,
	expectedAppID applicationinstance.InternalID,
	pendingPublicID string,
	tokenHash [32]byte,
	code string,
	final TOTPAuthenticationFinalize,
) (TOTPAuthenticationResult, error) {
	if s == nil || s.protocol == nil || s.protector == nil || s.now == nil || !s.protector.Enabled() || !expectedAppID.Valid() || pendingPublicID == "" || tokenHash == ([32]byte{}) || code == "" || final.CorrelationID == (audit.CorrelationID{}) {
		return TOTPAuthenticationResult{}, ErrTOTPEnrollmentInvalid
	}
	persistence, ok := s.persistence.(TOTPAuthenticationPersistence)
	if !ok {
		return TOTPAuthenticationResult{}, ErrTOTPUnavailable
	}
	snapshot, err := persistence.LoadPendingTOTPAuthentication(ctx, pendingPublicID, tokenHash)
	if err != nil {
		return TOTPAuthenticationResult{}, mapTOTPError(ctx, err)
	}
	now := s.now().UTC()
	if snapshot.PendingPublicID != pendingPublicID || snapshot.TokenHash != tokenHash || snapshot.ApplicationInstanceID != expectedAppID || !snapshot.UserID.Valid() || snapshot.PrimaryMethod == "" || snapshot.PrimaryContext == "" || snapshot.CredentialID == "" || snapshot.FailedAttempts < 0 || snapshot.FailedAttempts >= 5 || !now.Before(snapshot.ExpiresAt.UTC()) {
		return TOTPAuthenticationResult{}, ErrTOTPEnrollmentInvalid
	}
	secretRaw, err := s.protector.DecryptTOTP(TOTPSecretContext{
		ApplicationID: snapshot.ApplicationInstanceID,
		UserID:        snapshot.UserID,
		CredentialID:  snapshot.CredentialID,
	}, snapshot.Envelope)
	if err != nil {
		return TOTPAuthenticationResult{}, ErrTOTPUnavailable
	}
	timestep, valid, err := s.protocol.Verify(secretRaw, code, now)
	if err != nil || !valid {
		if recordErr := persistence.RecordPendingTOTPFailure(ctx, pendingPublicID, tokenHash); recordErr != nil {
			return TOTPAuthenticationResult{}, mapTOTPError(ctx, recordErr)
		}
		return TOTPAuthenticationResult{}, ErrTOTPInvalidCode
	}
	if snapshot.LastAcceptedTimestep != nil && timestep <= *snapshot.LastAcceptedTimestep {
		return TOTPAuthenticationResult{}, ErrTOTPReplay
	}
	final.PendingPublicID = pendingPublicID
	final.TokenHash = tokenHash
	final.Snapshot = snapshot
	final.Timestep = timestep
	result, err := persistence.FinalizePendingTOTPAuthentication(ctx, final)
	if err != nil {
		return TOTPAuthenticationResult{}, mapTOTPError(ctx, err)
	}
	result.PrimaryMethod = snapshot.PrimaryMethod
	result.PrimaryContext = snapshot.PrimaryContext
	return result, nil
}
