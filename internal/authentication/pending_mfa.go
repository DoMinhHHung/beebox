package authentication

import (
	"errors"
	"time"
)

const PendingMFATTL = 5 * time.Minute

const (
	PrimaryMethodPassword  = "password"
	PrimaryMethodEmailOTP  = "email_otp"
	PrimaryMethodEmailLink = "email_link"
	PrimaryMethodPhoneOTP  = "phone_otp"
	PrimaryMethodSocial    = "social"
	PrimaryMethodPasskey   = "passkey"
)

var (
	ErrPendingMFAInvalid     = errors.New("invalid pending MFA transaction")
	ErrPendingMFAExpired     = errors.New("pending MFA transaction expired")
	ErrPendingMFAProof       = errors.New("MFA proof failed")
	ErrPendingMFAReplay      = errors.New("MFA proof replayed")
	ErrPendingMFAPersistence = errors.New("pending MFA persistence failure")
)

// PendingMFAWrite is prepared after a primary proof succeeds. Persistence must
// decide atomically whether an active TOTP credential requires this transaction
// instead of creating an ordinary session.
type PendingMFAWrite struct {
	PublicID       string
	TokenHash      [32]byte
	PrimaryMethod  string
	PrimaryContext string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

func (w PendingMFAWrite) Valid() bool {
	return w.PublicID != "" && w.TokenHash != ([32]byte{}) && validPrimaryMethod(w.PrimaryMethod) &&
		len(w.PrimaryContext) >= 1 && len(w.PrimaryContext) <= 128 && !w.CreatedAt.IsZero() &&
		w.ExpiresAt.After(w.CreatedAt) && !w.ExpiresAt.After(w.CreatedAt.Add(PendingMFATTL))
}

func validPrimaryMethod(method string) bool {
	switch method {
	case PrimaryMethodPassword, PrimaryMethodEmailOTP, PrimaryMethodEmailLink, PrimaryMethodPhoneOTP, PrimaryMethodSocial, PrimaryMethodPasskey:
		return true
	default:
		return false
	}
}

type PrimaryAssuranceResult struct {
	UserPublicID          string
	ApplicationPublicID   string
	MFARequired           bool
	PendingMFAPublicID    string
	PendingMFAExpiresAt   time.Time
	RecoveryCodeAvailable bool
}
