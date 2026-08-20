package authentication

import (
	"context"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	TOTPEnrollmentTTL = 10 * time.Minute
	TOTPPeriodSeconds = int64(30)
)

var (
	ErrTOTPUnavailable            = errors.New("TOTP unavailable")
	ErrTOTPInvalidSession         = errors.New("invalid TOTP session")
	ErrTOTPReverificationRequired = errors.New("TOTP reverification required")
	ErrTOTPEnrollmentInvalid      = errors.New("invalid TOTP enrollment")
	ErrTOTPInvalidCode            = errors.New("invalid TOTP code")
	ErrTOTPReplay                 = errors.New("TOTP replay")
	ErrTOTPPersistence            = errors.New("TOTP persistence failure")
	ErrTOTPAlreadyActive          = errors.New("TOTP already active")
)

type TOTPSession struct {
	ApplicationInstanceID applicationinstance.InternalID
	ApplicationPublicID   applicationinstance.PublicID
	UserID                identity.InternalID
	UserPublicID          identity.PublicID
	SessionPublicID       string
	CreatedAt             time.Time
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	Revoked               bool
}

type TOTPSecretEnvelope struct {
	Version    int
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type TOTPSecretContext struct {
	ApplicationID applicationinstance.InternalID
	UserID        identity.InternalID
	CredentialID  string
}

type TOTPSecretProtector interface {
	EncryptTOTP(TOTPSecretContext, []byte) (TOTPSecretEnvelope, error)
	DecryptTOTP(TOTPSecretContext, TOTPSecretEnvelope) ([]byte, error)
	Enabled() bool
}

type TOTPProtocolEnrollment struct {
	SecretRaw []byte
	Secret    string
	URI       string
}

type TOTPProtocol interface {
	Generate(string, string) (TOTPProtocolEnrollment, error)
	Verify([]byte, string, time.Time) (int64, bool, error)
}

type TOTPIdentifierGenerator interface {
	NewEnrollmentID() (string, error)
	NewCredentialID() (string, error)
}

type TOTPEnrollmentWrite struct {
	EnrollmentID          string
	CredentialID          string
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	SessionPublicID       string
	Envelope              TOTPSecretEnvelope
	CreatedAt             time.Time
	ExpiresAt             time.Time
	CorrelationID         audit.CorrelationID
}

type TOTPEnrollmentSnapshot struct {
	EnrollmentID          string
	CredentialID          string
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	SessionPublicID       string
	Envelope              TOTPSecretEnvelope
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

type TOTPCredentialView struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

type TOTPPersistence interface {
	CreateTOTPEnrollment(context.Context, TOTPEnrollmentWrite) error
	LoadTOTPEnrollment(context.Context, applicationinstance.InternalID, identity.InternalID, string) (TOTPEnrollmentSnapshot, error)
	ActivateTOTPEnrollment(context.Context, TOTPEnrollmentSnapshot, int64, audit.CorrelationID) (TOTPCredentialView, error)
	GetTOTPCredential(context.Context, applicationinstance.InternalID, identity.InternalID) (TOTPCredentialView, error)
	RemoveTOTPCredential(context.Context, TOTPSession, audit.CorrelationID) error
}

type TOTPEnrollmentResult struct {
	EnrollmentID string `json:"enrollment_id"`
	Secret       string `json:"secret"`
	OTPAuthURI   string `json:"otpauth_uri"`
	ExpiresIn    int64  `json:"expires_in"`
}

type TOTPService struct {
	persistence TOTPPersistence
	protocol    TOTPProtocol
	protector   TOTPSecretProtector
	ids         TOTPIdentifierGenerator
	now         func() time.Time
}

func NewTOTPService(p TOTPPersistence, protocol TOTPProtocol, protector TOTPSecretProtector, ids TOTPIdentifierGenerator) *TOTPService {
	return &TOTPService{persistence: p, protocol: protocol, protector: protector, ids: ids, now: time.Now}
}

func (s *TOTPService) StartEnrollment(ctx context.Context, current TOTPSession, correlationID audit.CorrelationID) (TOTPEnrollmentResult, error) {
	if s == nil || s.persistence == nil || s.protocol == nil || s.protector == nil || s.ids == nil || s.now == nil || !s.protector.Enabled() {
		return TOTPEnrollmentResult{}, ErrTOTPUnavailable
	}
	now := s.now().UTC()
	if err := validateTOTPFreshSession(current, now); err != nil {
		return TOTPEnrollmentResult{}, err
	}
	if correlationID == (audit.CorrelationID{}) {
		return TOTPEnrollmentResult{}, ErrTOTPUnavailable
	}
	enrollmentID, err := s.ids.NewEnrollmentID()
	if err != nil {
		return TOTPEnrollmentResult{}, ErrTOTPUnavailable
	}
	credentialID, err := s.ids.NewCredentialID()
	if err != nil {
		return TOTPEnrollmentResult{}, ErrTOTPUnavailable
	}
	generated, err := s.protocol.Generate(string(current.ApplicationPublicID), string(current.UserPublicID))
	if err != nil || len(generated.SecretRaw) == 0 || generated.Secret == "" || generated.URI == "" {
		return TOTPEnrollmentResult{}, ErrTOTPUnavailable
	}
	envelope, err := s.protector.EncryptTOTP(TOTPSecretContext{
		ApplicationID: current.ApplicationInstanceID,
		UserID:        current.UserID,
		CredentialID:  credentialID,
	}, generated.SecretRaw)
	if err != nil {
		return TOTPEnrollmentResult{}, ErrTOTPUnavailable
	}
	deadline := earliestTime(now.Add(TOTPEnrollmentTTL), current.CreatedAt.UTC().Add(SocialLinkFreshness), current.IdleExpiresAt.UTC(), current.ExpiresAt.UTC())
	if !deadline.After(now) {
		return TOTPEnrollmentResult{}, ErrTOTPReverificationRequired
	}
	if err := s.persistence.CreateTOTPEnrollment(ctx, TOTPEnrollmentWrite{
		EnrollmentID:          enrollmentID,
		CredentialID:          credentialID,
		ApplicationInstanceID: current.ApplicationInstanceID,
		UserID:                current.UserID,
		SessionPublicID:       current.SessionPublicID,
		Envelope:              envelope,
		CreatedAt:             now,
		ExpiresAt:             deadline,
		CorrelationID:         correlationID,
	}); err != nil {
		return TOTPEnrollmentResult{}, mapTOTPError(ctx, err)
	}
	return TOTPEnrollmentResult{EnrollmentID: enrollmentID, Secret: generated.Secret, OTPAuthURI: generated.URI, ExpiresIn: int64(deadline.Sub(now) / time.Second)}, nil
}

func (s *TOTPService) ConfirmEnrollment(ctx context.Context, current TOTPSession, enrollmentID, code string, correlationID audit.CorrelationID) (TOTPCredentialView, error) {
	if s == nil || s.persistence == nil || s.protocol == nil || s.protector == nil || s.now == nil || !s.protector.Enabled() || enrollmentID == "" || correlationID == (audit.CorrelationID{}) {
		return TOTPCredentialView{}, ErrTOTPEnrollmentInvalid
	}
	now := s.now().UTC()
	if err := validateTOTPFreshSession(current, now); err != nil {
		return TOTPCredentialView{}, err
	}
	enrollment, err := s.persistence.LoadTOTPEnrollment(ctx, current.ApplicationInstanceID, current.UserID, enrollmentID)
	if err != nil {
		return TOTPCredentialView{}, mapTOTPError(ctx, err)
	}
	if enrollment.SessionPublicID != current.SessionPublicID || !now.Before(enrollment.ExpiresAt.UTC()) {
		return TOTPCredentialView{}, ErrTOTPEnrollmentInvalid
	}
	secretRaw, err := s.protector.DecryptTOTP(TOTPSecretContext{
		ApplicationID: current.ApplicationInstanceID,
		UserID:        current.UserID,
		CredentialID:  enrollment.CredentialID,
	}, enrollment.Envelope)
	if err != nil {
		return TOTPCredentialView{}, ErrTOTPUnavailable
	}
	timestep, valid, err := s.protocol.Verify(secretRaw, code, now)
	if err != nil || !valid {
		return TOTPCredentialView{}, ErrTOTPInvalidCode
	}
	credential, err := s.persistence.ActivateTOTPEnrollment(ctx, enrollment, timestep, correlationID)
	if err != nil {
		return TOTPCredentialView{}, mapTOTPError(ctx, err)
	}
	return credential, nil
}

func (s *TOTPService) Current(ctx context.Context, current TOTPSession) (TOTPCredentialView, error) {
	if s == nil || s.persistence == nil || s.now == nil || !validTOTPSession(current) {
		return TOTPCredentialView{}, ErrTOTPInvalidSession
	}
	now := s.now().UTC()
	if current.Revoked || !now.Before(current.IdleExpiresAt.UTC()) || !now.Before(current.ExpiresAt.UTC()) {
		return TOTPCredentialView{}, ErrTOTPInvalidSession
	}
	view, err := s.persistence.GetTOTPCredential(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil {
		return TOTPCredentialView{}, mapTOTPError(ctx, err)
	}
	return view, nil
}

func (s *TOTPService) Remove(ctx context.Context, current TOTPSession, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || s.now == nil || correlationID == (audit.CorrelationID{}) {
		return ErrTOTPUnavailable
	}
	if err := validateTOTPFreshSession(current, s.now().UTC()); err != nil {
		return err
	}
	if err := s.persistence.RemoveTOTPCredential(ctx, current, correlationID); err != nil {
		return mapTOTPError(ctx, err)
	}
	return nil
}

func validateTOTPFreshSession(current TOTPSession, now time.Time) error {
	if !validTOTPSession(current) || current.Revoked || !now.Before(current.IdleExpiresAt.UTC()) || !now.Before(current.ExpiresAt.UTC()) {
		return ErrTOTPInvalidSession
	}
	if !now.Before(current.CreatedAt.UTC().Add(SocialLinkFreshness)) {
		return ErrTOTPReverificationRequired
	}
	return nil
}

func validTOTPSession(current TOTPSession) bool {
	return current.ApplicationInstanceID.Valid() && current.ApplicationPublicID.Valid() && current.UserID.Valid() && current.UserPublicID.Valid() && current.SessionPublicID != "" && !current.CreatedAt.IsZero() && !current.IdleExpiresAt.IsZero() && !current.ExpiresAt.IsZero()
}

func mapTOTPError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrTOTPInvalidSession), errors.Is(err, ErrTOTPReverificationRequired), errors.Is(err, ErrTOTPEnrollmentInvalid), errors.Is(err, ErrTOTPInvalidCode), errors.Is(err, ErrTOTPReplay), errors.Is(err, ErrTOTPAlreadyActive), errors.Is(err, ErrLastAuthenticationMethod), errors.Is(err, ErrPendingMFAInvalid), errors.Is(err, ErrPendingMFAExpired), errors.Is(err, ErrPendingMFAReplay):
		return err
	default:
		return ErrTOTPPersistence
	}
}
