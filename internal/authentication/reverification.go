package authentication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

const (
	ReverificationLifetime   = 10 * time.Minute
	ReverificationMaxFailure = 5
	ReverificationSecretSize = 32
)

const (
	ReverificationPurposeTOTPEnroll          = "totp_enroll"
	ReverificationPurposeTOTPRemove          = "totp_remove"
	ReverificationPurposeTOTPReplace         = "totp_replace"
	ReverificationPurposeRecoveryRegenerate  = "recovery_regenerate"
	ReverificationPurposePasskeyRegister     = "passkey_register"
	ReverificationPurposePasskeyRemove       = "passkey_remove"
	ReverificationPurposeSocialLink          = "social_link"
	ReverificationPurposeSocialUnlink        = "social_unlink"
	ReverificationPurposeSessionRevoke       = "session_revoke"
	ReverificationPurposeSessionRevokeOthers = "session_revoke_others"
	ReverificationPurposeSignOutEverywhere   = "sign_out_everywhere"
	ReverificationPurposeIdentifierAdd       = "identifier_add"
	ReverificationPurposeIdentifierRemove    = "identifier_remove"
	ReverificationPurposeIdentifierPrimary   = "identifier_primary"
)

var (
	ErrReverificationInvalid     = errors.New("invalid reverification")
	ErrReverificationExpired     = errors.New("expired reverification")
	ErrReverificationReplay      = errors.New("replayed reverification")
	ErrReverificationRecovery    = errors.New("recovery code cannot mint generic reverification")
	ErrReverificationPersistence = errors.New("reverification persistence failure")
)

type ReverificationSessionEvidence struct {
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	SessionPublicID       string
	AuthenticatedAt       time.Time
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	Revoked               bool
	MFAMethod             string
}

type ReverificationGrantWrite struct {
	PublicID              string
	VerifierHash          [32]byte
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	TargetSessionPublicID string
	ProofSessionPublicID  string
	Purpose               string
	CreatedAt             time.Time
	ExpiresAt             time.Time
	CorrelationID         audit.CorrelationID
}

type ReverificationGrantConsume struct {
	PublicID              string
	VerifierHash          [32]byte
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	TargetSessionPublicID string
	Purpose               string
	CorrelationID         audit.CorrelationID
}

type ReverificationPersistence interface {
	ReverificationRequiresTOTP(context.Context, applicationinstance.InternalID, identity.InternalID) (bool, error)
	CreateReverificationGrant(context.Context, ReverificationGrantWrite) (time.Time, error)
	ConsumeReverificationGrant(context.Context, ReverificationGrantConsume) error
}

type ReverificationGrant struct {
	Token     string    `json:"reverification_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ReverificationService struct {
	persistence ReverificationPersistence
	now         func() time.Time
}

func NewReverificationService(persistence ReverificationPersistence) *ReverificationService {
	return &ReverificationService{persistence: persistence, now: time.Now}
}

func (s *ReverificationService) Mint(ctx context.Context, target, proof ReverificationSessionEvidence, purpose string, correlationID audit.CorrelationID) (ReverificationGrant, error) {
	if s == nil || s.persistence == nil || s.now == nil || !ValidReverificationPurpose(purpose) || correlationID == (audit.CorrelationID{}) {
		return ReverificationGrant{}, ErrReverificationInvalid
	}
	now := s.now().UTC()
	if !validReverificationSession(target) || !activeReverificationSession(target, now) || !validReverificationSession(proof) || !activeReverificationSession(proof, now) {
		return ReverificationGrant{}, ErrReverificationInvalid
	}
	if target.ApplicationInstanceID != proof.ApplicationInstanceID || target.UserID != proof.UserID {
		return ReverificationGrant{}, ErrReverificationInvalid
	}
	proofAt := proof.AuthenticatedAt.UTC()
	if proofAt.After(now) || !now.Before(proofAt.Add(ReverificationLifetime)) {
		return ReverificationGrant{}, ErrReverificationExpired
	}
	requiresTOTP, err := s.persistence.ReverificationRequiresTOTP(ctx, target.ApplicationInstanceID, target.UserID)
	if err != nil {
		return ReverificationGrant{}, mapReverificationError(ctx, err)
	}
	if requiresTOTP {
		switch proof.MFAMethod {
		case "totp":
		case "recovery_code":
			return ReverificationGrant{}, ErrReverificationRecovery
		default:
			return ReverificationGrant{}, ErrReverificationInvalid
		}
	}
	expiresAt := earliestTime(now.Add(ReverificationLifetime), proofAt.Add(ReverificationLifetime), target.IdleExpiresAt.UTC(), target.ExpiresAt.UTC(), proof.IdleExpiresAt.UTC(), proof.ExpiresAt.UTC())
	if !now.Before(expiresAt) {
		return ReverificationGrant{}, ErrReverificationExpired
	}
	publicID, err := publicid.NewUUIDv4("rvg")
	if err != nil {
		return ReverificationGrant{}, ErrReverificationPersistence
	}
	secret := make([]byte, ReverificationSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return ReverificationGrant{}, ErrReverificationPersistence
	}
	verifier := reverificationHash(secret, target.ApplicationInstanceID, target.UserID, target.SessionPublicID, purpose)
	persistedExpiry, err := s.persistence.CreateReverificationGrant(ctx, ReverificationGrantWrite{
		PublicID:              publicID,
		VerifierHash:          verifier,
		ApplicationInstanceID: target.ApplicationInstanceID,
		UserID:                target.UserID,
		TargetSessionPublicID: target.SessionPublicID,
		ProofSessionPublicID:  proof.SessionPublicID,
		Purpose:               purpose,
		CreatedAt:             now,
		ExpiresAt:             expiresAt,
		CorrelationID:         correlationID,
	})
	if err != nil {
		return ReverificationGrant{}, mapReverificationError(ctx, err)
	}
	return ReverificationGrant{Token: publicID + "." + base64.RawURLEncoding.EncodeToString(secret), ExpiresAt: persistedExpiry.UTC()}, nil
}

func (s *ReverificationService) Consume(ctx context.Context, target ReverificationSessionEvidence, purpose, token string, correlationID audit.CorrelationID) (context.Context, error) {
	if s == nil || s.persistence == nil || s.now == nil || !ValidReverificationPurpose(purpose) || correlationID == (audit.CorrelationID{}) || !validReverificationSession(target) || !activeReverificationSession(target, s.now().UTC()) {
		return ctx, ErrReverificationInvalid
	}
	publicID, secret, ok := parseReverificationToken(token)
	if !ok {
		return ctx, ErrReverificationInvalid
	}
	verifier := reverificationHash(secret, target.ApplicationInstanceID, target.UserID, target.SessionPublicID, purpose)
	err := s.persistence.ConsumeReverificationGrant(ctx, ReverificationGrantConsume{
		PublicID:              publicID,
		VerifierHash:          verifier,
		ApplicationInstanceID: target.ApplicationInstanceID,
		UserID:                target.UserID,
		TargetSessionPublicID: target.SessionPublicID,
		Purpose:               purpose,
		CorrelationID:         correlationID,
	})
	if err != nil {
		return ctx, mapReverificationError(ctx, err)
	}
	return withReverificationAuthorization(ctx, target.ApplicationInstanceID, target.UserID, target.SessionPublicID, purpose), nil
}

type reverificationAuthorization struct {
	applicationInstanceID applicationinstance.InternalID
	userID                identity.InternalID
	targetSessionPublicID string
	purpose               string
}

type reverificationContextKey struct{}

func withReverificationAuthorization(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, targetSessionPublicID, purpose string) context.Context {
	return context.WithValue(ctx, reverificationContextKey{}, reverificationAuthorization{
		applicationInstanceID: appID,
		userID:                userID,
		targetSessionPublicID: targetSessionPublicID,
		purpose:               purpose,
	})
}

func RequireReverification(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, targetSessionPublicID, purpose string) error {
	if ctx == nil || !appID.Valid() || !userID.Valid() || targetSessionPublicID == "" || !ValidReverificationPurpose(purpose) {
		return ErrReverificationInvalid
	}
	authorization, ok := ctx.Value(reverificationContextKey{}).(reverificationAuthorization)
	if !ok || authorization.applicationInstanceID != appID || authorization.userID != userID || authorization.targetSessionPublicID != targetSessionPublicID || authorization.purpose != purpose {
		return ErrReverificationInvalid
	}
	return nil
}

func validReverificationSession(session ReverificationSessionEvidence) bool {
	return session.ApplicationInstanceID.Valid() && session.UserID.Valid() && session.SessionPublicID != "" && !session.AuthenticatedAt.IsZero() && !session.IdleExpiresAt.IsZero() && !session.ExpiresAt.IsZero()
}

func activeReverificationSession(session ReverificationSessionEvidence, now time.Time) bool {
	return !session.Revoked && now.Before(session.IdleExpiresAt.UTC()) && now.Before(session.ExpiresAt.UTC())
}

func ValidReverificationPurpose(purpose string) bool {
	switch purpose {
	case ReverificationPurposeTOTPEnroll,
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
		ReverificationPurposeIdentifierPrimary:
		return true
	default:
		return false
	}
}

func parseReverificationToken(token string) (string, []byte, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !publicid.IsUUIDv4(parts[0], "rvg") {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(secret) != ReverificationSecretSize {
		return "", nil, false
	}
	return parts[0], secret, true
}

func reverificationHash(secret []byte, appID applicationinstance.InternalID, userID identity.InternalID, targetSessionPublicID, purpose string) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("beebox:v1:reverification\x00%d\x00%d\x00%s\x00%s\x00%s", appID, userID, targetSessionPublicID, purpose, base64.RawURLEncoding.EncodeToString(secret))))
}

func mapReverificationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrReverificationInvalid), errors.Is(err, ErrReverificationExpired), errors.Is(err, ErrReverificationReplay), errors.Is(err, ErrReverificationRecovery):
		return err
	default:
		return ErrReverificationPersistence
	}
}
