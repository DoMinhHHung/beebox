package authentication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
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
	ErrReverificationExpired     = errors.New("reverification expired")
	ErrReverificationReplay      = errors.New("reverification replay")
	ErrReverificationRecovery    = errors.New("recovery cannot authorize reverification")
	ErrReverificationPersistence = errors.New("reverification persistence failure")
)

type ReverificationGrantWrite struct {
	PublicID              string
	VerifierHash          [32]byte
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	TargetSessionPublicID string
	ProofSessionPublicID  string
	Purpose               string
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
	CreateReverificationGrant(context.Context, ReverificationGrantWrite) (time.Time, error)
	ConsumeReverificationGrant(context.Context, ReverificationGrantConsume) error
}

type ReverificationGrant struct {
	Token     string    `json:"reverification_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ReverificationService struct {
	persistence ReverificationPersistence
}

func NewReverificationService(persistence ReverificationPersistence) *ReverificationService {
	return &ReverificationService{persistence: persistence}
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

func (s *ReverificationService) Mint(
	ctx context.Context,
	appID applicationinstance.InternalID,
	userID identity.InternalID,
	targetSessionPublicID string,
	proofSessionPublicID string,
	purpose string,
	correlationID audit.CorrelationID,
) (ReverificationGrant, error) {
	if s == nil || s.persistence == nil || !appID.Valid() || !userID.Valid() ||
		targetSessionPublicID == "" || proofSessionPublicID == "" || !ValidReverificationPurpose(purpose) ||
		correlationID == (audit.CorrelationID{}) {
		return ReverificationGrant{}, ErrReverificationInvalid
	}
	publicID, err := publicid.NewUUIDv4("rvg")
	if err != nil {
		return ReverificationGrant{}, ErrReverificationPersistence
	}
	secret := make([]byte, ReverificationSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return ReverificationGrant{}, ErrReverificationPersistence
	}
	hash := reverificationHash(secret, appID, userID, targetSessionPublicID, purpose)
	expiresAt, err := s.persistence.CreateReverificationGrant(ctx, ReverificationGrantWrite{
		PublicID:              publicID,
		VerifierHash:          hash,
		ApplicationInstanceID: appID,
		UserID:                userID,
		TargetSessionPublicID: targetSessionPublicID,
		ProofSessionPublicID:  proofSessionPublicID,
		Purpose:               purpose,
		CorrelationID:         correlationID,
	})
	if err != nil {
		return ReverificationGrant{}, err
	}
	token := publicID + "." + base64.RawURLEncoding.EncodeToString(secret)
	return ReverificationGrant{Token: token, ExpiresAt: expiresAt.UTC()}, nil
}

func (s *ReverificationService) Consume(
	ctx context.Context,
	appID applicationinstance.InternalID,
	userID identity.InternalID,
	targetSessionPublicID string,
	purpose string,
	token string,
	correlationID audit.CorrelationID,
) error {
	if s == nil || s.persistence == nil || !appID.Valid() || !userID.Valid() ||
		targetSessionPublicID == "" || !ValidReverificationPurpose(purpose) ||
		correlationID == (audit.CorrelationID{}) {
		return ErrReverificationInvalid
	}
	publicID, secret, ok := parseReverificationToken(token)
	if !ok {
		return ErrReverificationInvalid
	}
	hash := reverificationHash(secret, appID, userID, targetSessionPublicID, purpose)
	return s.persistence.ConsumeReverificationGrant(ctx, ReverificationGrantConsume{
		PublicID:              publicID,
		VerifierHash:          hash,
		ApplicationInstanceID: appID,
		UserID:                userID,
		TargetSessionPublicID: targetSessionPublicID,
		Purpose:               purpose,
		CorrelationID:         correlationID,
	})
}

func parseReverificationToken(token string) (string, []byte, bool) {
	publicID, encoded, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(encoded, ".") || !publicid.IsUUIDv4(publicID, "rvg") {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(secret) != ReverificationSecretSize {
		return "", nil, false
	}
	return publicID, secret, true
}

func reverificationHash(secret []byte, appID applicationinstance.InternalID, userID identity.InternalID, sessionPublicID, purpose string) [32]byte {
	h := sha256.New()
	h.Write([]byte("beebox/reverification/v1\x00"))
	h.Write([]byte(strconv.FormatInt(int64(appID), 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(int64(userID), 10)))
	h.Write([]byte{0})
	h.Write([]byte(sessionPublicID))
	h.Write([]byte{0})
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write(secret)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
