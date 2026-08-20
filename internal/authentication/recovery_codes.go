package authentication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	RecoveryCodeCount       = 10
	RecoveryCodeSymbols     = 26
	RecoveryRegenerateLimit = 3
)

const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	ErrRecoveryInvalid        = errors.New("invalid recovery proof")
	ErrRecoveryReplay         = errors.New("recovery proof replayed")
	ErrRecoveryUnavailable    = errors.New("recovery unavailable")
	ErrRecoveryPersistence    = errors.New("recovery persistence failure")
	ErrRecoveryRateLimited    = errors.New("recovery regeneration rate limited")
	ErrRecoveryReverification = errors.New("recovery reverification required")
)

type RecoveryCodeSetWrite struct {
	PublicID              string
	ApplicationInstanceID applicationinstance.InternalID
	UserID               identity.InternalID
	SessionPublicID      string
	Reason               string
	CodeHashes           [][32]byte
	CreatedAt            time.Time
}

func (w RecoveryCodeSetWrite) Valid() bool {
	if !publicid.IsUUIDv4(w.PublicID, "rcs") || !w.ApplicationInstanceID.Valid() || !w.UserID.Valid() || w.SessionPublicID == "" || len(w.CodeHashes) != RecoveryCodeCount || w.CreatedAt.IsZero() {
		return false
	}
	switch w.Reason {
	case "activation", "regeneration", "replacement":
	default:
		return false
	}
	seen := make(map[[32]byte]struct{}, len(w.CodeHashes))
	for _, hash := range w.CodeHashes {
		if hash == ([32]byte{}) {
			return false
		}
		if _, duplicate := seen[hash]; duplicate {
			return false
		}
		seen[hash] = struct{}{}
	}
	return true
}

type RecoveryCodeSetResult struct {
	Codes []string `json:"recovery_codes"`
}

type RecoveryCodeState struct {
	Available bool `json:"available"`
	Remaining int  `json:"remaining"`
}

type PendingRecoveryAuthenticationSnapshot struct {
	PendingPublicID       string
	TokenHash             [32]byte
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	PrimaryMethod         string
	PrimaryContext        string
	RecoverySetID         int64
	RecoverySetPublicID   string
	FailedAttempts        int
	ExpiresAt             time.Time
}

type RecoveryAuthenticationFinalize struct {
	Snapshot        PendingRecoveryAuthenticationSnapshot
	CodeHash        [32]byte
	SessionPublicID string
	RefreshVerifier [32]byte
	IdleExpiresAt   time.Time
	ExpiresAt       time.Time
	CorrelationID   audit.CorrelationID
}

type RecoveryAuthenticationResult struct {
	UserPublicID        identity.PublicID
	ApplicationPublicID applicationinstance.PublicID
}

type RecoveryAuthenticationPersistence interface {
	LoadPendingRecoveryAuthentication(context.Context, string, [32]byte) (PendingRecoveryAuthenticationSnapshot, error)
	FinalizePendingRecoveryAuthentication(context.Context, RecoveryAuthenticationFinalize) (RecoveryAuthenticationResult, error)
}

type RecoveryCodePersistence interface {
	RegenerateRecoveryCodes(context.Context, TOTPSession, RecoveryCodeSetWrite, audit.CorrelationID) error
	RecoveryCodeState(context.Context, applicationinstance.InternalID, identity.InternalID) (RecoveryCodeState, error)
}

type RecoveryCodeService struct {
	persistence RecoveryCodePersistence
	now         func() time.Time
}

func NewRecoveryCodeService(persistence RecoveryCodePersistence) *RecoveryCodeService {
	return &RecoveryCodeService{persistence: persistence, now: time.Now}
}

func (s *RecoveryCodeService) Regenerate(ctx context.Context, current TOTPSession, correlationID audit.CorrelationID) (RecoveryCodeSetResult, error) {
	if s == nil || s.persistence == nil || s.now == nil || correlationID == (audit.CorrelationID{}) {
		return RecoveryCodeSetResult{}, ErrRecoveryUnavailable
	}
	now := s.now().UTC()
	if err := validateTOTPFreshSession(current, now); err != nil {
		if errors.Is(err, ErrTOTPReverificationRequired) {
			return RecoveryCodeSetResult{}, ErrRecoveryReverification
		}
		return RecoveryCodeSetResult{}, ErrRecoveryUnavailable
	}
	set, codes, err := GenerateRecoveryCodeSet(current.ApplicationInstanceID, current.UserID, current.SessionPublicID, "regeneration", now)
	if err != nil {
		return RecoveryCodeSetResult{}, err
	}
	if err := s.persistence.RegenerateRecoveryCodes(ctx, current, set, correlationID); err != nil {
		return RecoveryCodeSetResult{}, mapRecoveryError(ctx, err)
	}
	return RecoveryCodeSetResult{Codes: codes}, nil
}

func (s *RecoveryCodeService) State(ctx context.Context, current TOTPSession) (RecoveryCodeState, error) {
	if s == nil || s.persistence == nil || s.now == nil || !validTOTPSession(current) {
		return RecoveryCodeState{}, ErrRecoveryUnavailable
	}
	now := s.now().UTC()
	if current.Revoked || !now.Before(current.IdleExpiresAt.UTC()) || !now.Before(current.ExpiresAt.UTC()) {
		return RecoveryCodeState{}, ErrRecoveryUnavailable
	}
	state, err := s.persistence.RecoveryCodeState(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil {
		return RecoveryCodeState{}, mapRecoveryError(ctx, err)
	}
	return state, nil
}

func (s *RecoveryCodeService) CompletePendingAuthentication(ctx context.Context, expectedAppID applicationinstance.InternalID, pendingPublicID string, tokenHash [32]byte, code string, final RecoveryAuthenticationFinalize) (RecoveryAuthenticationResult, error) {
	if s == nil || s.persistence == nil || s.now == nil || !expectedAppID.Valid() || pendingPublicID == "" || tokenHash == ([32]byte{}) || code == "" || final.CorrelationID == (audit.CorrelationID{}) {
		return RecoveryAuthenticationResult{}, ErrRecoveryInvalid
	}
	persistence, ok := s.persistence.(RecoveryAuthenticationPersistence)
	if !ok {
		return RecoveryAuthenticationResult{}, ErrRecoveryUnavailable
	}
	snapshot, err := persistence.LoadPendingRecoveryAuthentication(ctx, pendingPublicID, tokenHash)
	if err != nil {
		return RecoveryAuthenticationResult{}, mapRecoveryError(ctx, err)
	}
	if snapshot.ApplicationInstanceID != expectedAppID || !snapshot.UserID.Valid() || snapshot.RecoverySetID <= 0 || snapshot.RecoverySetPublicID == "" || snapshot.TokenHash != tokenHash || snapshot.PendingPublicID != pendingPublicID || snapshot.FailedAttempts < 0 || snapshot.FailedAttempts >= 5 || !s.now().UTC().Before(snapshot.ExpiresAt.UTC()) {
		return RecoveryAuthenticationResult{}, ErrRecoveryInvalid
	}
	normalized, valid := NormalizeRecoveryCode(code)
	if !valid {
		normalized = "INVALID-RECOVERY-CODE"
	}
	final.Snapshot = snapshot
	final.CodeHash = RecoveryCodeHash(snapshot.ApplicationInstanceID, snapshot.UserID, snapshot.RecoverySetPublicID, normalized)
	result, err := persistence.FinalizePendingRecoveryAuthentication(ctx, final)
	if err != nil {
		return RecoveryAuthenticationResult{}, mapRecoveryError(ctx, err)
	}
	return result, nil
}

func mapRecoveryError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrRecoveryInvalid), errors.Is(err, ErrRecoveryReplay), errors.Is(err, ErrRecoveryRateLimited), errors.Is(err, ErrRecoveryReverification), errors.Is(err, ErrRecoveryUnavailable):
		return err
	default:
		return ErrRecoveryPersistence
	}
}

func GenerateRecoveryCodeSet(appID applicationinstance.InternalID, userID identity.InternalID, sessionPublicID, reason string, now time.Time) (RecoveryCodeSetWrite, []string, error) {
	setID, err := publicid.NewUUIDv4("rcs")
	if err != nil {
		return RecoveryCodeSetWrite{}, nil, ErrRecoveryUnavailable
	}
	write := RecoveryCodeSetWrite{
		PublicID:              setID,
		ApplicationInstanceID: appID,
		UserID:                userID,
		SessionPublicID:       sessionPublicID,
		Reason:                reason,
		CodeHashes:            make([][32]byte, 0, RecoveryCodeCount),
		CreatedAt:             now.UTC(),
	}
	codes := make([]string, 0, RecoveryCodeCount)
	seen := make(map[string]struct{}, RecoveryCodeCount)
	for len(codes) < RecoveryCodeCount {
		raw := make([]byte, RecoveryCodeSymbols)
		if _, err := rand.Read(raw); err != nil {
			return RecoveryCodeSetWrite{}, nil, ErrRecoveryUnavailable
		}
		for i := range raw {
			raw[i] = recoveryAlphabet[int(raw[i])&31]
		}
		normalized := string(raw)
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		write.CodeHashes = append(write.CodeHashes, RecoveryCodeHash(appID, userID, setID, normalized))
		codes = append(codes, formatRecoveryCode(normalized))
	}
	if !write.Valid() {
		return RecoveryCodeSetWrite{}, nil, ErrRecoveryUnavailable
	}
	return write, codes, nil
}

func NormalizeRecoveryCode(code string) (string, bool) {
	if len(code) != RecoveryCodeSymbols && len(code) != RecoveryCodeSymbols+4 {
		return "", false
	}
	if len(code) == RecoveryCodeSymbols+4 {
		for _, position := range []int{5, 11, 17, 23} {
			if code[position] != '-' {
				return "", false
			}
		}
		code = strings.ReplaceAll(code, "-", "")
	}
	if len(code) != RecoveryCodeSymbols {
		return "", false
	}
	upper := strings.ToUpper(code)
	for i := 0; i < len(upper); i++ {
		if !strings.ContainsRune(recoveryAlphabet, rune(upper[i])) {
			return "", false
		}
	}
	return upper, true
}

func RecoveryCodeHash(appID applicationinstance.InternalID, userID identity.InternalID, setID, normalized string) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("beebox:v1:recovery-code\x00%d\x00%d\x00%s\x00%s", appID, userID, setID, normalized)))
}

func formatRecoveryCode(normalized string) string {
	return normalized[:5] + "-" + normalized[5:10] + "-" + normalized[10:15] + "-" + normalized[15:20] + "-" + normalized[20:]
}
