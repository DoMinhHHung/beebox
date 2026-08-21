package authentication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

type recoveryCodePersistenceStub struct {
	set   RecoveryCodeSetWrite
	state RecoveryCodeState
	err   error
}

func (s *recoveryCodePersistenceStub) RegenerateRecoveryCodes(_ context.Context, _ TOTPSession, set RecoveryCodeSetWrite, _ audit.CorrelationID) error {
	s.set = set
	return s.err
}

func (s *recoveryCodePersistenceStub) RecoveryCodeState(_ context.Context, _ applicationinstance.InternalID, _ identity.InternalID) (RecoveryCodeState, error) {
	return s.state, s.err
}

func TestGenerateRecoveryCodeSetProducesTenIndependent130BitCodes(t *testing.T) {
	appID := applicationinstance.InternalID(7)
	userID := identity.InternalID(11)
	write, codes, err := GenerateRecoveryCodeSet(appID, userID, "ses_123e4567-e89b-42d3-a456-426614174000", "activation", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !write.Valid() || len(codes) != RecoveryCodeCount || len(write.CodeHashes) != RecoveryCodeCount {
		t.Fatalf("write=%+v codes=%d", write, len(codes))
	}
	seenCodes := make(map[string]struct{}, RecoveryCodeCount)
	seenHashes := make(map[[32]byte]struct{}, RecoveryCodeCount)
	for i, display := range codes {
		normalized, ok := NormalizeRecoveryCode(display)
		if !ok || len(normalized) != RecoveryCodeSymbols || strings.Contains(normalized, "-") {
			t.Fatalf("code %d invalid: %q normalized=%q", i, display, normalized)
		}
		if _, duplicate := seenCodes[normalized]; duplicate {
			t.Fatalf("duplicate code %q", normalized)
		}
		seenCodes[normalized] = struct{}{}
		if hash := RecoveryCodeHash(appID, userID, write.PublicID, normalized); hash != write.CodeHashes[i] {
			t.Fatalf("code %d hash mismatch", i)
		}
		if _, duplicate := seenHashes[write.CodeHashes[i]]; duplicate {
			t.Fatalf("duplicate hash %x", write.CodeHashes[i])
		}
		seenHashes[write.CodeHashes[i]] = struct{}{}
	}
}

func TestNormalizeRecoveryCodeAcceptsOnlyCaseAndExpectedHyphens(t *testing.T) {
	plain := "0123456789ABCDEFGHJKMNPQRS"
	display := "01234-56789-ABCDE-FGHJK-MNPQRS"
	for _, input := range []string{plain, strings.ToLower(plain), display, strings.ToLower(display)} {
		got, ok := NormalizeRecoveryCode(input)
		if !ok || got != plain {
			t.Fatalf("input=%q got=%q ok=%v", input, got, ok)
		}
	}
	for _, input := range []string{
		"01234_56789_ABCDE_FGHJK_MNPQRS",
		"0123-456789-ABCDE-FGHJK-MNPQRS",
		"O1234-56789-ABCDE-FGHJK-MNPQRS",
		"01234-56789-ABCDE-FGHJK-MNPQR",
		" 01234-56789-ABCDE-FGHJK-MNPQRS",
	} {
		if _, ok := NormalizeRecoveryCode(input); ok {
			t.Fatalf("invalid code accepted: %q", input)
		}
	}
}

func TestRecoveryCodeHashBindsApplicationUserAndSet(t *testing.T) {
	code := "0123456789ABCDEFGHJKMNPQRS"
	base := RecoveryCodeHash(1, 2, "rcs_123e4567-e89b-42d3-a456-426614174000", code)
	for _, other := range [][32]byte{
		RecoveryCodeHash(2, 2, "rcs_123e4567-e89b-42d3-a456-426614174000", code),
		RecoveryCodeHash(1, 3, "rcs_123e4567-e89b-42d3-a456-426614174000", code),
		RecoveryCodeHash(1, 2, "rcs_223e4567-e89b-42d3-a456-426614174000", code),
	} {
		if other == base {
			t.Fatal("recovery verifier was not context bound")
		}
	}
}

func TestRecoveryCodeServiceRegenerationReturnsFreshCodesExactlyOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	persistence := &recoveryCodePersistenceStub{state: RecoveryCodeState{Available: true, Remaining: RecoveryCodeCount}}
	service := NewRecoveryCodeService(persistence)
	service.now = func() time.Time { return now }
	current := TOTPSession{
		ApplicationInstanceID: 7,
		ApplicationPublicID:   "app_123e4567-e89b-42d3-a456-426614174001",
		UserID:                11,
		UserPublicID:          "usr_123e4567-e89b-42d3-a456-426614174002",
		SessionPublicID:       "ses_123e4567-e89b-42d3-a456-426614174003",
		CreatedAt:             now.Add(-24 * time.Hour),
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(2 * time.Hour),
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testReverificationContext(current.ApplicationInstanceID, current.UserID, current.SessionPublicID, ReverificationPurposeRecoveryRegenerate)
	result, err := service.Regenerate(ctx, current, correlationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Codes) != RecoveryCodeCount || !persistence.set.Valid() || persistence.set.Reason != "regeneration" {
		t.Fatalf("result=%+v set=%+v", result, persistence.set)
	}
	state, err := service.State(context.Background(), current)
	if err != nil || !state.Available || state.Remaining != RecoveryCodeCount {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	for _, display := range result.Codes {
		if strings.Contains(string(persistence.set.CodeHashes[0][:]), display) {
			t.Fatal("plaintext code persisted in verifier material")
		}
	}

	persistence.err = ErrRecoveryRateLimited
	if _, err := service.Regenerate(ctx, current, correlationID); !errors.Is(err, ErrRecoveryRateLimited) {
		t.Fatalf("rate limit error=%v", err)
	}
}
