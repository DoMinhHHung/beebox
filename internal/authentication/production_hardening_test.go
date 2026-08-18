package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

var errAdmissionProbe = errors.New("admission probe")

type hardeningDelivery struct{}

func (hardeningDelivery) DeliverVerificationCode(context.Context, string, string, time.Time) error {
	return nil
}
func (hardeningDelivery) DeliverPasswordResetCode(context.Context, string, string, time.Time) error {
	return nil
}

type hardeningSignupStore struct {
	admitErr     error
	persistCalls int
}

func (s *hardeningSignupStore) AdmitPublicSignup(context.Context, applicationinstance.InternalID, [32]byte, [32]byte, [32]byte) (bool, error) {
	return false, s.admitErr
}
func (s *hardeningSignupStore) PersistPublicSignup(context.Context, PublicSignupWrite) (PublicSignupPersistenceResult, error) {
	s.persistCalls++
	return PublicSignupPersistenceResult{}, nil
}

type hardeningVerificationStore struct {
	issueCalls int
	snapshot   EmailVerificationChallengeSnapshot
}

func (s *hardeningVerificationStore) IssueEmailVerification(context.Context, EmailVerificationIssue) (EmailVerificationIssueResult, error) {
	s.issueCalls++
	return EmailVerificationIssueResult{Destination: "user@example.com", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (s *hardeningVerificationStore) LoadEmailVerificationChallenge(context.Context, applicationinstance.InternalID, identity.EmailIdentifierInternalID) (EmailVerificationChallengeSnapshot, error) {
	return s.snapshot, nil
}
func (*hardeningVerificationStore) FinalizeEmailVerification(context.Context, EmailVerificationAttempt) (VerifiedEmailResult, error) {
	return VerifiedEmailResult{}, nil
}

type hardeningResolver struct {
	identifier identity.EmailIdentifier
	err        error
	calls      int
}

func (r *hardeningResolver) ResolveEmailIdentifierByAddress(context.Context, applicationinstance.InternalID, string) (identity.EmailIdentifier, error) {
	r.calls++
	return r.identifier, r.err
}

type hardeningVerificationLimiter struct {
	issueErr   error
	confirmErr error
}

func (l hardeningVerificationLimiter) AllowPublicVerificationIssue(context.Context, applicationinstance.InternalID, [32]byte) error {
	return l.issueErr
}
func (l hardeningVerificationLimiter) AllowPublicVerificationConfirm(context.Context, applicationinstance.InternalID, [32]byte) error {
	return l.confirmErr
}

type hardeningResetStore struct {
	issueAdmissionErr   error
	confirmAdmissionErr error
	loadCalls           int
	finalizeCalls       int
	snapshot            PasswordResetSnapshot
	finalized           PasswordResetFinalize
}

func (s *hardeningResetStore) AllowPasswordResetIssue(context.Context, applicationinstance.InternalID, [32]byte) error {
	return s.issueAdmissionErr
}
func (s *hardeningResetStore) AllowPasswordResetConfirm(context.Context, applicationinstance.InternalID, [32]byte) error {
	return s.confirmAdmissionErr
}
func (*hardeningResetStore) IssuePasswordReset(context.Context, PasswordResetIssue) (PasswordResetIssueResult, error) {
	return PasswordResetIssueResult{}, nil
}
func (s *hardeningResetStore) LoadPasswordReset(context.Context, applicationinstance.InternalID, string) (PasswordResetSnapshot, error) {
	s.loadCalls++
	return s.snapshot, nil
}
func (s *hardeningResetStore) FinalizePasswordReset(_ context.Context, finalized PasswordResetFinalize) error {
	s.finalizeCalls++
	s.finalized = finalized
	return nil
}

func saturateProcessKDFForTest(t *testing.T) {
	t.Helper()
	processKDFMu.Lock()
	previous := processKDFGate
	gate := NewKDFGate(1)
	gate.running <- struct{}{}
	gate.waiting <- struct{}{}
	processKDFGate = gate
	processKDFMu.Unlock()
	t.Cleanup(func() { processKDFMu.Lock(); processKDFGate = previous; processKDFMu.Unlock() })
}
func testCorrelationID() audit.CorrelationID { var id audit.CorrelationID; id[0] = 1; return id }

func TestPublicSignupAdmissionRunsBeforeExpensiveKDF(t *testing.T) {
	saturateProcessKDFForTest(t)
	store := &hardeningSignupStore{admitErr: errAdmissionProbe}
	service := NewPublicSignupService(store, hardeningDelivery{})
	err := service.SignUpWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", "correct horse battery staple", "signup-key", testCorrelationID())
	if !errors.Is(err, errAdmissionProbe) {
		t.Fatalf("SignUpWithCorrelation() error = %v, want admission probe before KDF", err)
	}
	if store.persistCalls != 0 {
		t.Fatalf("persistence calls = %d, want 0", store.persistCalls)
	}
}
func TestVerificationConfirmAdmissionRunsBeforeExpensiveKDF(t *testing.T) {
	saturateProcessKDFForTest(t)
	resolver := &hardeningResolver{identifier: identity.EmailIdentifier{InternalID: identity.EmailIdentifierInternalID(2)}}
	core := NewEmailVerificationService(&hardeningVerificationStore{}, hardeningDelivery{})
	service := NewPublicVerificationService(resolver, hardeningVerificationLimiter{confirmErr: errAdmissionProbe}, core)
	err := service.ConfirmWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", "123456", testCorrelationID())
	if !errors.Is(err, errAdmissionProbe) {
		t.Fatalf("ConfirmWithCorrelation() error = %v, want admission probe before KDF", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want 0 before denied admission", resolver.calls)
	}
}
func TestPasswordResetIssueAdmissionRunsBeforeExpensiveKDF(t *testing.T) {
	saturateProcessKDFForTest(t)
	store := &hardeningResetStore{issueAdmissionErr: errAdmissionProbe}
	service := NewPasswordResetService(store, hardeningDelivery{})
	err := service.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", testCorrelationID())
	if !errors.Is(err, errAdmissionProbe) {
		t.Fatalf("RequestWithCorrelation() error = %v, want admission probe before KDF", err)
	}
}
func TestPasswordResetConfirmAdmissionRunsBeforeExpensiveKDF(t *testing.T) {
	saturateProcessKDFForTest(t)
	store := &hardeningResetStore{confirmAdmissionErr: errAdmissionProbe}
	service := NewPasswordResetService(store, hardeningDelivery{})
	err := service.ConfirmWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", "12345678", "correct horse battery staple", testCorrelationID())
	if !errors.Is(err, errAdmissionProbe) {
		t.Fatalf("ConfirmWithCorrelation() error = %v, want admission probe before KDF", err)
	}
	if store.loadCalls != 0 {
		t.Fatalf("reset load calls = %d, want 0 before denied admission", store.loadCalls)
	}
}
func TestPasswordResetInvalidCodeDoesNotProduceCandidatePasswordHash(t *testing.T) {
	stored, err := HashPasswordResetCode("12345678")
	if err != nil {
		t.Fatalf("HashPasswordResetCode() error = %v", err)
	}
	store := &hardeningResetStore{snapshot: PasswordResetSnapshot{UserID: identity.InternalID(3), EmailIdentifierID: identity.EmailIdentifierInternalID(2), ChallengeGeneration: 1, CredentialGeneration: 1, CodeHash: stored}}
	service := NewPasswordResetService(store, hardeningDelivery{})
	err = service.ConfirmWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", "87654321", "candidate password that must not be hashed", testCorrelationID())
	if !errors.Is(err, ErrPasswordResetFailed) {
		t.Fatalf("ConfirmWithCorrelation() error = %v, want reset failed", err)
	}
	if store.finalizeCalls != 1 || store.finalized.Matched {
		t.Fatalf("finalize calls/matched = %d/%v, want 1/false", store.finalizeCalls, store.finalized.Matched)
	}
	if store.finalized.NewPasswordHash.Valid() {
		t.Fatal("invalid reset code produced a candidate new-password hash")
	}
}
func TestVerificationRequestCollapsesKDFSaturationForAntiEnumeration(t *testing.T) {
	saturateProcessKDFForTest(t)
	store := &hardeningVerificationStore{}
	core := NewEmailVerificationService(store, hardeningDelivery{})
	unverifiedResolver := &hardeningResolver{identifier: identity.EmailIdentifier{InternalID: identity.EmailIdentifierInternalID(2)}}
	unverified := NewPublicVerificationService(unverifiedResolver, hardeningVerificationLimiter{}, core)
	if err := unverified.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", testCorrelationID()); err != nil {
		t.Fatalf("unverified identifier under KDF saturation error = %v, want generic accepted behavior", err)
	}
	if store.issueCalls != 0 {
		t.Fatalf("issue persistence calls = %d, want 0 when KDF admission is saturated", store.issueCalls)
	}
	unknown := NewPublicVerificationService(&hardeningResolver{err: identity.ErrEmailIdentifierNotFound}, hardeningVerificationLimiter{}, core)
	if err := unknown.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "unknown@example.com", testCorrelationID()); err != nil {
		t.Fatalf("unknown identifier error = %v, want generic accepted behavior", err)
	}
	verifiedAt := time.Now().UTC()
	verified := NewPublicVerificationService(&hardeningResolver{identifier: identity.EmailIdentifier{InternalID: identity.EmailIdentifierInternalID(3), VerifiedAt: &verifiedAt}}, hardeningVerificationLimiter{}, core)
	if err := verified.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "verified@example.com", testCorrelationID()); err != nil {
		t.Fatalf("verified identifier error = %v, want generic accepted behavior", err)
	}
}
func TestHashVerificationCodeContextPreservesAdmissionAndCancellation(t *testing.T) {
	t.Run("saturation", func(t *testing.T) {
		saturateProcessKDFForTest(t)
		_, err := HashVerificationCodeContext(context.Background(), "123456")
		if !errors.Is(err, ErrKDFAdmissionLimited) {
			t.Fatalf("HashVerificationCodeContext() error = %v, want KDF admission limited", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := HashVerificationCodeContext(ctx, "123456")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HashVerificationCodeContext() error = %v, want context canceled", err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		_, err := HashVerificationCodeContext(ctx, "123456")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("HashVerificationCodeContext() error = %v, want deadline exceeded", err)
		}
	})
}
