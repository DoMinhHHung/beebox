package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
)

type emailOTPTestStore struct {
	admissionErr error
	issueResult  EmailOTPIssueResult
	issueErr     error
	issued       int
}

func (s *emailOTPTestStore) AllowEmailOTPIssue(context.Context, applicationinstance.InternalID, [32]byte) error {
	return s.admissionErr
}
func (s *emailOTPTestStore) AllowEmailOTPConfirm(context.Context, applicationinstance.InternalID, [32]byte) error {
	return nil
}
func (s *emailOTPTestStore) IssueEmailOTP(_ context.Context, issue EmailOTPIssue) (EmailOTPIssueResult, error) {
	s.issued++
	if issue.NormalizedEmail != "user@example.com" || !issue.CodeHash.Valid() {
		return EmailOTPIssueResult{}, ErrEmailOTPPersistence
	}
	return s.issueResult, s.issueErr
}
func (*emailOTPTestStore) LoadEmailOTP(context.Context, applicationinstance.InternalID, string) (EmailOTPChallengeSnapshot, error) {
	return EmailOTPChallengeSnapshot{}, ErrEmailOTPInvalid
}
func (*emailOTPTestStore) FinalizeEmailOTP(context.Context, EmailOTPFinalize) (EmailOTPFinalizeResult, error) {
	return EmailOTPFinalizeResult{}, ErrEmailOTPInvalid
}

type emailOTPTestDelivery struct {
	calls int
	code  string
	err   error
}

func (d *emailOTPTestDelivery) DeliverSignInCode(_ context.Context, destination, code string, expiresAt time.Time) error {
	d.calls++
	d.code = code
	if destination != "User@example.com" || len(code) != 6 || expiresAt.IsZero() {
		return errors.New("bad delivery")
	}
	return d.err
}

func TestEmailOTPRequestNormalizesHashesAndDelivers(t *testing.T) {
	store := &emailOTPTestStore{issueResult: EmailOTPIssueResult{ShouldSend: true, Destination: "User@example.com", ExpiresAt: time.Now().Add(EmailOTPCodeTTL)}}
	delivery := &emailOTPTestDelivery{}
	service := NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := service.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "User@example.com", correlation); err != nil {
		t.Fatalf("RequestWithCorrelation() error = %v", err)
	}
	if store.issued != 1 || delivery.calls != 1 || len(delivery.code) != 6 {
		t.Fatalf("issued=%d delivery=%d code=%q", store.issued, delivery.calls, delivery.code)
	}
}

func TestEmailOTPRateLimitIsGenericAndDoesNotIssue(t *testing.T) {
	store := &emailOTPTestStore{admissionErr: ErrPublicRateLimited}
	delivery := &emailOTPTestDelivery{}
	service := NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := service.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", correlation); err != nil {
		t.Fatalf("rate-limited request leaked error = %v", err)
	}
	if store.issued != 0 || delivery.calls != 0 {
		t.Fatalf("rate limited flow performed work: issue=%d delivery=%d", store.issued, delivery.calls)
	}
}

func TestEmailOTPDeliveryFailureReturnsStableInternalError(t *testing.T) {
	store := &emailOTPTestStore{issueResult: EmailOTPIssueResult{ShouldSend: true, Destination: "User@example.com", ExpiresAt: time.Now().Add(EmailOTPCodeTTL)}}
	delivery := &emailOTPTestDelivery{err: errors.New("provider detail")}
	service := NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	err := service.RequestWithCorrelation(context.Background(), applicationinstance.InternalID(1), "user@example.com", correlation)
	if !errors.Is(err, ErrEmailOTPDelivery) || err.Error() != "email OTP delivery failure" {
		t.Fatalf("delivery error = %v", err)
	}
}
