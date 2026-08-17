package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

type emailVerificationPersistenceStub struct {
	issue       EmailVerificationIssue
	issueResult EmailVerificationIssueResult
	issueErr    error
	snapshot    EmailVerificationChallengeSnapshot
	loadErr     error
	attempt     EmailVerificationAttempt
	finalResult VerifiedEmailResult
	finalErr    error
}

func (s *emailVerificationPersistenceStub) IssueEmailVerification(_ context.Context, issue EmailVerificationIssue) (EmailVerificationIssueResult, error) {
	s.issue = issue
	return s.issueResult, s.issueErr
}

func (s *emailVerificationPersistenceStub) LoadEmailVerificationChallenge(_ context.Context, _ applicationinstance.InternalID, _ identity.EmailIdentifierInternalID) (EmailVerificationChallengeSnapshot, error) {
	return s.snapshot, s.loadErr
}

func (s *emailVerificationPersistenceStub) FinalizeEmailVerification(_ context.Context, attempt EmailVerificationAttempt) (VerifiedEmailResult, error) {
	s.attempt = attempt
	return s.finalResult, s.finalErr
}

type recordingVerificationDelivery struct {
	destination string
	code        string
	expiresAt   time.Time
	err         error
}

func (d *recordingVerificationDelivery) DeliverVerificationCode(_ context.Context, destination string, code string, expiresAt time.Time) error {
	d.destination = destination
	d.code = code
	d.expiresAt = expiresAt
	return d.err
}

func TestEmailVerificationIssueUsesStoredDestinationAndDoesNotReturnCode(t *testing.T) {
	expiresAt := time.Now().UTC().Add(EmailVerificationCodeTTL)
	persistence := &emailVerificationPersistenceStub{
		issueResult: EmailVerificationIssueResult{Destination: "alice@example.test", ExpiresAt: expiresAt},
	}
	delivery := &recordingVerificationDelivery{}
	service := NewEmailVerificationService(persistence, delivery)

	if err := service.IssueEmailVerification(context.Background(), 9, 7); err != nil {
		t.Fatalf("IssueEmailVerification() error = %v", err)
	}
	if delivery.destination != "alice@example.test" || len(delivery.code) != 6 || !delivery.expiresAt.Equal(expiresAt) {
		t.Fatal("delivery did not receive persistence-resolved destination and issued code metadata")
	}
	if persistence.issue.ApplicationInstanceID != 9 || persistence.issue.EmailIdentifierID != 7 || !persistence.issue.CodeHash.Valid() {
		t.Fatal("issue persistence did not receive scoped hashed verification material")
	}
}

func TestEmailVerificationDeliveryFailureIsStableAfterPersistence(t *testing.T) {
	persistence := &emailVerificationPersistenceStub{
		issueResult: EmailVerificationIssueResult{Destination: "alice@example.test", ExpiresAt: time.Now().UTC().Add(EmailVerificationCodeTTL)},
	}
	delivery := &recordingVerificationDelivery{err: errors.New("provider detail")}
	service := NewEmailVerificationService(persistence, delivery)
	if err := service.IssueEmailVerification(context.Background(), 1, 1); !errors.Is(err, ErrEmailVerificationDelivery) {
		t.Fatalf("delivery failure = %v, want stable delivery error", err)
	}
	if !persistence.issue.CodeHash.Valid() {
		t.Fatal("challenge persistence did not complete before delivery failure")
	}
}

func TestEmailVerificationVerifySeparatesHashWorkFromFinalization(t *testing.T) {
	hash, err := HashVerificationCode("123456")
	if err != nil {
		t.Fatalf("HashVerificationCode() error = %v", err)
	}
	persistence := &emailVerificationPersistenceStub{
		snapshot:    EmailVerificationChallengeSnapshot{Generation: 4, CodeHash: hash},
		finalResult: VerifiedEmailResult{EmailIdentifier: identity.EmailIdentifier{InternalID: 7, ApplicationInstanceID: 9}},
	}
	service := NewEmailVerificationService(persistence, nil)
	if _, err := service.VerifyEmailCode(context.Background(), 9, 7, "123456"); err != nil {
		t.Fatalf("VerifyEmailCode(correct) error = %v", err)
	}
	if persistence.attempt.Generation != 4 || !persistence.attempt.Matched {
		t.Fatalf("finalization attempt = %#v", persistence.attempt)
	}

	persistence.attempt = EmailVerificationAttempt{}
	if _, err := service.VerifyEmailCode(context.Background(), 9, 7, "654321"); err != nil {
		t.Fatalf("VerifyEmailCode(wrong) orchestration error = %v", err)
	}
	if persistence.attempt.Generation != 4 || persistence.attempt.Matched {
		t.Fatalf("wrong-code finalization attempt = %#v", persistence.attempt)
	}
}

func TestEmailVerificationValidatesScopeIdentifierCodeAndContext(t *testing.T) {
	service := NewEmailVerificationService(&emailVerificationPersistenceStub{}, &recordingVerificationDelivery{})
	if err := service.IssueEmailVerification(context.Background(), 0, 1); !errors.Is(err, ErrInvalidApplicationInstanceScope) {
		t.Fatalf("invalid app issue error = %v", err)
	}
	if err := service.IssueEmailVerification(context.Background(), 1, 0); !errors.Is(err, ErrInvalidEmailIdentifierInternalID) {
		t.Fatalf("invalid identifier issue error = %v", err)
	}
	if _, err := service.VerifyEmailCode(context.Background(), 1, 1, " 12345"); !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("invalid code error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	persistence := &emailVerificationPersistenceStub{loadErr: context.Canceled}
	if _, err := NewEmailVerificationService(persistence, nil).VerifyEmailCode(ctx, 1, 1, "123456"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verify error = %v", err)
	}
}
