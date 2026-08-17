package authentication

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *EmailVerificationService) IssueEmailVerificationWithCorrelation(ctx context.Context, applicationInstanceID applicationinstance.InternalID, emailIdentifierID identity.EmailIdentifierInternalID, correlationID audit.CorrelationID) error {
	if !applicationInstanceID.Valid() { return ErrInvalidApplicationInstanceScope }
	if !emailIdentifierID.Valid() { return ErrInvalidEmailIdentifierInternalID }
	if correlationID == (audit.CorrelationID{}) || s == nil || s.persistence == nil { return ErrEmailVerificationPersistence }
	if s.delivery == nil { return ErrEmailVerificationDelivery }
	code, err := GenerateVerificationCode()
	if err != nil { return err }
	codeHash, err := HashVerificationCodeContext(ctx, code)
	if err != nil { return err }
	if err := ctx.Err(); err != nil { return err }
	issued, err := s.persistence.IssueEmailVerification(ctx, EmailVerificationIssue{ApplicationInstanceID: applicationInstanceID, EmailIdentifierID: emailIdentifierID, CodeHash: codeHash, CorrelationID: correlationID})
	if err != nil { return err }
	if err := s.delivery.DeliverVerificationCode(ctx, issued.Destination, code, issued.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return ctxErr }
		return ErrEmailVerificationDelivery
	}
	return nil
}

func (s *EmailVerificationService) VerifyEmailCodeWithCorrelation(ctx context.Context, applicationInstanceID applicationinstance.InternalID, emailIdentifierID identity.EmailIdentifierInternalID, rawCode string, correlationID audit.CorrelationID) (VerifiedEmailResult, error) {
	if !applicationInstanceID.Valid() { return VerifiedEmailResult{}, ErrInvalidApplicationInstanceScope }
	if !emailIdentifierID.Valid() { return VerifiedEmailResult{}, ErrInvalidEmailIdentifierInternalID }
	if !validVerificationCode(rawCode) { return VerifiedEmailResult{}, ErrInvalidVerificationCode }
	if correlationID == (audit.CorrelationID{}) || s == nil || s.persistence == nil { return VerifiedEmailResult{}, ErrEmailVerificationPersistence }

	snapshot, err := s.persistence.LoadEmailVerificationChallenge(ctx, applicationInstanceID, emailIdentifierID)
	if err != nil { return VerifiedEmailResult{}, err }
	matched := true
	if err := VerifyVerificationCodeContext(ctx, snapshot.CodeHash, rawCode); err != nil {
		switch {
		case errors.Is(err, ErrVerificationCodeMismatch):
			matched = false
		case errors.Is(err, ErrInvalidVerificationCodeHash):
			return VerifiedEmailResult{}, ErrEmailVerificationPersistence
		default:
			return VerifiedEmailResult{}, err
		}
	}
	if err := ctx.Err(); err != nil { return VerifiedEmailResult{}, err }
	return s.persistence.FinalizeEmailVerification(ctx, EmailVerificationAttempt{ApplicationInstanceID: applicationInstanceID, EmailIdentifierID: emailIdentifierID, Generation: snapshot.Generation, Matched: matched, CorrelationID: correlationID})
}
