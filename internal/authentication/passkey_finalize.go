package authentication

import "context"

type PasskeyAssurancePersistence interface {
	FinalizePasskeyAuthenticationWithAssurance(context.Context, PasskeyAuthFinalize, PendingMFAWrite) (PasskeyAuthResult, PrimaryAssuranceResult, error)
}

func (s *PasskeyService) FinalizeAuthentication(ctx context.Context, final PasskeyAuthFinalize) (PasskeyAuthResult, error) {
	if s == nil || s.persistence == nil {
		return PasskeyAuthResult{}, ErrPasskeyUnavailable
	}
	result, err := s.persistence.FinalizePasskeyAuthentication(ctx, final)
	if err != nil {
		return PasskeyAuthResult{}, mapPasskeyPersistenceError(ctx, err)
	}
	return result, nil
}

func (s *PasskeyService) FinalizeAuthenticationWithAssurance(ctx context.Context, final PasskeyAuthFinalize, pending PendingMFAWrite) (PasskeyAuthResult, PrimaryAssuranceResult, error) {
	if s == nil || s.persistence == nil {
		return PasskeyAuthResult{}, PrimaryAssuranceResult{}, ErrPasskeyUnavailable
	}
	persistence, ok := s.persistence.(PasskeyAssurancePersistence)
	if !ok {
		return PasskeyAuthResult{}, PrimaryAssuranceResult{}, ErrPasskeyUnavailable
	}
	result, assurance, err := persistence.FinalizePasskeyAuthenticationWithAssurance(ctx, final, pending)
	if err != nil {
		return PasskeyAuthResult{}, PrimaryAssuranceResult{}, mapPasskeyPersistenceError(ctx, err)
	}
	return result, assurance, nil
}
