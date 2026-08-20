package authentication

import "context"

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
