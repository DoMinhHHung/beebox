package application

import (
	"strings"
	"unicode"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/google/uuid"
)

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", domain.ErrInvalidInput
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') || at == len(email)-1 {
		return "", domain.ErrInvalidInput
	}
	local := email[:at]
	host := email[at+1:]
	if strings.ContainsFunc(local, unicode.IsSpace) || strings.ContainsFunc(host, unicode.IsSpace) {
		return "", domain.ErrInvalidInput
	}
	if !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return "", domain.ErrInvalidInput
	}
	return email, nil
}

func validatePassword(password string) error {
	if len(password) < domain.MinPasswordLength {
		return domain.ErrInvalidInput
	}
	return nil
}

func requireAuthModule(scope domain.Scope) error {
	if scope.Disabled {
		return domain.ErrProjectDisabled
	}
	if scope.ProjectID == uuid.Nil || !domain.ValidEnv(scope.Env) {
		return domain.ErrUnauthorized
	}
	if !scope.HasModule(domain.ModuleAuthPassword) {
		return domain.ErrModuleDisabled
	}
	return nil
}
