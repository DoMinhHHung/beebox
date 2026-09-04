package application

import (
	"context"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
)

type CreateAccount struct {
	Accounts domain.AccountRepository
	Hasher   domain.PasswordHasher
}

func (u CreateAccount) Execute(ctx context.Context, email, password string) (domain.Account, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(email) {
		return domain.Account{}, domain.ErrInvalidInput
	}
	if len(password) < domain.MinPasswordLength {
		return domain.Account{}, domain.ErrInvalidInput
	}
	hash, err := u.Hasher.Hash(password)
	if err != nil {
		return domain.Account{}, err
	}
	newID, err := id.New()
	if err != nil {
		return domain.Account{}, err
	}
	account := domain.Account{ID: newID, Email: email, PasswordHash: hash}
	if err := u.Accounts.Create(ctx, account); err != nil {
		return domain.Account{}, err
	}
	return account, nil
}
