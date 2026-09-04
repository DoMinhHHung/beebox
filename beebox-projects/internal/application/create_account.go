package application

import (
	"context"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
)

type CreateAccount struct {
	Accounts domain.AccountRepository
}

func (u CreateAccount) Execute(ctx context.Context, email string) (domain.Account, error) {
	email = strings.TrimSpace(email)
	if !validEmail(email) {
		return domain.Account{}, domain.ErrInvalidInput
	}
	newID, err := id.New()
	if err != nil {
		return domain.Account{}, err
	}
	account := domain.Account{ID: newID, Email: email}
	if err := u.Accounts.Create(ctx, account); err != nil {
		return domain.Account{}, err
	}
	return account, nil
}
