package application

import (
	"context"
	"strings"

	beeboxid "github.com/DoMinhHHung/beebox/beebox-id"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

type CreateAccount struct {
	Accounts domain.AccountRepository
}

func (u CreateAccount) Execute(ctx context.Context, email string) (domain.Account, error) {
	email = strings.TrimSpace(email)
	if !validEmail(email) {
		return domain.Account{}, domain.ErrInvalidInput
	}
	id, err := beeboxid.New()
	if err != nil {
		return domain.Account{}, err
	}
	account := domain.Account{ID: id, Email: email}
	if err := u.Accounts.Create(ctx, account); err != nil {
		return domain.Account{}, err
	}
	return account, nil
}
