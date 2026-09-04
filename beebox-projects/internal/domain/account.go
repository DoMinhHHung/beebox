package domain

import (
	"context"

	"github.com/google/uuid"
)

type Account struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
}

type AccountRepository interface {
	Create(ctx context.Context, account Account) error
	FindByID(ctx context.Context, id uuid.UUID) (Account, error)
	FindByEmail(ctx context.Context, email string) (Account, error)
}
