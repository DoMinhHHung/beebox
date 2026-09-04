package domain

import (
	"context"

	"github.com/google/uuid"
)

type Account struct {
	ID    uuid.UUID
	Email string
}

type AccountRepository interface {
	Create(ctx context.Context, account Account) error
	FindByID(ctx context.Context, id uuid.UUID) (Account, error)
}
