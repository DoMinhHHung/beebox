package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const OwnerTokenPrefix = "own_"

type OwnerSession struct {
	ID        uuid.UUID
	AccountID uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type OwnerSessionRepository interface {
	Create(ctx context.Context, session OwnerSession) error
	FindByTokenHash(ctx context.Context, tokenHash string) (OwnerSession, error)
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encoded string) bool
}

type TokenSource interface {
	New() (raw string, hash string, err error)
	Hash(raw string) string
}
