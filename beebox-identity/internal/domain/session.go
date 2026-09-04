package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const SessionTokenPrefix = "sess_"

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ProjectID uuid.UUID
	Env       string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type SessionRepository interface {
	Create(ctx context.Context, session Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (Session, error)
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
