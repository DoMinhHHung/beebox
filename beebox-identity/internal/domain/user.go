package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	EnvTest = "test"
	EnvLive = "live"

	ModuleAuthPassword = "auth.password"

	MinPasswordLength = 8
)

type User struct {
	ID           uuid.UUID
	ProjectID    uuid.UUID
	Env          string
	Email        string
	PasswordHash string
	NeedsEmail   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type UserRepository interface {
	Create(ctx context.Context, user User) error
	FindByEmail(ctx context.Context, projectID uuid.UUID, env, email string) (User, error)
	FindByID(ctx context.Context, id uuid.UUID) (User, error)
}
