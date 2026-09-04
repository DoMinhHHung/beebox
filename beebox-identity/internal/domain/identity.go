package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	OAuthInvalidDomain = "oauth.invalid"
	OAuthStateTTL      = 10 * time.Minute
)

type Identity struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ProjectID uuid.UUID
	Env       string
	Provider  string
	Subject   string
	CreatedAt time.Time
}

type IdentityRepository interface {
	Create(ctx context.Context, identity Identity) error
	FindBySubject(ctx context.Context, projectID uuid.UUID, env, provider, subject string) (Identity, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]Identity, error)
}

type OAuthState struct {
	StateHash string
	ProjectID uuid.UUID
	Env       string
	Slug      string
	Verifier  string
	Redirect  string
	Nonce     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type OAuthStateRepository interface {
	Create(ctx context.Context, state OAuthState) error
	TakeByHash(ctx context.Context, stateHash string) (OAuthState, error)
}
