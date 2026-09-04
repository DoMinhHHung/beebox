package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	KeyKindPublishable = "publishable"
	KeyKindSecret      = "secret"
)

type APIKey struct {
	ID         uuid.UUID
	ProjectID  uuid.UUID
	Prefix     string
	SecretHash string
	Kind       string
	Env        string
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

type IssuedKey struct {
	Key    APIKey
	Secret string
}

type APIKeyRepository interface {
	Create(ctx context.Context, ownerID uuid.UUID, key APIKey) error
	ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]APIKey, error)
	Revoke(ctx context.Context, ownerID, projectID, keyID uuid.UUID) error
	FindActiveByHash(ctx context.Context, secretHash string) (APIKey, Project, error)
}
