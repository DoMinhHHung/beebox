package domain

import (
	"context"

	"github.com/google/uuid"
)

type OAuthProvider struct {
	ID               uuid.UUID
	ProjectID        uuid.UUID
	Slug             string
	ClientID         string
	ClientSecret     string
	SecretEnc        string
	Extra            map[string]string
	RedirectURI      string
	Enabled          bool
	SecretConfigured bool
}

type OAuthProviderRepository interface {
	Upsert(ctx context.Context, ownerID uuid.UUID, provider OAuthProvider) error
	Find(ctx context.Context, ownerID, projectID uuid.UUID, slug string) (OAuthProvider, error)
	FindByProject(ctx context.Context, projectID uuid.UUID, slug string) (OAuthProvider, error)
}
