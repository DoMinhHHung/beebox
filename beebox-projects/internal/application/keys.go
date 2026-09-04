package application

import (
	"context"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type ListKeys struct {
	Projects domain.ProjectRepository
	Keys     domain.APIKeyRepository
}

func (u ListKeys) Execute(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.APIKey, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return nil, err
	}
	return u.Keys.ListByProject(ctx, ownerID, projectID)
}

type CreateKey struct {
	Projects domain.ProjectRepository
	Keys     domain.APIKeyRepository
}

type CreateKeyInput struct {
	OwnerID   uuid.UUID
	ProjectID uuid.UUID
	Kind      string
	Env       string
}

func (u CreateKey) Execute(ctx context.Context, in CreateKeyInput) (domain.IssuedKey, error) {
	if in.OwnerID == uuid.Nil || in.ProjectID == uuid.Nil {
		return domain.IssuedKey{}, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, in.OwnerID, in.ProjectID); err != nil {
		return domain.IssuedKey{}, err
	}
	issued, err := issueKey(in.ProjectID, in.Kind, in.Env)
	if err != nil {
		return domain.IssuedKey{}, err
	}
	if err := u.Keys.Create(ctx, in.OwnerID, issued.Key); err != nil {
		return domain.IssuedKey{}, err
	}
	return issued, nil
}

type RevokeKey struct {
	Projects domain.ProjectRepository
	Keys     domain.APIKeyRepository
}

func (u RevokeKey) Execute(ctx context.Context, ownerID, projectID, keyID uuid.UUID) error {
	if ownerID == uuid.Nil || projectID == uuid.Nil || keyID == uuid.Nil {
		return domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return err
	}
	return u.Keys.Revoke(ctx, ownerID, projectID, keyID)
}
