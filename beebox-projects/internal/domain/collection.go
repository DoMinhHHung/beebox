package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Collection struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	Name      string
	Slug      string
	CreatedAt time.Time
}

type Document struct {
	ID           uuid.UUID
	ProjectID    uuid.UUID
	CollectionID uuid.UUID
	Data         map[string]any
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type CollectionRepository interface {
	Create(ctx context.Context, ownerID uuid.UUID, collection Collection) error
	ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]Collection, error)
	Find(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) (Collection, error)
	Update(ctx context.Context, ownerID uuid.UUID, collection Collection) error
	Delete(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) error
	CountByProject(ctx context.Context, ownerID, projectID uuid.UUID) (int, error)
}

type DocumentRepository interface {
	Create(ctx context.Context, ownerID uuid.UUID, doc Document) error
	ListByCollection(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) ([]Document, error)
	Find(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID) (Document, error)
	Update(ctx context.Context, ownerID uuid.UUID, doc Document) error
	Delete(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID) error
	CountByProject(ctx context.Context, ownerID, projectID uuid.UUID) (int, error)
}

func CollectionQuota(planSlug string) (maxCollections, maxDocuments int) {
	if planSlug == "pro" {
		return 20, 10000
	}
	return 2, 100
}
