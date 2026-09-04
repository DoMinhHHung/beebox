package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Origin struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	Origin    string
	CreatedAt time.Time
}

type OriginRepository interface {
	Create(ctx context.Context, ownerID uuid.UUID, origin Origin) error
	ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]Origin, error)
	Delete(ctx context.Context, ownerID, projectID, originID uuid.UUID) error
	ListByProjectID(ctx context.Context, projectID uuid.UUID) ([]string, error)
}
