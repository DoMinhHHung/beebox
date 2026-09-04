package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	EnvTest        = "test"
	EnvLive        = "live"
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

type Project struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	PlanID    uuid.UUID
	PlanSlug  string
	Name      string
	Slug      string
	Env       string
	Status    string
	UpdatedAt time.Time
}

type CatalogPlan struct {
	ID   uuid.UUID
	Slug string
}

type ProjectRepository interface {
	Create(ctx context.Context, ownerID uuid.UUID, project Project) error
	CreateWithIAM(ctx context.Context, ownerID uuid.UUID, project Project, keys []APIKey, modules []string) error
	List(ctx context.Context, ownerID uuid.UUID) ([]Project, error)
	FindByID(ctx context.Context, ownerID, id uuid.UUID) (Project, error)
	FindBySlug(ctx context.Context, slug string) (Project, error)
	Update(ctx context.Context, ownerID uuid.UUID, project Project) error
	Delete(ctx context.Context, ownerID, id uuid.UUID) error
}

type PlanCatalog interface {
	FindBySlug(ctx context.Context, slug string) (CatalogPlan, error)
}
