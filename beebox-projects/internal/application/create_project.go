package application

import (
	"context"
	"strings"

	beeboxid "github.com/DoMinhHHung/beebox/beebox-id"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type CreateProject struct {
	Projects domain.ProjectRepository
	Catalog  domain.PlanCatalog
}

type CreateProjectInput struct {
	OwnerID  uuid.UUID
	Name     string
	Slug     string
	PlanSlug string
}

func (u CreateProject) Execute(ctx context.Context, in CreateProjectInput) (domain.Project, error) {
	if in.OwnerID == uuid.Nil {
		return domain.Project{}, domain.ErrInvalidInput
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.TrimSpace(in.Slug)
	in.PlanSlug = strings.TrimSpace(in.PlanSlug)
	if in.Name == "" || !validSlug(in.Slug) || in.PlanSlug == "" {
		return domain.Project{}, domain.ErrInvalidInput
	}
	plan, err := u.Catalog.FindBySlug(ctx, in.PlanSlug)
	if err != nil {
		return domain.Project{}, err
	}
	id, err := beeboxid.New()
	if err != nil {
		return domain.Project{}, err
	}
	project := domain.Project{
		ID:       id,
		OwnerID:  in.OwnerID,
		PlanID:   plan.ID,
		PlanSlug: plan.Slug,
		Name:     in.Name,
		Slug:     in.Slug,
		Env:      domain.EnvTest,
		Status:   domain.StatusActive,
	}
	if err := u.Projects.Create(ctx, in.OwnerID, project); err != nil {
		return domain.Project{}, err
	}
	return project, nil
}
