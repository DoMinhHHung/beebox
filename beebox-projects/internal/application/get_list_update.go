package application

import (
	"context"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type ListProjects struct {
	Projects domain.ProjectRepository
}

func (u ListProjects) Execute(ctx context.Context, ownerID uuid.UUID) ([]domain.Project, error) {
	if ownerID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	return u.Projects.List(ctx, ownerID)
}

type GetProject struct {
	Projects domain.ProjectRepository
}

func (u GetProject) Execute(ctx context.Context, ownerID, id uuid.UUID) (domain.Project, error) {
	if ownerID == uuid.Nil || id == uuid.Nil {
		return domain.Project{}, domain.ErrInvalidInput
	}
	return u.Projects.FindByID(ctx, ownerID, id)
}

type UpdateProject struct {
	Projects domain.ProjectRepository
	Catalog  domain.PlanCatalog
}

type UpdateProjectInput struct {
	OwnerID  uuid.UUID
	ID       uuid.UUID
	Name     *string
	Slug     *string
	PlanSlug *string
	Status   *string
}

func (u UpdateProject) Execute(ctx context.Context, in UpdateProjectInput) (domain.Project, error) {
	if in.OwnerID == uuid.Nil || in.ID == uuid.Nil {
		return domain.Project{}, domain.ErrInvalidInput
	}
	project, err := u.Projects.FindByID(ctx, in.OwnerID, in.ID)
	if err != nil {
		return domain.Project{}, err
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return domain.Project{}, domain.ErrInvalidInput
		}
		project.Name = name
	}
	if in.Slug != nil {
		slug := strings.TrimSpace(*in.Slug)
		if !validSlug(slug) {
			return domain.Project{}, domain.ErrInvalidInput
		}
		project.Slug = slug
	}
	if in.Status != nil {
		status := strings.TrimSpace(*in.Status)
		if status != domain.StatusActive && status != domain.StatusDisabled {
			return domain.Project{}, domain.ErrInvalidInput
		}
		project.Status = status
	}
	if in.PlanSlug != nil {
		planSlug := strings.TrimSpace(*in.PlanSlug)
		if planSlug == "" {
			return domain.Project{}, domain.ErrInvalidInput
		}
		plan, err := u.Catalog.FindBySlug(ctx, planSlug)
		if err != nil {
			return domain.Project{}, err
		}
		project.PlanID = plan.ID
		project.PlanSlug = plan.Slug
	}
	if err := u.Projects.Update(ctx, in.OwnerID, project); err != nil {
		return domain.Project{}, err
	}
	return project, nil
}
