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

type CreateProjectResult struct {
	Project domain.Project
	Keys    []domain.IssuedKey
}

func (u CreateProject) Execute(ctx context.Context, in CreateProjectInput) (CreateProjectResult, error) {
	if in.OwnerID == uuid.Nil {
		return CreateProjectResult{}, domain.ErrInvalidInput
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.TrimSpace(in.Slug)
	in.PlanSlug = strings.TrimSpace(in.PlanSlug)
	if in.Name == "" || !validSlug(in.Slug) || in.PlanSlug == "" {
		return CreateProjectResult{}, domain.ErrInvalidInput
	}
	plan, err := u.Catalog.FindBySlug(ctx, in.PlanSlug)
	if err != nil {
		return CreateProjectResult{}, err
	}
	id, err := beeboxid.New()
	if err != nil {
		return CreateProjectResult{}, err
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
	pk, err := issueKey(id, domain.KeyKindPublishable, domain.EnvTest)
	if err != nil {
		return CreateProjectResult{}, err
	}
	sk, err := issueKey(id, domain.KeyKindSecret, domain.EnvTest)
	if err != nil {
		return CreateProjectResult{}, err
	}
	keys := []domain.IssuedKey{pk, sk}
	stored := []domain.APIKey{pk.Key, sk.Key}
	if err := u.Projects.CreateWithIAM(ctx, in.OwnerID, project, stored, domain.DefaultModules); err != nil {
		return CreateProjectResult{}, err
	}
	return CreateProjectResult{Project: project, Keys: keys}, nil
}
