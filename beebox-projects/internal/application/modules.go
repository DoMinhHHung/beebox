package application

import (
	"context"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type ListModules struct {
	Projects domain.ProjectRepository
	Modules  domain.ModuleRepository
}

func (u ListModules) Execute(ctx context.Context, ownerID, projectID uuid.UUID) ([]string, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return nil, err
	}
	return u.Modules.ListByProject(ctx, ownerID, projectID)
}

type PutModules struct {
	Projects domain.ProjectRepository
	Modules  domain.ModuleRepository
}

func (u PutModules) Execute(ctx context.Context, ownerID, projectID uuid.UUID, names []string) ([]string, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	project, err := u.Projects.FindByID(ctx, ownerID, projectID)
	if err != nil {
		return nil, err
	}
	clean := make([]string, 0, len(names))
	seen := map[string]struct{}{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, domain.ErrInvalidInput
		}
		if !knownModule(name) {
			return nil, domain.ErrInvalidInput
		}
		if !moduleAllowed(project.PlanSlug, name) {
			return nil, domain.ErrPlanLimit
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		clean = append(clean, name)
	}
	if err := u.Modules.Replace(ctx, ownerID, projectID, clean); err != nil {
		return nil, err
	}
	return clean, nil
}
