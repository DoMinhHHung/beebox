package application

import (
	"context"
	"errors"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type ResolveProject struct {
	Projects domain.ProjectRepository
	Keys     domain.APIKeyRepository
	Origins  domain.OriginRepository
	Modules  domain.ModuleRepository
	Fields   domain.FieldRepository
}

type ResolvedKey struct {
	ID   string
	Kind string
	Env  string
}

type ResolvedField struct {
	Name             string
	Type             string
	Required         bool
	UniquePerProject bool
}

type ResolveResult struct {
	ProjectID string
	Slug      string
	PlanSlug  string
	Env       string
	Origins   []string
	Modules   []string
	Fields    []ResolvedField
	Key       *ResolvedKey
}

func (u ResolveProject) ByPublishableKey(ctx context.Context, raw string) (ResolveResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ResolveResult{}, domain.ErrUnauthorized
	}
	if strings.HasPrefix(raw, "sk_") {
		return ResolveResult{}, domain.ErrUnauthorized
	}
	if !strings.HasPrefix(raw, "pk_") {
		return ResolveResult{}, domain.ErrUnauthorized
	}
	key, project, err := u.Keys.FindActiveByHash(ctx, hashSecret(raw))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ResolveResult{}, domain.ErrUnauthorized
		}
		return ResolveResult{}, err
	}
	if key.Kind != domain.KeyKindPublishable {
		return ResolveResult{}, domain.ErrUnauthorized
	}
	if project.Status != domain.StatusActive {
		return ResolveResult{}, domain.ErrUnauthorized
	}
	origins, modules, fields, err := u.loadIAM(ctx, project.ID)
	if err != nil {
		return ResolveResult{}, err
	}
	return ResolveResult{
		ProjectID: project.ID.String(),
		Slug:      project.Slug,
		PlanSlug:  project.PlanSlug,
		Env:       key.Env,
		Origins:   origins,
		Modules:   modules,
		Fields:    fields,
		Key:       &ResolvedKey{ID: key.ID.String(), Kind: key.Kind, Env: key.Env},
	}, nil
}

func (u ResolveProject) BySlug(ctx context.Context, slug string) (ResolveResult, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" || !validSlug(slug) {
		return ResolveResult{}, domain.ErrNotFound
	}
	project, err := u.Projects.FindBySlug(ctx, slug)
	if err != nil {
		return ResolveResult{}, err
	}
	if project.Status != domain.StatusActive {
		return ResolveResult{}, domain.ErrUnauthorized
	}
	origins, modules, fields, err := u.loadIAM(ctx, project.ID)
	if err != nil {
		return ResolveResult{}, err
	}
	return ResolveResult{
		ProjectID: project.ID.String(),
		Slug:      project.Slug,
		PlanSlug:  project.PlanSlug,
		Env:       project.Env,
		Origins:   origins,
		Modules:   modules,
		Fields:    fields,
	}, nil
}

func (u ResolveProject) loadIAM(ctx context.Context, projectID uuid.UUID) ([]string, []string, []ResolvedField, error) {
	origins, err := u.Origins.ListByProjectID(ctx, projectID)
	if err != nil {
		return nil, nil, nil, err
	}
	modules, err := u.Modules.ListByProjectID(ctx, projectID)
	if err != nil {
		return nil, nil, nil, err
	}
	var fields []ResolvedField
	if u.Fields != nil {
		stored, err := u.Fields.ListByProjectID(ctx, projectID)
		if err != nil {
			return nil, nil, nil, err
		}
		fields = toResolvedFields(stored)
	}
	if fields == nil {
		fields = []ResolvedField{}
	}
	return origins, modules, fields, nil
}

func toResolvedFields(stored []domain.Field) []ResolvedField {
	out := make([]ResolvedField, 0, len(stored))
	for _, field := range stored {
		out = append(out, ResolvedField{
			Name:             field.Name,
			Type:             field.Type,
			Required:         field.Required,
			UniquePerProject: field.UniquePerProject,
		})
	}
	return out
}
