package httpapi

import (
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

type accountDTO struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type projectDTO struct {
	ID       string `json:"id"`
	OwnerID  string `json:"owner_id"`
	PlanID   string `json:"plan_id"`
	PlanSlug string `json:"plan_slug"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Env      string `json:"env"`
	Status   string `json:"status"`
}

type createProjectDTO struct {
	projectDTO
	Keys []keyDTO `json:"keys"`
}

type keyDTO struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Env    string `json:"env"`
	Prefix string `json:"prefix"`
	Secret string `json:"secret,omitempty"`
}

type originDTO struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Origin    string `json:"origin"`
}

type resolveKeyDTO struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Env  string `json:"env"`
}

type fieldDTO struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Required         bool   `json:"required"`
	UniquePerProject bool   `json:"unique_per_project"`
	SortOrder        int    `json:"sort_order"`
}

type resolveFieldDTO struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Required         bool   `json:"required"`
	UniquePerProject bool   `json:"unique_per_project"`
}

type resolveDTO struct {
	ProjectID string            `json:"project_id"`
	Slug      string            `json:"slug"`
	PlanSlug  string            `json:"plan_slug"`
	Env       string            `json:"env"`
	Origins   []string          `json:"origins"`
	Modules   []string          `json:"modules"`
	Fields    []resolveFieldDTO `json:"fields"`
	Key       *resolveKeyDTO    `json:"key,omitempty"`
}

func toProjectDTO(p domain.Project) projectDTO {
	return projectDTO{
		ID: p.ID.String(), OwnerID: p.OwnerID.String(), PlanID: p.PlanID.String(),
		PlanSlug: p.PlanSlug, Name: p.Name, Slug: p.Slug, Env: p.Env, Status: p.Status,
	}
}

func toCreateProjectDTO(result application.CreateProjectResult) createProjectDTO {
	keys := make([]keyDTO, 0, len(result.Keys))
	for _, k := range result.Keys {
		keys = append(keys, toKeyDTO(k.Key, k.Secret))
	}
	return createProjectDTO{projectDTO: toProjectDTO(result.Project), Keys: keys}
}

func toKeyDTO(k domain.APIKey, secret string) keyDTO {
	return keyDTO{ID: k.ID.String(), Kind: k.Kind, Env: k.Env, Prefix: k.Prefix, Secret: secret}
}

func toOriginDTO(item domain.Origin) originDTO {
	return originDTO{ID: item.ID.String(), ProjectID: item.ProjectID.String(), Origin: item.Origin}
}

func toResolveDTO(result application.ResolveResult) resolveDTO {
	out := resolveDTO{
		ProjectID: result.ProjectID,
		Slug:      result.Slug,
		PlanSlug:  result.PlanSlug,
		Env:       result.Env,
		Origins:   result.Origins,
		Modules:   result.Modules,
	}
	if out.Origins == nil {
		out.Origins = []string{}
	}
	if out.Modules == nil {
		out.Modules = []string{}
	}
	out.Fields = make([]resolveFieldDTO, 0, len(result.Fields))
	for _, field := range result.Fields {
		out.Fields = append(out.Fields, resolveFieldDTO{
			Name:             field.Name,
			Type:             field.Type,
			Required:         field.Required,
			UniquePerProject: field.UniquePerProject,
		})
	}
	if result.Key != nil {
		out.Key = &resolveKeyDTO{ID: result.Key.ID, Kind: result.Key.Kind, Env: result.Key.Env}
	}
	return out
}

func toFieldDTO(field domain.Field) fieldDTO {
	return fieldDTO{
		ID:               field.ID.String(),
		Name:             field.Name,
		Type:             field.Type,
		Required:         field.Required,
		UniquePerProject: field.UniquePerProject,
		SortOrder:        field.SortOrder,
	}
}
