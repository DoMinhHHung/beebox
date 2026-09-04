package application

import (
	"context"
	"regexp"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
)

var fieldNameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

var reservedFieldNames = map[string]struct{}{
	"email":      {},
	"password":   {},
	"id":         {},
	"project_id": {},
	"env":        {},
	"session":    {},
}

type ListFields struct {
	Projects domain.ProjectRepository
	Fields   domain.FieldRepository
}

func (u ListFields) Execute(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.Field, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return nil, err
	}
	return u.Fields.ListByProject(ctx, ownerID, projectID)
}

type PutFields struct {
	Projects domain.ProjectRepository
	Fields   domain.FieldRepository
	Catalog  domain.PlanCatalog
}

func (u PutFields) Execute(ctx context.Context, ownerID, projectID uuid.UUID, inputs []domain.FieldInput) ([]domain.Field, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	project, err := u.Projects.FindByID(ctx, ownerID, projectID)
	if err != nil {
		return nil, err
	}
	plan, err := u.Catalog.FindBySlug(ctx, project.PlanSlug)
	if err != nil {
		return nil, err
	}
	max := plan.Limits.UserFields
	if len(inputs) > max {
		return nil, domain.ErrPlanLimit
	}
	allowUnique := project.PlanSlug == "pro"
	seen := map[string]struct{}{}
	out := make([]domain.Field, 0, len(inputs))
	for i, in := range inputs {
		name := strings.TrimSpace(in.Name)
		typ := strings.TrimSpace(in.Type)
		if !validFieldName(name) || !validFieldType(typ) {
			return nil, domain.ErrInvalidInput
		}
		if _, dup := seen[name]; dup {
			return nil, domain.ErrInvalidInput
		}
		seen[name] = struct{}{}
		if in.UniquePerProject && !allowUnique {
			return nil, domain.ErrPlanLimit
		}
		newID, err := id.New()
		if err != nil {
			return nil, err
		}
		out = append(out, domain.Field{
			ID:               newID,
			ProjectID:        projectID,
			Name:             name,
			Type:             typ,
			Required:         in.Required,
			UniquePerProject: in.UniquePerProject,
			SortOrder:        i,
		})
	}
	if err := u.Fields.Replace(ctx, ownerID, projectID, out); err != nil {
		return nil, err
	}
	return out, nil
}

func validFieldName(name string) bool {
	if !fieldNameRE.MatchString(name) {
		return false
	}
	_, reserved := reservedFieldNames[strings.ToLower(name)]
	return !reserved
}

func validFieldType(typ string) bool {
	switch typ {
	case domain.FieldTypeString, domain.FieldTypeNumber, domain.FieldTypeBoolean, domain.FieldTypeDate:
		return true
	default:
		return false
	}
}
