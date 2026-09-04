package domain

import (
	"context"

	"github.com/google/uuid"
)

const (
	FieldTypeString  = "string"
	FieldTypeNumber  = "number"
	FieldTypeBoolean = "boolean"
	FieldTypeDate    = "date"
)

type Field struct {
	ID               uuid.UUID
	ProjectID        uuid.UUID
	Name             string
	Type             string
	Required         bool
	UniquePerProject bool
	SortOrder        int
}

type FieldInput struct {
	Name             string
	Type             string
	Required         bool
	UniquePerProject bool
}

type FieldRepository interface {
	Replace(ctx context.Context, ownerID, projectID uuid.UUID, fields []Field) error
	ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]Field, error)
	ListByProjectID(ctx context.Context, projectID uuid.UUID) ([]Field, error)
}
