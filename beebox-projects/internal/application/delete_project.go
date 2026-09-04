package application

import (
	"context"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type DeleteProject struct {
	Projects domain.ProjectRepository
}

func (u DeleteProject) Execute(ctx context.Context, ownerID, id uuid.UUID, confirmation string) error {
	if ownerID == uuid.Nil || id == uuid.Nil {
		return domain.ErrInvalidInput
	}
	project, err := u.Projects.FindByID(ctx, ownerID, id)
	if err != nil {
		return err
	}
	if confirmation != "delete project "+project.Name {
		return domain.ErrInvalidInput
	}
	return u.Projects.Delete(ctx, ownerID, id)
}
