package application

import (
	"context"
	"net/url"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
)

type ListOrigins struct {
	Projects domain.ProjectRepository
	Origins  domain.OriginRepository
}

func (u ListOrigins) Execute(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.Origin, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return nil, err
	}
	return u.Origins.ListByProject(ctx, ownerID, projectID)
}

type AddOrigin struct {
	Projects domain.ProjectRepository
	Origins  domain.OriginRepository
}

func (u AddOrigin) Execute(ctx context.Context, ownerID, projectID uuid.UUID, raw string) (domain.Origin, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return domain.Origin{}, domain.ErrInvalidInput
	}
	originVal, err := normalizeOrigin(raw)
	if err != nil {
		return domain.Origin{}, err
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return domain.Origin{}, err
	}
	newID, err := id.New()
	if err != nil {
		return domain.Origin{}, err
	}
	item := domain.Origin{ID: newID, ProjectID: projectID, Origin: originVal}
	if err := u.Origins.Create(ctx, ownerID, item); err != nil {
		return domain.Origin{}, err
	}
	return item, nil
}

type DeleteOrigin struct {
	Projects domain.ProjectRepository
	Origins  domain.OriginRepository
}

func (u DeleteOrigin) Execute(ctx context.Context, ownerID, projectID, originID uuid.UUID) error {
	if ownerID == uuid.Nil || projectID == uuid.Nil || originID == uuid.Nil {
		return domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return err
	}
	return u.Origins.Delete(ctx, ownerID, projectID, originID)
}

func normalizeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", domain.ErrInvalidInput
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", domain.ErrInvalidInput
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", domain.ErrInvalidInput
	}
	if u.Path != "" && u.Path != "/" {
		return "", domain.ErrInvalidInput
	}
	return u.Scheme + "://" + u.Host, nil
}
