package application

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
)

var collectionSlugRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

type ListCollections struct {
	Projects    domain.ProjectRepository
	Collections domain.CollectionRepository
}

func (u ListCollections) Execute(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.Collection, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return nil, err
	}
	return u.Collections.ListByProject(ctx, ownerID, projectID)
}

type CreateCollection struct {
	Projects    domain.ProjectRepository
	Collections domain.CollectionRepository
}

func (u CreateCollection) Execute(ctx context.Context, ownerID, projectID uuid.UUID, name, slug string) (domain.Collection, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil {
		return domain.Collection{}, domain.ErrInvalidInput
	}
	project, err := u.Projects.FindByID(ctx, ownerID, projectID)
	if err != nil {
		return domain.Collection{}, err
	}
	name = strings.TrimSpace(name)
	slug = strings.TrimSpace(slug)
	if slug == "" {
		slug = strings.ReplaceAll(name, " ", "_")
	}
	if name == "" || !collectionSlugRE.MatchString(slug) {
		return domain.Collection{}, domain.ErrInvalidInput
	}
	maxColl, _ := domain.CollectionQuota(project.PlanSlug)
	count, err := u.Collections.CountByProject(ctx, ownerID, projectID)
	if err != nil {
		return domain.Collection{}, err
	}
	if count >= maxColl {
		return domain.Collection{}, domain.ErrPlanLimit
	}
	newID, err := id.New()
	if err != nil {
		return domain.Collection{}, err
	}
	item := domain.Collection{ID: newID, ProjectID: projectID, Name: name, Slug: slug, CreatedAt: time.Now().UTC()}
	if err := u.Collections.Create(ctx, ownerID, item); err != nil {
		return domain.Collection{}, err
	}
	return item, nil
}

type ListDocuments struct {
	Collections domain.CollectionRepository
	Documents   domain.DocumentRepository
}

func (u ListDocuments) Execute(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) ([]domain.Document, error) {
	if _, err := u.Collections.Find(ctx, ownerID, projectID, collectionID); err != nil {
		return nil, err
	}
	return u.Documents.ListByCollection(ctx, ownerID, projectID, collectionID)
}

type GetDocument struct {
	Documents domain.DocumentRepository
}

func (u GetDocument) Execute(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID) (domain.Document, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil || collectionID == uuid.Nil || documentID == uuid.Nil {
		return domain.Document{}, domain.ErrInvalidInput
	}
	return u.Documents.Find(ctx, ownerID, projectID, collectionID, documentID)
}

type CreateDocument struct {
	Projects    domain.ProjectRepository
	Collections domain.CollectionRepository
	Documents   domain.DocumentRepository
}

func (u CreateDocument) Execute(ctx context.Context, ownerID, projectID, collectionID uuid.UUID, data map[string]any) (domain.Document, error) {
	project, err := u.Projects.FindByID(ctx, ownerID, projectID)
	if err != nil {
		return domain.Document{}, err
	}
	if _, err := u.Collections.Find(ctx, ownerID, projectID, collectionID); err != nil {
		return domain.Document{}, err
	}
	payload, err := normalizeDocumentData(data)
	if err != nil {
		return domain.Document{}, err
	}
	_, maxDocs := domain.CollectionQuota(project.PlanSlug)
	count, err := u.Documents.CountByProject(ctx, ownerID, projectID)
	if err != nil {
		return domain.Document{}, err
	}
	if count >= maxDocs {
		return domain.Document{}, domain.ErrPlanLimit
	}
	newID, err := id.New()
	if err != nil {
		return domain.Document{}, err
	}
	now := time.Now().UTC()
	doc := domain.Document{ID: newID, ProjectID: projectID, CollectionID: collectionID, Data: payload, CreatedAt: now, UpdatedAt: now}
	if err := u.Documents.Create(ctx, ownerID, doc); err != nil {
		return domain.Document{}, err
	}
	return doc, nil
}

type UpdateDocument struct {
	Documents domain.DocumentRepository
}

func (u UpdateDocument) Execute(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID, data map[string]any) (domain.Document, error) {
	doc, err := u.Documents.Find(ctx, ownerID, projectID, collectionID, documentID)
	if err != nil {
		return domain.Document{}, err
	}
	payload, err := normalizeDocumentData(data)
	if err != nil {
		return domain.Document{}, err
	}
	doc.Data = payload
	doc.UpdatedAt = time.Now().UTC()
	if err := u.Documents.Update(ctx, ownerID, doc); err != nil {
		return domain.Document{}, err
	}
	return doc, nil
}

type DeleteDocument struct {
	Documents domain.DocumentRepository
}

func (u DeleteDocument) Execute(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID) error {
	if ownerID == uuid.Nil || projectID == uuid.Nil || collectionID == uuid.Nil || documentID == uuid.Nil {
		return domain.ErrInvalidInput
	}
	return u.Documents.Delete(ctx, ownerID, projectID, collectionID, documentID)
}

func normalizeDocumentData(data map[string]any) (map[string]any, error) {
	if data == nil {
		return map[string]any{}, nil
	}
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > 1<<20 {
		return nil, domain.ErrInvalidInput
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, domain.ErrInvalidInput
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}
