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

type atomicCollectionCreator interface {
	CreateIfBelowLimit(ctx context.Context, ownerID, projectID uuid.UUID, collection domain.Collection, limit int) error
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
	newID, err := id.New()
	if err != nil {
		return domain.Collection{}, err
	}
	item := domain.Collection{ID: newID, ProjectID: projectID, Name: name, Slug: slug, CreatedAt: time.Now().UTC()}
	if atomic, ok := u.Collections.(atomicCollectionCreator); ok {
		err = atomic.CreateIfBelowLimit(ctx, ownerID, projectID, item, maxColl)
	} else {
		count, countErr := u.Collections.CountByProject(ctx, ownerID, projectID)
		if countErr != nil {
			return domain.Collection{}, countErr
		}
		if count >= maxColl {
			return domain.Collection{}, domain.ErrPlanLimit
		}
		err = u.Collections.Create(ctx, ownerID, item)
	}
	if err != nil {
		return domain.Collection{}, err
	}
	return item, nil
}

type UpdateCollection struct {
	Collections domain.CollectionRepository
}

func (u UpdateCollection) Execute(ctx context.Context, ownerID, projectID, collectionID uuid.UUID, name, slug string) (domain.Collection, error) {
	if ownerID == uuid.Nil || projectID == uuid.Nil || collectionID == uuid.Nil {
		return domain.Collection{}, domain.ErrInvalidInput
	}
	item, err := u.Collections.Find(ctx, ownerID, projectID, collectionID)
	if err != nil {
		return domain.Collection{}, err
	}
	name = strings.TrimSpace(name)
	slug = strings.TrimSpace(slug)
	if name == "" || !collectionSlugRE.MatchString(slug) {
		return domain.Collection{}, domain.ErrInvalidInput
	}
	item.Name, item.Slug = name, slug
	if err := u.Collections.Update(ctx, ownerID, item); err != nil {
		return domain.Collection{}, err
	}
	return item, nil
}

type DeleteCollection struct {
	Collections domain.CollectionRepository
}

func (u DeleteCollection) Execute(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) error {
	if ownerID == uuid.Nil || projectID == uuid.Nil || collectionID == uuid.Nil {
		return domain.ErrInvalidInput
	}
	// The collection foreign key uses ON DELETE CASCADE, so its documents are removed atomically.
	return u.Collections.Delete(ctx, ownerID, projectID, collectionID)
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

type atomicDocumentCreator interface {
	CreateIfBelowLimit(ctx context.Context, ownerID, projectID uuid.UUID, doc domain.Document, limit int) error
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
	newID, err := id.New()
	if err != nil {
		return domain.Document{}, err
	}
	now := time.Now().UTC()
	doc := domain.Document{ID: newID, ProjectID: projectID, CollectionID: collectionID, Data: payload, CreatedAt: now, UpdatedAt: now}
	if atomic, ok := u.Documents.(atomicDocumentCreator); ok {
		err = atomic.CreateIfBelowLimit(ctx, ownerID, projectID, doc, maxDocs)
	} else {
		count, countErr := u.Documents.CountByProject(ctx, ownerID, projectID)
		if countErr != nil {
			return domain.Document{}, countErr
		}
		if count >= maxDocs {
			return domain.Document{}, domain.ErrPlanLimit
		}
		err = u.Documents.Create(ctx, ownerID, doc)
	}
	if err != nil {
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
