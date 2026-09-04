package application

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type fakeCollections struct{ items []domain.Collection }

type concurrentCollections struct {
	*fakeCollections
	mu sync.Mutex
}

func (f *concurrentCollections) CreateIfBelowLimit(_ context.Context, _ uuid.UUID, projectID uuid.UUID, collection domain.Collection, limit int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, item := range f.items {
		if item.ProjectID == projectID {
			count++
		}
	}
	if count >= limit {
		return domain.ErrPlanLimit
	}
	f.items = append(f.items, collection)
	return nil
}

func (f *fakeCollections) Create(_ context.Context, _ uuid.UUID, collection domain.Collection) error {
	for _, item := range f.items {
		if item.ProjectID == collection.ProjectID && item.Slug == collection.Slug {
			return domain.ErrConflict
		}
	}
	f.items = append(f.items, collection)
	return nil
}
func (f *fakeCollections) ListByProject(_ context.Context, _, projectID uuid.UUID) ([]domain.Collection, error) {
	var out []domain.Collection
	for _, item := range f.items {
		if item.ProjectID == projectID {
			out = append(out, item)
		}
	}
	return out, nil
}
func (f *fakeCollections) Find(_ context.Context, _, projectID, collectionID uuid.UUID) (domain.Collection, error) {
	for _, item := range f.items {
		if item.ProjectID == projectID && item.ID == collectionID {
			return item, nil
		}
	}
	return domain.Collection{}, domain.ErrNotFound
}
func (f *fakeCollections) Update(_ context.Context, _ uuid.UUID, collection domain.Collection) error {
	for i, item := range f.items {
		if item.ID == collection.ID && item.ProjectID == collection.ProjectID {
			f.items[i] = collection
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *fakeCollections) Delete(_ context.Context, _, projectID, collectionID uuid.UUID) error {
	for i, item := range f.items {
		if item.ID == collectionID && item.ProjectID == projectID {
			f.items = append(f.items[:i], f.items[i+1:]...)
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *fakeCollections) CountByProject(_ context.Context, _, projectID uuid.UUID) (int, error) {
	n := 0
	for _, item := range f.items {
		if item.ProjectID == projectID {
			n++
		}
	}
	return n, nil
}

type fakeDocuments struct{ items []domain.Document }

func (f *fakeDocuments) Create(_ context.Context, _ uuid.UUID, doc domain.Document) error {
	f.items = append(f.items, doc)
	return nil
}
func (f *fakeDocuments) ListByCollection(_ context.Context, _, _, collectionID uuid.UUID) ([]domain.Document, error) {
	var out []domain.Document
	for _, item := range f.items {
		if item.CollectionID == collectionID {
			out = append(out, item)
		}
	}
	return out, nil
}
func (f *fakeDocuments) Find(_ context.Context, _, _, collectionID, documentID uuid.UUID) (domain.Document, error) {
	for _, item := range f.items {
		if item.CollectionID == collectionID && item.ID == documentID {
			return item, nil
		}
	}
	return domain.Document{}, domain.ErrNotFound
}
func (f *fakeDocuments) Update(_ context.Context, _ uuid.UUID, doc domain.Document) error {
	for i, item := range f.items {
		if item.ID == doc.ID {
			f.items[i] = doc
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *fakeDocuments) Delete(_ context.Context, _, _, _, documentID uuid.UUID) error {
	for i, item := range f.items {
		if item.ID == documentID {
			f.items = append(f.items[:i], f.items[i+1:]...)
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *fakeDocuments) CountByProject(_ context.Context, _, projectID uuid.UUID) (int, error) {
	n := 0
	for _, item := range f.items {
		if item.ProjectID == projectID {
			n++
		}
	}
	return n, nil
}

func TestCreateCollectionFreeLimit(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-000000000001")
	projectID := uuid.MustParse("01800000-0000-7000-8000-000000000002")
	projects := &fakeProjects{items: map[uuid.UUID]domain.Project{projectID: {
		ID: projectID, OwnerID: owner, Name: "Shop", Slug: "shop", PlanSlug: "free", Env: domain.EnvTest, Status: domain.StatusActive,
	}}}
	uc := CreateCollection{Projects: projects, Collections: &fakeCollections{}}
	for i := 0; i < 2; i++ {
		if _, err := uc.Execute(context.Background(), owner, projectID, "Col", "col_"+string(rune('a'+i))); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	_, err := uc.Execute(context.Background(), owner, projectID, "Overflow", "overflow")
	if !errors.Is(err, domain.ErrPlanLimit) {
		t.Fatalf("want plan limit, got %v", err)
	}
}

func TestCreateDocumentStoresPayload(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-000000000001")
	projectID := uuid.MustParse("01800000-0000-7000-8000-000000000002")
	colID := uuid.MustParse("01800000-0000-7000-8000-000000000003")
	projects := &fakeProjects{items: map[uuid.UUID]domain.Project{projectID: {
		ID: projectID, OwnerID: owner, Name: "Shop", Slug: "shop", PlanSlug: "pro", Env: domain.EnvTest, Status: domain.StatusActive,
	}}}
	cols := &fakeCollections{items: []domain.Collection{{ID: colID, ProjectID: projectID, Name: "Posts", Slug: "posts"}}}
	got, err := (CreateDocument{Projects: projects, Collections: cols, Documents: &fakeDocuments{}}).Execute(
		context.Background(), owner, projectID, colID, map[string]any{"title": "hi"},
	)
	if err != nil {
		t.Fatalf("create doc: %v", err)
	}
	if got.Data["title"] != "hi" {
		t.Fatalf("data=%v", got.Data)
	}
}

func TestCreateCollectionConcurrentQuota(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-000000000001")
	projectID := uuid.MustParse("01800000-0000-7000-8000-000000000002")
	projects := &fakeProjects{items: map[uuid.UUID]domain.Project{projectID: {
		ID: projectID, OwnerID: owner, Name: "Shop", Slug: "shop", PlanSlug: "free", Env: domain.EnvTest, Status: domain.StatusActive,
	}}}
	collections := &concurrentCollections{fakeCollections: &fakeCollections{items: []domain.Collection{{ProjectID: projectID, Slug: "existing"}}}}
	uc := CreateCollection{Projects: projects, Collections: collections}
	const attempts = 8
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := uc.Execute(context.Background(), owner, projectID, "New", "new_"+string(rune('a'+i)))
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	var succeeded, limited int
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, domain.ErrPlanLimit) {
			limited++
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || limited != attempts-1 {
		t.Fatalf("succeeded=%d limited=%d", succeeded, limited)
	}
}
