package application

import (
	"context"
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type fakeAccounts struct {
	items  map[uuid.UUID]domain.Account
	byMail map[string]uuid.UUID
}

func (f *fakeAccounts) Create(_ context.Context, account domain.Account) error {
	if f.items == nil {
		f.items = map[uuid.UUID]domain.Account{}
		f.byMail = map[string]uuid.UUID{}
	}
	if _, ok := f.byMail[account.Email]; ok {
		return domain.ErrConflict
	}
	f.items[account.ID] = account
	f.byMail[account.Email] = account.ID
	return nil
}

func (f *fakeAccounts) FindByID(_ context.Context, id uuid.UUID) (domain.Account, error) {
	a, ok := f.items[id]
	if !ok {
		return domain.Account{}, domain.ErrNotFound
	}
	return a, nil
}

type fakeProjects struct {
	items   map[uuid.UUID]domain.Project
	deleted int
}

func (f *fakeProjects) Create(_ context.Context, _ uuid.UUID, project domain.Project) error {
	if f.items == nil {
		f.items = map[uuid.UUID]domain.Project{}
	}
	f.items[project.ID] = project
	return nil
}

func (f *fakeProjects) List(_ context.Context, ownerID uuid.UUID) ([]domain.Project, error) {
	var out []domain.Project
	for _, p := range f.items {
		if p.OwnerID == ownerID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeProjects) FindByID(_ context.Context, ownerID, id uuid.UUID) (domain.Project, error) {
	p, ok := f.items[id]
	if !ok || p.OwnerID != ownerID {
		return domain.Project{}, domain.ErrNotFound
	}
	return p, nil
}

func (f *fakeProjects) Update(_ context.Context, ownerID uuid.UUID, project domain.Project) error {
	cur, ok := f.items[project.ID]
	if !ok || cur.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	if !project.UpdatedAt.IsZero() && !cur.UpdatedAt.IsZero() && !project.UpdatedAt.Equal(cur.UpdatedAt) {
		return domain.ErrConflict
	}
	f.items[project.ID] = project
	return nil
}

func (f *fakeProjects) Delete(_ context.Context, ownerID, id uuid.UUID) error {
	p, ok := f.items[id]
	if !ok || p.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	f.deleted++
	delete(f.items, id)
	return nil
}

type fakeCatalog struct {
	plans map[string]domain.CatalogPlan
}

func (f fakeCatalog) FindBySlug(_ context.Context, slug string) (domain.CatalogPlan, error) {
	p, ok := f.plans[slug]
	if !ok {
		return domain.CatalogPlan{}, domain.ErrNotFound
	}
	return p, nil
}

func TestCreateProjectUsesCatalog(t *testing.T) {
	planID := uuid.MustParse("01800000-0000-7000-8000-0000000000aa")
	owner := uuid.MustParse("01800000-0000-7000-8000-0000000000bb")
	u := CreateProject{
		Projects: &fakeProjects{items: map[uuid.UUID]domain.Project{}},
		Catalog:  fakeCatalog{plans: map[string]domain.CatalogPlan{"free": {ID: planID, Slug: "free"}}},
	}
	got, err := u.Execute(context.Background(), CreateProjectInput{OwnerID: owner, Name: "Shop", Slug: "shop", PlanSlug: "free"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.PlanID != planID || got.PlanSlug != "free" || got.Env != domain.EnvTest || got.ID.Version() != 7 {
		t.Fatalf("got=%+v", got)
	}
}

func TestDeleteProjectWrongConfirmationDoesNotDelete(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-0000000000bb")
	id := uuid.MustParse("01800000-0000-7000-8000-0000000000cc")
	repo := &fakeProjects{items: map[uuid.UUID]domain.Project{id: {ID: id, OwnerID: owner, Name: "Shop"}}}
	err := (DeleteProject{Projects: repo}).Execute(context.Background(), owner, id, "delete project wrong")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err=%v", err)
	}
	if repo.deleted != 0 {
		t.Fatalf("Delete should not be called")
	}
	if err := (DeleteProject{Projects: repo}).Execute(context.Background(), owner, id, "delete project Shop"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if repo.deleted != 1 {
		t.Fatalf("deleted=%d", repo.deleted)
	}
}

func TestCreateAccount(t *testing.T) {
	u := CreateAccount{Accounts: &fakeAccounts{}}
	got, err := u.Execute(context.Background(), "owner@example.com")
	if err != nil || got.ID.Version() != 7 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
