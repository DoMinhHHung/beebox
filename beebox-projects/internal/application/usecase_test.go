package application

import (
	"context"
	"errors"
	"testing"
	"time"

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

func (f *fakeProjects) CreateWithIAM(ctx context.Context, ownerID uuid.UUID, project domain.Project, _ []domain.APIKey, _ []string) error {
	return f.Create(ctx, ownerID, project)
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

func (f *fakeProjects) FindBySlug(_ context.Context, slug string) (domain.Project, error) {
	for _, p := range f.items {
		if p.Slug == slug {
			return p, nil
		}
	}
	return domain.Project{}, domain.ErrNotFound
}

func (f *fakeProjects) Update(_ context.Context, ownerID uuid.UUID, project domain.Project) error {
	cur, ok := f.items[project.ID]
	if !ok || cur.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	if !cur.UpdatedAt.Equal(project.UpdatedAt) {
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
	if got.Project.PlanID != planID || got.Project.PlanSlug != "free" || got.Project.Env != domain.EnvTest || got.Project.ID.Version() != 7 {
		t.Fatalf("got=%+v", got.Project)
	}
	if len(got.Keys) != 2 {
		t.Fatalf("keys=%d", len(got.Keys))
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

func TestPutModulesFreeRejectsOAuth(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-0000000000bb")
	id := uuid.MustParse("01800000-0000-7000-8000-0000000000cc")
	projects := &fakeProjects{items: map[uuid.UUID]domain.Project{id: {ID: id, OwnerID: owner, PlanSlug: "free"}}}
	mods := &fakeModules{byID: map[uuid.UUID][]string{}}
	_, err := (PutModules{Projects: projects, Modules: mods}).Execute(context.Background(), owner, id, []string{
		domain.ModuleAuthPassword, domain.ModuleUsersProfile, domain.ModuleAuthOAuthGoogle,
	})
	if !errors.Is(err, domain.ErrPlanLimit) {
		t.Fatalf("err=%v", err)
	}
}

func TestFakeUpdateRejectsStaleUpdatedAt(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-0000000000bb")
	id := uuid.MustParse("01800000-0000-7000-8000-0000000000cc")
	cur := domain.Project{ID: id, OwnerID: owner, Name: "Shop", UpdatedAt: time.Unix(2, 0).UTC()}
	repo := &fakeProjects{items: map[uuid.UUID]domain.Project{id: cur}}
	stale := cur
	stale.Name = "Old"
	stale.UpdatedAt = time.Unix(1, 0).UTC()
	if err := repo.Update(context.Background(), owner, stale); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("err=%v", err)
	}
	fresh := cur
	fresh.Name = "New"
	if err := repo.Update(context.Background(), owner, fresh); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	if repo.items[id].Name != "New" {
		t.Fatalf("name=%q", repo.items[id].Name)
	}
}

type fakeModules struct {
	byID map[uuid.UUID][]string
}

func (f *fakeModules) Replace(_ context.Context, _, projectID uuid.UUID, names []string) error {
	if f.byID == nil {
		f.byID = map[uuid.UUID][]string{}
	}
	f.byID[projectID] = append([]string(nil), names...)
	return nil
}
func (f *fakeModules) ListByProject(_ context.Context, _, projectID uuid.UUID) ([]string, error) {
	return append([]string(nil), f.byID[projectID]...), nil
}
func (f *fakeModules) ListByProjectID(_ context.Context, projectID uuid.UUID) ([]string, error) {
	return append([]string(nil), f.byID[projectID]...), nil
}
