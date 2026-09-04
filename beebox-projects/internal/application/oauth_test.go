package application

import (
	"context"
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type memOAuth struct {
	items map[string]domain.OAuthProvider
}

func (m *memOAuth) key(pid uuid.UUID, slug string) string { return pid.String() + ":" + slug }

func (m *memOAuth) Upsert(_ context.Context, _ uuid.UUID, provider domain.OAuthProvider) error {
	if m.items == nil {
		m.items = map[string]domain.OAuthProvider{}
	}
	m.items[m.key(provider.ProjectID, provider.Slug)] = provider
	return nil
}

func (m *memOAuth) Find(_ context.Context, _, projectID uuid.UUID, slug string) (domain.OAuthProvider, error) {
	item, ok := m.items[m.key(projectID, slug)]
	if !ok {
		return domain.OAuthProvider{}, domain.ErrNotFound
	}
	item.SecretConfigured = item.SecretEnc != ""
	return item, nil
}

func (m *memOAuth) FindByProject(ctx context.Context, projectID uuid.UUID, slug string) (domain.OAuthProvider, error) {
	return m.Find(ctx, uuid.Nil, projectID, slug)
}

type passthroughBox struct{}

func (passthroughBox) Encrypt(plain string) (string, error) { return "enc:" + plain, nil }
func (passthroughBox) Decrypt(enc string) (string, error)   { return enc[4:], nil }

func TestPutOAuthFreeRejected(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-0000000000bb")
	id := uuid.MustParse("01800000-0000-7000-8000-0000000000cc")
	_, err := (PutOAuthProvider{
		Projects: &fakeProjects{items: map[uuid.UUID]domain.Project{id: {ID: id, OwnerID: owner, PlanSlug: "free"}}},
		OAuth:    &memOAuth{},
		Catalog:  fakeCatalog{plans: map[string]domain.CatalogPlan{"free": {Slug: "free", Limits: domain.PlanLimits{}}}},
		Box:      passthroughBox{},
	}).Execute(context.Background(), PutOAuthInput{
		OwnerID: owner, ProjectID: id, Slug: "google", ClientID: "cid", ClientSecret: "sec", RedirectURI: "https://app.example/cb", Enabled: true,
	})
	if !errors.Is(err, domain.ErrPlanLimit) {
		t.Fatalf("err=%v", err)
	}
}

func TestPutOAuthProStoresConfigured(t *testing.T) {
	owner := uuid.MustParse("01800000-0000-7000-8000-0000000000bb")
	id := uuid.MustParse("01800000-0000-7000-8000-0000000000cc")
	got, err := (PutOAuthProvider{
		Projects: &fakeProjects{items: map[uuid.UUID]domain.Project{id: {ID: id, OwnerID: owner, PlanSlug: "pro"}}},
		OAuth:    &memOAuth{},
		Catalog:  fakeCatalog{plans: map[string]domain.CatalogPlan{"pro": {Slug: "pro", Limits: domain.PlanLimits{OAuth: true}}}},
		Box:      passthroughBox{},
	}).Execute(context.Background(), PutOAuthInput{
		OwnerID: owner, ProjectID: id, Slug: "github", ClientID: "cid", ClientSecret: "sec", RedirectURI: "https://app.example/cb", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecret != "" || !got.SecretConfigured || got.Slug != "github" {
		t.Fatalf("%+v", got)
	}
}
