package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/infrastructure/crypto"
	"github.com/google/uuid"
)

type memAccounts struct {
	items  map[uuid.UUID]domain.Account
	byMail map[string]uuid.UUID
}

func (f *memAccounts) Create(_ context.Context, a domain.Account) error {
	if f.items == nil {
		f.items, f.byMail = map[uuid.UUID]domain.Account{}, map[string]uuid.UUID{}
	}
	if _, ok := f.byMail[a.Email]; ok {
		return domain.ErrConflict
	}
	f.items[a.ID], f.byMail[a.Email] = a, a.ID
	return nil
}
func (f *memAccounts) FindByID(_ context.Context, id uuid.UUID) (domain.Account, error) {
	a, ok := f.items[id]
	if !ok {
		return domain.Account{}, domain.ErrNotFound
	}
	return a, nil
}
func (f *memAccounts) FindByEmail(_ context.Context, email string) (domain.Account, error) {
	id, ok := f.byMail[email]
	if !ok {
		return domain.Account{}, domain.ErrNotFound
	}
	return f.FindByID(context.Background(), id)
}

type memSessions struct {
	items map[string]domain.OwnerSession
}

func (f *memSessions) Create(_ context.Context, s domain.OwnerSession) error {
	if f.items == nil {
		f.items = map[string]domain.OwnerSession{}
	}
	f.items[s.TokenHash] = s
	return nil
}
func (f *memSessions) FindByTokenHash(_ context.Context, h string) (domain.OwnerSession, error) {
	s, ok := f.items[h]
	if !ok {
		return domain.OwnerSession{}, domain.ErrNotFound
	}
	return s, nil
}
func (f *memSessions) DeleteByTokenHash(_ context.Context, h string) error {
	delete(f.items, h)
	return nil
}

type memProjects struct{ items map[uuid.UUID]domain.Project }

func (f *memProjects) Create(_ context.Context, _ uuid.UUID, p domain.Project) error {
	if f.items == nil {
		f.items = map[uuid.UUID]domain.Project{}
	}
	f.items[p.ID] = p
	return nil
}
func (f *memProjects) CreateWithIAM(ctx context.Context, o uuid.UUID, p domain.Project, _ []domain.APIKey, _ []string) error {
	return f.Create(ctx, o, p)
}
func (f *memProjects) List(_ context.Context, o uuid.UUID) ([]domain.Project, error) {
	var out []domain.Project
	for _, p := range f.items {
		if p.OwnerID == o {
			out = append(out, p)
		}
	}
	return out, nil
}
func (f *memProjects) FindByID(_ context.Context, o, id uuid.UUID) (domain.Project, error) {
	p, ok := f.items[id]
	if !ok || p.OwnerID != o {
		return domain.Project{}, domain.ErrNotFound
	}
	return p, nil
}
func (f *memProjects) FindBySlug(_ context.Context, slug string) (domain.Project, error) {
	for _, p := range f.items {
		if p.Slug == slug {
			return p, nil
		}
	}
	return domain.Project{}, domain.ErrNotFound
}
func (f *memProjects) Update(context.Context, uuid.UUID, domain.Project) error { return nil }
func (f *memProjects) Delete(context.Context, uuid.UUID, uuid.UUID) error      { return nil }

type memCatalog struct{}

func (memCatalog) FindBySlug(_ context.Context, slug string) (domain.CatalogPlan, error) {
	if slug != "free" {
		return domain.CatalogPlan{}, domain.ErrNotFound
	}
	return domain.CatalogPlan{ID: uuid.MustParse("01800000-0000-7000-8000-0000000000aa"), Slug: "free"}, nil
}

func ownerHandler() http.Handler {
	accounts, sessions, projects := &memAccounts{}, &memSessions{}, &memProjects{}
	h, tok := crypto.Argon2id{}, crypto.SessionTokens{}
	return New(Deps{
		CreateAccount: application.CreateAccount{Accounts: accounts, Hasher: h},
		CreateProject: application.CreateProject{Projects: projects, Catalog: memCatalog{}},
		OwnerSignUp:   application.OwnerSignUp{Accounts: accounts, Sessions: sessions, Hasher: h, Tokens: tok},
		OwnerSignIn:   application.OwnerSignIn{Accounts: accounts, Sessions: sessions, Hasher: h, Tokens: tok},
		OwnerSignOut:  application.OwnerSignOut{Sessions: sessions, Tokens: tok},
		OwnerMe:       application.OwnerMe{Accounts: accounts, Sessions: sessions, Tokens: tok},
	})
}

func TestOwnerSessionCreatesProjectWithoutHeader(t *testing.T) {
	h := ownerHandler()
	sign := httptest.NewRecorder()
	h.ServeHTTP(sign, httptest.NewRequest(http.MethodPost, "/v1/owner/sign-up", strings.NewReader(`{"email":"owner@example.com","password":"password1"}`)))
	if sign.Code != http.StatusCreated {
		t.Fatalf("sign-up=%d body=%s", sign.Code, sign.Body.String())
	}
	var auth ownerAuthDTO
	if err := json.Unmarshal(sign.Body.Bytes(), &auth); err != nil {
		t.Fatalf("json: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects", bytes.NewReader([]byte(`{"name":"Shop","slug":"shop","plan_slug":"free"}`)))
	req.Header.Set("Authorization", "Bearer "+auth.Session.Token)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create project=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOwnerHeaderUnauthorizedByDefault(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set(ownerHeader, "01800000-0000-7000-8000-0000000000bb")
	ownerHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOwnerMeAndSignOut(t *testing.T) {
	h := ownerHandler()
	sign := httptest.NewRecorder()
	h.ServeHTTP(sign, httptest.NewRequest(http.MethodPost, "/v1/owner/sign-up", strings.NewReader(`{"email":"me@example.com","password":"password1"}`)))
	var auth ownerAuthDTO
	if err := json.Unmarshal(sign.Body.Bytes(), &auth); err != nil {
		t.Fatalf("json: %v", err)
	}
	me := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/owner/me", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Session.Token)
	h.ServeHTTP(me, req)
	if me.Code != http.StatusOK {
		t.Fatalf("me=%d body=%s", me.Code, me.Body.String())
	}
	out := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/owner/sign-out", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Session.Token)
	h.ServeHTTP(out, req)
	if out.Code != http.StatusNoContent {
		t.Fatalf("sign-out=%d", out.Code)
	}
}

func TestPostAccountRequiresPassword(t *testing.T) {
	h := ownerHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/accounts", strings.NewReader(`{"email":"a@example.com"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("passwordless accounts=%d body=%s", rec.Code, rec.Body.String())
	}
	ok := httptest.NewRecorder()
	h.ServeHTTP(ok, httptest.NewRequest(http.MethodPost, "/v1/accounts", strings.NewReader(`{"email":"a@example.com","password":"password1"}`)))
	if ok.Code != http.StatusCreated {
		t.Fatalf("accounts with password=%d body=%s", ok.Code, ok.Body.String())
	}
}
