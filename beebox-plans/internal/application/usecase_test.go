package application

import (
	"context"
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
	"github.com/google/uuid"
)

func TestListPlans(t *testing.T) {
	repo := newFakePlanRepo(domain.Plan{ID: uuid.MustParse("01800000-0000-7000-8000-000000000001"), Slug: "free", Name: "Free"})
	got, err := ListPlans{Plans: repo}.Execute(context.Background())
	if err != nil {
		t.Fatalf("ListPlans: %v", err)
	}
	if len(got) != 1 || got[0].Slug != "free" {
		t.Fatalf("got=%+v", got)
	}
}

func TestGetPlan(t *testing.T) {
	repo := newFakePlanRepo(domain.Plan{Slug: "pro", Name: "Pro"})
	got, err := GetPlan{Plans: repo}.Execute(context.Background(), "pro")
	if err != nil {
		t.Fatalf("GetPlan: %v", err)
	}
	if got.Slug != "pro" {
		t.Fatalf("slug=%q", got.Slug)
	}
	_, err = GetPlan{Plans: repo}.Execute(context.Background(), "missing")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing err=%v", err)
	}
	_, err = GetPlan{Plans: repo}.Execute(context.Background(), "  ")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("blank err=%v", err)
	}
}

func TestSeedInsertsMissing(t *testing.T) {
	repo := newFakePlanRepo()
	if err := Seed(context.Background(), repo); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	free, err := repo.FindBySlug(context.Background(), "free")
	if err != nil {
		t.Fatalf("free: %v", err)
	}
	if free.ID == uuid.Nil || free.ID.Version() != 7 {
		t.Fatalf("free id=%s version=%d", free.ID, free.ID.Version())
	}
	if free.Limits.UserFields != 3 || free.Limits.Collections != 1 || free.Limits.OAuth || free.Limits.OTP || free.Limits.Realtime {
		t.Fatalf("free limits=%+v", free.Limits)
	}
	pro, err := repo.FindBySlug(context.Background(), "pro")
	if err != nil {
		t.Fatalf("pro: %v", err)
	}
	if pro.Limits.UserFields != 20 || pro.Limits.Collections != 20 || !pro.Limits.OAuth || !pro.Limits.OTP || !pro.Limits.Realtime {
		t.Fatalf("pro limits=%+v", pro.Limits)
	}
}

func TestSeedSkipsExisting(t *testing.T) {
	existing := domain.Plan{ID: uuid.MustParse("01800000-0000-7000-8000-00000000000a"), Slug: "free", Name: "Kept"}
	repo := newFakePlanRepo(existing)
	if err := Seed(context.Background(), repo); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	got, err := repo.FindBySlug(context.Background(), "free")
	if err != nil {
		t.Fatalf("free: %v", err)
	}
	if got.Name != "Kept" || got.ID != existing.ID {
		t.Fatalf("got=%+v", got)
	}
	if _, err := repo.FindBySlug(context.Background(), "pro"); err != nil {
		t.Fatalf("pro should be seeded: %v", err)
	}
}
