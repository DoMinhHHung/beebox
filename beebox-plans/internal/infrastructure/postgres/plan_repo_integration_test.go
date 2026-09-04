//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("BEEBOX_DATABASE_URL")
	if url == "" {
		url = "postgres://beebox:beebox@127.0.0.1:5432/beebox?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func TestPlanRepositorySeedAndRead(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	repo := NewPlanRepository(pool)
	if err := application.Seed(ctx, repo); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := application.Seed(ctx, repo); err != nil {
		t.Fatalf("seed again: %v", err)
	}
	free, err := repo.FindBySlug(ctx, "free")
	if err != nil {
		t.Fatalf("free: %v", err)
	}
	if free.Limits.UserFields != 3 || free.Name != "Free" {
		t.Fatalf("free=%+v", free)
	}
	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("list len=%d", len(list))
	}
	_, err = repo.FindBySlug(ctx, "does-not-exist")
	if err != domain.ErrNotFound {
		t.Fatalf("missing err=%v", err)
	}
}
