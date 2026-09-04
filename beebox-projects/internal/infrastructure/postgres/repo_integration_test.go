//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	beeboxid "github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
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

func TestProjectRepositoryHardDeleteAndRLS(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	accounts := NewAccountRepository(pool)
	projects := NewProjectRepository(pool)
	ownerID, err := beeboxid.New()
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := beeboxid.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.Create(ctx, domain.Account{ID: ownerID, Email: ownerID.String() + "@ex.com"}); err != nil {
		t.Fatalf("owner: %v", err)
	}
	if err := accounts.Create(ctx, domain.Account{ID: otherID, Email: otherID.String() + "@ex.com"}); err != nil {
		t.Fatalf("other: %v", err)
	}
	planID := uuid.MustParse("01800000-0000-7000-8000-0000000000aa")
	projectID, err := beeboxid.New()
	if err != nil {
		t.Fatal(err)
	}
	slug := "p-" + projectID.String()[24:]
	err = projects.Create(ctx, ownerID, domain.Project{
		ID: projectID, OwnerID: ownerID, PlanID: planID, PlanSlug: "free",
		Name: "Shop-" + projectID.String()[24:], Slug: slug, Env: domain.EnvTest, Status: domain.StatusActive,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = projects.FindByID(ctx, otherID, projectID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rls other get err=%v", err)
	}
	if err := projects.Delete(ctx, ownerID, projectID); err != nil {
		t.Fatalf("delete: %v", err)
	}
}
