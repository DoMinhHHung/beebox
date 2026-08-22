//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/organization"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/jackc/pgx/v5"
)

func TestOrganizationCorePersistenceTenantIsolationPaginationAndAudit(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_organization_core")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applicationStore := applicationpostgres.New(pool)
	appA := createApplication(t, ctx, applicationStore)
	appB := createApplication(t, ctx, applicationStore)
	appOrder := createApplication(t, ctx, applicationStore)
	appConcurrent := createApplication(t, ctx, applicationStore)
	actorA := createActorUser(t, ctx, pool, appA.InternalID)
	actorB := createActorUser(t, ctx, pool, appB.InternalID)
	actorOrder := createActorUser(t, ctx, pool, appOrder.InternalID)
	actorConcurrent := createActorUser(t, ctx, pool, appConcurrent.InternalID)

	service := newService(t, New(pool))

	createA := mutationContext(t, appA.InternalID, actorA)
	orgA, err := service.Create(ctx, createA, "  Alpha Corporation  ", "Alpha_Corporation")
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	if !orgA.ID.Valid() || orgA.ApplicationInstanceID != appA.InternalID || orgA.Name != "Alpha Corporation" || orgA.Slug != "alpha-corporation" {
		t.Fatalf("Create(app A) = %#v", orgA)
	}
	if orgA.CreatedAt.Location() != time.UTC || orgA.UpdatedAt.Location() != time.UTC || orgA.UpdatedAt.Before(orgA.CreatedAt) {
		t.Fatalf("organization timestamps = created %v updated %v", orgA.CreatedAt, orgA.UpdatedAt)
	}

	createB := mutationContext(t, appB.InternalID, actorB)
	orgB, err := service.Create(ctx, createB, "Alpha in another app", "alpha-corporation")
	if err != nil {
		t.Fatalf("same slug across applications error = %v", err)
	}
	if orgB.ApplicationInstanceID != appB.InternalID || orgB.Slug != orgA.Slug {
		t.Fatalf("cross-app same-slug organization = %#v", orgB)
	}

	if _, err := service.Create(ctx, mutationContext(t, appA.InternalID, actorA), "Duplicate", "alpha corporation"); !errors.Is(err, organization.ErrSlugUnavailable) {
		t.Fatalf("same-app duplicate slug error = %v, want ErrSlugUnavailable", err)
	}

	resolvedA, err := service.Get(ctx, appA.InternalID, orgA.ID)
	if err != nil || resolvedA.ID != orgA.ID {
		t.Fatalf("Get(app A) = %#v, %v", resolvedA, err)
	}
	if _, err := service.Get(ctx, appB.InternalID, orgA.ID); !errors.Is(err, organization.ErrNotFound) {
		t.Fatalf("cross-app Get error = %v, want ErrNotFound", err)
	}
	if _, err := service.Update(ctx, mutationContext(t, appB.InternalID, actorB), orgA.ID, "Escaped", "escaped"); !errors.Is(err, organization.ErrNotFound) {
		t.Fatalf("cross-app Update error = %v, want ErrNotFound", err)
	}
	unchanged, err := service.Get(ctx, appA.InternalID, orgA.ID)
	if err != nil || unchanged.Name != orgA.Name || unchanged.Slug != orgA.Slug {
		t.Fatalf("cross-app update changed authoritative resource: %#v, %v", unchanged, err)
	}

	updateA := mutationContext(t, appA.InternalID, actorA)
	updated, err := service.Update(ctx, updateA, orgA.ID, "Alpha Platform", "Alpha Platform")
	if err != nil {
		t.Fatalf("Update(app A) error = %v", err)
	}
	if updated.ID != orgA.ID || updated.ApplicationInstanceID != appA.InternalID || updated.Name != "Alpha Platform" || updated.Slug != "alpha-platform" || updated.UpdatedAt.Before(updated.CreatedAt) {
		t.Fatalf("updated organization = %#v", updated)
	}
	assertAuditEvent(t, ctx, pool, createA, audit.ActionOrganizationCreated, orgA.ID)
	assertAuditEvent(t, ctx, pool, updateA, audit.ActionOrganizationUpdated, orgA.ID)

	badAuditContext := mutationContext(t, appA.InternalID, identity.InternalID(9_999_999))
	if _, err := service.Create(ctx, badAuditContext, "Must Roll Back", "must-roll-back"); !errors.Is(err, organization.ErrPersistence) {
		t.Fatalf("audit failure Create() error = %v, want ErrPersistence", err)
	}
	assertOrganizationCount(t, ctx, pool, appA.InternalID, "must-roll-back", 0)
	if _, err := service.Update(ctx, badAuditContext, orgA.ID, "Must Also Roll Back", "must-also-roll-back"); !errors.Is(err, organization.ErrPersistence) {
		t.Fatalf("audit failure Update() error = %v, want ErrPersistence", err)
	}
	afterAuditFailure, err := service.Get(ctx, appA.InternalID, orgA.ID)
	if err != nil || afterAuditFailure.Name != updated.Name || afterAuditFailure.Slug != updated.Slug {
		t.Fatalf("audit failure update committed authoritative mutation: %#v, %v", afterAuditFailure, err)
	}

	ordered := make([]organization.Organization, 0, 5)
	for i, slug := range []string{"order-a", "order-b", "order-c", "order-d", "order-e"} {
		item, err := service.Create(ctx, mutationContext(t, appOrder.InternalID, actorOrder), "Ordered Organization", slug)
		if err != nil {
			t.Fatalf("Create(order %d) error = %v", i, err)
		}
		ordered = append(ordered, item)
	}
	forceSameCreatedAt(t, ctx, pool, appOrder.InternalID, time.Unix(1_700_000_000, 123_000_000).UTC())
	page1, err := service.List(ctx, appOrder.InternalID, 2, "")
	if err != nil {
		t.Fatalf("List(page 1) error = %v", err)
	}
	if len(page1.Organizations) != 2 || page1.NextCursor == "" {
		t.Fatalf("page 1 = %#v", page1)
	}
	page2, err := service.List(ctx, appOrder.InternalID, 2, page1.NextCursor)
	if err != nil {
		t.Fatalf("List(page 2) error = %v", err)
	}
	if len(page2.Organizations) != 2 || page2.NextCursor == "" {
		t.Fatalf("page 2 = %#v", page2)
	}
	page3, err := service.List(ctx, appOrder.InternalID, 2, page2.NextCursor)
	if err != nil {
		t.Fatalf("List(page 3) error = %v", err)
	}
	if len(page3.Organizations) != 1 || page3.NextCursor != "" {
		t.Fatalf("page 3 = %#v", page3)
	}
	gotIDs := pageIDs(page1, page2, page3)
	wantIDs := make([]string, 0, len(ordered))
	for _, item := range ordered {
		wantIDs = append(wantIDs, string(item.ID))
	}
	sort.Strings(wantIDs)
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("listed IDs = %v, want %v", gotIDs, wantIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("deterministic order = %v, want %v", gotIDs, wantIDs)
		}
	}
	if _, err := service.List(ctx, appB.InternalID, 2, page1.NextCursor); !errors.Is(err, organization.ErrInvalidCursor) {
		t.Fatalf("cross-app cursor error = %v, want ErrInvalidCursor", err)
	}
	tampered := tamperCursor(page1.NextCursor)
	if _, err := service.List(ctx, appOrder.InternalID, 2, tampered); !errors.Is(err, organization.ErrInvalidCursor) {
		t.Fatalf("tampered cursor error = %v, want ErrInvalidCursor", err)
	}
	if _, err := service.List(ctx, appOrder.InternalID, 2, "malformed"); !errors.Is(err, organization.ErrInvalidCursor) {
		t.Fatalf("malformed cursor error = %v, want ErrInvalidCursor", err)
	}

	const creators = 8
	mutations := make([]organization.MutationContext, creators)
	for i := range mutations {
		mutations[i] = mutationContext(t, appConcurrent.InternalID, actorConcurrent)
	}
	results := make(chan error, creators)
	var wg sync.WaitGroup
	for i := range creators {
		wg.Add(1)
		current := mutations[i]
		go func() {
			defer wg.Done()
			callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer callCancel()
			_, err := service.Create(callCtx, current, "Concurrent Organization", "concurrent-slug")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, organization.ErrSlugUnavailable):
			conflicts++
		default:
			t.Fatalf("concurrent Create() error = %v", err)
		}
	}
	if successes != 1 || conflicts != creators-1 {
		t.Fatalf("concurrent results success=%d conflict=%d, want 1/%d", successes, conflicts, creators-1)
	}
	assertOrganizationCount(t, ctx, pool, appConcurrent.InternalID, "concurrent-slug", 1)
}

func newService(t *testing.T, store *Store) *organization.Service {
	t.Helper()
	var key organization.CursorKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	service, err := organization.NewService(store, key)
	if err != nil {
		t.Fatalf("organization.NewService() error = %v", err)
	}
	return service
}

func createApplication(t *testing.T, ctx context.Context, store *applicationpostgres.Store) applicationinstance.Instance {
	t.Helper()
	instance, err := store.Create(ctx)
	if err != nil {
		t.Fatalf("application Store.Create() error = %v", err)
	}
	return instance
}

func createActorUser(t *testing.T, ctx context.Context, pool *database.Pool, applicationID applicationinstance.InternalID) identity.InternalID {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var id int64
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, int64(applicationID)).Scan(&id); err != nil {
		t.Fatalf("create actor user error = %v", err)
	}
	return identity.InternalID(id)
}

func mutationContext(t *testing.T, applicationID applicationinstance.InternalID, actorID identity.InternalID) organization.MutationContext {
	t.Helper()
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatalf("audit.NewCorrelationID() error = %v", err)
	}
	return organization.MutationContext{
		ApplicationInstanceID: applicationID,
		ActorUserID:           actorID,
		CorrelationID:         correlationID,
	}
}

func assertAuditEvent(t *testing.T, ctx context.Context, pool *database.Pool, current organization.MutationContext, action string, organizationID organization.ID) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var actorID int64
	var actorKind, storedAction, category, reference, outcome, source string
	var correlation []byte
	var occurredAt time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT actor_kind,actor_user_id,action,resource_category,resource_reference,outcome,correlation_id,source,occurred_at
		FROM audit_events
		WHERE application_instance_id=$1 AND action=$2 AND resource_reference=$3`,
		int64(current.ApplicationInstanceID), action, string(organizationID),
	).Scan(&actorKind, &actorID, &storedAction, &category, &reference, &outcome, &correlation, &source, &occurredAt); err != nil {
		t.Fatalf("query organization audit error = %v", err)
	}
	if actorKind != audit.ActorKindUser || actorID != int64(current.ActorUserID) || storedAction != action || category != audit.ResourceCategoryOrganization || reference != string(organizationID) || outcome != audit.OutcomeSuccess || source != audit.SourceInternalOrganization {
		t.Fatalf("organization audit = actor=%s/%d category=%s ref=%s outcome=%s source=%s", actorKind, actorID, category, reference, outcome, source)
	}
	if !bytes.Equal(correlation, current.CorrelationID[:]) {
		t.Fatalf("organization audit correlation = %x, want %x", correlation, current.CorrelationID)
	}
	if occurredAt.IsZero() {
		t.Fatal("organization audit occurred_at is zero")
	}
}

func assertOrganizationCount(t *testing.T, ctx context.Context, pool *database.Pool, applicationID applicationinstance.InternalID, slug string, want int) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organizations WHERE application_instance_id=$1 AND slug=$2`, int64(applicationID), slug).Scan(&count); err != nil {
		t.Fatalf("organization count query error = %v", err)
	}
	if count != want {
		t.Fatalf("organization count for app=%d slug=%q = %d, want %d", applicationID, slug, count, want)
	}
}

func forceSameCreatedAt(t *testing.T, ctx context.Context, pool *database.Pool, applicationID applicationinstance.InternalID, createdAt time.Time) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `UPDATE organizations SET created_at=$2 WHERE application_instance_id=$1`, int64(applicationID), createdAt.UTC()); err != nil {
		t.Fatalf("force organization created_at error = %v", err)
	}
}

func pageIDs(pages ...organization.Page) []string {
	var ids []string
	for _, page := range pages {
		if len(page.Organizations) > 2 {
			panic("organization page exceeded requested bound")
		}
		for _, item := range page.Organizations {
			ids = append(ids, string(item.ID))
		}
	}
	return ids
}

func tamperCursor(cursor string) string {
	if cursor == "" {
		return "tampered"
	}
	last := cursor[len(cursor)-1]
	replacement := byte('A')
	if last == replacement {
		replacement = 'B'
	}
	return cursor[:len(cursor)-1] + string(replacement)
}

func isolatedDatabaseURL(t *testing.T, schema string) string {
	t.Helper()
	databaseURL := os.Getenv("BEEBOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("BEEBOX_TEST_DATABASE_URL is required for integration tests")
	}
	adminPool := openPool(t, databaseURL)
	adminDB := adminPool.OpenSQLDB()
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := adminDB.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
		adminDB.Close()
		t.Fatalf("drop test schema error = %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminDB.Close()
		t.Fatalf("create test schema error = %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		_ = adminDB.Close()
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal("BEEBOX_TEST_DATABASE_URL must be a valid URI")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func openPool(t *testing.T, databaseURL string) *database.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping() error = %v", err)
	}
	return pool
}
