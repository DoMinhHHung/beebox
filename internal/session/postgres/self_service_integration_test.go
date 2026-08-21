//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestSessionSelfServiceScopesPaginationAndRevocation(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_session_self_service"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := identitypostgres.New(pool)
	userA, err := ids.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := ids.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	userC, err := ids.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatal(err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	currentID := "ses_10000000-0000-4000-8000-000000000001"
	ownA := "ses_20000000-0000-4000-8000-000000000002"
	ownB := "ses_30000000-0000-4000-8000-000000000003"
	foreignSameApp := "ses_40000000-0000-4000-8000-000000000004"
	foreignApp := "ses_50000000-0000-4000-8000-000000000005"
	insert := func(publicID string, appID, userID int64, created time.Time) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO sessions(public_id,application_instance_id,user_id,created_at,last_seen_at,idle_expires_at,expires_at) VALUES($1,$2,$3,$4,$4,$5,$6)`, publicID, appID, userID, created, now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	insert(currentID, int64(appA.InternalID), int64(userA.InternalID), now.Add(-time.Minute))
	insert(ownA, int64(appA.InternalID), int64(userA.InternalID), now.Add(-2*time.Minute))
	insert(ownB, int64(appA.InternalID), int64(userA.InternalID), now.Add(-3*time.Minute))
	insert(foreignSameApp, int64(appA.InternalID), int64(userB.InternalID), now)
	insert(foreignApp, int64(appB.InternalID), int64(userC.InternalID), now)

	store := New(pool)
	first, err := store.ListUserSessions(ctx, appA.InternalID, userA.InternalID, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].PublicID != currentID || first[1].PublicID != ownA {
		t.Fatalf("first page=%+v", first)
	}
	second, err := store.ListUserSessions(ctx, appA.InternalID, userA.InternalID, 2, &session.Cursor{CreatedAt: first[1].CreatedAt, PublicID: first[1].PublicID})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].PublicID != ownB {
		t.Fatalf("second page=%+v", second)
	}

	current := session.Record{PublicID: currentID, ApplicationInstanceID: appA.InternalID, UserInternalID: userA.InternalID, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)}
	if err := store.RevokeUserSession(ctx, current, foreignSameApp, mustCorrelation(t)); err != nil {
		t.Fatalf("cross-user revoke returned distinguishable failure: %v", err)
	}
	assertSessionRevoked(t, ctx, db, foreignSameApp, false)
	if err := store.RevokeUserSession(ctx, current, foreignApp, mustCorrelation(t)); err != nil {
		t.Fatalf("cross-app revoke returned distinguishable failure: %v", err)
	}
	assertSessionRevoked(t, ctx, db, foreignApp, false)

	if err := store.RevokeUserSession(ctx, current, ownA, mustCorrelation(t)); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeUserSession(ctx, current, ownA, mustCorrelation(t)); err != nil {
		t.Fatal(err)
	}
	assertSessionRevoked(t, ctx, db, ownA, true)

	if err := store.RevokeOtherUserSessions(ctx, current, mustCorrelation(t)); err != nil {
		t.Fatal(err)
	}
	assertSessionRevoked(t, ctx, db, currentID, false)
	assertSessionRevoked(t, ctx, db, ownB, true)
	assertSessionRevoked(t, ctx, db, foreignSameApp, false)
	assertSessionRevoked(t, ctx, db, foreignApp, false)
}

func TestSessionSelfServiceConcurrentMutationsConvergeAndRefreshFails(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_session_self_service_concurrency"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	currentID := "ses_60000000-0000-4000-8000-000000000006"
	targetID := "ses_70000000-0000-4000-8000-000000000007"
	db := pool.OpenSQLDB()
	defer db.Close()
	for _, id := range []string{currentID, targetID} {
		if _, err := db.ExecContext(ctx, `INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at) VALUES($1,$2,$3,$4,$5)`, id, int64(app.InternalID), int64(user.InternalID), now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	refresh := "refresh-self-service-test"
	refreshHash := session.HashRefreshSecret(refresh)
	if _, err := db.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) SELECT id,$2 FROM sessions WHERE public_id=$1`, targetID, refreshHash[:]); err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	current := session.Record{PublicID: currentID, ApplicationInstanceID: app.InternalID, UserInternalID: user.InternalID, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 4; i++ {
		correlation := mustCorrelation(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.RevokeUserSession(ctx, current, targetID, correlation)
		}()
	}
	for i := 0; i < 4; i++ {
		correlation := mustCorrelation(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.RevokeOtherUserSessions(ctx, current, correlation)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent revoke error=%v", err)
		}
	}
	assertSessionRevoked(t, ctx, db, currentID, false)
	assertSessionRevoked(t, ctx, db, targetID, true)
	newHash := session.HashRefreshSecret("new-refresh")
	if _, _, err := store.RotateRefresh(ctx, app.InternalID, refreshHash, newHash, now, now.Add(time.Hour), mustCorrelation(t)); !errors.Is(err, session.ErrRefreshInvalid) {
		t.Fatalf("refresh after revoke error=%v", err)
	}

	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		correlation := mustCorrelation(t)
		go func() { results <- store.RevokeAllUserSessions(ctx, current, correlation) }()
	}
	first, second := <-results, <-results
	if first != nil && second != nil {
		t.Fatalf("both sign-out-everywhere calls failed: %v / %v", first, second)
	}
	for _, err := range []error{first, second} {
		if err != nil && !errors.Is(err, session.ErrSessionRevoked) {
			t.Fatalf("unexpected concurrent sign-out error=%v", err)
		}
	}
	assertSessionRevoked(t, ctx, db, currentID, true)
}

func TestSessionSelfServiceAuditFailureRollsBackRevocation(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_session_self_service_audit"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	currentID := "ses_80000000-0000-4000-8000-000000000008"
	targetID := "ses_90000000-0000-4000-8000-000000000009"
	db := pool.OpenSQLDB()
	defer db.Close()
	for _, id := range []string{currentID, targetID} {
		if _, err := db.ExecContext(ctx, `INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at) VALUES($1,$2,$3,$4,$5)`, id, int64(app.InternalID), int64(user.InternalID), now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_session_self CHECK (action <> 'authentication.session.self_revoke')`); err != nil {
		t.Fatal(err)
	}
	correlation := mustCorrelation(t)
	current := session.Record{PublicID: currentID, ApplicationInstanceID: app.InternalID, UserInternalID: user.InternalID, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)}
	if err := New(pool).RevokeUserSession(ctx, current, targetID, correlation); !errors.Is(err, session.ErrSessionUnavailable) {
		t.Fatalf("audit failure error=%v", err)
	}
	assertSessionRevoked(t, ctx, db, targetID, false)
}

func assertSessionRevoked(t *testing.T, ctx context.Context, db *sql.DB, publicID string, want bool) {
	t.Helper()
	var revoked bool
	if err := db.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE public_id=$1`, publicID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != want {
		t.Fatalf("session %s revoked=%v want=%v", publicID, revoked, want)
	}
}
