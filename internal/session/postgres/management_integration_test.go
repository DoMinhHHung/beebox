//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestSessionManagementIsApplicationScoped(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_session_management")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
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
	user, err := identitypostgres.New(pool).Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	publicID, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sessions (public_id, application_instance_id, user_id, idle_expires_at, expires_at)
		VALUES ($1,$2,$3,$4,$5)`, publicID, int64(appA.InternalID), int64(user.InternalID), now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := New(pool)
	if _, err := store.ResolveSession(ctx, appB.InternalID, publicID); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("cross-app ResolveSession error = %v", err)
	}
	if err := store.RevokeSession(ctx, appB.InternalID, publicID, mustCorrelation(t)); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("cross-app RevokeSession error = %v", err)
	}
	record, err := store.ResolveSession(ctx, appA.InternalID, publicID)
	if err != nil {
		t.Fatalf("ResolveSession(app A) error = %v", err)
	}
	if record.ApplicationInstanceID != appA.InternalID || record.UserPublicID != string(user.PublicID) {
		t.Fatalf("resolved wrong scope: %#v", record)
	}
	if err := store.RevokeSession(ctx, appA.InternalID, publicID, mustCorrelation(t)); err != nil {
		t.Fatalf("RevokeSession(app A) error = %v", err)
	}
	record, err = store.ResolveSession(ctx, appA.InternalID, publicID)
	if err != nil || record.RevokedAt == nil {
		t.Fatalf("revocation not persisted: record=%#v err=%v", record, err)
	}

	db = pool.OpenSQLDB()
	defer db.Close()
	var audits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action='authentication.session.revoke'`, int64(appA.InternalID)).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("revoke audit count = %d", audits)
	}
}
