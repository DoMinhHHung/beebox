//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
	"github.com/jackc/pgx/v5"
)

func TestSignInRefreshRotationAndReplayRevokesSession(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_session_refresh")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(application) error = %v", err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user) error = %v", err)
	}
	passwordHash, err := authentication.HashPassword([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO email_identifiers (application_instance_id, user_id, email_address, normalized_email, verified_at)
		VALUES ($1,$2,'user@example.test','user@example.test',CURRENT_TIMESTAMP)`, int64(app.InternalID), int64(user.InternalID)); err != nil {
		db.Close()
		t.Fatalf("insert verified email error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO password_credentials (application_instance_id, user_id, password_hash)
		VALUES ($1,$2,$3)`, int64(app.InternalID), int64(user.InternalID), passwordHash.StorageEncoding()); err != nil {
		db.Close()
		t.Fatalf("insert password error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := session.NewKeyRing(
		"https://auth.example.test",
		"active",
		privateKey,
		map[string]ed25519.PublicKey{"active": publicKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	service := session.NewService(store, store, ring)

	pair, err := service.SignIn(ctx, app.InternalID, "USER@example.test", "correct horse battery staple", mustCorrelation(t))
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}
	if !session.ValidPublicID(pair.SessionID) || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("invalid token pair = %#v", pair)
	}
	if _, err := ring.Verify(pair.AccessToken, string(app.PublicID), time.Now().UTC()); err != nil {
		t.Fatalf("Verify(access) error = %v", err)
	}

	rotated, err := service.Refresh(ctx, app.InternalID, pair.RefreshToken, mustCorrelation(t))
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if rotated.RefreshToken == pair.RefreshToken || rotated.SessionID != pair.SessionID {
		t.Fatal("refresh did not rotate credential while preserving session")
	}
	if _, err := service.Refresh(ctx, app.InternalID, pair.RefreshToken, mustCorrelation(t)); !errors.Is(err, session.ErrRefreshReused) {
		t.Fatalf("reused refresh error = %v, want %v", err, session.ErrRefreshReused)
	}
	if _, err := service.Refresh(ctx, app.InternalID, rotated.RefreshToken, mustCorrelation(t)); !errors.Is(err, session.ErrRefreshInvalid) {
		t.Fatalf("refresh after replay revocation error = %v, want invalid refresh", err)
	}

	db = pool.OpenSQLDB()
	defer db.Close()
	var sessionCount, refreshCount, consumedCount int
	var revokedAt *time.Time
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*), count(*) FILTER (WHERE consumed_at IS NOT NULL)
		FROM session_refresh_credentials r JOIN sessions s ON s.id=r.session_id
		WHERE s.application_instance_id=$1`, int64(app.InternalID)).Scan(&refreshCount, &consumedCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT revoked_at FROM sessions WHERE public_id=$1`, pair.SessionID).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 || refreshCount != 2 || consumedCount != 1 || revokedAt == nil {
		t.Fatalf("session/refresh/consumed/revoked = %d/%d/%d/%v", sessionCount, refreshCount, consumedCount, revokedAt)
	}
}

func mustCorrelation(t *testing.T) [16]byte {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return value
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
