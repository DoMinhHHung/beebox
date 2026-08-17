//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestSignInRateLimitIsApplicationScoped(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_session_signin_rate")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applications := applicationpostgres.New(pool)
	appA, err := applications.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := applications.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}

	fingerprint := sha256.Sum256([]byte("signin-email\x00user@example.test"))
	store := New(pool)
	for attempt := 1; attempt <= session.SignInIdentifierLimit; attempt++ {
		if err := store.AllowSignInAttempt(ctx, appA.InternalID, fingerprint); err != nil {
			t.Fatalf("AllowSignInAttempt(app A, %d) error = %v", attempt, err)
		}
	}
	if err := store.AllowSignInAttempt(ctx, appA.InternalID, fingerprint); !errors.Is(err, session.ErrSignInRateLimited) {
		t.Fatalf("AllowSignInAttempt(app A over limit) error = %v, want %v", err, session.ErrSignInRateLimited)
	}
	if err := store.AllowSignInAttempt(ctx, appB.InternalID, fingerprint); err != nil {
		t.Fatalf("AllowSignInAttempt(app B first attempt) error = %v", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var appACount, appBCount int
	if err := db.QueryRowContext(ctx, `
		SELECT request_count FROM public_auth_rate_limits
		WHERE application_instance_id=$1 AND operation='signin_identifier' AND subject_hash=$2`,
		int64(appA.InternalID), fingerprint[:],
	).Scan(&appACount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT request_count FROM public_auth_rate_limits
		WHERE application_instance_id=$1 AND operation='signin_identifier' AND subject_hash=$2`,
		int64(appB.InternalID), fingerprint[:],
	).Scan(&appBCount); err != nil {
		t.Fatal(err)
	}
	if appACount != session.SignInIdentifierLimit+1 || appBCount != 1 {
		t.Fatalf("rate counts app A/B = %d/%d", appACount, appBCount)
	}
}
