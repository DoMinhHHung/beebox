//go:build integration

package migration

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestSocialLinkMigrationRejectsConsumptionAfterExpiry(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_consumed_time")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
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
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID := insertMigrationSession(t, ctx, db, int64(app.InternalID), int64(user.InternalID))
	state := sha256.Sum256([]byte("consumed-after-expiry"))

	if _, err := db.ExecContext(ctx, `
		INSERT INTO social_link_attempts(
			application_instance_id,user_id,session_id,provider,canonical_redirect_url,
			state_hash,recent_auth_at,created_at,expires_at,consumed_at
		)
		VALUES(
			$1,$2,$3,'github','https://app.example/link',$4,
			CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP+INTERVAL '5 minutes',
			CURRENT_TIMESTAMP+INTERVAL '6 minutes'
		)`, int64(app.InternalID), int64(user.InternalID), sessionID, state[:]); err == nil {
		t.Fatal("consumed_at after expires_at was accepted")
	}
}
