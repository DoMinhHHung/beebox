//go:build integration

package maintenance

import (
	"crypto/sha256"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestCleanupSecurityStateRemovesConsumedAndExpiredSocialLinkAttempts(t *testing.T) {
	pool, ctx := cleanupPool(t, "beebox_cleanup_social_links")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	publicID, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	var sessionID int64
	if err := db.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,CURRENT_TIMESTAMP+INTERVAL '30 minutes',CURRENT_TIMESTAMP+INTERVAL '1 hour')
		RETURNING id`, publicID, int64(app.InternalID), int64(user.InternalID)).Scan(&sessionID); err != nil {
		t.Fatal(err)
	}

	insert := func(label string, createdAgo, expiresAgo time.Duration, consumed bool) {
		t.Helper()
		state := sha256.Sum256([]byte(label))
		consumedExpr := "NULL"
		if consumed {
			consumedExpr = "CURRENT_TIMESTAMP"
		}
		_, err := db.ExecContext(ctx, `
			INSERT INTO social_link_attempts(
				application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,
				recent_auth_at,created_at,expires_at,consumed_at
			)
			VALUES($1,$2,$3,'github','https://app.example/link',$4,
				CURRENT_TIMESTAMP-$5*INTERVAL '1 second',
				CURRENT_TIMESTAMP-$5*INTERVAL '1 second',
				CURRENT_TIMESTAMP-$6*INTERVAL '1 second',`+consumedExpr+`)`,
			int64(app.InternalID), int64(user.InternalID), sessionID, state[:], createdAgo.Seconds(), expiresAgo.Seconds())
		if err != nil {
			t.Fatal(err)
		}
	}

	insert("expired", 9*time.Minute, time.Minute, false)
	insert("consumed", 2*time.Minute, -5*time.Minute, true)
	insert("active", 2*time.Minute, -5*time.Minute, false)

	result, err := CleanupSecurityState(ctx, db, DefaultBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	if result.SocialLinkAttempts != 2 {
		t.Fatalf("SocialLinkAttempts = %d, want 2", result.SocialLinkAttempts)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_link_attempts`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining social link attempts = %d, want 1", remaining)
	}
}
