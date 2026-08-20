//go:build integration

package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"io/fs"
	"regexp"
	"testing"
	"testing/fstest"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestSocialAccountManagementMigrationUpgradesVersion16(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_social_account_management_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		t.Fatal(err)
	}
	version16 := fstest.MapFS{}
	version17 := fstest.MapFS{}
	for _, entry := range entries {
		data, err := fs.ReadFile(sources, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name() != "00017_social_account_management.sql" && entry.Name() != "00018_passkeys.sql" && entry.Name() != "00019_totp_mfa.sql" && entry.Name() != "00020_recovery_codes.sql" && entry.Name() != "00021_reverification.sql" {
			version16[entry.Name()] = &fstest.MapFile{Data: data}
		}
		if entry.Name() != "00018_passkeys.sql" && entry.Name() != "00019_totp_mfa.sql" && entry.Name() != "00020_recovery_codes.sql" && entry.Name() != "00021_reverification.sql" {
			version17[entry.Name()] = &fstest.MapFile{Data: data}
		}
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), version16); err != nil {
		t.Fatal(err)
	}
	assertMigrationState(t, ctx, pool, 16)
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject) VALUES($1,$2,'github','existing')`, int64(app.InternalID), int64(user.InternalID)); err != nil {
		t.Fatal(err)
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), version17); err != nil {
		t.Fatalf("upgrade to 17: %v", err)
	}
	assertMigrationState(t, ctx, pool, 17)

	var publicID string
	if err := db.QueryRowContext(ctx, `SELECT public_id FROM external_identities WHERE provider_subject='existing'`).Scan(&publicID); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sli_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(publicID) {
		t.Fatalf("backfilled public_id=%q", publicID)
	}
	var futureID string
	if err := db.QueryRowContext(ctx, `INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject) VALUES($1,$2,'google','future') RETURNING public_id`, int64(app.InternalID), int64(user.InternalID)).Scan(&futureID); err != nil {
		t.Fatal(err)
	}
	if futureID == publicID || !regexp.MustCompile(`^sli_`).MatchString(futureID) {
		t.Fatalf("future public_id=%q existing=%q", futureID, publicID)
	}
	if _, err := db.ExecContext(ctx, `UPDATE external_identities SET public_id='sli_123e4567-e89b-12d3-a456-426614174000' WHERE provider_subject='future'`); err == nil {
		t.Fatal("non-v4 public ID accepted")
	}

	sessionID := insertMigrationSession(t, ctx, db, int64(app.InternalID), int64(user.InternalID))
	state := sha256.Sum256([]byte("cancel-constraint"))
	var attemptID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,created_at,expires_at) VALUES($1,$2,$3,'github','https://app.example/link',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes') RETURNING id`, int64(app.InternalID), int64(user.InternalID), sessionID, state[:]).Scan(&attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE social_link_attempts SET canceled_at=expires_at+INTERVAL '1 second' WHERE id=$1`, attemptID); err == nil {
		t.Fatal("canceled_at after expiry accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE social_link_attempts SET canceled_at=created_at WHERE id=$1`, attemptID); err != nil {
		t.Fatalf("valid cancellation rejected: %v", err)
	}

	var indexes int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname='external_identities_application_user_created_public_idx'`).Scan(&indexes); err != nil || indexes != 1 {
		t.Fatalf("listing index count=%d err=%v", indexes, err)
	}
}

var _ *sql.DB