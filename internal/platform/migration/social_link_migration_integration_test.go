//go:build integration

package migration

import (
	"context"
	cryptosha256 "crypto/sha256"
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestSocialLinkMigrationUpgradesVersion15AndEnforcesBindings(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_migration")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		t.Fatal(err)
	}
	version15 := fstest.MapFS{}
	for _, entry := range entries {
		if entry.Name() == "00016_social_account_linking.sql" {
			continue
		}
		data, err := fs.ReadFile(sources, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		version15[entry.Name()] = &fstest.MapFile{Data: data}
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), version15); err != nil {
		t.Fatalf("apply version 15 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 15)
	db := pool.OpenSQLDB()
	defer db.Close()
	var before *string
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('social_link_attempts')::text`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != nil {
		t.Fatalf("version 15 unexpectedly contains social_link_attempts: %q", *before)
	}

	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("upgrade to version 16: %v", err)
	}
	assertMigrationState(t, ctx, pool, 16)

	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identities := identitypostgres.New(pool)
	userA, err := identities.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := identities.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	sessionA := insertMigrationSession(t, ctx, db, int64(appA.InternalID), int64(userA.InternalID))
	sessionB := insertMigrationSession(t, ctx, db, int64(appB.InternalID), int64(userB.InternalID))

	providers := []string{"google", "apple", "microsoft", "github", "gitlab", "facebook", "slack", "discord", "linkedin", "x", "tiktok"}
	for i, provider := range providers {
		state := cryptosha256.Sum256([]byte(provider))
		if _, err := db.ExecContext(ctx, `
            INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,created_at,expires_at)
            VALUES($1,$2,$3,$4,'https://app.example/link',$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`,
			int64(appA.InternalID), int64(userA.InternalID), sessionA, provider, state[:]); err != nil {
			t.Fatalf("provider[%d]=%s rejected: %v", i, provider, err)
		}
	}

	invalidState := cryptosha256.Sum256([]byte("provider-12"))
	if _, err := db.ExecContext(ctx, `
        INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,created_at,expires_at)
        VALUES($1,$2,$3,'custom','https://app.example/link',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`,
		int64(appA.InternalID), int64(userA.InternalID), sessionA, invalidState[:]); err == nil {
		t.Fatal("provider outside exact eleven-provider vocabulary was accepted")
	}

	shortState := make([]byte, 31)
	if _, err := db.ExecContext(ctx, `
        INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,created_at,expires_at)
        VALUES($1,$2,$3,'github','https://app.example/link',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`,
		int64(appA.InternalID), int64(userA.InternalID), sessionA, shortState); err == nil {
		t.Fatal("31-byte state hash was accepted")
	}

	crossState := cryptosha256.Sum256([]byte("cross-app-session"))
	if _, err := db.ExecContext(ctx, `
        INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,created_at,expires_at)
        VALUES($1,$2,$3,'github','https://app.example/link',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`,
		int64(appA.InternalID), int64(userA.InternalID), sessionB, crossState[:]); err == nil {
		t.Fatal("cross-application session binding was accepted")
	}

	lateState := cryptosha256.Sum256([]byte("late-expiry"))
	if _, err := db.ExecContext(ctx, `
        INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,created_at,expires_at)
        VALUES($1,$2,$3,'github','https://app.example/link',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '11 minutes')`,
		int64(appA.InternalID), int64(userA.InternalID), sessionA, lateState[:]); err == nil {
		t.Fatal("attempt expiry beyond ten-minute bound was accepted")
	}
}

func insertMigrationSession(t *testing.T, ctx context.Context, db *sql.DB, appID, userID int64) int64 {
	t.Helper()
	publicID, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.QueryRowContext(ctx, `
        INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
        VALUES($1,$2,$3,CURRENT_TIMESTAMP+INTERVAL '30 minutes',CURRENT_TIMESTAMP+INTERVAL '1 hour')
        RETURNING id`, publicID, appID, userID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
