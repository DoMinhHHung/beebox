//go:build integration

package migration

import (
	"context"
	"crypto/sha256"
	"regexp"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestPasskeyMigrationUpgradesVersion17(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_passkey_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesThrough(t, 17)); err != nil {
		t.Fatal(err)
	}
	assertMigrationState(t, ctx, pool, 17)
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("upgrade through current schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 26)

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
	var sessionPublicID string
	if err := db.QueryRowContext(ctx, `SELECT public_id FROM sessions WHERE id=$1`, sessionID).Scan(&sessionPublicID); err != nil {
		t.Fatal(err)
	}

	credentialID := []byte("credential-id")
	var passkeyID string
	if err := db.QueryRowContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json,name) VALUES($1,$2,'app.example',$3,'{"id":"credential-id"}'::jsonb,'Laptop') RETURNING public_id`, int64(app.InternalID), int64(user.InternalID), credentialID).Scan(&passkeyID); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^pky_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(passkeyID) {
		t.Fatalf("passkey public id=%q", passkeyID)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'app.example',$3,'{}'::jsonb)`, int64(app.InternalID), int64(user.InternalID), credentialID); err == nil {
		t.Fatal("duplicate application credential id accepted")
	}

	challenge := sha256.Sum256([]byte("passkey-migration-challenge"))
	var attemptID string
	if err := db.QueryRowContext(ctx, `INSERT INTO passkey_attempts(application_instance_id,user_id,session_public_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at) VALUES($1,$2,$3,'registration','https://app.example','app.example','{"challenge":"test"}'::jsonb,$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes') RETURNING public_id`, int64(app.InternalID), int64(user.InternalID), sessionPublicID, challenge[:]).Scan(&attemptID); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^pka_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(attemptID) {
		t.Fatalf("attempt public id=%q", attemptID)
	}
	if _, err := db.ExecContext(ctx, `UPDATE passkey_attempts SET consumed_at=expires_at+INTERVAL '1 second' WHERE public_id=$1`, attemptID); err == nil {
		t.Fatal("consumption after expiry accepted")
	}
	badBinding := sha256.Sum256([]byte("bad-binding"))
	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_attempts(application_instance_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at) VALUES($1,'registration','https://app.example','app.example','{}'::jsonb,$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 minute')`, int64(app.InternalID), badBinding[:]); err == nil {
		t.Fatal("registration attempt without user/session accepted")
	}
}
