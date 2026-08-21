//go:build integration

package migration

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestPasskeyMigrationIndexesScopeAndChallengeBoundary(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_passkey_security_schema"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()

	for _, index := range []string{
		"passkey_credentials_application_user_created_public_idx",
		"passkey_credentials_application_rp_credential_idx",
		"passkey_attempts_expiry_idx",
		"passkey_attempts_consumed_cleanup_idx",
		"passkey_attempts_application_user_purpose_idx",
	} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1`, index).Scan(&count); err != nil || count != 1 {
			t.Fatalf("index %q count=%d err=%v", index, count, err)
		}
	}

	var rawChallengeColumns int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='passkey_attempts' AND column_name IN ('challenge','raw_challenge')`).Scan(&rawChallengeColumns); err != nil {
		t.Fatal(err)
	}
	if rawChallengeColumns != 0 {
		t.Fatalf("raw challenge columns=%d want 0", rawChallengeColumns)
	}

	var appA, appB, userB int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, appB).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'app.example',$3,'{}'::jsonb)`, appA, userB, []byte("cross-app")); err == nil {
		t.Fatal("cross-application passkey owner accepted")
	}

	shortHash := bytes.Repeat([]byte{1}, 31)
	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_attempts(application_instance_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at) VALUES($1,'authentication','https://app.example','app.example','{}'::jsonb,$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 minute')`, appA, shortHash); err == nil {
		t.Fatal("31-byte challenge hash accepted")
	}
	validHash := bytes.Repeat([]byte{2}, 32)
	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_attempts(application_instance_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at) VALUES($1,'authentication','https://app.example','app.example','{}'::jsonb,$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '6 minutes')`, appA, validHash); err == nil {
		t.Fatal("ceremony expiry beyond five-minute bound accepted")
	}
}
