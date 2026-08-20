//go:build integration

package migration

import (
	"context"
	"io/fs"
	"strconv"
	"testing"
	"testing/fstest"
	"time"
)

func TestReverificationMigrationUpgradesExactVersion20AndEnforcesScope(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_reverification_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	throughTwenty := migrationSourcesThrough(t, 20)
	if err := upWithSources(ctx, pool.OpenSQLDB(), throughTwenty); err != nil {
		t.Fatalf("apply exact version 20 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 20)

	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO application_instances(public_id) VALUES
			('app_123e4567-e89b-42d3-a456-426614175001'),
			('app_123e4567-e89b-42d3-a456-426614175002');
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175003',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175001';
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175004',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175001';
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175005',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175002';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_123e4567-e89b-42d3-a456-426614175006',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175003';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_123e4567-e89b-42d3-a456-426614175007',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175003';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_123e4567-e89b-42d3-a456-426614175008',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175004';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_123e4567-e89b-42d3-a456-426614175009',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175005'`); err != nil {
		t.Fatal(err)
	}

	onlyTwentyOne := migrationSourcesRange(t, 21, 21)
	if err := upWithSources(ctx, pool.OpenSQLDB(), onlyTwentyOne); err != nil {
		t.Fatalf("upgrade exact 20 -> 21: %v", err)
	}
	assertMigrationState(t, ctx, pool, 21)

	var tableName string
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('reverification_grants')::text`).Scan(&tableName); err != nil || tableName != "reverification_grants" {
		t.Fatalf("reverification table=%q err=%v", tableName, err)
	}
	var indexes int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM pg_indexes
		WHERE schemaname=current_schema()
		  AND indexname IN (
			'reverification_grants_target_session_idx',
			'reverification_grants_proof_session_idx',
			'reverification_grants_expiry_idx',
			'reverification_grants_cleanup_idx'
		  )`).Scan(&indexes); err != nil || indexes != 4 {
		t.Fatalf("reverification index count=%d err=%v", indexes, err)
	}

	var preserved any
	if err := db.QueryRowContext(ctx, `SELECT mfa_method FROM sessions WHERE public_id='ses_123e4567-e89b-42d3-a456-426614175006'`).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	if preserved != nil {
		t.Fatalf("pre-existing session mfa_method=%v, want NULL", preserved)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='totp' WHERE public_id='ses_123e4567-e89b-42d3-a456-426614175007'`); err != nil {
		t.Fatalf("valid totp provenance rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='recovery_code' WHERE public_id='ses_123e4567-e89b-42d3-a456-426614175006'`); err != nil {
		t.Fatalf("valid recovery provenance rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='sms' WHERE public_id='ses_123e4567-e89b-42d3-a456-426614175006'`); err == nil {
		t.Fatal("invalid MFA provenance accepted")
	}

	validInsert := `
		INSERT INTO reverification_grants(
			public_id,verifier_hash,application_instance_id,user_id,target_session_public_id,proof_session_public_id,purpose,created_at,expires_at
		)
		SELECT $1,$2,u.application_instance_id,u.id,$3,$4,$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes'
		FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175003'`
	if _, err := db.ExecContext(ctx, validInsert,
		"rvg_123e4567-e89b-42d3-a456-426614175010", make([]byte, 32),
		"ses_123e4567-e89b-42d3-a456-426614175006", "ses_123e4567-e89b-42d3-a456-426614175007", "passkey_register"); err != nil {
		t.Fatalf("valid reverification grant rejected: %v", err)
	}

	invalidCases := []struct {
		name     string
		publicID string
		hash     []byte
		target   string
		proof    string
		purpose  string
		expiry   string
	}{
		{name: "cross application target", publicID: "rvg_223e4567-e89b-42d3-a456-426614175011", hash: bytes32(1), target: "ses_123e4567-e89b-42d3-a456-426614175009", proof: "ses_123e4567-e89b-42d3-a456-426614175007", purpose: "passkey_remove", expiry: "5 minutes"},
		{name: "cross user proof", publicID: "rvg_323e4567-e89b-42d3-a456-426614175012", hash: bytes32(2), target: "ses_123e4567-e89b-42d3-a456-426614175006", proof: "ses_123e4567-e89b-42d3-a456-426614175008", purpose: "passkey_remove", expiry: "5 minutes"},
		{name: "short verifier", publicID: "rvg_423e4567-e89b-42d3-a456-426614175013", hash: []byte("short"), target: "ses_123e4567-e89b-42d3-a456-426614175006", proof: "ses_123e4567-e89b-42d3-a456-426614175007", purpose: "passkey_remove", expiry: "5 minutes"},
		{name: "invalid purpose", publicID: "rvg_523e4567-e89b-42d3-a456-426614175014", hash: bytes32(4), target: "ses_123e4567-e89b-42d3-a456-426614175006", proof: "ses_123e4567-e89b-42d3-a456-426614175007", purpose: "admin", expiry: "5 minutes"},
		{name: "expiry over ten minutes", publicID: "rvg_623e4567-e89b-42d3-a456-426614175015", hash: bytes32(5), target: "ses_123e4567-e89b-42d3-a456-426614175006", proof: "ses_123e4567-e89b-42d3-a456-426614175007", purpose: "passkey_remove", expiry: "11 minutes"},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.ExecContext(ctx, `
				INSERT INTO reverification_grants(
					public_id,verifier_hash,application_instance_id,user_id,target_session_public_id,proof_session_public_id,purpose,created_at,expires_at
				)
				SELECT $1,$2,u.application_instance_id,u.id,$3,$4,$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+($6::interval)
				FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175003'`,
				tc.publicID, tc.hash, tc.target, tc.proof, tc.purpose, tc.expiry)
			if err == nil {
				t.Fatal("invalid reverification grant committed")
			}
		})
	}
}

func migrationSourcesThrough(t *testing.T, maxVersion int) fstest.MapFS {
	t.Helper()
	return migrationSourcesRange(t, 1, maxVersion)
}

func migrationSourcesRange(t *testing.T, minVersion, maxVersion int) fstest.MapFS {
	t.Helper()
	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		t.Fatal(err)
	}
	selected := fstest.MapFS{}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 5 {
			continue
		}
		version, err := strconv.Atoi(name[:5])
		if err != nil || version < minVersion || version > maxVersion {
			continue
		}
		data, err := fs.ReadFile(sources, name)
		if err != nil {
			t.Fatal(err)
		}
		selected[name] = &fstest.MapFile{Data: data}
	}
	return selected
}

func bytes32(seed byte) []byte {
	value := make([]byte, 32)
	for i := range value {
		value[i] = seed
	}
	return value
}
