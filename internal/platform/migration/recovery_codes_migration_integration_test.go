//go:build integration

package migration

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestRecoveryCodesUpgradeFromExactP2PointSixPredecessor(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "recovery_codes_predecessor_upgrade")
	pool := openPool(t, databaseURL)
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
	predecessor := fstest.MapFS{}
	for _, entry := range entries {
		if entry.Name() == "00020_recovery_codes.sql" || entry.Name() == "00021_reverification.sql" {
			continue
		}
		data, err := fs.ReadFile(sources, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		predecessor[entry.Name()] = &fstest.MapFile{Data: data}
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), predecessor); err != nil {
		t.Fatal(err)
	}
	assertMigrationState(t, ctx, pool, 19)
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO application_instances(public_id) VALUES('app_123e4567-e89b-42d3-a456-426614174901');
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614174902',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614174901';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_123e4567-e89b-42d3-a456-426614174903',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614174902';
		INSERT INTO totp_credentials(public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret)
		SELECT 'mfc_123e4567-e89b-42d3-a456-426614174904',application_instance_id,id,1,'upgrade-key',decode('000000000000000000000000','hex'),decode('0000000000000000000000000000000000','hex')
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614174902';
		INSERT INTO totp_enrollments(public_id,credential_public_id,application_instance_id,user_id,session_public_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,expires_at)
		SELECT 'mfe_123e4567-e89b-42d3-a456-426614174905','mfc_123e4567-e89b-42d3-a456-426614174906',application_instance_id,id,
		       'ses_123e4567-e89b-42d3-a456-426614174903',1,'upgrade-key',decode('000000000000000000000000','hex'),decode('0000000000000000000000000000000000','hex'),CURRENT_TIMESTAMP+INTERVAL '5 minutes'
		FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614174902'`); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	assertMigrationState(t, ctx, pool, 21)
	var setsTable, codesTable, admissionTable *string
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('recovery_code_sets')::text,to_regclass('recovery_codes')::text,to_regclass('sensitive_operation_admission')::text`).Scan(&setsTable, &codesTable, &admissionTable); err != nil {
		t.Fatal(err)
	}
	if setsTable == nil || codesTable == nil || admissionTable == nil {
		t.Fatalf("tables sets=%v codes=%v admission=%v", setsTable, codesTable, admissionTable)
	}
	var activePurpose string
	if err := db.QueryRowContext(ctx, `SELECT purpose FROM totp_enrollments WHERE public_id='mfe_123e4567-e89b-42d3-a456-426614174905'`).Scan(&activePurpose); err != nil || activePurpose != "activation" {
		t.Fatalf("existing enrollment purpose=%q err=%v", activePurpose, err)
	}
}

func TestRecoveryCodeSchemaRejectsMalformedVerifierAndSecondActiveSet(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "recovery_codes_constraints")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO application_instances(public_id) VALUES('app_223e4567-e89b-42d3-a456-426614174901');
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_223e4567-e89b-42d3-a456-426614174902',id FROM application_instances WHERE public_id='app_223e4567-e89b-42d3-a456-426614174901';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_223e4567-e89b-42d3-a456-426614174903',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_223e4567-e89b-42d3-a456-426614174902';
		INSERT INTO totp_credentials(public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret)
		SELECT 'mfc_223e4567-e89b-42d3-a456-426614174904',application_instance_id,id,1,'constraint-key',decode('000000000000000000000000','hex'),decode('0000000000000000000000000000000000','hex')
		FROM users WHERE public_id='usr_223e4567-e89b-42d3-a456-426614174902'`); err != nil {
		t.Fatal(err)
	}
	insertSet := `INSERT INTO recovery_code_sets(public_id,application_instance_id,user_id,totp_credential_id,created_by_session_public_id,reason)
		SELECT $1,t.application_instance_id,t.user_id,t.id,'ses_223e4567-e89b-42d3-a456-426614174903','activation'
		FROM totp_credentials t WHERE t.public_id='mfc_223e4567-e89b-42d3-a456-426614174904' RETURNING id`
	var setID int64
	if err := db.QueryRowContext(ctx, insertSet, "rcs_223e4567-e89b-42d3-a456-426614174905").Scan(&setID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, insertSet, "rcs_223e4567-e89b-42d3-a456-426614174906").Scan(new(int64)); err == nil {
		t.Fatal("second active recovery set accepted")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO recovery_codes(recovery_set_id,code_hash) VALUES($1,$2)`, setID, []byte("short")); err == nil {
		t.Fatal("malformed recovery verifier accepted")
	}
}
