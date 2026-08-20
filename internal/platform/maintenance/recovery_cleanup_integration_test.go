//go:build integration

package maintenance

import "testing"

func TestRecoveryAndSensitiveAdmissionCleanupIsBounded(t *testing.T) {
	pool, ctx := cleanupPool(t, "beebox_recovery_cleanup")
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO application_instances(public_id) VALUES('app_323e4567-e89b-42d3-a456-426614174901');
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_323e4567-e89b-42d3-a456-426614174902',id FROM application_instances WHERE public_id='app_323e4567-e89b-42d3-a456-426614174901';
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		SELECT 'ses_323e4567-e89b-42d3-a456-426614174903',application_instance_id,id,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users WHERE public_id='usr_323e4567-e89b-42d3-a456-426614174902';
		INSERT INTO totp_credentials(public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret)
		SELECT 'mfc_323e4567-e89b-42d3-a456-426614174904',application_instance_id,id,1,'cleanup-key',decode('000000000000000000000000','hex'),decode('0000000000000000000000000000000000','hex')
		FROM users WHERE public_id='usr_323e4567-e89b-42d3-a456-426614174902';
		INSERT INTO recovery_code_sets(public_id,application_instance_id,user_id,totp_credential_id,created_by_session_public_id,reason,created_at,invalidated_at)
		SELECT 'rcs_323e4567-e89b-42d3-a456-426614174905',t.application_instance_id,t.user_id,t.id,
		       'ses_323e4567-e89b-42d3-a456-426614174903','activation',CURRENT_TIMESTAMP-INTERVAL '2 hours',CURRENT_TIMESTAMP-INTERVAL '1 hour'
		FROM totp_credentials t WHERE t.public_id='mfc_323e4567-e89b-42d3-a456-426614174904';
		INSERT INTO sensitive_operation_admission(application_instance_id,user_id,session_public_id,operation,window_started_at,successful_count,expires_at)
		SELECT application_instance_id,id,'ses_323e4567-e89b-42d3-a456-426614174903','recovery_regeneration',
		       CURRENT_TIMESTAMP-INTERVAL '2 hours',3,CURRENT_TIMESTAMP-INTERVAL '1 hour'
		FROM users WHERE public_id='usr_323e4567-e89b-42d3-a456-426614174902'`); err != nil {
		t.Fatal(err)
	}
	result, err := CleanupSecurityState(ctx, db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.RecoveryCodeSets != 1 || result.SensitiveAdmission != 1 {
		t.Fatalf("cleanup result=%+v", result)
	}
	var sets, admission int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets`).Scan(&sets); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sensitive_operation_admission`).Scan(&admission); err != nil {
		t.Fatal(err)
	}
	if sets != 0 || admission != 0 {
		t.Fatalf("remaining sets=%d admission=%d", sets, admission)
	}
}
