//go:build integration

package migration

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestEmailOTPMigrationUpgradesExisting00012Schema(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_00013_upgrade")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatal(err)
	}
	throughTwelve := fstest.MapFS{}
	throughThirteen := fstest.MapFS{}
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		content, err := fs.ReadFile(sources, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name() != "00014_phone_sms.sql" && entry.Name() != "00015_social_oauth.sql" && entry.Name() != "00016_social_account_linking.sql" && entry.Name() != "00017_social_account_management.sql" && entry.Name() != "00018_passkeys.sql" && entry.Name() != "00019_totp_mfa.sql" && entry.Name() != "00020_recovery_codes.sql" {
			throughThirteen[entry.Name()] = &fstest.MapFile{Data: content}
		}
		if entry.Name() != "00013_email_otp_signin.sql" && entry.Name() != "00014_phone_sms.sql" && entry.Name() != "00015_social_oauth.sql" && entry.Name() != "00016_social_account_linking.sql" && entry.Name() != "00017_social_account_management.sql" && entry.Name() != "00018_passkeys.sql" && entry.Name() != "00019_totp_mfa.sql" && entry.Name() != "00020_recovery_codes.sql" {
			throughTwelve[entry.Name()] = &fstest.MapFile{Data: content}
		}
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), throughTwelve); err != nil {
		t.Fatalf("migrate through 00012 error = %v", err)
	}
	assertMigrationState(t, ctx, pool, 12)
	if err := upWithSources(ctx, pool.OpenSQLDB(), throughThirteen); err != nil {
		t.Fatalf("upgrade to 00013 error = %v", err)
	}
	assertMigrationState(t, ctx, pool, 13)

	db := pool.OpenSQLDB()
	defer db.Close()
	var tableName string
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('email_otp_signin_challenges')::text`).Scan(&tableName); err != nil {
		t.Fatalf("query OTP table error = %v", err)
	}
	if tableName != "email_otp_signin_challenges" {
		t.Fatalf("OTP table = %q", tableName)
	}
	for _, operation := range []string{
		"signup_global", "signup_identifier", "verification_issue_global", "verification_issue_identifier",
		"signin_global", "signin_identifier", "password_reset_global", "password_reset_identifier",
		"signup_pre_kdf_global", "signup_pre_kdf_identifier", "verification_confirm_global", "verification_confirm_identifier",
		"password_reset_issue_pre_kdf_global", "password_reset_issue_pre_kdf_identifier", "password_reset_confirm_global", "password_reset_confirm_identifier",
		"email_otp_issue_global", "email_otp_issue_identifier", "email_otp_confirm_global", "email_otp_confirm_identifier",
	} {
		var accepted bool
		err := db.QueryRowContext(ctx, `
			WITH app AS (INSERT INTO application_instances DEFAULT VALUES RETURNING id)
			INSERT INTO public_auth_rate_limits(application_instance_id,operation,subject_hash,window_started_at,request_count,expires_at)
			SELECT id,$1,decode(repeat('ab',32),'hex'),CURRENT_TIMESTAMP,1,CURRENT_TIMESTAMP+INTERVAL '1 minute' FROM app
			RETURNING true`, operation).Scan(&accepted)
		if err != nil || !accepted {
			t.Fatalf("rate-limit operation %q rejected: %v", operation, err)
		}
	}
}

func TestEmailOTPMigrationChallengeConstraintsRejectInvalidState(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_00013_constraints")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	var appID, userID, emailID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO users(public_id,application_instance_id) VALUES('usr_12345678-1234-4123-8123-123456789abc',$1) RETURNING id`, appID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'otp@example.test','otp@example.test',CURRENT_TIMESTAMP) RETURNING id`, appID, userID).Scan(&emailID); err != nil {
		t.Fatal(err)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO email_otp_signin_challenges(application_instance_id,email_identifier_id,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at) VALUES($1,$2,0,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appID, emailID)
	if err == nil {
		t.Fatal("generation=0 unexpectedly satisfied challenge constraint")
	}
	_, err = db.ExecContext(ctx, `INSERT INTO email_otp_signin_challenges(application_instance_id,email_identifier_id,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at) VALUES($1,$2,1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',6,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appID, emailID)
	if err == nil {
		t.Fatal("failed_attempts=6 unexpectedly satisfied challenge constraint")
	}
}
