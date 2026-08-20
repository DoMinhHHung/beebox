//go:build integration

package migration

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestPhoneSMSMigrationUpgradesExisting00013SchemaAndPreservesLimiterVocabulary(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_00014_upgrade")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatal(err)
	}
	throughThirteen := fstest.MapFS{}
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "00014_phone_sms.sql" || entry.Name() == "00015_social_oauth.sql" || entry.Name() == "00016_social_account_linking.sql" || entry.Name() == "00017_social_account_management.sql" || entry.Name() == "00018_passkeys.sql" || entry.Name() == "00019_totp_mfa.sql" || entry.Name() == "00020_recovery_codes.sql" || entry.Name() == "00021_reverification.sql" {
			continue
		}
		content, err := fs.ReadFile(sources, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		throughThirteen[entry.Name()] = &fstest.MapFile{Data: content}
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), throughThirteen); err != nil {
		t.Fatalf("migrate through 00013 error = %v", err)
	}
	assertMigrationState(t, ctx, pool, 13)
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("upgrade through current schema error = %v", err)
	}
	assertMigrationState(t, ctx, pool, 21)

	db := pool.OpenSQLDB()
	defer db.Close()
	for _, table := range []string{"phone_identifiers", "phone_signup_challenges", "phone_otp_signin_challenges"} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, table).Scan(&got); err != nil || got != table {
			t.Fatalf("table %q = %q err=%v", table, got, err)
		}
	}
	var appID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	operations := []string{
		"signup_global", "signup_identifier", "verification_issue_global", "verification_issue_identifier",
		"signin_global", "signin_identifier", "password_reset_global", "password_reset_identifier",
		"signup_pre_kdf_global", "signup_pre_kdf_identifier", "verification_confirm_global", "verification_confirm_identifier",
		"password_reset_issue_pre_kdf_global", "password_reset_issue_pre_kdf_identifier", "password_reset_confirm_global", "password_reset_confirm_identifier",
		"email_otp_issue_global", "email_otp_issue_identifier", "email_otp_confirm_global", "email_otp_confirm_identifier",
		"phone_signup_issue_global", "phone_signup_issue_identifier", "phone_signup_confirm_global", "phone_signup_confirm_identifier",
		"phone_otp_issue_global", "phone_otp_issue_identifier", "phone_otp_confirm_global", "phone_otp_confirm_identifier",
	}
	for _, operation := range operations {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO public_auth_rate_limits(application_instance_id,operation,subject_hash,window_started_at,request_count,expires_at)
			VALUES($1,$2,decode(repeat('ab',32),'hex'),CURRENT_TIMESTAMP,1,CURRENT_TIMESTAMP+INTERVAL '1 minute')`, appID, operation); err != nil {
			t.Fatalf("rate-limit operation %q rejected: %v", operation, err)
		}
	}
}

func TestPhoneSMSMigrationFreshSchemaOwnershipUniquenessAndChallengeConstraints(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_00014_constraints")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	assertMigrationState(t, ctx, pool, 21)
	db := pool.OpenSQLDB()
	defer db.Close()

	var appA, appB, userA1, userA2, userB, phoneA int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appB); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		app int64
		id  *int64
	}{{appA, &userA1}, {appA, &userA2}, {appB, &userB}} {
		if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, target.app).Scan(target.id); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at) VALUES($1,$2,'+84901234567',CURRENT_TIMESTAMP) RETURNING id`, appA, userA1).Scan(&phoneA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at) VALUES($1,$2,'+84901234567',CURRENT_TIMESTAMP)`, appA, userA2); err == nil {
		t.Fatal("same-app verified phone duplicate unexpectedly committed")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at) VALUES($1,$2,'+84901234567',CURRENT_TIMESTAMP)`, appB, userB); err != nil {
		t.Fatalf("cross-app same verified phone rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164) VALUES($1,$2,'0901234567')`, appA, userA2); err == nil {
		t.Fatal("non-E.164 phone unexpectedly committed")
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_signup_challenges(application_instance_id,phone_fingerprint,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,decode(repeat('ab',31),'hex'),1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA); err == nil {
		t.Fatal("31-byte signup fingerprint unexpectedly committed")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_signup_challenges(application_instance_id,phone_fingerprint,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,decode(repeat('ab',32),'hex'),0,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA); err == nil {
		t.Fatal("signup generation=0 unexpectedly committed")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_signup_challenges(application_instance_id,phone_fingerprint,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,decode(repeat('ac',32),'hex'),1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',6,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA); err == nil {
		t.Fatal("signup failed_attempts=6 unexpectedly committed")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_signup_challenges(application_instance_id,phone_fingerprint,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,decode(repeat('ad',32),'hex'),1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',0,4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA); err == nil {
		t.Fatal("signup issue_count=4 unexpectedly committed")
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_otp_signin_challenges(application_instance_id,phone_identifier_id,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,$2,1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appB, phoneA); err == nil {
		t.Fatal("cross-app phone challenge FK unexpectedly committed")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_otp_signin_challenges(application_instance_id,phone_identifier_id,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,$2,1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',6,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA, phoneA); err == nil {
		t.Fatal("signin failed_attempts=6 unexpectedly committed")
	}
}