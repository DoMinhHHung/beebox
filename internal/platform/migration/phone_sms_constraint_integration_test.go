//go:build integration

package migration

import (
	"context"
	"testing"
	"time"
)

func TestPhoneSMSMigrationRejectsUsableConsumedVerifierAndInvalidTimeOrdering(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_00014_state_constraints")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()

	var appID, userID, phoneID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, appID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at)
		VALUES($1,$2,'+84901234567',CURRENT_TIMESTAMP)
		RETURNING id`, appID, userID).Scan(&phoneID); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_signup_challenges(
			application_instance_id,phone_fingerprint,generation,code_hash,expires_at,
			failed_attempts,issue_count,issue_window_started_at,last_issued_at,consumed_at
		) VALUES(
			$1,decode(repeat('ab',32),'hex'),1,'still-usable',CURRENT_TIMESTAMP+INTERVAL '10 minutes',
			0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
		)`, appID); err == nil {
		t.Fatal("consumed phone signup challenge retained a usable verifier")
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_signup_challenges(
			application_instance_id,phone_fingerprint,generation,code_hash,expires_at,
			failed_attempts,issue_count,issue_window_started_at,last_issued_at
		) VALUES(
			$1,decode(repeat('ac',32),'hex'),1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',
			0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP-INTERVAL '1 minute'
		)`, appID); err == nil {
		t.Fatal("phone signup challenge accepted issue_window_started_at after last_issued_at")
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_otp_signin_challenges(
			application_instance_id,phone_identifier_id,generation,code_hash,expires_at,
			failed_attempts,issue_count,issue_window_started_at,last_issued_at,consumed_at
		) VALUES(
			$1,$2,1,'still-usable',CURRENT_TIMESTAMP+INTERVAL '10 minutes',
			0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
		)`, appID, phoneID); err == nil {
		t.Fatal("consumed phone sign-in challenge retained a usable verifier")
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO phone_otp_signin_challenges(
			application_instance_id,phone_identifier_id,generation,code_hash,expires_at,
			failed_attempts,issue_count,issue_window_started_at,last_issued_at
		) VALUES(
			$1,$2,1,'hash',CURRENT_TIMESTAMP-INTERVAL '1 minute',
			0,1,CURRENT_TIMESTAMP-INTERVAL '2 minutes',CURRENT_TIMESTAMP
		)`, appID, phoneID); err == nil {
		t.Fatal("phone sign-in challenge accepted last_issued_at at or after expires_at")
	}
}
