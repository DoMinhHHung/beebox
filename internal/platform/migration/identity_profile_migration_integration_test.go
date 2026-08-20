//go:build integration

package migration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIdentityProfileMigrationUpgradesExactVersion22AndPreservesOwnership(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_identity_profile_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesThrough(t, 22)); err != nil {
		t.Fatalf("apply exact version 22 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 22)

	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO application_instances(public_id) VALUES ('app_123e4567-e89b-42d3-a456-426614175201');
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175202',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175201';
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175203',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175201';
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at,created_at)
		SELECT u.application_instance_id,u.id,'first@example.test','first@example.test',CURRENT_TIMESTAMP-INTERVAL '2 hours',CURRENT_TIMESTAMP-INTERVAL '3 hours' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175202';
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at,created_at)
		SELECT u.application_instance_id,u.id,'second@example.test','second@example.test',CURRENT_TIMESTAMP-INTERVAL '1 hour',CURRENT_TIMESTAMP-INTERVAL '2 hours' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175202';
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at,created_at,updated_at)
		SELECT u.application_instance_id,u.id,'+15550001001',CURRENT_TIMESTAMP-INTERVAL '1 hour',CURRENT_TIMESTAMP-INTERVAL '2 hours',CURRENT_TIMESTAMP-INTERVAL '1 hour' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175202';
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at,created_at,updated_at)
		SELECT u.application_instance_id,u.id,'+15550001001',NULL,CURRENT_TIMESTAMP-INTERVAL '30 minutes',CURRENT_TIMESTAMP-INTERVAL '30 minutes' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175203';
	`); err != nil {
		t.Fatalf("seed version 22 data: %v", err)
	}

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesRange(t, 23, 23)); err != nil {
		t.Fatalf("upgrade exact 22 -> 23: %v", err)
	}
	assertMigrationState(t, ctx, pool, 23)

	var total, distinct int
	if err := db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT public_id) FROM email_identifiers`).Scan(&total, &distinct); err != nil || total != 2 || distinct != 2 {
		t.Fatalf("email public IDs total=%d distinct=%d err=%v", total, distinct, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT public_id) FROM phone_identifiers`).Scan(&total, &distinct); err != nil || total != 2 || distinct != 2 {
		t.Fatalf("phone public IDs total=%d distinct=%d err=%v", total, distinct, err)
	}
	var invalidIDs int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers WHERE public_id !~ '^eml_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`).Scan(&invalidIDs); err != nil || invalidIDs != 0 {
		t.Fatalf("invalid email public IDs=%d err=%v", invalidIDs, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE public_id !~ '^phn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`).Scan(&invalidIDs); err != nil || invalidIDs != 0 {
		t.Fatalf("invalid phone public IDs=%d err=%v", invalidIDs, err)
	}

	var primaryEmail string
	if err := db.QueryRowContext(ctx, `SELECT email_address FROM email_identifiers e JOIN users u ON u.id=e.user_id AND u.application_instance_id=e.application_instance_id WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175202' AND e.is_primary`).Scan(&primaryEmail); err != nil || primaryEmail != "first@example.test" {
		t.Fatalf("deterministic primary email=%q err=%v", primaryEmail, err)
	}
	var primaryPhones int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers p JOIN users u ON u.id=p.user_id AND u.application_instance_id=p.application_instance_id WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175202' AND p.is_primary AND p.verified_at IS NOT NULL`).Scan(&primaryPhones); err != nil || primaryPhones != 1 {
		t.Fatalf("verified primary phones=%d err=%v", primaryPhones, err)
	}
	var badPrimary int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM email_identifiers WHERE is_primary AND verified_at IS NULL)+(SELECT count(*) FROM phone_identifiers WHERE is_primary AND verified_at IS NULL)`).Scan(&badPrimary); err != nil || badPrimary != 0 {
		t.Fatalf("unverified primary count=%d err=%v", badPrimary, err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175204',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175201';
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164)
		SELECT u.application_instance_id,u.id,'+15550001001' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175204';
	`); err != nil {
		t.Fatalf("cross-user unverified phone claim: %v", err)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164)
		SELECT u.application_instance_id,u.id,'+15550001001' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175204'`)
	assertUniqueViolation(t, err, "same-user phone duplicate")

	_, err = db.ExecContext(ctx, `UPDATE phone_identifiers p SET verified_at=CURRENT_TIMESTAMP FROM users u WHERE u.id=p.user_id AND u.application_instance_id=p.application_instance_id AND u.public_id='usr_123e4567-e89b-42d3-a456-426614175203' AND p.phone_e164='+15550001001'`)
	assertUniqueViolation(t, err, "second verified phone owner")
	var stillUnverified bool
	if err := db.QueryRowContext(ctx, `SELECT verified_at IS NULL FROM phone_identifiers p JOIN users u ON u.id=p.user_id AND u.application_instance_id=p.application_instance_id WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175203' AND p.phone_e164='+15550001001'`).Scan(&stillUnverified); err != nil || !stillUnverified {
		t.Fatalf("losing phone claim remains unverified=%v err=%v", stillUnverified, err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email)
		SELECT u.application_instance_id,u.id,'third@example.test','third@example.test' FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175203';
		UPDATE email_identifiers e SET verified_at=CURRENT_TIMESTAMP FROM users u WHERE u.id=e.user_id AND u.application_instance_id=e.application_instance_id AND u.public_id='usr_123e4567-e89b-42d3-a456-426614175203' AND e.normalized_email='third@example.test';
	`); err != nil {
		t.Fatalf("verify first email: %v", err)
	}
	var verifiedPrimary bool
	if err := db.QueryRowContext(ctx, `SELECT verified_at IS NOT NULL AND is_primary FROM email_identifiers e JOIN users u ON u.id=e.user_id AND u.application_instance_id=e.application_instance_id WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175203' AND e.normalized_email='third@example.test'`).Scan(&verifiedPrimary); err != nil || !verifiedPrimary {
		t.Fatalf("first verified email primary=%v err=%v", verifiedPrimary, err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE users SET display_name=$1 WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175202'`, strings.Repeat("x", 101)); err == nil {
		t.Fatal("101-character display name unexpectedly accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET locale=$1 WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175202'`, strings.Repeat("x", 36)); err == nil {
		t.Fatal("36-byte locale unexpectedly accepted")
	}

	var phoneID, appID int64
	if err := db.QueryRowContext(ctx, `SELECT p.id,p.application_instance_id FROM phone_identifiers p JOIN users u ON u.id=p.user_id AND u.application_instance_id=p.application_instance_id WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175203' LIMIT 1`).Scan(&phoneID, &appID); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO phone_identifier_verification_challenges(application_instance_id,phone_identifier_id,generation,code_hash,expires_at,failed_attempts,issue_count,issue_window_started_at,last_issued_at) VALUES($1,$2,1,'hash',CURRENT_TIMESTAMP+INTERVAL '10 minutes',6,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appID, phoneID)
	if err == nil {
		t.Fatal("phone verification challenge accepted failed_attempts=6")
	}

	for _, index := range []string{
		"email_identifiers_application_user_primary_key",
		"email_identifiers_application_user_created_public_idx",
		"phone_identifiers_verified_application_phone_key",
		"phone_identifiers_application_user_phone_key",
		"phone_identifiers_application_user_primary_key",
		"phone_identifiers_application_user_created_public_idx",
		"phone_identifier_verification_challenges_expiry_idx",
	} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1)`, index).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected index %q exists=%v err=%v", index, exists, err)
		}
	}
}

func assertUniqueViolation(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", label)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("%s error=%v, want PostgreSQL unique violation", label, err)
	}
}
