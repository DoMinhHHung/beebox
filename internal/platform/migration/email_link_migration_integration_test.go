//go:build integration

package migration

import (
	"context"
	"testing"
	"time"
)

func TestEmailLinkMigrationUpgradesExactVersion23AndEnforcesScope(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_email_link_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesThrough(t, 23)); err != nil {
		t.Fatalf("apply exact version 23 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 23)
	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesRange(t, 24, 24)); err != nil {
		t.Fatalf("upgrade exact 23 -> 24: %v", err)
	}
	assertMigrationState(t, ctx, pool, 24)

	db := pool.OpenSQLDB()
	defer db.Close()
	var appA, appB, userA, userB, emailA int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, appA).Scan(&userA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, appB).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'a@example.test','a@example.test',CURRENT_TIMESTAMP) RETURNING id`, appA, userA).Scan(&emailA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO email_signin_links(application_instance_id,email_identifier_id,public_id,secret_hash,completion_url,generation,expires_at,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,$2,'eln_123e4567-e89b-42d3-a456-426614175301',decode(repeat('ab',32),'hex'),'https://app.example/callback',1,CURRENT_TIMESTAMP+INTERVAL '10 minutes',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA, emailA); err != nil {
		t.Fatalf("valid email link row rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO email_signin_links(application_instance_id,email_identifier_id,public_id,secret_hash,completion_url,generation,expires_at,issue_count,issue_window_started_at,last_issued_at)
		VALUES($1,$2,'eln_223e4567-e89b-42d3-a456-426614175302',decode(repeat('ab',31),'hex'),'https://app.example/callback',1,CURRENT_TIMESTAMP+INTERVAL '10 minutes',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appA, emailA); err == nil {
		t.Fatal("31-byte email-link verifier unexpectedly accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_signin_links SET failed_attempts=6 WHERE application_instance_id=$1 AND email_identifier_id=$2`, appA, emailA); err == nil {
		t.Fatal("failed_attempts=6 unexpectedly accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_signin_links SET application_instance_id=$1 WHERE application_instance_id=$2 AND email_identifier_id=$3`, appB, appA, emailA); err == nil {
		t.Fatal("cross-application challenge ownership unexpectedly accepted")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO pending_mfa_authentications(public_id,token_hash,application_instance_id,user_id,primary_method,primary_context,required_factor,expires_at)
		VALUES('mfp_123e4567-e89b-42d3-a456-426614175303',decode(repeat('ef',32),'hex'),$1,$2,'email_link','eln_123e4567-e89b-42d3-a456-426614175301','totp',CURRENT_TIMESTAMP+INTERVAL '5 minutes')`, appA, userA); err != nil {
		t.Fatalf("email-link pending MFA method rejected after 23 -> 24 upgrade: %v", err)
	}

	operations := []string{
		"social_attempt_global", "social_attempt_application_provider", "social_exchange_global", "social_exchange_application",
		"social_link_attempt_global", "social_link_attempt_user_provider",
		"email_link_issue_global", "email_link_issue_identifier", "email_link_confirm_global", "email_link_confirm_identifier",
	}
	for i, operation := range operations {
		if _, err := db.ExecContext(ctx, `INSERT INTO public_auth_rate_limits(application_instance_id,operation,subject_hash,window_started_at,request_count,expires_at) VALUES($1,$2,digest($3,'sha256'),CURRENT_TIMESTAMP,1,CURRENT_TIMESTAMP+INTERVAL '1 minute')`, appA, operation, operation); err != nil {
			t.Fatalf("rate-limit operation[%d] %q rejected after 23 -> 24 upgrade: %v", i, operation, err)
		}
	}
}
