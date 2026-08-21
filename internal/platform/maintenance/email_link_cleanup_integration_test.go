//go:build integration

package maintenance

import (
	"context"
	"testing"
)

func TestEmailLinkCleanupIsBoundedAndNeverDeletesActiveProof(t *testing.T) {
	pool, ctx := cleanupPool(t, "beebox_email_link_cleanup")
	db := pool.OpenSQLDB()
	defer db.Close()
	var appID, userID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, appID).Scan(&userID); err != nil {
		t.Fatal(err)
	}

	for i, email := range []string{"one@example.test", "two@example.test", "active@example.test"} {
		var emailID int64
		if err := db.QueryRowContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,$3,$3,CURRENT_TIMESTAMP) RETURNING id`, appID, userID, email).Scan(&emailID); err != nil {
			t.Fatal(err)
		}
		challenge := []string{
			"eln_123e4567-e89b-42d3-a456-426614176301",
			"eln_123e4567-e89b-42d3-a456-426614176302",
			"eln_123e4567-e89b-42d3-a456-426614176303",
		}[i]
		if i < 2 {
			if _, err := db.ExecContext(ctx, `
				INSERT INTO email_signin_links(application_instance_id,email_identifier_id,public_id,secret_hash,completion_url,generation,expires_at,issue_count,issue_window_started_at,last_issued_at,created_at,updated_at)
				VALUES($1,$2,$3,decode(repeat('ab',32),'hex'),'https://app.example/complete',1,CURRENT_TIMESTAMP-INTERVAL '30 minutes',1,CURRENT_TIMESTAMP-INTERVAL '2 hours',CURRENT_TIMESTAMP-INTERVAL '1 hour',CURRENT_TIMESTAMP-INTERVAL '2 hours',CURRENT_TIMESTAMP-INTERVAL '2 hours')`, appID, emailID, challenge); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := db.ExecContext(ctx, `
				INSERT INTO email_signin_links(application_instance_id,email_identifier_id,public_id,secret_hash,completion_url,generation,expires_at,issue_count,issue_window_started_at,last_issued_at)
				VALUES($1,$2,$3,decode(repeat('cd',32),'hex'),'https://app.example/complete',1,CURRENT_TIMESTAMP+INTERVAL '10 minutes',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, appID, emailID, challenge); err != nil {
				t.Fatal(err)
			}
		}
	}

	result, err := CleanupSecurityState(ctx, db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.EmailLinkChallenges != 1 {
		t.Fatalf("deleted email links=%d want 1", result.EmailLinkChallenges)
	}
	var remaining, active int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_signin_links`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_signin_links WHERE expires_at>CURRENT_TIMESTAMP AND consumed_at IS NULL`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 || active != 1 {
		t.Fatalf("remaining=%d active=%d want 2/1", remaining, active)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CleanupSecurityState(canceled, db, 1); err != context.Canceled {
		t.Fatalf("canceled cleanup error=%v", err)
	}
}
