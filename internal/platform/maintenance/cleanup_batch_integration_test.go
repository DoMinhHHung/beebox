//go:build integration

package maintenance

import (
	"bytes"
	"context"
	"testing"
)

func TestCleanupSecurityStateRespectsBatchAndCancellation(t *testing.T) {
	pool, ctx := cleanupPool(t, "beebox_security_cleanup_batch")
	db := pool.OpenSQLDB()
	defer db.Close()
	var appID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 3; i++ {
		h := bytes.Repeat([]byte{i}, 32)
		if _, err := db.ExecContext(ctx, `INSERT INTO public_auth_rate_limits(application_instance_id,operation,subject_hash,window_started_at,request_count,expires_at) VALUES ($1,'signup_identifier',$2,CURRENT_TIMESTAMP-INTERVAL '2 hours',1,CURRENT_TIMESTAMP-INTERVAL '1 hour')`, appID, h); err != nil {
			t.Fatal(err)
		}
	}
	result, err := CleanupSecurityState(ctx, db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.RateLimits != 1 {
		t.Fatalf("deleted rate limits = %d, want 1", result.RateLimits)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public_auth_rate_limits`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining rate limits = %d, want 2", remaining)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := CleanupSecurityState(canceled, db, 1); err != context.Canceled {
		t.Fatalf("canceled cleanup error = %v", err)
	}
}
