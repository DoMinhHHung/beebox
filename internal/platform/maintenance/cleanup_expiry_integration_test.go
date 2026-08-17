//go:build integration

package maintenance

import (
	"bytes"
	"testing"
	"time"
)

func TestCleanupSecurityStateRemovesExpiredOperationalRowsAndKeepsLive(t *testing.T) {
	pool, ctx := cleanupPool(t, "beebox_security_cleanup")
	db := pool.OpenSQLDB()
	defer db.Close()
	var appID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)
	hashA := bytes.Repeat([]byte{1}, 32)
	hashB := bytes.Repeat([]byte{2}, 32)
	if _, err := db.ExecContext(ctx, `INSERT INTO public_auth_rate_limits(application_instance_id,operation,subject_hash,window_started_at,request_count,expires_at) VALUES ($1,'signup_global',$2,$3,1,$4),($1,'signup_identifier',$5,$3,1,$6)`, appID, hashA, expired.Add(-time.Minute), expired, hashB, future); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO public_auth_idempotency(application_instance_id,operation,key_hash,request_fingerprint,result_status,created_at,expires_at) VALUES ($1,'signup',$2,$3,'verification_pending',$4,$5),($1,'signup',$6,$7,'verification_pending',$4,$8)`, appID, hashA, hashB, expired.Add(-time.Hour), expired, hashB, hashA, future); err != nil {
		t.Fatal(err)
	}
	result, err := CleanupSecurityState(ctx, db, 100)
	if err != nil {
		t.Fatalf("CleanupSecurityState() error = %v", err)
	}
	if result.RateLimits != 1 || result.Idempotency != 1 {
		t.Fatalf("cleanup result = %+v, want one expired limiter and idempotency row", result)
	}
	for _, table := range []string{"public_auth_rate_limits", "public_auth_idempotency"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s rows = %d, want one live row", table, count)
		}
	}
	second, err := CleanupSecurityState(ctx, db, 100)
	if err != nil {
		t.Fatal(err)
	}
	if second != (Result{}) {
		t.Fatalf("second cleanup = %+v, want zero result", second)
	}
}
