//go:build integration

package maintenance

import (
	"bytes"
	"testing"
	"time"
)

func TestCleanupSecurityStateBoundsPasskeyCeremonyRetention(t *testing.T) {
	pool, ctx := cleanupPool(t, "beebox_passkey_cleanup")
	db := pool.OpenSQLDB()
	defer db.Close()

	var appID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i, state := range []struct {
		expires  time.Time
		consumed *time.Time
	}{
		{expires: now.Add(-time.Minute)},
		{expires: now.Add(time.Minute), consumed: ptrTime(now)},
		{expires: now.Add(time.Minute)},
	} {
		hash := bytes.Repeat([]byte{byte(i + 1)}, 32)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO passkey_attempts(
				application_instance_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at,consumed_at
			) VALUES($1,'authentication','https://app.example','app.example','{}'::jsonb,$2,$3,$4,$5)`,
			appID, hash, now.Add(-2*time.Minute), state.expires, state.consumed); err != nil {
			t.Fatal(err)
		}
	}

	first, err := CleanupSecurityState(ctx, db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.PasskeyAttempts != 1 {
		t.Fatalf("first passkey cleanup=%d want 1", first.PasskeyAttempts)
	}
	second, err := CleanupSecurityState(ctx, db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.PasskeyAttempts != 1 {
		t.Fatalf("second passkey cleanup=%d want 1", second.PasskeyAttempts)
	}
	third, err := CleanupSecurityState(ctx, db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if third.PasskeyAttempts != 0 {
		t.Fatalf("third passkey cleanup=%d want 0", third.PasskeyAttempts)
	}

	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM passkey_attempts`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining passkey attempts=%d want live row only", remaining)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
