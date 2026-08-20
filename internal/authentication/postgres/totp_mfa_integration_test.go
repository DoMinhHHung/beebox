//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestPendingTOTPAuthenticationSameTokenConcurrentCompletionIsAtMostOnce(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-mfa-same-token")
	store := New(pool)
	app, user, pendingID, tokenHash := seedPendingTOTPAuthentication(t, ctx, pool, 100, 1)
	snapshot, err := store.LoadPendingTOTPAuthentication(ctx, pendingID, tokenHash)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			correlation, _ := audit.NewCorrelationID()
			refresh := sha256.Sum256([]byte{byte(index + 1)})
			_, err := store.FinalizePendingTOTPAuthentication(context.Background(), authentication.TOTPAuthenticationFinalize{
				PendingPublicID: pendingID,
				TokenHash:       tokenHash,
				Snapshot:        snapshot,
				Timestep:        101,
				SessionPublicID: []string{"ses_123e4567-e89b-42d3-a456-426614174101", "ses_123e4567-e89b-42d3-a456-426614174102"}[index],
				RefreshVerifier: refresh,
				IdleExpiresAt:   time.Now().UTC().Add(time.Hour),
				ExpiresAt:       time.Now().UTC().Add(2 * time.Hour),
				CorrelationID:   correlation,
			})
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authentication.ErrPendingMFAInvalid), errors.Is(err, authentication.ErrPendingMFAReplay), errors.Is(err, authentication.ErrTOTPReplay):
			rejected++
		default:
			t.Fatalf("unexpected completion error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("success=%d rejected=%d", succeeded, rejected)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2 AND public_id IN ('ses_123e4567-e89b-42d3-a456-426614174101','ses_123e4567-e89b-42d3-a456-426614174102')`, int64(app.InternalID), int64(user.InternalID)).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
}

func TestPendingTOTPAuthenticationSameTimestepAcrossTransactionsIsReplayRejected(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-mfa-same-step")
	store := New(pool)
	_, _, firstID, firstHash := seedPendingTOTPAuthentication(t, ctx, pool, 200, 1)
	first, err := store.LoadPendingTOTPAuthentication(ctx, firstID, firstHash)
	if err != nil {
		t.Fatal(err)
	}
	correlation, _ := audit.NewCorrelationID()
	refresh := sha256.Sum256([]byte("first"))
	if _, err := store.FinalizePendingTOTPAuthentication(ctx, authentication.TOTPAuthenticationFinalize{
		PendingPublicID: firstID, TokenHash: firstHash, Snapshot: first, Timestep: 201,
		SessionPublicID: "ses_123e4567-e89b-42d3-a456-426614174201", RefreshVerifier: refresh,
		IdleExpiresAt: time.Now().UTC().Add(time.Hour), ExpiresAt: time.Now().UTC().Add(2 * time.Hour), CorrelationID: correlation,
	}); err != nil {
		t.Fatal(err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	secondID := "mfp_123e4567-e89b-42d3-a456-426614174202"
	secondHash := sha256.Sum256([]byte("second-pending-token"))
	if _, err := db.ExecContext(ctx, `
		INSERT INTO pending_mfa_authentications(public_id,token_hash,application_instance_id,user_id,purpose,primary_method,primary_context,required_factor,created_at,expires_at)
		SELECT $1,$2,application_instance_id,user_id,'authentication','password','second-proof','totp',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + INTERVAL '4 minutes'
		FROM pending_mfa_authentications WHERE public_id=$3`, secondID, secondHash[:], firstID); err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadPendingTOTPAuthentication(ctx, secondID, secondHash)
	if err != nil {
		t.Fatal(err)
	}
	correlation2, _ := audit.NewCorrelationID()
	refresh2 := sha256.Sum256([]byte("second"))
	_, err = store.FinalizePendingTOTPAuthentication(ctx, authentication.TOTPAuthenticationFinalize{
		PendingPublicID: secondID, TokenHash: secondHash, Snapshot: second, Timestep: 201,
		SessionPublicID: "ses_123e4567-e89b-42d3-a456-426614174203", RefreshVerifier: refresh2,
		IdleExpiresAt: time.Now().UTC().Add(time.Hour), ExpiresAt: time.Now().UTC().Add(2 * time.Hour), CorrelationID: correlation2,
	})
	if !errors.Is(err, authentication.ErrTOTPReplay) {
		t.Fatalf("same timestep error=%v", err)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM pending_mfa_authentications WHERE public_id=$1`, secondID).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("replayed pending consumed=%v err=%v", consumed.Valid, err)
	}
}

func TestPendingTOTPAuthenticationAuditFailureRollsBackAllAuthorityState(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-mfa-audit-rollback")
	store := New(pool)
	app, user, pendingID, tokenHash := seedPendingTOTPAuthentication(t, ctx, pool, 300, 1)
	snapshot, err := store.LoadPendingTOTPAuthentication(ctx, pendingID, tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_totp_auth CHECK (source <> 'internal_totp')`); err != nil {
		t.Fatal(err)
	}
	correlation, _ := audit.NewCorrelationID()
	refresh := sha256.Sum256([]byte("rollback"))
	_, err = store.FinalizePendingTOTPAuthentication(ctx, authentication.TOTPAuthenticationFinalize{
		PendingPublicID: pendingID, TokenHash: tokenHash, Snapshot: snapshot, Timestep: 301,
		SessionPublicID: "ses_123e4567-e89b-42d3-a456-426614174301", RefreshVerifier: refresh,
		IdleExpiresAt: time.Now().UTC().Add(time.Hour), ExpiresAt: time.Now().UTC().Add(2 * time.Hour), CorrelationID: correlation,
	})
	if !errors.Is(err, authentication.ErrTOTPPersistence) {
		t.Fatalf("audit failure=%v", err)
	}

	var consumed sql.NullTime
	var last sql.NullInt64
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM pending_mfa_authentications WHERE public_id=$1`, pendingID).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("pending consumed=%v err=%v", consumed.Valid, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT last_accepted_timestep FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&last); err != nil || !last.Valid || last.Int64 != 300 {
		t.Fatalf("last timestep=%v err=%v", last, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id='ses_123e4567-e89b-42d3-a456-426614174301'`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
}

func seedPendingTOTPAuthentication(t *testing.T, ctx context.Context, pool interface{ OpenSQLDB() *sql.DB }, lastTimestep int64, suffix int) (appResult, userResult interface{}, pendingID string, tokenHash [32]byte) {
	t.Helper()
	panic("unreachable")
}
