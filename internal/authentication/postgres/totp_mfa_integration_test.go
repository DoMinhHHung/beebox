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

func TestPendingTOTPAuthenticationConcurrentSameTimestepIsAtMostOnce(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-mfa-concurrent-step")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 100)
	firstID, firstHash := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174101", "first-token", "first-proof")
	secondID, secondHash := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174102", "second-token", "second-proof")

	store := New(pool)
	first, err := store.LoadPendingTOTPAuthentication(ctx, firstID, firstHash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadPendingTOTPAuthentication(ctx, secondID, secondHash)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	finals := []authentication.TOTPAuthenticationFinalize{
		newTOTPFinalize(t, firstID, firstHash, first, 101, "ses_123e4567-e89b-42d3-a456-426614174111", "refresh-one"),
		newTOTPFinalize(t, secondID, secondHash, second, 101, "ses_123e4567-e89b-42d3-a456-426614174112", "refresh-two"),
	}
	for _, final := range finals {
		final := final
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.FinalizePendingTOTPAuthentication(context.Background(), final)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, replayed int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authentication.ErrTOTPReplay):
			replayed++
		default:
			t.Fatalf("unexpected completion error: %v", err)
		}
	}
	if succeeded != 1 || replayed != 1 {
		t.Fatalf("success=%d replayed=%d", succeeded, replayed)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2 AND public_id IN ('ses_123e4567-e89b-42d3-a456-426614174111','ses_123e4567-e89b-42d3-a456-426614174112')`, int64(app.InternalID), int64(user.InternalID)).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
	var last int64
	if err := db.QueryRowContext(ctx, `SELECT last_accepted_timestep FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&last); err != nil || last != 101 {
		t.Fatalf("last timestep=%d err=%v", last, err)
	}
}

func TestPendingTOTPAuthenticationSameTokenReplayFails(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-mfa-token-replay")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 200)
	pendingID, tokenHash := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174201", "replay-token", "password-proof")
	store := New(pool)
	snapshot, err := store.LoadPendingTOTPAuthentication(ctx, pendingID, tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	first := newTOTPFinalize(t, pendingID, tokenHash, snapshot, 201, "ses_123e4567-e89b-42d3-a456-426614174211", "refresh-first")
	if _, err := store.FinalizePendingTOTPAuthentication(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := newTOTPFinalize(t, pendingID, tokenHash, snapshot, 202, "ses_123e4567-e89b-42d3-a456-426614174212", "refresh-second")
	if _, err := store.FinalizePendingTOTPAuthentication(ctx, second); !errors.Is(err, authentication.ErrPendingMFAInvalid) && !errors.Is(err, authentication.ErrPendingMFAReplay) {
		t.Fatalf("replayed pending token error=%v", err)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
}

func TestPendingTOTPAuthenticationAuditFailureRollsBackAuthorityState(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-mfa-audit-rollback")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 300)
	pendingID, tokenHash := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174301", "rollback-token", "password-proof")
	store := New(pool)
	snapshot, err := store.LoadPendingTOTPAuthentication(ctx, pendingID, tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_totp_auth CHECK (source <> 'internal_totp')`); err != nil {
		t.Fatal(err)
	}
	final := newTOTPFinalize(t, pendingID, tokenHash, snapshot, 301, "ses_123e4567-e89b-42d3-a456-426614174311", "refresh-rollback")
	if _, err := store.FinalizePendingTOTPAuthentication(ctx, final); !errors.Is(err, authentication.ErrTOTPPersistence) {
		t.Fatalf("audit failure=%v", err)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM pending_mfa_authentications WHERE public_id=$1`, pendingID).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("pending consumed=%v err=%v", consumed.Valid, err)
	}
	var last int64
	if err := db.QueryRowContext(ctx, `SELECT last_accepted_timestep FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&last); err != nil || last != 300 {
		t.Fatalf("last timestep=%d err=%v", last, err)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id='ses_123e4567-e89b-42d3-a456-426614174311'`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
}

func seedTOTPCredential(t *testing.T, ctx context.Context, db *sql.DB, appID, userID, lastTimestep int64) {
	t.Helper()
	nonce := []byte("123456789012")
	ciphertext := []byte("12345678901234567")
	if _, err := db.ExecContext(ctx, `INSERT INTO totp_credentials(public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,last_accepted_timestep) VALUES('mfc_123e4567-e89b-42d3-a456-426614174400',$1,$2,1,'test-key',$3,$4,$5)`, appID, userID, nonce, ciphertext, lastTimestep); err != nil {
		t.Fatal(err)
	}
}

func seedPendingMFA(t *testing.T, ctx context.Context, db *sql.DB, appID, userID int64, publicID, token, proof string) (string, [32]byte) {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := db.ExecContext(ctx, `INSERT INTO pending_mfa_authentications(public_id,token_hash,application_instance_id,user_id,purpose,primary_method,primary_context,required_factor,created_at,expires_at) VALUES($1,$2,$3,$4,'authentication','password',$5,'totp',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + INTERVAL '4 minutes')`, publicID, tokenHash[:], appID, userID, proof); err != nil {
		t.Fatal(err)
	}
	return publicID, tokenHash
}

func newTOTPFinalize(t *testing.T, pendingID string, tokenHash [32]byte, snapshot authentication.PendingTOTPAuthenticationSnapshot, timestep int64, sessionID, refreshSeed string) authentication.TOTPAuthenticationFinalize {
	t.Helper()
	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	refresh := sha256.Sum256([]byte(refreshSeed))
	now := time.Now().UTC()
	return authentication.TOTPAuthenticationFinalize{
		PendingPublicID: pendingID,
		TokenHash:       tokenHash,
		Snapshot:        snapshot,
		Timestep:        timestep,
		SessionPublicID: sessionID,
		RefreshVerifier: refresh,
		IdleExpiresAt:   now.Add(time.Hour),
		ExpiresAt:       now.Add(2 * time.Hour),
		CorrelationID:   correlation,
	}
}
