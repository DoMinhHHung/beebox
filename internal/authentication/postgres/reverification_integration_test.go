//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestReverificationConcurrentConsumeIsAtMostOnce(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-concurrent")
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
	sessionID := "ses_123e4567-e89b-42d3-a456-426614175101"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	service := authentication.NewReverificationService(New(pool))
	correlationID, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, app.InternalID, user.InternalID, sessionID, sessionID, authentication.ReverificationPurposeTOTPEnroll, correlationID)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			cid, _ := audit.NewCorrelationID()
			results <- service.Consume(context.Background(), app.InternalID, user.InternalID, sessionID, authentication.ReverificationPurposeTOTPEnroll, grant.Token, cid)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var succeeded, replayed int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authentication.ErrReverificationReplay):
			replayed++
		default:
			t.Fatalf("consume error=%v", err)
		}
	}
	if succeeded != 1 || replayed != 1 {
		t.Fatalf("succeeded=%d replayed=%d", succeeded, replayed)
	}
}

func TestReverificationPurposeAndSessionBinding(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-binding")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	first := "ses_123e4567-e89b-42d3-a456-426614175201"
	second := "ses_123e4567-e89b-42d3-a456-426614175202"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), first)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), second)
	service := authentication.NewReverificationService(New(pool))
	cid, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, app.InternalID, user.InternalID, first, first, authentication.ReverificationPurposeTOTPEnroll, cid)
	if err != nil {
		t.Fatal(err)
	}
	wrongPurposeCID, _ := audit.NewCorrelationID()
	if err := service.Consume(ctx, app.InternalID, user.InternalID, first, authentication.ReverificationPurposeTOTPRemove, grant.Token, wrongPurposeCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("cross-purpose consume=%v", err)
	}
	wrongSessionCID, _ := audit.NewCorrelationID()
	if err := service.Consume(ctx, app.InternalID, user.InternalID, second, authentication.ReverificationPurposeTOTPEnroll, grant.Token, wrongSessionCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("cross-session consume=%v", err)
	}
	correctCID, _ := audit.NewCorrelationID()
	if err := service.Consume(ctx, app.InternalID, user.InternalID, first, authentication.ReverificationPurposeTOTPEnroll, grant.Token, correctCID); err != nil {
		t.Fatalf("correct consume=%v", err)
	}
}

func TestReverificationIsInvalidAfterTargetSessionRevocation(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-revocation")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID := "ses_123e4567-e89b-42d3-a456-426614175301"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	service := authentication.NewReverificationService(New(pool))
	cid, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, app.InternalID, user.InternalID, sessionID, sessionID, authentication.ReverificationPurposeSessionRevokeOthers, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`, int64(app.InternalID), int64(user.InternalID), sessionID); err != nil {
		t.Fatal(err)
	}
	consumeCID, _ := audit.NewCorrelationID()
	if err := service.Consume(ctx, app.InternalID, user.InternalID, sessionID, authentication.ReverificationPurposeSessionRevokeOthers, grant.Token, consumeCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("consume after revoke=%v", err)
	}
}

func TestReverificationWithActiveTOTPRejectsRecoverySessionAndAcceptsTOTP(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-totp-source")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO totp_credentials(
			public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret
		) VALUES('mfc_123e4567-e89b-42d3-a456-426614175401',$1,$2,1,'test-key',$3,$4)`,
		int64(app.InternalID), int64(user.InternalID), []byte("abcdefghijkl"), []byte("0123456789abcdefg")); err != nil {
		t.Fatal(err)
	}
	recoverySession := "ses_123e4567-e89b-42d3-a456-426614175402"
	totpSession := "ses_123e4567-e89b-42d3-a456-426614175403"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), recoverySession)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), totpSession)
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='recovery_code' WHERE public_id=$1`, recoverySession); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='totp' WHERE public_id=$1`, totpSession); err != nil {
		t.Fatal(err)
	}
	service := authentication.NewReverificationService(New(pool))
	recoveryCID, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, app.InternalID, user.InternalID, recoverySession, recoverySession, authentication.ReverificationPurposeTOTPRemove, recoveryCID); !errors.Is(err, authentication.ErrReverificationRecovery) {
		t.Fatalf("recovery session mint=%v", err)
	}
	totpCID, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, app.InternalID, user.InternalID, totpSession, totpSession, authentication.ReverificationPurposeTOTPRemove, totpCID); err != nil {
		t.Fatalf("TOTP session mint=%v", err)
	}
}

func TestReverificationAuditFailureRollsBackGrant(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-audit-rollback")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID := "ses_123e4567-e89b-42d3-a456-426614175501"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_reverification CHECK (source <> 'internal_reverification')`); err != nil {
		t.Fatal(err)
	}
	service := authentication.NewReverificationService(New(pool))
	cid, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, app.InternalID, user.InternalID, sessionID, sessionID, authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationPersistence) {
		t.Fatalf("mint audit failure=%v", err)
	}
	var grants int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM reverification_grants WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("grants=%d after rolled-back audit", grants)
	}
}
