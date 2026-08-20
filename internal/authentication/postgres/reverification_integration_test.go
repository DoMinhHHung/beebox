//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestReverificationOldTargetAndFreshSeparateProofSessionSucceeds(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-separate-proof")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175001"
	proofID := "ses_123e4567-e89b-42d3-a456-426614175002"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), targetID)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), proofID)
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET created_at=CURRENT_TIMESTAMP-INTERVAL '2 hours' WHERE public_id=$1`, targetID); err != nil {
		t.Fatal(err)
	}
	service := authentication.NewReverificationService(New(pool))
	now := time.Now().UTC()
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now.Add(-2*time.Hour), now.Add(time.Hour), now.Add(2*time.Hour), "")
	proof := reverifyEvidence(app.InternalID, user.InternalID, proofID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	cid, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeSessionRevokeOthers, cid)
	if err != nil {
		t.Fatalf("mint with separate proof: %v", err)
	}
	consumeCID, _ := audit.NewCorrelationID()
	authorized, err := service.Consume(ctx, target, authentication.ReverificationPurposeSessionRevokeOthers, grant.Token, consumeCID)
	if err != nil {
		t.Fatalf("consume=%v", err)
	}
	if err := authentication.RequireReverification(authorized, app.InternalID, user.InternalID, targetID, authentication.ReverificationPurposeSessionRevokeOthers); err != nil {
		t.Fatalf("authorized context=%v", err)
	}
}

func TestReverificationRejectsCrossUserAndCrossApplicationProof(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-cross-scope")
	apps := applicationpostgres.New(pool)
	appA, _ := apps.Create(ctx)
	appB, _ := apps.Create(ctx)
	identities := identitypostgres.New(pool)
	userA, _ := identities.Create(ctx, appA.InternalID)
	userA2, _ := identities.Create(ctx, appA.InternalID)
	userB, _ := identities.Create(ctx, appB.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175011"
	userProofID := "ses_123e4567-e89b-42d3-a456-426614175012"
	appProofID := "ses_123e4567-e89b-42d3-a456-426614175013"
	seedRecoverySession(t, ctx, db, int64(appA.InternalID), int64(userA.InternalID), targetID)
	seedRecoverySession(t, ctx, db, int64(appA.InternalID), int64(userA2.InternalID), userProofID)
	seedRecoverySession(t, ctx, db, int64(appB.InternalID), int64(userB.InternalID), appProofID)
	service := authentication.NewReverificationService(New(pool))
	target := reverifyEvidence(appA.InternalID, userA.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	cid, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, target, reverifyEvidence(appA.InternalID, userA2.InternalID, userProofID, now, now.Add(time.Hour), now.Add(2*time.Hour), ""), authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("cross-user proof=%v", err)
	}
	cid, _ = audit.NewCorrelationID()
	if _, err := service.Mint(ctx, target, reverifyEvidence(appB.InternalID, userB.InternalID, appProofID, now, now.Add(time.Hour), now.Add(2*time.Hour), ""), authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("cross-app proof=%v", err)
	}
}

func TestReverificationRejectsRevokedExpiredAndStaleProof(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-proof-state")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175021"
	proofID := "ses_123e4567-e89b-42d3-a456-426614175022"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), targetID)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), proofID)
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	service := authentication.NewReverificationService(New(pool))

	if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE public_id=$1`, proofID); err != nil {
		t.Fatal(err)
	}
	cid, _ := audit.NewCorrelationID()
	freshClaim := reverifyEvidence(app.InternalID, user.InternalID, proofID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	if _, err := service.Mint(ctx, target, freshClaim, authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("revoked DB proof=%v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=NULL, idle_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE public_id=$1`, proofID); err != nil {
		t.Fatal(err)
	}
	cid, _ = audit.NewCorrelationID()
	if _, err := service.Mint(ctx, target, freshClaim, authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("expired DB proof=%v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET idle_expires_at=CURRENT_TIMESTAMP+INTERVAL '1 hour', created_at=CURRENT_TIMESTAMP-INTERVAL '11 minutes' WHERE public_id=$1`, proofID); err != nil {
		t.Fatal(err)
	}
	cid, _ = audit.NewCorrelationID()
	stale := reverifyEvidence(app.InternalID, user.InternalID, proofID, now.Add(-11*time.Minute), now.Add(time.Hour), now.Add(2*time.Hour), "")
	if _, err := service.Mint(ctx, target, stale, authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationExpired) {
		t.Fatalf("stale proof=%v", err)
	}
}

func TestReverificationTargetPurposeBindingReplayAndRevocation(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-binding")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175031"
	otherID := "ses_123e4567-e89b-42d3-a456-426614175032"
	proofID := "ses_123e4567-e89b-42d3-a456-426614175033"
	for _, id := range []string{targetID, otherID, proofID} {
		seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), id)
	}
	service := authentication.NewReverificationService(New(pool))
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	proof := reverifyEvidence(app.InternalID, user.InternalID, proofID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	cid, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeTOTPEnroll, cid)
	if err != nil {
		t.Fatal(err)
	}
	wrongPurposeCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, target, authentication.ReverificationPurposeTOTPRemove, grant.Token, wrongPurposeCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("wrong purpose=%v", err)
	}
	wrongTarget := reverifyEvidence(app.InternalID, user.InternalID, otherID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	wrongTargetCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, wrongTarget, authentication.ReverificationPurposeTOTPEnroll, grant.Token, wrongTargetCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("wrong target=%v", err)
	}
	consumeCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, target, authentication.ReverificationPurposeTOTPEnroll, grant.Token, consumeCID); err != nil {
		t.Fatalf("correct consume=%v", err)
	}
	replayCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, target, authentication.ReverificationPurposeTOTPEnroll, grant.Token, replayCID); !errors.Is(err, authentication.ErrReverificationReplay) {
		t.Fatalf("replay=%v", err)
	}

	cid, _ = audit.NewCorrelationID()
	second, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeTOTPEnroll, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE public_id=$1`, targetID); err != nil {
		t.Fatal(err)
	}
	targetRevokedCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, target, authentication.ReverificationPurposeTOTPEnroll, second.Token, targetRevokedCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("target revoked before consume=%v", err)
	}
}

func TestReverificationProofRevocationAfterIssueInvalidatesGrant(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-proof-revocation")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175041"
	proofID := "ses_123e4567-e89b-42d3-a456-426614175042"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), targetID)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), proofID)
	service := authentication.NewReverificationService(New(pool))
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	proof := reverifyEvidence(app.InternalID, user.InternalID, proofID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	cid, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeSessionRevoke, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE public_id=$1`, proofID); err != nil {
		t.Fatal(err)
	}
	consumeCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, target, authentication.ReverificationPurposeSessionRevoke, grant.Token, consumeCID); !errors.Is(err, authentication.ErrReverificationInvalid) {
		t.Fatalf("proof revoked after issue=%v", err)
	}
}

func TestReverificationConcurrentConsumeIsAtMostOnce(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-concurrent")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175051"
	proofID := "ses_123e4567-e89b-42d3-a456-426614175052"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), targetID)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), proofID)
	service := authentication.NewReverificationService(New(pool))
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	proof := reverifyEvidence(app.InternalID, user.InternalID, proofID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	cid, _ := audit.NewCorrelationID()
	grant, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeTOTPEnroll, cid)
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
			attemptCID, _ := audit.NewCorrelationID()
			_, err := service.Consume(context.Background(), target, authentication.ReverificationPurposeTOTPEnroll, grant.Token, attemptCID)
			results <- err
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

func TestReverificationWithActiveTOTPRejectsRecoveryProofAndAcceptsTOTPProof(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-totp-source")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO totp_credentials(public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret)
		VALUES('mfc_123e4567-e89b-42d3-a456-426614175061',$1,$2,1,'test-key',$3,$4)`,
		int64(app.InternalID), int64(user.InternalID), []byte("abcdefghijkl"), []byte("0123456789abcdefg")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175062"
	recoveryID := "ses_123e4567-e89b-42d3-a456-426614175063"
	totpID := "ses_123e4567-e89b-42d3-a456-426614175064"
	for _, id := range []string{targetID, recoveryID, totpID} {
		seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), id)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='recovery_code' WHERE public_id=$1`, recoveryID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET mfa_method='totp' WHERE public_id=$1`, totpID); err != nil {
		t.Fatal(err)
	}
	service := authentication.NewReverificationService(New(pool))
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	recoveryProof := reverifyEvidence(app.InternalID, user.InternalID, recoveryID, now, now.Add(time.Hour), now.Add(2*time.Hour), "recovery_code")
	totpProof := reverifyEvidence(app.InternalID, user.InternalID, totpID, now, now.Add(time.Hour), now.Add(2*time.Hour), "totp")
	recoveryCID, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, target, recoveryProof, authentication.ReverificationPurposeTOTPRemove, recoveryCID); !errors.Is(err, authentication.ErrReverificationRecovery) {
		t.Fatalf("recovery proof mint=%v", err)
	}
	totpCID, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, target, totpProof, authentication.ReverificationPurposeTOTPRemove, totpCID); err != nil {
		t.Fatalf("TOTP proof mint=%v", err)
	}
}

func TestReverificationAuditFailuresRollbackIssueAndConsume(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "reverification-audit-rollback")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	targetID := "ses_123e4567-e89b-42d3-a456-426614175071"
	proofID := "ses_123e4567-e89b-42d3-a456-426614175072"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), targetID)
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), proofID)
	service := authentication.NewReverificationService(New(pool))
	target := reverifyEvidence(app.InternalID, user.InternalID, targetID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	proof := reverifyEvidence(app.InternalID, user.InternalID, proofID, now, now.Add(time.Hour), now.Add(2*time.Hour), "")
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_reverification_issue CHECK (action <> 'authentication.reverification.issue')`); err != nil {
		t.Fatal(err)
	}
	cid, _ := audit.NewCorrelationID()
	if _, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeTOTPEnroll, cid); !errors.Is(err, authentication.ErrReverificationPersistence) {
		t.Fatalf("mint audit failure=%v", err)
	}
	var grants int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM reverification_grants WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("grants after issue rollback=%d err=%v", grants, err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events DROP CONSTRAINT audit_events_test_reject_reverification_issue`); err != nil {
		t.Fatal(err)
	}
	cid, _ = audit.NewCorrelationID()
	grant, err := service.Mint(ctx, target, proof, authentication.ReverificationPurposeTOTPEnroll, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_reverification_consume CHECK (action <> 'authentication.reverification.consume')`); err != nil {
		t.Fatal(err)
	}
	consumeCID, _ := audit.NewCorrelationID()
	if _, err := service.Consume(ctx, target, authentication.ReverificationPurposeTOTPEnroll, grant.Token, consumeCID); !errors.Is(err, authentication.ErrReverificationPersistence) {
		t.Fatalf("consume audit failure=%v", err)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM reverification_grants WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed.Valid {
		t.Fatal("grant consumed despite rolled-back consume audit")
	}
}

func reverifyEvidence(appID applicationinstance.InternalID, userID identity.InternalID, sessionID string, authenticatedAt, idleExpiresAt, expiresAt time.Time, mfaMethod string) authentication.ReverificationSessionEvidence {
	return authentication.ReverificationSessionEvidence{
		ApplicationInstanceID: appID,
		UserID:                userID,
		SessionPublicID:       sessionID,
		AuthenticatedAt:       authenticatedAt.UTC(),
		IdleExpiresAt:         idleExpiresAt.UTC(),
		ExpiresAt:             expiresAt.UTC(),
		MFAMethod:             mfaMethod,
	}
}
