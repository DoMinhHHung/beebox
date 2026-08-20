//go:build integration

package postgres

import (
	"context"
	cryptosha256 "crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const (
	createReadyKey      int64 = 810001
	createBarrierKey    int64 = 810002
	finalReadyKey       int64 = 810011
	finalBarrierKey     int64 = 810012
	proofReadyKey       int64 = 810021
	proofBarrierKey     int64 = 810022
	exchangeReadyKey    int64 = 810031
	exchangeBarrierKey  int64 = 810032
)

func TestSocialUnlinkNoKeyUpdateAllowsFKProtectionAndStillSerializesInventory(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "no_key_update_compat")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)

	inventoryTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer inventoryTx.Rollback()
	var locked int64
	if err := inventoryTx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR NO KEY UPDATE`, int64(app.InternalID), int64(user.InternalID)).Scan(&locked); err != nil {
		t.Fatal(err)
	}

	state := cryptosha256.Sum256([]byte("no-key-update-fk"))
	write := authentication.SocialLinkAttemptWrite{
		ApplicationInstanceID: app.InternalID,
		UserID:                user.InternalID,
		SessionPublicID:       sessionID,
		Provider:              authentication.ProviderGitHub,
		CanonicalRedirectURL:  "https://app.example.test/link-complete",
		StateHash:             state,
		RecentAuthAt:          created,
		CreatedAt:             time.Now().UTC(),
		ExpiresAt:             created.Add(authentication.SocialLinkFreshness),
	}
	childCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := New(pool).CreateSocialLinkAttempt(childCtx, write); err != nil {
		t.Fatalf("FK-backed child insert blocked by FOR NO KEY UPDATE: %v", err)
	}

	probeTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer probeTx.Rollback()
	var probe int64
	err = probeTx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR NO KEY UPDATE NOWAIT`, int64(app.InternalID), int64(user.InternalID)).Scan(&probe)
	if !isLockNotAvailable(err) {
		t.Fatalf("second FOR NO KEY UPDATE error=%v want lock_not_available", err)
	}
}

func TestCreateSocialLinkAttemptAndUnlinkForcedLockCrossing(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "create_unlink_barrier")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "create-target", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	installBarrierTrigger(t, ctx, db, "test_create_barrier_fn", "test_create_barrier_trg", "social_link_attempts", "", createReadyKey, createBarrierKey)
	barrier := holdBarrier(t, ctx, db, createBarrierKey)

	state := cryptosha256.Sum256([]byte("forced-create-unlink"))
	write := authentication.SocialLinkAttemptWrite{
		ApplicationInstanceID:  app.InternalID,
		UserID:                 user.InternalID,
		SessionPublicID:        sessionID,
		Provider:               authentication.ProviderGitHub,
		CanonicalRedirectURL:   "https://app.example.test/link-complete",
		StateHash:              state,
		RecentAuthAt:           created,
		ProviderPKCECiphertext: []byte("forced-create-pkce"),
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              created.Add(authentication.SocialLinkFreshness),
	}
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	store := New(pool)
	runCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	createResult := make(chan error, 1)
	go func() { createResult <- store.CreateSocialLinkAttempt(runCtx, write) }()
	waitForAdvisoryHeld(t, runCtx, db, createReadyKey)

	unlinkResult := make(chan error, 1)
	go func() {
		correlation, _ := audit.NewCorrelationID()
		unlinkResult <- store.UnlinkSocialAccount(runCtx, current, target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation)
	}()
	waitForUserInventoryLock(t, runCtx, db, app.InternalID, user.InternalID)
	releaseBarrier(t, ctx, barrier, createBarrierKey)

	if err := receiveErr(t, runCtx, createResult, "create"); err != nil {
		t.Fatalf("create error=%v", err)
	}
	if err := receiveErr(t, runCtx, unlinkResult, "unlink"); err != nil {
		t.Fatalf("unlink error=%v", err)
	}
	assertIdentityExists(t, ctx, db, target, false)
	var canceled sql.NullTime
	var ciphertext []byte
	if err := db.QueryRowContext(ctx, `SELECT canceled_at,provider_pkce_ciphertext FROM social_link_attempts WHERE state_hash=$1`, state[:]).Scan(&canceled, &ciphertext); err != nil || !canceled.Valid || len(ciphertext) != 0 {
		t.Fatalf("create/unlink final canceled=%v ciphertext=%x err=%v", canceled, ciphertext, err)
	}
}

func TestFinalizeSocialLinkAndUnlinkForcedLockCrossing(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "finalize_unlink_barrier")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "finalize-target", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	store := New(pool)
	attempt := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, user.InternalID, sessionID, created, authentication.ProviderGitHub, "forced-finalize-unlink")
	installBarrierTrigger(t, ctx, db, "test_finalize_barrier_fn", "test_finalize_barrier_trg", "audit_events", "NEW.action = 'authentication.social.link_succeeded'", finalReadyKey, finalBarrierKey)
	barrier := holdBarrier(t, ctx, db, finalBarrierKey)

	runCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	finalizeResult := make(chan error, 1)
	go func() {
		correlation, _ := audit.NewCorrelationID()
		finalizeResult <- store.FinalizeSocialLink(runCtx, authentication.SocialLinkFinalize{AttemptID: attempt.AttemptID, ProviderSubject: "finalize-target", CorrelationID: correlation})
	}()
	waitForAdvisoryHeld(t, runCtx, db, finalReadyKey)

	unlinkResult := make(chan error, 1)
	go func() {
		correlation, _ := audit.NewCorrelationID()
		unlinkResult <- store.UnlinkSocialAccount(runCtx, socialAccountSession(app, user.InternalID, sessionID, created), target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation)
	}()
	waitForUserInventoryLock(t, runCtx, db, app.InternalID, user.InternalID)
	releaseBarrier(t, ctx, barrier, finalBarrierKey)

	if err := receiveErr(t, runCtx, finalizeResult, "finalize"); err != nil {
		t.Fatalf("finalize error=%v", err)
	}
	if err := receiveErr(t, runCtx, unlinkResult, "unlink"); err != nil {
		t.Fatalf("unlink error=%v", err)
	}
	assertIdentityExists(t, ctx, db, target, false)
	var canceled sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT canceled_at FROM social_link_attempts WHERE id=$1`, attempt.AttemptID).Scan(&canceled); err != nil || !canceled.Valid {
		t.Fatalf("finalize/unlink attempt canceled=%v err=%v", canceled, err)
	}
}

func TestFinalizeSocialProofAndUnlinkForcedLockCrossing(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "proof_unlink_barrier")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "proof-barrier-target", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	installBarrierTrigger(t, ctx, db, "test_proof_barrier_fn", "test_proof_barrier_trg", "social_auth_completion_grants", "", proofReadyKey, proofBarrierKey)
	barrier := holdBarrier(t, ctx, db, proofBarrierKey)

	completion := cryptosha256.Sum256([]byte("forced-proof-unlink"))
	correlation, _ := audit.NewCorrelationID()
	proof := authentication.SocialProofFinalize{ApplicationInstanceID: app.InternalID, Provider: authentication.ProviderGitHub, ProviderSubject: "proof-barrier-target", ClientCodeChallenge: crossFlowChallenge, CompletionCodeHash: completion, CompletionExpiresAt: time.Now().UTC().Add(5 * time.Minute), CorrelationID: correlation}
	store := New(pool)
	runCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	proofResult := make(chan error, 1)
	go func() { proofResult <- store.FinalizeSocialProof(runCtx, proof) }()
	waitForAdvisoryHeld(t, runCtx, db, proofReadyKey)

	unlinkResult := make(chan error, 1)
	go func() {
		correlation, _ := audit.NewCorrelationID()
		unlinkResult <- store.UnlinkSocialAccount(runCtx, socialAccountSession(app, user.InternalID, sessionID, created), target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation)
	}()
	waitForUserInventoryLock(t, runCtx, db, app.InternalID, user.InternalID)
	releaseBarrier(t, ctx, barrier, proofBarrierKey)

	if err := receiveErr(t, runCtx, proofResult, "proof"); err != nil {
		t.Fatalf("proof error=%v", err)
	}
	if err := receiveErr(t, runCtx, unlinkResult, "unlink"); err != nil {
		t.Fatalf("unlink error=%v", err)
	}
	assertIdentityExists(t, ctx, db, target, false)
	var pending int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_auth_completion_grants WHERE application_instance_id=$1 AND user_id=$2 AND consumed_at IS NULL`, int64(app.InternalID), int64(user.InternalID)).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("proof/unlink pending=%d err=%v", pending, err)
	}
}

func TestExchangeSocialCompletionAndUnlinkForcedLockCrossing(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "exchange_unlink_barrier")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	currentSession, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "exchange-barrier-target", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	codeHash := cryptosha256.Sum256([]byte("forced-exchange-unlink"))
	mustExec(t, ctx, db, `INSERT INTO social_auth_completion_grants(application_instance_id,user_id,code_hash,client_code_challenge,expires_at) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`, int64(app.InternalID), int64(user.InternalID), codeHash[:], crossFlowChallenge)
	installBarrierTrigger(t, ctx, db, "test_exchange_barrier_fn", "test_exchange_barrier_trg", "sessions", "", exchangeReadyKey, exchangeBarrierKey)
	barrier := holdBarrier(t, ctx, db, exchangeBarrierKey)

	newSession, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	refresh := cryptosha256.Sum256([]byte("forced-exchange-refresh"))
	correlation, _ := audit.NewCorrelationID()
	final := authentication.SocialCompletionFinalize{ApplicationInstanceID: app.InternalID, CompletionCodeHash: codeHash, ClientCodeChallenge: crossFlowChallenge, SessionPublicID: newSession, RefreshVerifier: refresh, IdleExpiresAt: time.Now().UTC().Add(30 * time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), CorrelationID: correlation}
	store := New(pool)
	runCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	exchangeResult := make(chan error, 1)
	go func() {
		_, err := store.ExchangeSocialCompletion(runCtx, final)
		exchangeResult <- err
	}()
	waitForAdvisoryHeld(t, runCtx, db, exchangeReadyKey)

	unlinkResult := make(chan error, 1)
	go func() {
		correlation, _ := audit.NewCorrelationID()
		unlinkResult <- store.UnlinkSocialAccount(runCtx, socialAccountSession(app, user.InternalID, currentSession, created), target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation)
	}()
	waitForUserInventoryLock(t, runCtx, db, app.InternalID, user.InternalID)
	releaseBarrier(t, ctx, barrier, exchangeBarrierKey)

	if err := receiveErr(t, runCtx, exchangeResult, "exchange"); err != nil {
		t.Fatalf("exchange error=%v", err)
	}
	if err := receiveErr(t, runCtx, unlinkResult, "unlink"); err != nil {
		t.Fatalf("unlink error=%v", err)
	}
	assertIdentityExists(t, ctx, db, target, false)
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id=$1 AND revoked_at IS NULL`, newSession).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("exchange/unlink session count=%d err=%v", sessions, err)
	}
}

func installBarrierTrigger(t *testing.T, ctx context.Context, db *sql.DB, functionName, triggerName, tableName, condition string, readyKey, barrierKey int64) {
	t.Helper()
	guard := ""
	if condition != "" {
		guard = fmt.Sprintf("IF NOT (%s) THEN RETURN NEW; END IF;", condition)
	}
	mustExec(t, ctx, db, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN
		%s
		PERFORM pg_advisory_xact_lock(%d);
		PERFORM pg_advisory_xact_lock(%d);
		RETURN NEW;
	END $$`, functionName, guard, readyKey, barrierKey))
	mustExec(t, ctx, db, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, triggerName, tableName, functionName))
}

func holdBarrier(t *testing.T, ctx context.Context, db *sql.DB, key int64) *sql.Conn {
	t.Helper()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = conn.ExecContext(cleanupCtx, `SELECT pg_advisory_unlock($1)`, key)
		_ = conn.Close()
	})
	return conn
}

func releaseBarrier(t *testing.T, ctx context.Context, conn *sql.Conn, key int64) {
	t.Helper()
	var unlocked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("release barrier key=%d unlocked=%v err=%v", key, unlocked, err)
	}
}

func waitForAdvisoryHeld(t *testing.T, ctx context.Context, db *sql.DB, key int64) {
	t.Helper()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for {
		if err := ctx.Err(); err != nil {
			t.Fatalf("waiting for advisory key %d: %v", key, err)
		}
		var acquired bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&acquired); err != nil {
			t.Fatal(err)
		}
		if !acquired {
			return
		}
		var unlocked bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked); err != nil || !unlocked {
			t.Fatalf("probe unlock key=%d unlocked=%v err=%v", key, unlocked, err)
		}
		runtime.Gosched()
	}
}

func waitForUserInventoryLock(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, userID identity.InternalID) {
	t.Helper()
	if !appID.Valid() || !userID.Valid() {
		t.Fatal("invalid inventory lock identifiers")
	}
	for {
		if err := ctx.Err(); err != nil {
			t.Fatalf("waiting for user inventory lock: %v", err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR NO KEY UPDATE NOWAIT`, int64(appID), int64(userID)).Scan(&id)
		_ = tx.Rollback()
		if isLockNotAvailable(err) {
			return
		}
		if err != nil {
			t.Fatalf("inventory probe error=%v", err)
		}
		runtime.Gosched()
	}
}

func isLockNotAvailable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}

func receiveErr(t *testing.T, ctx context.Context, ch <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		t.Fatalf("%s did not complete within bounded context: %v", name, ctx.Err())
		return ctx.Err()
	}
}
