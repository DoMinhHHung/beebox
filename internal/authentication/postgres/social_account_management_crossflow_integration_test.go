//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const crossFlowChallenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestSocialLinkFinalizeAndUnlinkConvergeWithoutResurrection(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "finalize_unlink")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "same-subject", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	store := New(pool)
	attempt := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, user.InternalID, sessionID, created, authentication.ProviderGitHub, "finalize-unlink")
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	availability := authentication.SocialMethodAvailability{EmailOTP: true}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		correlation, _ := audit.NewCorrelationID()
		errs <- store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{
			AttemptID:       attempt.AttemptID,
			ProviderSubject: "same-subject",
			CorrelationID:   correlation,
		})
	}()
	go func() {
		defer wg.Done()
		<-start
		correlation, _ := audit.NewCorrelationID()
		errs <- store.UnlinkSocialAccount(ctx, current, target, availability, correlation)
	}()
	close(start)
	wg.Wait()
	close(errs)

	var successes int
	var denied int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, authentication.ErrSocialLinkDenied):
			denied++
		default:
			t.Fatalf("unexpected race error: %v", err)
		}
	}
	if successes < 1 || successes+denied != 2 {
		t.Fatalf("successes=%d denied=%d", successes, denied)
	}
	assertIdentityExists(t, ctx, db, target, false)

	var canceled sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT canceled_at FROM social_link_attempts WHERE id=$1`, attempt.AttemptID).Scan(&canceled); err != nil || !canceled.Valid {
		t.Fatalf("attempt canceled=%v err=%v", canceled, err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND provider='github' AND provider_subject='same-subject'`, int64(app.InternalID)).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("provider subject rows=%d err=%v", rows, err)
	}
}

func TestSocialLinkAttemptCreationAndUnlinkHaveSerializableOutcome(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "create_unlink")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "target", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	store := New(pool)
	state := sha256.Sum256([]byte("create-unlink-state"))
	write := authentication.SocialLinkAttemptWrite{
		ApplicationInstanceID:  app.InternalID,
		UserID:                 user.InternalID,
		SessionPublicID:        sessionID,
		Provider:               authentication.ProviderGitHub,
		CanonicalRedirectURL:   "https://app.example.test/link-complete",
		StateHash:              state,
		RecentAuthAt:           created,
		ProviderPKCECiphertext: []byte("provider-pkce"),
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              created.Add(authentication.SocialLinkFreshness),
	}
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	availability := authentication.SocialMethodAvailability{EmailOTP: true}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- store.CreateSocialLinkAttempt(ctx, write)
	}()
	go func() {
		defer wg.Done()
		<-start
		correlation, _ := audit.NewCorrelationID()
		errs <- store.UnlinkSocialAccount(ctx, current, target, availability, correlation)
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent create/unlink error=%v", err)
		}
	}
	assertIdentityExists(t, ctx, db, target, false)

	var canceled sql.NullTime
	var ciphertext []byte
	if err := db.QueryRowContext(ctx, `SELECT canceled_at,provider_pkce_ciphertext FROM social_link_attempts WHERE state_hash=$1`, state[:]).Scan(&canceled, &ciphertext); err != nil {
		t.Fatal(err)
	}
	_, consumeErr := store.ConsumeSocialLinkAttempt(ctx, state, authentication.ProviderGitHub)
	if canceled.Valid {
		if !errors.Is(consumeErr, authentication.ErrSocialLinkInvalidState) || len(ciphertext) != 0 {
			t.Fatalf("canceled attempt consume=%v ciphertext=%x", consumeErr, ciphertext)
		}
	} else if consumeErr != nil {
		t.Fatalf("post-unlink newly serialized attempt was not usable: %v", consumeErr)
	}
}

func TestSocialProofAndUnlinkNeverReauthenticateFormerOwner(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "proof_unlink")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "proof-subject", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	store := New(pool)
	completion := sha256.Sum256([]byte("proof-completion"))
	correlationProof, _ := audit.NewCorrelationID()
	proof := authentication.SocialProofFinalize{
		ApplicationInstanceID: app.InternalID,
		Provider:              authentication.ProviderGitHub,
		ProviderSubject:       "proof-subject",
		ClientCodeChallenge:   crossFlowChallenge,
		CompletionCodeHash:    completion,
		CompletionExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		CorrelationID:         correlationProof,
	}
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	availability := authentication.SocialMethodAvailability{EmailOTP: true}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- store.FinalizeSocialProof(ctx, proof)
	}()
	go func() {
		defer wg.Done()
		<-start
		correlation, _ := audit.NewCorrelationID()
		errs <- store.UnlinkSocialAccount(ctx, current, target, availability, correlation)
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("proof/unlink race error=%v", err)
		}
	}

	var owner int64
	err := db.QueryRowContext(ctx, `SELECT user_id FROM external_identities WHERE application_instance_id=$1 AND provider='github' AND provider_subject='proof-subject'`, int64(app.InternalID)).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if err == nil && owner == int64(user.InternalID) {
		t.Fatalf("provider subject resurrected former owner user_id=%d", owner)
	}
	var oldOwnerUnconsumed int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_auth_completion_grants WHERE application_instance_id=$1 AND user_id=$2 AND consumed_at IS NULL`, int64(app.InternalID), int64(user.InternalID)).Scan(&oldOwnerUnconsumed); err != nil || oldOwnerUnconsumed != 0 {
		t.Fatalf("old-owner pending grants=%d err=%v", oldOwnerUnconsumed, err)
	}
}

func TestSocialCompletionExchangeAndUnlinkLinearize(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "exchange_unlink")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	currentSession, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "exchange-subject", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	codeHash := sha256.Sum256([]byte("exchange-code"))
	mustExec(t, ctx, db, `INSERT INTO social_auth_completion_grants(application_instance_id,user_id,code_hash,client_code_challenge,expires_at) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`, int64(app.InternalID), int64(user.InternalID), codeHash[:], crossFlowChallenge)
	newSession, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	refresh := sha256.Sum256([]byte("exchange-refresh"))
	correlationExchange, _ := audit.NewCorrelationID()
	final := authentication.SocialCompletionFinalize{
		ApplicationInstanceID: app.InternalID,
		CompletionCodeHash:    codeHash,
		ClientCodeChallenge:   crossFlowChallenge,
		SessionPublicID:       newSession,
		RefreshVerifier:       refresh,
		IdleExpiresAt:         time.Now().UTC().Add(30 * time.Minute),
		ExpiresAt:             time.Now().UTC().Add(time.Hour),
		CorrelationID:         correlationExchange,
	}
	current := socialAccountSession(app, user.InternalID, currentSession, created)
	availability := authentication.SocialMethodAvailability{EmailOTP: true}
	store := New(pool)

	type raceResult struct {
		kind string
		err  error
	}
	start := make(chan struct{})
	results := make(chan raceResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := store.ExchangeSocialCompletion(ctx, final)
		results <- raceResult{kind: "exchange", err: err}
	}()
	go func() {
		defer wg.Done()
		<-start
		correlation, _ := audit.NewCorrelationID()
		results <- raceResult{kind: "unlink", err: store.UnlinkSocialAccount(ctx, current, target, availability, correlation)}
	}()
	close(start)
	wg.Wait()
	close(results)

	var exchangeErr error
	for result := range results {
		if result.kind == "unlink" && result.err != nil {
			t.Fatalf("unlink error=%v", result.err)
		}
		if result.kind == "exchange" {
			exchangeErr = result.err
		}
	}
	if exchangeErr != nil && !errors.Is(exchangeErr, authentication.ErrSocialCompletionInvalid) {
		t.Fatalf("exchange error=%v", exchangeErr)
	}
	var newSessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id=$1 AND revoked_at IS NULL`, newSession).Scan(&newSessions); err != nil {
		t.Fatal(err)
	}
	if exchangeErr == nil && newSessions != 1 {
		t.Fatalf("successful exchange sessions=%d", newSessions)
	}
	if errors.Is(exchangeErr, authentication.ErrSocialCompletionInvalid) && newSessions != 0 {
		t.Fatalf("invalid exchange created sessions=%d", newSessions)
	}
	var currentRevoked sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT revoked_at FROM sessions WHERE public_id=$1`, currentSession).Scan(&currentRevoked); err != nil || currentRevoked.Valid {
		t.Fatalf("current session revoked=%v err=%v", currentRevoked, err)
	}
}

func TestLastMethodDenialPreservesPendingSecurityStateAndAuditIsMinimized(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "denial_preserves")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "secret-provider-subject", time.Now().UTC())
	store := New(pool)
	state := sha256.Sum256([]byte("denial-link-state"))
	ciphertext := []byte("ciphertext-must-survive-denial")
	if err := store.CreateSocialLinkAttempt(ctx, authentication.SocialLinkAttemptWrite{
		ApplicationInstanceID:  app.InternalID,
		UserID:                 user.InternalID,
		SessionPublicID:        sessionID,
		Provider:               authentication.ProviderGitHub,
		CanonicalRedirectURL:   "https://app.example.test/link-complete",
		StateHash:              state,
		RecentAuthAt:           created,
		ProviderPKCECiphertext: ciphertext,
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              created.Add(authentication.SocialLinkFreshness),
	}); err != nil {
		t.Fatal(err)
	}
	completion := sha256.Sum256([]byte("denial-completion"))
	mustExec(t, ctx, db, `INSERT INTO social_auth_completion_grants(application_instance_id,user_id,code_hash,client_code_challenge,expires_at) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`, int64(app.InternalID), int64(user.InternalID), completion[:], crossFlowChallenge)
	correlation, _ := audit.NewCorrelationID()
	err := store.UnlinkSocialAccount(ctx, socialAccountSession(app, user.InternalID, sessionID, created), target, authentication.SocialMethodAvailability{}, correlation)
	if !errors.Is(err, authentication.ErrLastAuthenticationMethod) {
		t.Fatalf("unlink error=%v", err)
	}
	assertIdentityExists(t, ctx, db, target, true)

	var canceled sql.NullTime
	var gotCiphertext []byte
	if err := db.QueryRowContext(ctx, `SELECT canceled_at,provider_pkce_ciphertext FROM social_link_attempts WHERE state_hash=$1`, state[:]).Scan(&canceled, &gotCiphertext); err != nil || canceled.Valid || !reflect.DeepEqual(gotCiphertext, ciphertext) {
		t.Fatalf("attempt canceled=%v ciphertext=%x err=%v", canceled, gotCiphertext, err)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM social_auth_completion_grants WHERE code_hash=$1`, completion[:]).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("grant consumed=%v err=%v", consumed, err)
	}
	var appID, actorID, subjectID int64
	var action, reference, outcome string
	if err := db.QueryRowContext(ctx, `SELECT application_instance_id,actor_user_id,subject_user_id,action,resource_reference,outcome FROM audit_events WHERE action=$1 AND correlation_id=$2`, audit.ActionSocialUnlinkDenied, correlation[:]).Scan(&appID, &actorID, &subjectID, &action, &reference, &outcome); err != nil {
		t.Fatal(err)
	}
	if appID != int64(app.InternalID) || actorID != int64(user.InternalID) || subjectID != int64(user.InternalID) || action != audit.ActionSocialUnlinkDenied || reference != "social_link:"+target || outcome != audit.OutcomeDenied {
		t.Fatalf("denial audit app=%d actor=%d subject=%d action=%q ref=%q outcome=%q", appID, actorID, subjectID, action, reference, outcome)
	}
	if reference == "secret-provider-subject" {
		t.Fatal("audit leaked provider subject")
	}
}

func TestSocialUnlinkAuditFailureRollsBackAllSuccessSideMutation(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "audit_rollback")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "audit-subject", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	store := New(pool)
	state := sha256.Sum256([]byte("audit-link-state"))
	ciphertext := []byte("audit-pkce")
	if err := store.CreateSocialLinkAttempt(ctx, authentication.SocialLinkAttemptWrite{
		ApplicationInstanceID:  app.InternalID,
		UserID:                 user.InternalID,
		SessionPublicID:        sessionID,
		Provider:               authentication.ProviderGitHub,
		CanonicalRedirectURL:   "https://app.example.test/link-complete",
		StateHash:              state,
		RecentAuthAt:           created,
		ProviderPKCECiphertext: ciphertext,
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              created.Add(authentication.SocialLinkFreshness),
	}); err != nil {
		t.Fatal(err)
	}
	completion := sha256.Sum256([]byte("audit-completion"))
	mustExec(t, ctx, db, `INSERT INTO social_auth_completion_grants(application_instance_id,user_id,code_hash,client_code_challenge,expires_at) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`, int64(app.InternalID), int64(user.InternalID), completion[:], crossFlowChallenge)
	mustExec(t, ctx, db, `CREATE FUNCTION reject_social_unlink_success_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'authentication.social.unlink_succeeded' THEN
				RAISE EXCEPTION 'reject unlink audit';
			END IF;
			RETURN NEW;
		END $$`)
	mustExec(t, ctx, db, `CREATE TRIGGER reject_social_unlink_success_audit_trigger
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_social_unlink_success_audit()`)
	correlation, _ := audit.NewCorrelationID()
	err := store.UnlinkSocialAccount(ctx, socialAccountSession(app, user.InternalID, sessionID, created), target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation)
	if !errors.Is(err, authentication.ErrSocialAccountPersistence) {
		t.Fatalf("unlink error=%v", err)
	}
	assertIdentityExists(t, ctx, db, target, true)

	var canceled sql.NullTime
	var gotCiphertext []byte
	if err := db.QueryRowContext(ctx, `SELECT canceled_at,provider_pkce_ciphertext FROM social_link_attempts WHERE state_hash=$1`, state[:]).Scan(&canceled, &gotCiphertext); err != nil || canceled.Valid || !reflect.DeepEqual(gotCiphertext, ciphertext) {
		t.Fatalf("attempt rollback canceled=%v ciphertext=%x err=%v", canceled, gotCiphertext, err)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM social_auth_completion_grants WHERE code_hash=$1`, completion[:]).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("grant rollback consumed=%v err=%v", consumed, err)
	}
}
