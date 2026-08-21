//go:build integration

package postgres

import (
	"context"
	cryptosha256 "crypto/sha256"
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

const recoveryIntegrationCode = "0123456789ABCDEFGHJKMNPQRS"

func TestRecoveryCodeConcurrentUseCompletesAtMostOnePendingAuthentication(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "recovery-code-concurrent")
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
	sessionID := "ses_123e4567-e89b-42d3-a456-426614174501"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 500)
	setID, setPublicID := seedRecoverySet(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID, recoveryIntegrationCode)
	firstID, firstToken := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174511", "recovery-first", "password-proof-one")
	secondID, secondToken := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174512", "recovery-second", "password-proof-two")
	store := New(pool)
	first, err := store.LoadPendingRecoveryAuthentication(ctx, firstID, firstToken)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadPendingRecoveryAuthentication(ctx, secondID, secondToken)
	if err != nil {
		t.Fatal(err)
	}
	codeHash := authentication.RecoveryCodeHash(app.InternalID, user.InternalID, setPublicID, recoveryIntegrationCode)
	finals := []authentication.RecoveryAuthenticationFinalize{
		newRecoveryFinalize(t, first, codeHash, "ses_123e4567-e89b-42d3-a456-426614174521", "recovery-refresh-one"),
		newRecoveryFinalize(t, second, codeHash, "ses_123e4567-e89b-42d3-a456-426614174522", "recovery-refresh-two"),
	}
	start := make(chan struct{})
	results := make(chan error, len(finals))
	var wait sync.WaitGroup
	for _, final := range finals {
		final := final
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.FinalizePendingRecoveryAuthentication(context.Background(), final)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var succeeded, denied int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authentication.ErrRecoveryInvalid), errors.Is(err, authentication.ErrRecoveryReplay):
			denied++
		default:
			t.Fatalf("completion error=%v", err)
		}
	}
	if succeeded != 1 || denied != 1 {
		t.Fatalf("succeeded=%d denied=%d", succeeded, denied)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM recovery_codes WHERE recovery_set_id=$1 AND code_hash=$2`, setID, codeHash[:]).Scan(&consumed); err != nil || !consumed.Valid {
		t.Fatalf("consumed=%v err=%v", consumed.Valid, err)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id IN ($1,$2)`, finals[0].SessionPublicID, finals[1].SessionPublicID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
	var timestep int64
	if err := db.QueryRowContext(ctx, `SELECT last_accepted_timestep FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&timestep); err != nil || timestep != 500 {
		t.Fatalf("TOTP changed timestep=%d err=%v", timestep, err)
	}
}

func TestRecoveryCodeAuditFailureRollsBackCodePendingAndSession(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "recovery-code-audit-rollback")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "ses_123e4567-e89b-42d3-a456-426614174601")
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 600)
	setID, setPublicID := seedRecoverySet(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "ses_123e4567-e89b-42d3-a456-426614174601", recoveryIntegrationCode)
	pendingID, tokenHash := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174611", "recovery-audit", "password-proof")
	store := New(pool)
	snapshot, err := store.LoadPendingRecoveryAuthentication(ctx, pendingID, tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_recovery CHECK (source <> 'internal_recovery')`); err != nil {
		t.Fatal(err)
	}
	codeHash := authentication.RecoveryCodeHash(app.InternalID, user.InternalID, setPublicID, recoveryIntegrationCode)
	final := newRecoveryFinalize(t, snapshot, codeHash, "ses_123e4567-e89b-42d3-a456-426614174621", "recovery-audit-refresh")
	if _, err := store.FinalizePendingRecoveryAuthentication(ctx, final); !errors.Is(err, authentication.ErrRecoveryPersistence) {
		t.Fatalf("audit failure=%v", err)
	}
	var codeConsumed, pendingConsumed sql.NullTime
	_ = db.QueryRowContext(ctx, `SELECT consumed_at FROM recovery_codes WHERE recovery_set_id=$1 AND code_hash=$2`, setID, codeHash[:]).Scan(&codeConsumed)
	_ = db.QueryRowContext(ctx, `SELECT consumed_at FROM pending_mfa_authentications WHERE public_id=$1`, pendingID).Scan(&pendingConsumed)
	var sessions int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id=$1`, final.SessionPublicID).Scan(&sessions)
	if codeConsumed.Valid || pendingConsumed.Valid || sessions != 0 {
		t.Fatalf("rollback code=%v pending=%v sessions=%d", codeConsumed.Valid, pendingConsumed.Valid, sessions)
	}
}

func TestPendingRecoveryAuthenticationLocksAfterFiveFailedProofs(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "recovery-code-five-failures")
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
	sessionID := "ses_123e4567-e89b-42d3-a456-426614174631"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 601)
	_, _ = seedRecoverySet(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID, recoveryIntegrationCode)
	pendingID, tokenHash := seedPendingMFA(t, ctx, db, int64(app.InternalID), int64(user.InternalID), "mfp_123e4567-e89b-42d3-a456-426614174632", "recovery-five-failures", "password-proof")
	store := New(pool)
	wrongHash := cryptosha256.Sum256([]byte("wrong-recovery-code"))
	for attempt := 1; attempt <= 5; attempt++ {
		snapshot, err := store.LoadPendingRecoveryAuthentication(ctx, pendingID, tokenHash)
		if err != nil {
			t.Fatalf("load attempt %d: %v", attempt, err)
		}
		final := newRecoveryFinalize(t, snapshot, wrongHash, "ses_123e4567-e89b-42d3-a456-426614174633", "wrong-recovery-refresh")
		if _, err := store.FinalizePendingRecoveryAuthentication(ctx, final); !errors.Is(err, authentication.ErrRecoveryInvalid) {
			t.Fatalf("attempt %d error=%v", attempt, err)
		}
	}
	if _, err := store.LoadPendingRecoveryAuthentication(ctx, pendingID, tokenHash); !errors.Is(err, authentication.ErrRecoveryInvalid) {
		t.Fatalf("locked pending proof error=%v", err)
	}
	var failedAttempts, sessions int
	if err := db.QueryRowContext(ctx, `SELECT failed_attempts FROM pending_mfa_authentications WHERE public_id=$1`, pendingID).Scan(&failedAttempts); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id=$1`, "ses_123e4567-e89b-42d3-a456-426614174633").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if failedAttempts != 5 || sessions != 0 {
		t.Fatalf("failed_attempts=%d sessions=%d", failedAttempts, sessions)
	}
}

func TestRecoveryCodeRegenerationInvalidatesEveryOldUnusedCode(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "recovery-code-regeneration")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID := "ses_123e4567-e89b-42d3-a456-426614174701"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 700)
	_, oldSetPublicID := seedRecoverySet(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID, recoveryIntegrationCode)
	set, _, err := authentication.GenerateRecoveryCodeSet(app.InternalID, user.InternalID, sessionID, "regeneration", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	correlationID, _ := audit.NewCorrelationID()
	current := authentication.TOTPSession{
		ApplicationInstanceID: app.InternalID,
		ApplicationPublicID:   app.PublicID,
		UserID:                user.InternalID,
		UserPublicID:          user.PublicID,
		SessionPublicID:       sessionID,
		CreatedAt:             time.Now().Add(-time.Minute),
		IdleExpiresAt:         time.Now().Add(time.Hour),
		ExpiresAt:             time.Now().Add(2 * time.Hour),
	}
	store := New(pool)
	if err := store.RegenerateRecoveryCodes(ctx, current, set, correlationID); err != nil {
		t.Fatal(err)
	}
	var activeSets, oldActive, newCodes int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets WHERE application_instance_id=$1 AND user_id=$2 AND invalidated_at IS NULL`, int64(app.InternalID), int64(user.InternalID)).Scan(&activeSets)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets WHERE public_id=$1 AND invalidated_at IS NULL`, oldSetPublicID).Scan(&oldActive)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes c JOIN recovery_code_sets s ON s.id=c.recovery_set_id WHERE s.public_id=$1 AND c.consumed_at IS NULL`, set.PublicID).Scan(&newCodes)
	if activeSets != 1 || oldActive != 0 || newCodes != authentication.RecoveryCodeCount {
		t.Fatalf("active=%d oldActive=%d newCodes=%d", activeSets, oldActive, newCodes)
	}
}

func TestTOTPReplacementKeepsOldCredentialUntilAtomicConfirmation(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-replacement-atomic")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID := "ses_123e4567-e89b-42d3-a456-426614174901"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 800)
	oldSetID, oldSetPublicID := seedRecoverySet(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID, recoveryIntegrationCode)
	nonce := []byte("abcdefghijkl")
	ciphertext := []byte("replacement-cipher")
	enrollmentID := "mfe_123e4567-e89b-42d3-a456-426614174902"
	credentialID := "mfc_123e4567-e89b-42d3-a456-426614174903"
	now := time.Now().UTC()
	current := authentication.TOTPSession{
		ApplicationInstanceID: app.InternalID,
		ApplicationPublicID:   app.PublicID,
		UserID:                user.InternalID,
		UserPublicID:          user.PublicID,
		SessionPublicID:       sessionID,
		CreatedAt:             now.Add(-time.Minute),
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(2 * time.Hour),
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	if err := store.CreateTOTPReplacement(ctx, current, authentication.TOTPReplacementWrite{
		Enrollment: authentication.TOTPEnrollmentWrite{
			EnrollmentID:          enrollmentID,
			CredentialID:          credentialID,
			ApplicationInstanceID: app.InternalID,
			UserID:                user.InternalID,
			SessionPublicID:       sessionID,
			Envelope:              authentication.TOTPSecretEnvelope{Version: 1, KeyID: "replacement-key", Nonce: nonce, Ciphertext: ciphertext},
			CreatedAt:             now,
			ExpiresAt:             now.Add(5 * time.Minute),
			CorrelationID:         correlationID,
		},
		RecoverySetID: oldSetID,
		CodeHash:      authentication.RecoveryCodeHash(app.InternalID, user.InternalID, oldSetPublicID, recoveryIntegrationCode),
	}); err != nil {
		t.Fatal(err)
	}
	var beforeCredential string
	_ = db.QueryRowContext(ctx, `SELECT public_id FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&beforeCredential)
	if beforeCredential == credentialID {
		t.Fatal("replacement changed TOTP before confirmation")
	}
	var consumedRecovery sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM recovery_codes WHERE recovery_set_id=$1`, oldSetID).Scan(&consumedRecovery); err != nil || !consumedRecovery.Valid {
		t.Fatalf("replacement recovery consumed=%v err=%v", consumedRecovery.Valid, err)
	}
	newSet, _, err := authentication.GenerateRecoveryCodeSet(app.InternalID, user.InternalID, sessionID, "replacement", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := authentication.TOTPReplacementSnapshot{
		TOTPEnrollmentSnapshot: authentication.TOTPEnrollmentSnapshot{
			EnrollmentID:          enrollmentID,
			CredentialID:          credentialID,
			ApplicationInstanceID: app.InternalID,
			UserID:                user.InternalID,
			SessionPublicID:       sessionID,
			Envelope:              authentication.TOTPSecretEnvelope{Version: 1, KeyID: "replacement-key", Nonce: nonce, Ciphertext: ciphertext},
			CreatedAt:             now,
			ExpiresAt:             now.Add(5 * time.Minute),
		},
		RecoverySetID: oldSetID,
	}
	credential, err := store.ActivateTOTPReplacement(ctx, current, snapshot, 801, newSet, correlationID)
	if err != nil {
		t.Fatal(err)
	}
	if credential.ID != credentialID {
		t.Fatalf("credential=%+v", credential)
	}
	var activeOld, activeNew, newCodes int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets WHERE public_id=$1 AND invalidated_at IS NULL`, oldSetPublicID).Scan(&activeOld)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets WHERE public_id=$1 AND invalidated_at IS NULL`, newSet.PublicID).Scan(&activeNew)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes c JOIN recovery_code_sets s ON s.id=c.recovery_set_id WHERE s.public_id=$1`, newSet.PublicID).Scan(&newCodes)
	if activeOld != 0 || activeNew != 1 || newCodes != authentication.RecoveryCodeCount {
		t.Fatalf("old=%d new=%d codes=%d", activeOld, activeNew, newCodes)
	}
	var afterCredential string
	var timestep int64
	if err := db.QueryRowContext(ctx, `SELECT public_id,last_accepted_timestep FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&afterCredential, &timestep); err != nil || afterCredential != credentialID || timestep != 801 {
		t.Fatalf("credential=%q timestep=%d err=%v", afterCredential, timestep, err)
	}
}

func TestTOTPReplacementAuditFailureKeepsOldCredentialAndRecoverySet(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "totp-replacement-audit-rollback")
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
	sessionID := "ses_123e4567-e89b-42d3-a456-426614174951"
	seedRecoverySession(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID)
	seedTOTPCredential(t, ctx, db, int64(app.InternalID), int64(user.InternalID), 900)
	oldSetID, oldSetPublicID := seedRecoverySet(t, ctx, db, int64(app.InternalID), int64(user.InternalID), sessionID, recoveryIntegrationCode)
	now := time.Now().UTC()
	current := authentication.TOTPSession{
		ApplicationInstanceID: app.InternalID,
		ApplicationPublicID:   app.PublicID,
		UserID:                user.InternalID,
		UserPublicID:          user.PublicID,
		SessionPublicID:       sessionID,
		CreatedAt:             now.Add(-time.Minute),
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(2 * time.Hour),
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	enrollmentID := "mfe_123e4567-e89b-42d3-a456-426614174952"
	credentialID := "mfc_123e4567-e89b-42d3-a456-426614174953"
	nonce := []byte("abcdefghijkl")
	ciphertext := []byte("replacement-cipher")
	store := New(pool)
	if err := store.CreateTOTPReplacement(ctx, current, authentication.TOTPReplacementWrite{
		Enrollment: authentication.TOTPEnrollmentWrite{
			EnrollmentID:          enrollmentID,
			CredentialID:          credentialID,
			ApplicationInstanceID: app.InternalID,
			UserID:                user.InternalID,
			SessionPublicID:       sessionID,
			Envelope:              authentication.TOTPSecretEnvelope{Version: 1, KeyID: "replacement-key", Nonce: nonce, Ciphertext: ciphertext},
			CreatedAt:             now,
			ExpiresAt:             now.Add(5 * time.Minute),
			CorrelationID:         correlationID,
		},
		RecoverySetID: oldSetID,
		CodeHash:      authentication.RecoveryCodeHash(app.InternalID, user.InternalID, oldSetPublicID, recoveryIntegrationCode),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_replacement_complete CHECK (action <> 'authentication.totp.replacement_completed')`); err != nil {
		t.Fatal(err)
	}
	newSet, _, err := authentication.GenerateRecoveryCodeSet(app.InternalID, user.InternalID, sessionID, "replacement", now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := authentication.TOTPReplacementSnapshot{
		TOTPEnrollmentSnapshot: authentication.TOTPEnrollmentSnapshot{
			EnrollmentID:          enrollmentID,
			CredentialID:          credentialID,
			ApplicationInstanceID: app.InternalID,
			UserID:                user.InternalID,
			SessionPublicID:       sessionID,
			Envelope:              authentication.TOTPSecretEnvelope{Version: 1, KeyID: "replacement-key", Nonce: nonce, Ciphertext: ciphertext},
			CreatedAt:             now,
			ExpiresAt:             now.Add(5 * time.Minute),
		},
		RecoverySetID: oldSetID,
	}
	if _, err := store.ActivateTOTPReplacement(ctx, current, snapshot, 901, newSet, correlationID); !errors.Is(err, authentication.ErrRecoveryPersistence) {
		t.Fatalf("replacement audit failure=%v", err)
	}
	var credential string
	var timestep int64
	if err := db.QueryRowContext(ctx, `SELECT public_id,last_accepted_timestep FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&credential, &timestep); err != nil {
		t.Fatal(err)
	}
	var oldActive, newSets, enrollmentConsumed int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets WHERE public_id=$1 AND invalidated_at IS NULL`, oldSetPublicID).Scan(&oldActive); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_code_sets WHERE public_id=$1`, newSet.PublicID).Scan(&newSets); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM totp_enrollments WHERE public_id=$1 AND consumed_at IS NOT NULL`, enrollmentID).Scan(&enrollmentConsumed); err != nil {
		t.Fatal(err)
	}
	if credential == credentialID || timestep != 900 || oldActive != 1 || newSets != 0 || enrollmentConsumed != 0 {
		t.Fatalf("credential=%q timestep=%d old_active=%d new_sets=%d enrollment_consumed=%d", credential, timestep, oldActive, newSets, enrollmentConsumed)
	}
}

func seedRecoverySession(t *testing.T, ctx context.Context, db *sql.DB, appID, userID int64, sessionID string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at) VALUES($1,$2,$3,CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours')`, sessionID, appID, userID); err != nil {
		t.Fatal(err)
	}
}

func seedRecoverySet(t *testing.T, ctx context.Context, db *sql.DB, appID, userID int64, sessionID, normalizedCode string) (int64, string) {
	t.Helper()
	setPublicID := "rcs_123e4567-e89b-42d3-a456-426614174801"
	var credentialID, setID int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, appID, userID).Scan(&credentialID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO recovery_code_sets(public_id,application_instance_id,user_id,totp_credential_id,created_by_session_public_id,reason) VALUES($1,$2,$3,$4,$5,'activation') RETURNING id`, setPublicID, appID, userID, credentialID, sessionID).Scan(&setID); err != nil {
		t.Fatal(err)
	}
	codeHash := authentication.RecoveryCodeHash(authenticationApplicationID(appID), authenticationUserID(userID), setPublicID, normalizedCode)
	if _, err := db.ExecContext(ctx, `INSERT INTO recovery_codes(recovery_set_id,code_hash) VALUES($1,$2)`, setID, codeHash[:]); err != nil {
		t.Fatal(err)
	}
	return setID, setPublicID
}

func authenticationApplicationID(id int64) applicationinstance.InternalID {
	return applicationinstance.InternalID(id)
}

func authenticationUserID(id int64) identity.InternalID {
	return identity.InternalID(id)
}

func newRecoveryFinalize(t *testing.T, snapshot authentication.PendingRecoveryAuthenticationSnapshot, codeHash [32]byte, sessionID, refreshSeed string) authentication.RecoveryAuthenticationFinalize {
	t.Helper()
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return authentication.RecoveryAuthenticationFinalize{
		Snapshot:        snapshot,
		CodeHash:        codeHash,
		SessionPublicID: sessionID,
		RefreshVerifier: cryptosha256.Sum256([]byte(refreshSeed)),
		IdleExpiresAt:   now.Add(time.Hour),
		ExpiresAt:       now.Add(2 * time.Hour),
		CorrelationID:   correlationID,
	}
}
