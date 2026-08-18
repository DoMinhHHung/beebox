package postgres

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func (s *Store) CreateSocialAttempt(ctx context.Context, write authentication.SocialAttemptWrite) error {
	if s == nil || s.pool == nil || !write.ApplicationInstanceID.Valid() || !write.Provider.Valid() || write.StateHash == ([32]byte{}) || !authentication.ValidS256Challenge(write.ClientCodeChallenge) || write.ExpiresAt.IsZero() {
		return authentication.ErrSocialPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var nonce any
	if write.OIDCNonceHash != nil {
		nonce = write.OIDCNonceHash[:]
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO social_auth_attempts(
			application_instance_id,provider,canonical_redirect_url,purpose,state_hash,
			client_code_challenge,oidc_nonce_hash,provider_pkce_ciphertext,expires_at
		) VALUES($1,$2,$3,'social_auth',$4,$5,$6,$7,$8)`,
		int64(write.ApplicationInstanceID), string(write.Provider), write.CanonicalRedirectURL,
		write.StateHash[:], write.ClientCodeChallenge, nonce, nullableBytes(write.ProviderPKCECiphertext), write.ExpiresAt.UTC(),
	)
	if err != nil {
		return classifySocialError(ctx, err)
	}
	return nil
}

func (s *Store) ConsumeSocialAttempt(ctx context.Context, stateHash [32]byte, callbackProvider authentication.Provider) (authentication.SocialAttemptSnapshot, error) {
	if s == nil || s.pool == nil || stateHash == ([32]byte{}) || !callbackProvider.Valid() {
		return authentication.SocialAttemptSnapshot{}, authentication.ErrSocialInvalidState
	}
	if err := ctx.Err(); err != nil {
		return authentication.SocialAttemptSnapshot{}, err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.SocialAttemptSnapshot{}, classifySocialError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var snapshot authentication.SocialAttemptSnapshot
	var appID int64
	var provider string
	var storedState []byte
	var nonce []byte
	var ciphertext []byte
	var consumedAt sql.NullTime
	var now time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT a.application_instance_id,i.public_id,a.provider,a.canonical_redirect_url,
		       a.state_hash,a.client_code_challenge,a.oidc_nonce_hash,a.provider_pkce_ciphertext,
		       a.expires_at,a.consumed_at,CURRENT_TIMESTAMP
		FROM social_auth_attempts a
		JOIN application_instances i ON i.id=a.application_instance_id
		WHERE a.state_hash=$1
		FOR UPDATE`, stateHash[:],
	).Scan(&appID, &snapshot.ApplicationPublicID, &provider, &snapshot.CanonicalRedirectURL,
		&storedState, &snapshot.ClientCodeChallenge, &nonce, &ciphertext,
		&snapshot.ExpiresAt, &consumedAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.SocialAttemptSnapshot{}, authentication.ErrSocialInvalidState
	}
	if err != nil {
		return authentication.SocialAttemptSnapshot{}, classifySocialError(ctx, err)
	}
	if authentication.Provider(provider) != callbackProvider || consumedAt.Valid || !now.UTC().Before(snapshot.ExpiresAt.UTC()) || len(storedState) != 32 {
		return authentication.SocialAttemptSnapshot{}, authentication.ErrSocialInvalidState
	}
	snapshot.ApplicationInstanceID = applicationinstance.InternalID(appID)
	snapshot.Provider = authentication.Provider(provider)
	copy(snapshot.StateHash[:], storedState)
	if len(nonce) != 0 {
		if len(nonce) != 32 {
			return authentication.SocialAttemptSnapshot{}, authentication.ErrSocialPersistence
		}
		var h [32]byte
		copy(h[:], nonce)
		snapshot.OIDCNonceHash = &h
	}
	snapshot.ProviderPKCECiphertext = append([]byte(nil), ciphertext...)
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE social_auth_attempts
		SET consumed_at=$2,provider_pkce_ciphertext=NULL
		WHERE state_hash=$1 AND consumed_at IS NULL`, stateHash[:], now.UTC()); err != nil {
		return authentication.SocialAttemptSnapshot{}, classifySocialError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.SocialAttemptSnapshot{}, classifySocialError(ctx, err)
	}
	return snapshot, nil
}

func (s *Store) FinalizeSocialProof(ctx context.Context, final authentication.SocialProofFinalize) error {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || !final.Provider.Valid() || final.ProviderSubject == "" || len(final.ProviderSubject) > 512 || !authentication.ValidS256Challenge(final.ClientCodeChallenge) || final.CompletionCodeHash == ([32]byte{}) || final.CompletionExpiresAt.IsZero() || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.ErrSocialPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifySocialError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	lockDigest := authentication.SocialIdentityLockKey(final.ApplicationInstanceID, final.Provider, final.ProviderSubject)
	lockKey := int64(binary.BigEndian.Uint64(lockDigest[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return classifySocialError(ctx, err)
	}
	var userID int64
	err = tx.QueryRowContext(ctx, `
		SELECT user_id FROM external_identities
		WHERE application_instance_id=$1 AND provider=$2 AND provider_subject=$3`,
		int64(final.ApplicationInstanceID), string(final.Provider), final.ProviderSubject,
	).Scan(&userID)
	created := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := tx.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, int64(final.ApplicationInstanceID)).Scan(&userID); err != nil {
			return classifySocialError(ctx, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject)
			VALUES($1,$2,$3,$4)`, int64(final.ApplicationInstanceID), userID, string(final.Provider), final.ProviderSubject); err != nil {
			return classifySocialError(ctx, err)
		}
		created = true
	case err != nil:
		return classifySocialError(ctx, err)
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return classifySocialError(ctx, err)
	}
	now = now.UTC()
	if !now.Before(final.CompletionExpiresAt.UTC()) {
		return authentication.ErrSocialPersistence
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO social_auth_completion_grants(
			application_instance_id,user_id,code_hash,client_code_challenge,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6)`,
		int64(final.ApplicationInstanceID), userID, final.CompletionCodeHash[:], final.ClientCodeChallenge, now, final.CompletionExpiresAt.UTC(),
	); err != nil {
		return classifySocialError(ctx, err)
	}
	if created {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_events(application_instance_id,actor_kind,subject_user_id,action,resource_category,outcome,correlation_id,source)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			int64(final.ApplicationInstanceID), audit.ActorKindAnonymousSocial, userID,
			audit.ActionSocialIdentityCreated, audit.ResourceCategoryExternalIdentity,
			audit.OutcomeSuccess, final.CorrelationID[:], audit.SourceInternalSocial,
		); err != nil {
			return classifySocialError(ctx, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return classifySocialError(ctx, err)
	}
	return nil
}

func (s *Store) ExchangeSocialCompletion(ctx context.Context, final authentication.SocialCompletionFinalize) (authentication.SocialCompletionResult, error) {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || final.CompletionCodeHash == ([32]byte{}) || !authentication.ValidS256Challenge(final.ClientCodeChallenge) || !session.ValidPublicID(final.SessionPublicID) || final.RefreshVerifier == ([32]byte{}) || final.IdleExpiresAt.IsZero() || final.ExpiresAt.IsZero() || final.IdleExpiresAt.After(final.ExpiresAt) || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.SocialCompletionResult{}, authentication.ErrSocialPersistence
	}
	if err := ctx.Err(); err != nil {
		return authentication.SocialCompletionResult{}, err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var grantID, userID int64
	var storedChallenge string
	var expiresAt time.Time
	var consumedAt sql.NullTime
	var now time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT id,user_id,client_code_challenge,expires_at,consumed_at,CURRENT_TIMESTAMP
		FROM social_auth_completion_grants
		WHERE application_instance_id=$1 AND code_hash=$2
		FOR UPDATE`, int64(final.ApplicationInstanceID), final.CompletionCodeHash[:],
	).Scan(&grantID, &userID, &storedChallenge, &expiresAt, &consumedAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.SocialCompletionResult{}, authentication.ErrSocialCompletionInvalid
	}
	if err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	now = now.UTC()
	if consumedAt.Valid || !now.Before(expiresAt.UTC()) || storedChallenge != final.ClientCodeChallenge {
		if _, auditErr := tx.ExecContext(ctx, `
			INSERT INTO audit_events(application_instance_id,actor_kind,subject_user_id,action,resource_category,outcome,correlation_id,source)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			int64(final.ApplicationInstanceID), audit.ActorKindSocialUser, userID,
			audit.ActionSocialCompletionDenied, audit.ResourceCategorySocialCompletion,
			audit.OutcomeDenied, final.CorrelationID[:], audit.SourceInternalSocial,
		); auditErr != nil {
			return authentication.SocialCompletionResult{}, classifySocialError(ctx, auditErr)
		}
		if err := tx.Commit(); err != nil {
			return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
		}
		return authentication.SocialCompletionResult{}, authentication.ErrSocialCompletionInvalid
	}
	var userPublicID, appPublicID string
	if err := tx.QueryRowContext(ctx, `
		SELECT u.public_id,a.public_id
		FROM users u JOIN application_instances a ON a.id=u.application_instance_id
		WHERE u.application_instance_id=$1 AND u.id=$2`, int64(final.ApplicationInstanceID), userID,
	).Scan(&userPublicID, &appPublicID); err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE social_auth_completion_grants SET consumed_at=$2
		WHERE id=$1 AND consumed_at IS NULL`, grantID, now)
	if err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authentication.SocialCompletionResult{}, authentication.ErrSocialCompletionInvalid
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, final.SessionPublicID, int64(final.ApplicationInstanceID), userID, final.IdleExpiresAt.UTC(), final.ExpiresAt.UTC(),
	).Scan(&sessionID); err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, final.RefreshVerifier[:]); err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,subject_user_id,action,resource_category,outcome,correlation_id,source)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		int64(final.ApplicationInstanceID), audit.ActorKindSocialUser, userID,
		audit.ActionSocialSessionIssued, audit.ResourceCategorySession,
		audit.OutcomeSuccess, final.CorrelationID[:], audit.SourceInternalSocial,
	); err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.SocialCompletionResult{}, classifySocialError(ctx, err)
	}
	return authentication.SocialCompletionResult{UserPublicID: userPublicID, ApplicationPublicID: appPublicID}, nil
}

func (s *Store) AllowSocialAttempt(ctx context.Context, appID applicationinstance.InternalID, provider authentication.Provider) error {
	if !provider.Valid() {
		return authentication.ErrSocialPersistence
	}
	providerHash := authentication.SocialProviderRateLimitKey(provider)
	return s.allowPublicPair(ctx, appID,
		"social_attempt_global", [32]byte{21}, authentication.SocialAttemptGlobalLimit, time.Minute,
		"social_attempt_application_provider", providerHash, authentication.SocialAttemptProviderLimit, time.Minute,
		authentication.ErrSocialPersistence,
	)
}

func (s *Store) AllowSocialExchange(ctx context.Context, appID applicationinstance.InternalID) error {
	return s.allowPublicPair(ctx, appID,
		"social_exchange_global", [32]byte{22}, authentication.SocialExchangeGlobalLimit, time.Minute,
		"social_exchange_application", [32]byte{23}, authentication.SocialExchangeApplicationLimit, time.Minute,
		authentication.ErrSocialPersistence,
	)
}

func classifySocialError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, authentication.ErrSocialCompletionInvalid) || errors.Is(err, authentication.ErrSocialInvalidState) {
		return err
	}
	return authentication.ErrSocialPersistence
}
