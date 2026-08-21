package postgres

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *Store) AllowSocialLinkAttempt(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, provider authentication.Provider) error {
	if !appID.Valid() || !userID.Valid() || !provider.Valid() {
		return authentication.ErrSocialLinkPersistence
	}
	fingerprint := authentication.SocialLinkRateLimitKey(userID, provider)
	return s.allowPublicPair(
		ctx,
		appID,
		"social_link_attempt_global",
		[32]byte{24},
		authentication.SocialLinkAttemptGlobalLimit,
		time.Minute,
		"social_link_attempt_user_provider",
		fingerprint,
		authentication.SocialLinkAttemptUserProviderLimit,
		10*time.Minute,
		authentication.ErrSocialLinkPersistence,
	)
}

func (s *Store) CreateSocialLinkAttempt(ctx context.Context, write authentication.SocialLinkAttemptWrite) error {
	if s == nil || s.pool == nil || !write.ApplicationInstanceID.Valid() || !write.UserID.Valid() || write.SessionPublicID == "" || !write.Provider.Valid() || write.StateHash == ([32]byte{}) || write.CanonicalRedirectURL == "" || write.RecentAuthAt.IsZero() || write.CreatedAt.IsZero() || write.ExpiresAt.IsZero() {
		return authentication.ErrSocialLinkPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifySocialLinkError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	managementDigest := authentication.SocialLinkManagementLockKey(write.ApplicationInstanceID, write.UserID, write.Provider)
	managementKey := int64(binary.BigEndian.Uint64(managementDigest[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, managementKey); err != nil {
		return classifySocialLinkError(ctx, err)
	}

	var nonce any
	if write.OIDCNonceHash != nil {
		nonce = write.OIDCNonceHash[:]
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO social_link_attempts(
			application_instance_id,user_id,session_id,provider,canonical_redirect_url,purpose,
			state_hash,recent_auth_at,oidc_nonce_hash,provider_pkce_ciphertext,created_at,expires_at
		)
		SELECT s.application_instance_id,s.user_id,s.id,$4,$5,'social_link',$6,$11,$7,$8,$9,$10
		FROM sessions s
		WHERE s.application_instance_id=$1
		  AND s.user_id=$2
		  AND s.public_id=$3
		  AND s.revoked_at IS NULL
		  AND s.idle_expires_at>$9
		  AND s.expires_at>$9
		  AND $11 <= $9
		  AND $11 > $9 - INTERVAL '10 minutes'`,
		int64(write.ApplicationInstanceID), int64(write.UserID), write.SessionPublicID,
		string(write.Provider), write.CanonicalRedirectURL, write.StateHash[:], nonce,
		nullableBytes(write.ProviderPKCECiphertext), write.CreatedAt.UTC(), write.ExpiresAt.UTC(), write.RecentAuthAt.UTC(),
	)
	if err != nil {
		return classifySocialLinkError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return authentication.ErrSocialLinkPersistence
	}
	if rows != 1 {
		return authentication.ErrSocialLinkInvalidSession
	}
	if err := tx.Commit(); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	return nil
}

func (s *Store) ConsumeSocialLinkAttempt(ctx context.Context, stateHash [32]byte, callbackProvider authentication.Provider) (authentication.SocialLinkAttemptSnapshot, error) {
	if s == nil || s.pool == nil || stateHash == ([32]byte{}) || !callbackProvider.Valid() {
		return authentication.SocialLinkAttemptSnapshot{}, authentication.ErrSocialLinkInvalidState
	}
	if err := ctx.Err(); err != nil {
		return authentication.SocialLinkAttemptSnapshot{}, err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.SocialLinkAttemptSnapshot{}, classifySocialLinkError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var snapshot authentication.SocialLinkAttemptSnapshot
	var appID, userID int64
	var provider string
	var storedState, nonce, ciphertext []byte
	var consumedAt, canceledAt sql.NullTime
	var expiresAt, now time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT a.id,a.application_instance_id,i.public_id,a.user_id,a.provider,a.canonical_redirect_url,
		       a.state_hash,a.oidc_nonce_hash,a.provider_pkce_ciphertext,a.expires_at,a.consumed_at,a.canceled_at,CURRENT_TIMESTAMP
		FROM social_link_attempts a
		JOIN application_instances i ON i.id=a.application_instance_id
		WHERE a.state_hash=$1
		FOR UPDATE`, stateHash[:],
	).Scan(&snapshot.AttemptID, &appID, &snapshot.ApplicationPublicID, &userID, &provider, &snapshot.CanonicalRedirectURL,
		&storedState, &nonce, &ciphertext, &expiresAt, &consumedAt, &canceledAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.SocialLinkAttemptSnapshot{}, authentication.ErrSocialLinkInvalidState
	}
	if err != nil {
		return authentication.SocialLinkAttemptSnapshot{}, classifySocialLinkError(ctx, err)
	}
	if authentication.Provider(provider) != callbackProvider || consumedAt.Valid || canceledAt.Valid || !now.UTC().Before(expiresAt.UTC()) || len(storedState) != 32 {
		return authentication.SocialLinkAttemptSnapshot{}, authentication.ErrSocialLinkInvalidState
	}
	snapshot.ApplicationInstanceID = applicationinstance.InternalID(appID)
	snapshot.UserID = identity.InternalID(userID)
	snapshot.Provider = authentication.Provider(provider)
	copy(snapshot.StateHash[:], storedState)
	if len(nonce) != 0 {
		if len(nonce) != 32 {
			return authentication.SocialLinkAttemptSnapshot{}, authentication.ErrSocialLinkPersistence
		}
		var hash [32]byte
		copy(hash[:], nonce)
		snapshot.OIDCNonceHash = &hash
	}
	snapshot.ProviderPKCECiphertext = append([]byte(nil), ciphertext...)
	if _, err := tx.ExecContext(ctx, `
		UPDATE social_link_attempts
		SET consumed_at=$2,provider_pkce_ciphertext=NULL
		WHERE id=$1 AND consumed_at IS NULL AND canceled_at IS NULL`, snapshot.AttemptID, now.UTC()); err != nil {
		return authentication.SocialLinkAttemptSnapshot{}, classifySocialLinkError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.SocialLinkAttemptSnapshot{}, classifySocialLinkError(ctx, err)
	}
	return snapshot, nil
}

func (s *Store) FinalizeSocialLink(ctx context.Context, final authentication.SocialLinkFinalize) error {
	if s == nil || s.pool == nil || final.AttemptID <= 0 || final.ProviderSubject == "" || len(final.ProviderSubject) > 512 || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.ErrSocialLinkPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifySocialLinkError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var preAppID, preUserID int64
	var preProvider string
	if err := tx.QueryRowContext(ctx, `
		SELECT application_instance_id,user_id,provider
		FROM social_link_attempts
		WHERE id=$1`, final.AttemptID,
	).Scan(&preAppID, &preUserID, &preProvider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authentication.ErrSocialLinkDenied
		}
		return classifySocialLinkError(ctx, err)
	}
	managementDigest := authentication.SocialLinkManagementLockKey(applicationinstance.InternalID(preAppID), identity.InternalID(preUserID), authentication.Provider(preProvider))
	managementKey := int64(binary.BigEndian.Uint64(managementDigest[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, managementKey); err != nil {
		return classifySocialLinkError(ctx, err)
	}

	var appID, userID, sessionID int64
	var provider string
	var expiresAt, recentAuthAt, now time.Time
	var consumedAt, canceledAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT application_instance_id,user_id,session_id,provider,expires_at,recent_auth_at,consumed_at,canceled_at,CURRENT_TIMESTAMP
		FROM social_link_attempts
		WHERE id=$1
		FOR UPDATE`, final.AttemptID,
	).Scan(&appID, &userID, &sessionID, &provider, &expiresAt, &recentAuthAt, &consumedAt, &canceledAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrSocialLinkDenied
	}
	if err != nil {
		return classifySocialLinkError(ctx, err)
	}
	now = now.UTC()
	app := applicationinstance.InternalID(appID)
	boundUser := identity.InternalID(userID)
	storedProvider := authentication.Provider(provider)
	if appID != preAppID || userID != preUserID || provider != preProvider || !app.Valid() || !boundUser.Valid() || !storedProvider.Valid() || !consumedAt.Valid || canceledAt.Valid || !now.Before(expiresAt.UTC()) || !now.Before(recentAuthAt.UTC().Add(authentication.SocialLinkFreshness)) {
		return commitSocialLinkDenial(ctx, tx, appID, userID, final.AttemptID, final.CorrelationID)
	}

	var sessionAppID, sessionUserID int64
	var idleExpiresAt, sessionExpiresAt time.Time
	var revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT application_instance_id,user_id,idle_expires_at,expires_at,revoked_at
		FROM sessions
		WHERE id=$1
		FOR UPDATE`, sessionID,
	).Scan(&sessionAppID, &sessionUserID, &idleExpiresAt, &sessionExpiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return commitSocialLinkDenial(ctx, tx, appID, userID, final.AttemptID, final.CorrelationID)
	}
	if err != nil {
		return classifySocialLinkError(ctx, err)
	}
	if sessionAppID != appID || sessionUserID != userID || revokedAt.Valid || !now.Before(idleExpiresAt.UTC()) || !now.Before(sessionExpiresAt.UTC()) {
		return commitSocialLinkDenial(ctx, tx, appID, userID, final.AttemptID, final.CorrelationID)
	}

	lockDigest := authentication.SocialIdentityLockKey(app, storedProvider, final.ProviderSubject)
	lockKey := int64(binary.BigEndian.Uint64(lockDigest[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	var externalIdentityID, ownerUserID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id,user_id
		FROM external_identities
		WHERE application_instance_id=$1 AND provider=$2 AND provider_subject=$3`, appID, provider, final.ProviderSubject,
	).Scan(&externalIdentityID, &ownerUserID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject)
			VALUES($1,$2,$3,$4)
			RETURNING id`, appID, userID, provider, final.ProviderSubject,
		).Scan(&externalIdentityID); err != nil {
			return classifySocialLinkError(ctx, err)
		}
	case err != nil:
		return classifySocialLinkError(ctx, err)
	case ownerUserID != userID:
		return commitSocialLinkDenial(ctx, tx, appID, userID, final.AttemptID, final.CorrelationID)
	}

	resourceReference := "external_identity:" + strconv.FormatInt(externalIdentityID, 10)
	if err := insertSocialLinkAudit(ctx, tx, appID, userID, audit.ActionSocialLinkSucceeded, audit.OutcomeSuccess, resourceReference, final.CorrelationID); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	return nil
}

func (s *Store) DenySocialLink(ctx context.Context, attemptID int64, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || attemptID <= 0 || correlationID == (audit.CorrelationID{}) {
		return authentication.ErrSocialLinkPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifySocialLinkError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var appID, userID int64
	if err := tx.QueryRowContext(ctx, `SELECT application_instance_id,user_id FROM social_link_attempts WHERE id=$1 FOR UPDATE`, attemptID).Scan(&appID, &userID); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	if err := insertSocialLinkAudit(ctx, tx, appID, userID, audit.ActionSocialLinkDenied, audit.OutcomeDenied, "social_link_attempt:"+strconv.FormatInt(attemptID, 10), correlationID); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	return nil
}

func commitSocialLinkDenial(ctx context.Context, tx *sql.Tx, appID, userID, attemptID int64, correlationID audit.CorrelationID) error {
	if !applicationinstance.InternalID(appID).Valid() || !identity.InternalID(userID).Valid() {
		return authentication.ErrSocialLinkDenied
	}
	if err := insertSocialLinkAudit(ctx, tx, appID, userID, audit.ActionSocialLinkDenied, audit.OutcomeDenied, "social_link_attempt:"+strconv.FormatInt(attemptID, 10), correlationID); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifySocialLinkError(ctx, err)
	}
	return authentication.ErrSocialLinkDenied
}

func insertSocialLinkAudit(ctx context.Context, tx *sql.Tx, appID, userID int64, action, outcome, resourceReference string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source)
		VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`,
		appID, audit.ActorKindSocialUser, userID, action, audit.ResourceCategorySocialLink, resourceReference, outcome, correlationID[:], audit.SourceInternalSocialLink,
	)
	return err
}

func classifySocialLinkError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, authentication.ErrSocialLinkDenied) || errors.Is(err, authentication.ErrSocialLinkInvalidSession) {
		return err
	}
	if errors.Is(err, authentication.ErrPublicRateLimited) {
		return authentication.ErrSocialLinkRateLimited
	}
	return authentication.ErrSocialLinkPersistence
}
