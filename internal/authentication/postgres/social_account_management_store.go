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

func (s *Store) ListSocialAccounts(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, limit int, cursor *authentication.SocialAccountCursor) ([]authentication.LinkedSocialAccount, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || limit < 1 || limit > authentication.SocialLinkListMaxLimit+1 {
		return nil, authentication.ErrSocialAccountPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	query := `SELECT public_id,provider,created_at FROM external_identities WHERE application_instance_id=$1 AND user_id=$2`
	args := []any{int64(appID), int64(userID)}
	if cursor != nil {
		query += ` AND (created_at,public_id)>($3,$4)`
		args = append(args, cursor.CreatedAt.UTC(), cursor.PublicID)
	}
	query += ` ORDER BY created_at ASC,public_id ASC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, authentication.ErrSocialAccountPersistence
	}
	defer rows.Close()
	out := make([]authentication.LinkedSocialAccount, 0, limit)
	for rows.Next() {
		var item authentication.LinkedSocialAccount
		var provider string
		if err := rows.Scan(&item.PublicID, &provider, &item.CreatedAt); err != nil {
			return nil, authentication.ErrSocialAccountPersistence
		}
		item.Provider = authentication.Provider(provider)
		item.CreatedAt = item.CreatedAt.UTC()
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, authentication.ErrSocialAccountPersistence
	}
	return out, nil
}

func (s *Store) UnlinkSocialAccount(ctx context.Context, current authentication.SocialAccountSession, publicID string, availability authentication.SocialMethodAvailability, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() || !authentication.ValidSocialLinkPublicID(publicID) || correlationID == (audit.CorrelationID{}) {
		return authentication.ErrSocialAccountPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	defer func() { _ = tx.Rollback() }()

	var lockedUser int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR NO KEY UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&lockedUser); err != nil {
		return authentication.ErrSocialAccountPersistence
	}

	var targetID int64
	var provider, providerSubject string
	err = tx.QueryRowContext(ctx, `SELECT id,provider,provider_subject FROM external_identities WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), publicID).Scan(&targetID, &provider, &providerSubject)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return authentication.ErrSocialAccountPersistence
		}
		return nil
	}
	if err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	p := authentication.Provider(provider)
	managementDigest := authentication.SocialLinkManagementLockKey(current.ApplicationInstanceID, current.UserID, p)
	managementKey := int64(binary.BigEndian.Uint64(managementDigest[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, managementKey); err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	if err := tx.QueryRowContext(ctx, `SELECT id,provider,provider_subject FROM external_identities WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID), publicID).Scan(&targetID, &provider, &providerSubject); errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return authentication.ErrSocialAccountPersistence
		}
		return nil
	} else if err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	p = authentication.Provider(provider)
	identityDigest := authentication.SocialIdentityLockKey(current.ApplicationInstanceID, p, providerSubject)
	identityKey := int64(binary.BigEndian.Uint64(identityDigest[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, identityKey); err != nil {
		return authentication.ErrSocialAccountPersistence
	}

	var sessionAppID, sessionUserID int64
	var sessionCreatedAt, idleExpiresAt, expiresAt time.Time
	var revokedAt sql.NullTime
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT application_instance_id,user_id,created_at,idle_expires_at,expires_at,revoked_at,CURRENT_TIMESTAMP FROM sessions WHERE public_id=$1 FOR UPDATE`, current.SessionPublicID).Scan(&sessionAppID, &sessionUserID, &sessionCreatedAt, &idleExpiresAt, &expiresAt, &revokedAt, &now); err != nil {
		return authentication.ErrSocialAccountInvalidSession
	}
	now = now.UTC()
	if sessionAppID != int64(current.ApplicationInstanceID) || sessionUserID != int64(current.UserID) || revokedAt.Valid || !sessionCreatedAt.UTC().Equal(current.CreatedAt.UTC()) || !now.Before(idleExpiresAt.UTC()) || !now.Before(expiresAt.UTC()) {
		return authentication.ErrSocialAccountInvalidSession
	}
	if !now.Before(sessionCreatedAt.UTC().Add(authentication.SocialLinkFreshness)) {
		return authentication.ErrSocialAccountReverification
	}

	usable, err := usableAuthenticationPathRemains(ctx, tx, current, targetID, availability)
	if err != nil {
		return err
	}
	if !usable {
		if err := insertSocialUnlinkAudit(ctx, tx, current, publicID, audit.ActionSocialUnlinkDenied, audit.OutcomeDenied, correlationID); err != nil {
			return authentication.ErrSocialAccountPersistence
		}
		if err := tx.Commit(); err != nil {
			return authentication.ErrSocialAccountPersistence
		}
		return authentication.ErrLastAuthenticationMethod
	}

	if _, err := tx.ExecContext(ctx, `UPDATE social_link_attempts SET canceled_at=LEAST(CURRENT_TIMESTAMP,expires_at),provider_pkce_ciphertext=NULL WHERE application_instance_id=$1 AND user_id=$2 AND provider=$3 AND canceled_at IS NULL AND expires_at>CURRENT_TIMESTAMP`, int64(current.ApplicationInstanceID), int64(current.UserID), provider); err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	if _, err := tx.ExecContext(ctx, `UPDATE social_auth_completion_grants SET consumed_at=LEAST(CURRENT_TIMESTAMP,expires_at) WHERE application_instance_id=$1 AND user_id=$2 AND consumed_at IS NULL`, int64(current.ApplicationInstanceID), int64(current.UserID)); err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM external_identities WHERE application_instance_id=$1 AND user_id=$2 AND id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), targetID)
	if err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return authentication.ErrSocialAccountPersistence
	}
	if err := insertSocialUnlinkAudit(ctx, tx, current, publicID, audit.ActionSocialUnlinkSucceeded, audit.OutcomeSuccess, correlationID); err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	if err := tx.Commit(); err != nil {
		return authentication.ErrSocialAccountPersistence
	}
	return nil
}

func usableAuthenticationPathRemains(ctx context.Context, tx *sql.Tx, current authentication.SocialAccountSession, targetID int64, availability authentication.SocialMethodAvailability) (bool, error) {
	var passkeys int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&passkeys); err != nil {
		return false, authentication.ErrSocialAccountPersistence
	}
	if passkeys > 0 {
		return true, nil
	}

	var verifiedEmails, passwordCredentials, verifiedPhones int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&verifiedEmails); err != nil {
		return false, authentication.ErrSocialAccountPersistence
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM password_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&passwordCredentials); err != nil {
		return false, authentication.ErrSocialAccountPersistence
	}
	if passwordCredentials > 0 && verifiedEmails > 0 {
		return true, nil
	}
	if availability.EmailOTP && verifiedEmails > 0 {
		return true, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&verifiedPhones); err != nil {
		return false, authentication.ErrSocialAccountPersistence
	}
	if availability.PhoneOTP && verifiedPhones > 0 {
		return true, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT provider FROM external_identities WHERE application_instance_id=$1 AND user_id=$2 AND id<>$3`, int64(current.ApplicationInstanceID), int64(current.UserID), targetID)
	if err != nil {
		return false, authentication.ErrSocialAccountPersistence
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false, authentication.ErrSocialAccountPersistence
		}
		provider := authentication.Provider(raw)
		if availability.Social != nil {
			if _, ok := availability.Social.Resolve(current.ApplicationPublicID, provider); ok {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, authentication.ErrSocialAccountPersistence
	}
	return false, nil
}

func insertSocialUnlinkAudit(ctx context.Context, tx *sql.Tx, current authentication.SocialAccountSession, publicID, action, outcome string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`, int64(current.ApplicationInstanceID), audit.ActorKindSocialUser, int64(current.UserID), action, audit.ResourceCategorySocialLink, "social_link:"+publicID, outcome, correlationID[:], audit.SourceInternalSocialLink)
	return err
}
