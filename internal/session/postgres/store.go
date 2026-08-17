package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type Pool interface {
	OpenSQLDB() *sql.DB
}

type Store struct {
	pool Pool
}

func New(pool Pool) *Store { return &Store{pool: pool} }

func (s *Store) LookupPasswordCredential(ctx context.Context, appID applicationinstance.InternalID, normalizedEmail string) (session.CredentialRecord, error) {
	if s == nil || s.pool == nil || !appID.Valid() || normalizedEmail == "" {
		return session.CredentialRecord{}, session.ErrSessionUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var record session.CredentialRecord
	var userID int64
	var encoded string
	err := db.QueryRowContext(ctx, `
		SELECT u.id, u.public_id, a.public_id, p.password_hash
		FROM email_identifiers e
		JOIN users u ON u.application_instance_id = e.application_instance_id AND u.id = e.user_id
		JOIN password_credentials p ON p.application_instance_id = u.application_instance_id AND p.user_id = u.id
		JOIN application_instances a ON a.id = u.application_instance_id
		WHERE e.application_instance_id = $1 AND e.normalized_email = $2 AND e.verified_at IS NOT NULL`,
		int64(appID), normalizedEmail,
	).Scan(&userID, &record.UserPublicID, &record.ApplicationPublicID, &encoded)
	if err != nil {
		return session.CredentialRecord{}, err
	}
	hash, err := authentication.ParsePasswordHash(encoded)
	if err != nil {
		return session.CredentialRecord{}, session.ErrSessionUnavailable
	}
	record.UserInternalID = identity.InternalID(userID)
	record.PasswordHash = hash
	return record, nil
}

func (s *Store) CreateSession(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, publicID string, refreshHash [32]byte, idleExpiresAt, expiresAt time.Time, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || !session.ValidPublicID(publicID) || correlationID == (audit.CorrelationID{}) {
		return session.ErrSessionUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil { return classify(ctx, err) }
	defer func() { _ = tx.Rollback() }()
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions (public_id, application_instance_id, user_id, idle_expires_at, expires_at)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`, publicID, int64(appID), int64(userID), idleExpiresAt, expiresAt).Scan(&sessionID); err != nil {
		return classify(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials (session_id, verifier_hash) VALUES ($1,$2)`, sessionID, refreshHash[:]); err != nil {
		return classify(ctx, err)
	}
	if err := insertAudit(ctx, tx, appID, userID, "authentication.session.create", correlationID); err != nil { return err }
	if err := tx.Commit(); err != nil { return classify(ctx, err) }
	return nil
}

func (s *Store) RotateRefresh(ctx context.Context, appID applicationinstance.InternalID, oldHash, newHash [32]byte, now, requestedIdleExpiry time.Time, correlationID audit.CorrelationID) (session.CredentialRecord, string, error) {
	if s == nil || s.pool == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return session.CredentialRecord{}, "", session.ErrRefreshInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
	defer func() { _ = tx.Rollback() }()

	var credentialID, sessionInternalID, userID int64
	var consumedAt, revokedAt sql.NullTime
	var expiresAt, idleExpiresAt time.Time
	var sessionPublicID, userPublicID, appPublicID string
	err = tx.QueryRowContext(ctx, `
		SELECT r.id, s.id, s.user_id, r.consumed_at, s.revoked_at, s.expires_at, s.idle_expires_at,
		       s.public_id, u.public_id, a.public_id
		FROM session_refresh_credentials r
		JOIN sessions s ON s.id = r.session_id
		JOIN users u ON u.application_instance_id = s.application_instance_id AND u.id = s.user_id
		JOIN application_instances a ON a.id = s.application_instance_id
		WHERE s.application_instance_id = $1 AND r.verifier_hash = $2
		FOR UPDATE OF r, s`, int64(appID), oldHash[:]).Scan(
		&credentialID, &sessionInternalID, &userID, &consumedAt, &revokedAt, &expiresAt, &idleExpiresAt,
		&sessionPublicID, &userPublicID, &appPublicID,
	)
	if errors.Is(err, sql.ErrNoRows) { return session.CredentialRecord{}, "", session.ErrRefreshInvalid }
	if err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
	uid := identity.InternalID(userID)
	if consumedAt.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at,$2) WHERE id = $1`, sessionInternalID, now); err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
		if err := insertAudit(ctx, tx, appID, uid, "authentication.session.refresh_reuse", correlationID); err != nil { return session.CredentialRecord{}, "", err }
		if err := tx.Commit(); err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
		return session.CredentialRecord{}, "", session.ErrRefreshReused
	}
	if revokedAt.Valid || !expiresAt.After(now) || !idleExpiresAt.After(now) {
		return session.CredentialRecord{}, "", session.ErrRefreshInvalid
	}
	if requestedIdleExpiry.After(expiresAt) { requestedIdleExpiry = expiresAt }
	if _, err := tx.ExecContext(ctx, `UPDATE session_refresh_credentials SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`, credentialID, now); err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials (session_id, verifier_hash) VALUES ($1,$2)`, sessionInternalID, newHash[:]); err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id = $1`, sessionInternalID, now, requestedIdleExpiry); err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
	if err := insertAudit(ctx, tx, appID, uid, "authentication.session.refresh", correlationID); err != nil { return session.CredentialRecord{}, "", err }
	if err := tx.Commit(); err != nil { return session.CredentialRecord{}, "", classify(ctx, err) }
	return session.CredentialRecord{UserInternalID: uid, UserPublicID: userPublicID, ApplicationPublicID: appPublicID}, sessionPublicID, nil
}

func insertAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (application_instance_id, actor_kind, actor_user_id, subject_user_id, action, resource_category, outcome, correlation_id, source)
		VALUES ($1,'user',$2,$2,$3,'session','success',$4,'internal_session')`, int64(appID), int64(userID), action, correlationID[:])
	return classify(ctx, err)
}

func classify(ctx context.Context, err error) error {
	if err == nil { return nil }
	if ctxErr := ctx.Err(); ctxErr != nil { return ctxErr }
	return session.ErrSessionUnavailable
}
