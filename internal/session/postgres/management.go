package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func (s *Store) ResolveSession(ctx context.Context, appID applicationinstance.InternalID, publicID string) (session.Record, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !session.ValidPublicID(publicID) {
		return session.Record{}, session.ErrSessionNotFound
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var record session.Record
	var userID int64
	var revokedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT s.public_id, u.public_id, u.id, a.public_id, s.application_instance_id,
		       s.created_at, s.last_seen_at, s.idle_expires_at, s.expires_at, s.revoked_at
		FROM sessions s
		JOIN users u ON u.application_instance_id = s.application_instance_id AND u.id = s.user_id
		JOIN application_instances a ON a.id = s.application_instance_id
		WHERE s.application_instance_id = $1 AND s.public_id = $2`, int64(appID), publicID).Scan(
		&record.PublicID, &record.UserPublicID, &userID, &record.ApplicationPublicID, &record.ApplicationInstanceID,
		&record.CreatedAt, &record.LastSeenAt, &record.IdleExpiresAt, &record.ExpiresAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return session.Record{}, session.ErrSessionNotFound
	}
	if err != nil {
		return session.Record{}, classify(ctx, err)
	}
	record.UserInternalID = identity.InternalID(userID)
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		record.RevokedAt = &t
	}
	return record, nil
}

func (s *Store) RevokeSession(ctx context.Context, appID applicationinstance.InternalID, publicID string, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !appID.Valid() || !session.ValidPublicID(publicID) || correlationID == (audit.CorrelationID{}) {
		return session.ErrSessionNotFound
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classify(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var userID int64
	var revokedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `
		SELECT user_id, revoked_at FROM sessions
		WHERE application_instance_id = $1 AND public_id = $2
		FOR UPDATE`, int64(appID), publicID).Scan(&userID, &revokedAt); errors.Is(err, sql.ErrNoRows) {
		return session.ErrSessionNotFound
	} else if err != nil {
		return classify(ctx, err)
	}
	if !revokedAt.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE application_instance_id = $1 AND public_id = $2 AND revoked_at IS NULL`, int64(appID), publicID); err != nil {
			return classify(ctx, err)
		}
		if err := insertAudit(ctx, tx, appID, identity.InternalID(userID), "authentication.session.revoke", correlationID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return classify(ctx, err)
	}
	return nil
}
