package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func (s *Store) ListUserSessions(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, limit int, cursor *session.Cursor) ([]session.Record, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || limit < 1 || limit > session.SessionListMaxLimit+1 {
		return nil, session.ErrSessionUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	query := `SELECT public_id,created_at,last_seen_at,idle_expires_at,expires_at,revoked_at FROM sessions WHERE application_instance_id=$1 AND user_id=$2`
	args := []any{int64(appID), int64(userID)}
	if cursor != nil {
		query += ` AND (created_at,public_id)<($3,$4)`
		args = append(args, cursor.CreatedAt.UTC(), cursor.PublicID)
	}
	query += ` ORDER BY created_at DESC,public_id DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, classify(ctx, err)
	}
	defer rows.Close()
	out := make([]session.Record, 0, limit)
	for rows.Next() {
		var record session.Record
		var revokedAt sql.NullTime
		if err := rows.Scan(&record.PublicID, &record.CreatedAt, &record.LastSeenAt, &record.IdleExpiresAt, &record.ExpiresAt, &revokedAt); err != nil {
			return nil, classify(ctx, err)
		}
		record.ApplicationInstanceID = appID
		record.UserInternalID = userID
		if revokedAt.Valid {
			t := revokedAt.Time.UTC()
			record.RevokedAt = &t
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, classify(ctx, err)
	}
	return out, nil
}

func (s *Store) RevokeUserSession(ctx context.Context, current session.Record, selectedPublicID string, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !validSelfServiceCurrent(current) || !session.ValidPublicID(selectedPublicID) || correlationID == (audit.CorrelationID{}) {
		return session.ErrSessionUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classify(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockSelfServiceActor(ctx, tx, current); err != nil {
		return err
	}

	var revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT revoked_at FROM sessions
		WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3
		FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserInternalID), selectedPublicID).Scan(&revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if err := insertSessionSelfServiceAudit(ctx, tx, current, audit.ActionSessionSelfRevoke, "session:"+selectedPublicID, audit.OutcomeDenied, correlationID); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return classify(ctx, err)
		}
		return nil
	}
	if err != nil {
		return classify(ctx, err)
	}
	if !revokedAt.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 AND revoked_at IS NULL`, int64(current.ApplicationInstanceID), int64(current.UserInternalID), selectedPublicID); err != nil {
			return classify(ctx, err)
		}
	}
	if err := insertSessionSelfServiceAudit(ctx, tx, current, audit.ActionSessionSelfRevoke, "session:"+selectedPublicID, audit.OutcomeSuccess, correlationID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classify(ctx, err)
	}
	return nil
}

func (s *Store) RevokeOtherUserSessions(ctx context.Context, current session.Record, correlationID audit.CorrelationID) error {
	return s.revokeUserSessions(ctx, current, false, audit.ActionSessionRevokeOthers, "session_scope:others", correlationID)
}

func (s *Store) RevokeAllUserSessions(ctx context.Context, current session.Record, correlationID audit.CorrelationID) error {
	return s.revokeUserSessions(ctx, current, true, audit.ActionSessionSignOutEverywhere, "session_scope:all", correlationID)
}

func (s *Store) revokeUserSessions(ctx context.Context, current session.Record, includeCurrent bool, action, resourceReference string, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !validSelfServiceCurrent(current) || correlationID == (audit.CorrelationID{}) {
		return session.ErrSessionUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classify(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockSelfServiceActor(ctx, tx, current); err != nil {
		return err
	}
	query := `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND user_id=$2 AND revoked_at IS NULL`
	args := []any{int64(current.ApplicationInstanceID), int64(current.UserInternalID)}
	if !includeCurrent {
		query += ` AND public_id<>$3`
		args = append(args, current.PublicID)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return classify(ctx, err)
	}
	if err := insertSessionSelfServiceAudit(ctx, tx, current, action, resourceReference, audit.OutcomeSuccess, correlationID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classify(ctx, err)
	}
	return nil
}

func validSelfServiceCurrent(current session.Record) bool {
	return current.ApplicationInstanceID.Valid() && current.UserInternalID.Valid() && session.ValidPublicID(current.PublicID) && !current.IdleExpiresAt.IsZero() && !current.ExpiresAt.IsZero()
}

func lockSelfServiceActor(ctx context.Context, tx *sql.Tx, current session.Record) error {
	var lockedUser int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserInternalID)).Scan(&lockedUser); errors.Is(err, sql.ErrNoRows) {
		return session.ErrSessionRevoked
	} else if err != nil {
		return classify(ctx, err)
	}
	var revokedAt sql.NullTime
	var idleExpiresAt, expiresAt, now time.Time
	err := tx.QueryRowContext(ctx, `
		SELECT revoked_at,idle_expires_at,expires_at,CURRENT_TIMESTAMP
		FROM sessions
		WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3
		FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserInternalID), current.PublicID).Scan(&revokedAt, &idleExpiresAt, &expiresAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return session.ErrSessionRevoked
	}
	if err != nil {
		return classify(ctx, err)
	}
	now = now.UTC()
	if revokedAt.Valid || !now.Before(idleExpiresAt.UTC()) || !now.Before(expiresAt.UTC()) {
		return session.ErrSessionRevoked
	}
	return nil
}

func insertSessionSelfServiceAudit(ctx context.Context, tx *sql.Tx, current session.Record, action, resourceReference, outcome string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source)
		VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`, int64(current.ApplicationInstanceID), audit.ActorKindSessionUser, int64(current.UserInternalID), action, audit.ResourceCategorySession, resourceReference, outcome, correlationID[:], audit.SourceInternalSessionSelfService)
	return classify(ctx, err)
}
