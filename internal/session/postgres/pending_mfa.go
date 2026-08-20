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

func (s *Store) FinalizePrimarySession(
	ctx context.Context,
	appID applicationinstance.InternalID,
	userID identity.InternalID,
	credentialGeneration int64,
	publicID string,
	refreshHash [32]byte,
	idleExpiresAt, expiresAt time.Time,
	pending authentication.PendingMFAWrite,
	correlationID audit.CorrelationID,
) (authentication.PrimaryAssuranceResult, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || credentialGeneration <= 0 ||
		!session.ValidPublicID(publicID) || refreshHash == ([32]byte{}) || !idleExpiresAt.Before(expiresAt) ||
		!pending.Valid() || pending.PrimaryMethod != authentication.PrimaryMethodPassword ||
		correlationID == (audit.CorrelationID{}) {
		return authentication.PrimaryAssuranceResult{}, session.ErrSessionUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentGeneration int64
	err = tx.QueryRowContext(ctx, `
		SELECT p.generation
		FROM password_credentials p
		JOIN email_identifiers e ON e.application_instance_id=p.application_instance_id AND e.user_id=p.user_id
		WHERE p.application_instance_id=$1 AND p.user_id=$2 AND p.generation=$3 AND e.verified_at IS NOT NULL
		LIMIT 1 FOR SHARE OF p`, int64(appID), int64(userID), credentialGeneration).Scan(&currentGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PrimaryAssuranceResult{}, session.ErrInvalidCredentials
	}
	if err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}

	var userPublicID, appPublicID string
	if err := tx.QueryRowContext(ctx, `
		SELECT u.public_id,a.public_id
		FROM users u JOIN application_instances a ON a.id=u.application_instance_id
		WHERE u.application_instance_id=$1 AND u.id=$2
		FOR NO KEY UPDATE OF u`, int64(appID), int64(userID)).Scan(&userPublicID, &appPublicID); err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}
	var requiresTOTP bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2)`, int64(appID), int64(userID)).Scan(&requiresTOTP); err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}
	if requiresTOTP {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pending_mfa_authentications(
				public_id,token_hash,application_instance_id,user_id,primary_method,primary_context,required_factor,created_at,expires_at
			) VALUES($1,$2,$3,$4,$5,$6,'totp',$7,$8)`,
			pending.PublicID, pending.TokenHash[:], int64(appID), int64(userID), pending.PrimaryMethod, pending.PrimaryContext,
			pending.CreatedAt.UTC(), pending.ExpiresAt.UTC()); err != nil {
			return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
		}
		if err := insertPendingMFAAudit(ctx, tx, appID, userID, pending.PublicID, correlationID); err != nil {
			return authentication.PrimaryAssuranceResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
		}
		return authentication.PrimaryAssuranceResult{
			UserPublicID:        userPublicID,
			ApplicationPublicID: appPublicID,
			MFARequired:         true,
			PendingMFAPublicID:  pending.PublicID,
			PendingMFAExpiresAt: pending.ExpiresAt.UTC(),
		}, nil
	}

	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, publicID, int64(appID), int64(userID), idleExpiresAt.UTC(), expiresAt.UTC()).Scan(&sessionID); err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, refreshHash[:]); err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}
	if err := insertAudit(ctx, tx, appID, userID, "authentication.session.create", correlationID); err != nil {
		return authentication.PrimaryAssuranceResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.PrimaryAssuranceResult{}, classify(ctx, err)
	}
	return authentication.PrimaryAssuranceResult{UserPublicID: userPublicID, ApplicationPublicID: appPublicID}, nil
}

func insertPendingMFAAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, pendingID string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source)
		VALUES($1,'user',$2,$2,'authentication.mfa.pending','totp_credential',$3,'success',$4,'internal_totp')`,
		int64(appID), int64(userID), "pending_mfa:"+pendingID, correlationID[:])
	return classify(ctx, err)
}
