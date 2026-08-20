package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type primarySessionMaterial struct {
	PublicID       string
	RefreshHash    [32]byte
	IdleExpiresAt  time.Time
	ExpiresAt      time.Time
	Pending        authentication.PendingMFAWrite
	ExpectedMethod string
}

func finalizePrimaryAssurance(
	ctx context.Context,
	tx *sql.Tx,
	appID applicationinstance.InternalID,
	userID identity.InternalID,
	material primarySessionMaterial,
) (authentication.PrimaryAssuranceResult, error) {
	if tx == nil || !appID.Valid() || !userID.Valid() || !material.Pending.Valid() || material.Pending.PrimaryMethod != material.ExpectedMethod {
		return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
	}
	var userPublicID, appPublicID string
	if err := tx.QueryRowContext(ctx, `
		SELECT u.public_id,a.public_id
		FROM users u JOIN application_instances a ON a.id=u.application_instance_id
		WHERE u.application_instance_id=$1 AND u.id=$2
		FOR NO KEY UPDATE OF u`, int64(appID), int64(userID)).Scan(&userPublicID, &appPublicID); err != nil {
		return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
	}
	var requiresTOTP bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2)`, int64(appID), int64(userID)).Scan(&requiresTOTP); err != nil {
		return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
	}
	if requiresTOTP {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pending_mfa_authentications(
				public_id,token_hash,application_instance_id,user_id,primary_method,primary_context,required_factor,created_at,expires_at
			) VALUES($1,$2,$3,$4,$5,$6,'totp',$7,$8)`,
			material.Pending.PublicID, material.Pending.TokenHash[:], int64(appID), int64(userID), material.Pending.PrimaryMethod,
			material.Pending.PrimaryContext, material.Pending.CreatedAt.UTC(), material.Pending.ExpiresAt.UTC()); err != nil {
			return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
		}
		return authentication.PrimaryAssuranceResult{
			UserPublicID:        userPublicID,
			ApplicationPublicID: appPublicID,
			MFARequired:         true,
			PendingMFAPublicID:  material.Pending.PublicID,
			PendingMFAExpiresAt: material.Pending.ExpiresAt.UTC(),
		}, nil
	}
	if !session.ValidPublicID(material.PublicID) || material.RefreshHash == ([32]byte{}) || material.IdleExpiresAt.IsZero() || material.ExpiresAt.IsZero() || !material.IdleExpiresAt.Before(material.ExpiresAt) {
		return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, material.PublicID, int64(appID), int64(userID), material.IdleExpiresAt.UTC(), material.ExpiresAt.UTC()).Scan(&sessionID); err != nil {
		return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, material.RefreshHash[:]); err != nil {
		return authentication.PrimaryAssuranceResult{}, authentication.ErrPendingMFAPersistence
	}
	return authentication.PrimaryAssuranceResult{UserPublicID: userPublicID, ApplicationPublicID: appPublicID}, nil
}
