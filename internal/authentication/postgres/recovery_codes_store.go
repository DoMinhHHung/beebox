package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *Store) RegenerateRecoveryCodes(ctx context.Context, current authentication.TOTPSession, set authentication.RecoveryCodeSetWrite, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !set.Valid() || set.Reason != "regeneration" || set.ApplicationInstanceID != current.ApplicationInstanceID || set.UserID != current.UserID || set.SessionPublicID != current.SessionPublicID || correlationID == (audit.CorrelationID{}) {
		return authentication.ErrRecoveryPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateFreshTOTPSessionTx(ctx, tx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID); err != nil {
		if errors.Is(err, authentication.ErrTOTPReverificationRequired) {
			return authentication.ErrRecoveryReverification
		}
		return authentication.ErrRecoveryUnavailable
	}
	var credentialID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM totp_credentials
		WHERE application_instance_id=$1 AND user_id=$2
		FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&credentialID); errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrRecoveryUnavailable
	} else if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	if err := admitSensitiveInitiationTx(ctx, tx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID, "recovery_regeneration"); err != nil {
		if errors.Is(err, authentication.ErrRecoveryRateLimited) {
			return authentication.ErrRecoveryRateLimited
		}
		return classifyRecoveryError(ctx, err)
	}
	var now sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil || !now.Valid {
		return classifyRecoveryError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE recovery_code_sets SET invalidated_at=$3
		WHERE application_instance_id=$1 AND user_id=$2 AND invalidated_at IS NULL`,
		int64(current.ApplicationInstanceID), int64(current.UserID), now.Time.UTC()); err != nil {
		return classifyRecoveryError(ctx, err)
	}
	var setID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO recovery_code_sets(
			public_id,application_instance_id,user_id,totp_credential_id,created_by_session_public_id,reason,created_at
		) VALUES($1,$2,$3,$4,$5,'regeneration',$6) RETURNING id`,
		set.PublicID, int64(current.ApplicationInstanceID), int64(current.UserID), credentialID, current.SessionPublicID, set.CreatedAt.UTC()).Scan(&setID); err != nil {
		return classifyRecoveryError(ctx, err)
	}
	for _, codeHash := range set.CodeHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(recovery_set_id,code_hash) VALUES($1,$2)`, setID, codeHash[:]); err != nil {
			return classifyRecoveryError(ctx, err)
		}
	}
	if err := insertRecoveryAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionRecoveryCodesRegenerated, audit.OutcomeSuccess, "recovery_set:"+set.PublicID, correlationID); err != nil {
		return authentication.ErrRecoveryPersistence
	}
	if err := tx.Commit(); err != nil {
		return classifyRecoveryError(ctx, err)
	}
	return nil
}

func (s *Store) RecoveryCodeState(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) (authentication.RecoveryCodeState, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return authentication.RecoveryCodeState{}, authentication.ErrRecoveryPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var remaining int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM recovery_codes c
		JOIN recovery_code_sets s ON s.id=c.recovery_set_id
		JOIN totp_credentials t ON t.id=s.totp_credential_id
		WHERE s.application_instance_id=$1 AND s.user_id=$2 AND s.invalidated_at IS NULL
		  AND c.consumed_at IS NULL AND t.application_instance_id=$1 AND t.user_id=$2`, int64(appID), int64(userID)).Scan(&remaining)
	if err != nil {
		return authentication.RecoveryCodeState{}, classifyRecoveryError(ctx, err)
	}
	if remaining < 0 || remaining > authentication.RecoveryCodeCount {
		return authentication.RecoveryCodeState{}, authentication.ErrRecoveryPersistence
	}
	return authentication.RecoveryCodeState{Available: remaining > 0, Remaining: remaining}, nil
}

func insertRecoveryAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome, resource string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			application_instance_id,actor_kind,actor_user_id,subject_user_id,action,
			resource_category,resource_reference,outcome,correlation_id,source
		) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`,
		int64(appID), audit.ActorKindSocialUser, int64(userID), action, audit.ResourceCategoryRecovery,
		resource, outcome, correlationID[:], audit.SourceInternalRecovery)
	return err
}

func classifyRecoveryError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err == nil {
		return authentication.ErrRecoveryPersistence
	}
	return authentication.ErrRecoveryPersistence
}

func admitSensitiveInitiationTx(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, sessionPublicID, operation string) error {
	if tx == nil || !appID.Valid() || !userID.Valid() || sessionPublicID == "" || (operation != "totp_enrollment_start" && operation != "recovery_regeneration") {
		return authentication.ErrRecoveryPersistence
	}
	var count int
	err := tx.QueryRowContext(ctx, `
		INSERT INTO sensitive_operation_admission(
			application_instance_id,user_id,session_public_id,operation,window_started_at,successful_count,expires_at
		) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP,1,CURRENT_TIMESTAMP+INTERVAL '1 hour')
		ON CONFLICT (application_instance_id,user_id,session_public_id,operation) DO UPDATE SET
			window_started_at=CASE
				WHEN sensitive_operation_admission.expires_at<=CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP
				ELSE sensitive_operation_admission.window_started_at END,
			successful_count=CASE
				WHEN sensitive_operation_admission.expires_at<=CURRENT_TIMESTAMP THEN 1
				ELSE sensitive_operation_admission.successful_count+1 END,
			expires_at=CASE
				WHEN sensitive_operation_admission.expires_at<=CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP+INTERVAL '1 hour'
				ELSE sensitive_operation_admission.expires_at END
		WHERE sensitive_operation_admission.expires_at<=CURRENT_TIMESTAMP
		   OR sensitive_operation_admission.successful_count<3
		RETURNING successful_count`, int64(appID), int64(userID), sessionPublicID, operation).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrRecoveryRateLimited
	}
	if err != nil || count < 1 || count > authentication.RecoveryRegenerateLimit {
		return authentication.ErrRecoveryPersistence
	}
	return nil
}
