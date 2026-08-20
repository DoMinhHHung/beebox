package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

// ExchangeSocialCompletionWithAssurance consumes the one-time PKCE-bound
// completion grant and atomically chooses pending TOTP or an ordinary session.
func (s *Store) ExchangeSocialCompletionWithAssurance(
	ctx context.Context,
	final authentication.SocialCompletionFinalize,
	pending authentication.PendingMFAWrite,
) (authentication.SocialCompletionResult, authentication.PrimaryAssuranceResult, error) {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || final.CompletionCodeHash == ([32]byte{}) || !authentication.ValidS256Challenge(final.ClientCodeChallenge) || final.CorrelationID == (audit.CorrelationID{}) || !pending.Valid() || pending.PrimaryMethod != authentication.PrimaryMethodSocial {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrSocialPersistence
	}
	if err := ctx.Err(); err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, err
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
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
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrSocialCompletionInvalid
	}
	if err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
	}
	now = now.UTC()
	if consumedAt.Valid || !now.Before(expiresAt.UTC()) || storedChallenge != final.ClientCodeChallenge {
		resourceReference := "social_completion:" + strconv.FormatInt(grantID, 10)
		if _, auditErr := tx.ExecContext(ctx, `
			INSERT INTO audit_events(application_instance_id,actor_kind,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			int64(final.ApplicationInstanceID), audit.ActorKindSocialUser, userID,
			audit.ActionSocialCompletionDenied, audit.ResourceCategorySocialCompletion, resourceReference,
			audit.OutcomeDenied, final.CorrelationID[:], audit.SourceInternalSocial,
		); auditErr != nil {
			return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, auditErr)
		}
		if err := tx.Commit(); err != nil {
			return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
		}
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrSocialCompletionInvalid
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE social_auth_completion_grants SET consumed_at=$2
		WHERE id=$1 AND consumed_at IS NULL`, grantID, now)
	if err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrSocialCompletionInvalid
	}

	assurance, err := finalizePrimaryAssurance(ctx, tx, final.ApplicationInstanceID, identity.InternalID(userID), primarySessionMaterial{
		PublicID:       final.SessionPublicID,
		RefreshHash:    final.RefreshVerifier,
		IdleExpiresAt:  final.IdleExpiresAt,
		ExpiresAt:      final.ExpiresAt,
		Pending:        pending,
		ExpectedMethod: authentication.PrimaryMethodSocial,
	})
	if err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
	}
	resourceCategory := audit.ResourceCategorySession
	resourceReference := "session:" + final.SessionPublicID
	if assurance.MFARequired {
		resourceCategory = audit.ResourceCategorySocialCompletion
		resourceReference = "pending_mfa:" + assurance.PendingMFAPublicID
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		int64(final.ApplicationInstanceID), audit.ActorKindSocialUser, userID,
		audit.ActionSocialSessionIssued, resourceCategory, resourceReference,
		audit.OutcomeSuccess, final.CorrelationID[:], audit.SourceInternalSocial,
	); err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.SocialCompletionResult{}, authentication.PrimaryAssuranceResult{}, classifySocialError(ctx, err)
	}
	return authentication.SocialCompletionResult{
		UserPublicID:        assurance.UserPublicID,
		ApplicationPublicID: assurance.ApplicationPublicID,
	}, assurance, nil
}
