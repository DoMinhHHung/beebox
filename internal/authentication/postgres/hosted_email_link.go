package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func (s *Store) LoadPendingMFAContext(ctx context.Context, pendingPublicID string, tokenHash [32]byte) (session.PendingMFAContext, error) {
	if s == nil || s.pool == nil || !publicid.IsUUIDv4(pendingPublicID, "mfp") || tokenHash == ([32]byte{}) {
		return session.PendingMFAContext{}, authentication.ErrPendingMFAInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out session.PendingMFAContext
	var appID int64
	err := db.QueryRowContext(ctx, `
		SELECT application_instance_id,primary_method,primary_context
		FROM pending_mfa_authentications
		WHERE public_id=$1 AND token_hash=$2 AND purpose='authentication'
		  AND consumed_at IS NULL AND expires_at>CURRENT_TIMESTAMP AND failed_attempts<5`,
		pendingPublicID, tokenHash[:],
	).Scan(&appID, &out.PrimaryMethod, &out.PrimaryContext)
	if errors.Is(err, sql.ErrNoRows) {
		return session.PendingMFAContext{}, authentication.ErrPendingMFAInvalid
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return session.PendingMFAContext{}, ctxErr
		}
		return session.PendingMFAContext{}, authentication.ErrPendingMFAPersistence
	}
	out.ApplicationInstanceID = applicationinstance.InternalID(appID)
	if !out.ApplicationInstanceID.Valid() || out.PrimaryMethod == "" || out.PrimaryContext == "" {
		return session.PendingMFAContext{}, authentication.ErrPendingMFAInvalid
	}
	return out, nil
}

func (s *Store) LoadConsumedEmailLinkCompletion(ctx context.Context, appID applicationinstance.InternalID, challengeID string) (string, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !authentication.ValidEmailLinkChallengeID(challengeID) {
		return "", authentication.ErrEmailLinkInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var completion string
	err := db.QueryRowContext(ctx, `
		SELECT completion_url
		FROM email_signin_links
		WHERE application_instance_id=$1 AND public_id=$2 AND purpose='sign_in'
		  AND consumed_at IS NOT NULL AND secret_hash IS NULL`, int64(appID), challengeID,
	).Scan(&completion)
	if errors.Is(err, sql.ErrNoRows) {
		return "", authentication.ErrEmailLinkInvalid
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", authentication.ErrEmailLinkPersistence
	}
	return completion, nil
}
