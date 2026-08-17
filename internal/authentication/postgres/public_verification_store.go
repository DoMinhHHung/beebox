package postgres

import (
	"context"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func (s *Store) AllowPublicVerificationIssue(ctx context.Context, appID applicationinstance.InternalID, identifierFingerprint [32]byte) error {
	if !appID.Valid() {
		return authentication.ErrInvalidApplicationInstanceScope
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil {
		return authentication.ErrEmailVerificationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.ErrEmailVerificationPersistence
	}
	defer func() { _ = tx.Rollback() }()

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.ErrEmailVerificationPersistence
	}
	now = now.UTC()
	globalFingerprint := [32]byte{2}
	if err := enforcePublicRateLimit(ctx, tx, appID, "verification_issue_global", globalFingerprint, authentication.PublicVerificationGlobalLimit, authentication.PublicVerificationGlobalWindow, now); err != nil {
		return err
	}
	if err := enforcePublicRateLimit(ctx, tx, appID, "verification_issue_identifier", identifierFingerprint, authentication.PublicVerificationIdentifierLimit, authentication.PublicVerificationIdentifierWindow, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return authentication.ErrEmailVerificationPersistence
	}
	return nil
}
