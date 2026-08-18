package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *IntegrationStore) AddAllowedRedirectURL(ctx context.Context, appID applicationinstance.InternalID, canonical string, correlation applicationinstance.CorrelationID) (applicationinstance.AllowedRedirectURL, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.AllowedRedirectURL{}, err
	}
	if s == nil || s.pool == nil || !appID.Valid() || correlation == (applicationinstance.CorrelationID{}) {
		return applicationinstance.AllowedRedirectURL{}, applicationinstance.ErrIntegrationPersistence
	}
	validated, err := applicationinstance.CanonicalizeRedirectURL(canonical)
	if err != nil || validated != canonical {
		return applicationinstance.AllowedRedirectURL{}, applicationinstance.ErrInvalidRedirect
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return applicationinstance.AllowedRedirectURL{}, classifyIntegrationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var redirect applicationinstance.AllowedRedirectURL
	var storedAppID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO application_redirect_urls(application_instance_id,canonical_redirect_url)
		VALUES($1,$2)
		RETURNING id,application_instance_id,canonical_redirect_url,created_at`, int64(appID), canonical,
	).Scan(&redirect.InternalID, &storedAppID, &redirect.CanonicalURL, &redirect.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "application_redirect_urls_application_url_key" {
			return applicationinstance.AllowedRedirectURL{}, applicationinstance.ErrRedirectConflict
		}
		return applicationinstance.AllowedRedirectURL{}, classifyIntegrationError(ctx, err)
	}
	if err := insertIntegrationAudit(ctx, tx, appID, applicationinstance.AuditActionRedirectAdded, applicationinstance.AuditResourceRedirect, correlation); err != nil {
		return applicationinstance.AllowedRedirectURL{}, classifyIntegrationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return applicationinstance.AllowedRedirectURL{}, classifyIntegrationError(ctx, err)
	}
	redirect.ApplicationInstanceID = applicationinstance.InternalID(storedAppID)
	redirect.CreatedAt = redirect.CreatedAt.UTC()
	return redirect, nil
}

func (s *IntegrationStore) IsAllowedRedirectURL(ctx context.Context, appID applicationinstance.InternalID, raw string) (bool, error) {
	if !appID.Valid() {
		return false, applicationinstance.ErrInvalidRedirect
	}
	canonical, err := applicationinstance.CanonicalizeRedirectURL(raw)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s == nil || s.pool == nil {
		return false, applicationinstance.ErrIntegrationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM application_redirect_urls
		WHERE application_instance_id=$1 AND canonical_redirect_url=$2
	)`, int64(appID), canonical).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, applicationinstance.ErrIntegrationPersistence
	}
	return exists, nil
}
