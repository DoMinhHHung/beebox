package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

func (s *IntegrationStore) IsAllowedOrigin(ctx context.Context, appID applicationinstance.InternalID, rawOrigin string) (bool, error) {
	if !appID.Valid() {
		return false, applicationinstance.ErrInvalidOrigin
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(rawOrigin)
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
	err = db.QueryRowContext(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM application_allowed_origins
			WHERE application_instance_id = $1 AND canonical_origin = $2
		)`,
		int64(appID), canonical,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, applicationinstance.ErrIntegrationPersistence
	}
	return exists, nil
}
