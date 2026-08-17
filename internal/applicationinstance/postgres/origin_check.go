package postgres

import (
	"context"

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
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM application_allowed_origins
			WHERE application_instance_id = $1 AND canonical_origin = $2
		)`,
		int64(appID), canonical,
	).Scan(&exists); err != nil {
		return false, applicationinstance.ErrIntegrationPersistence
	}
	return exists, nil
}

// AnyAllowedOrigin is used only for CORS preflight, where browsers do not send
// the publishable-key value. Actual product requests still resolve the key and
// re-check the exact origin inside that application scope.
func (s *IntegrationStore) AnyAllowedOrigin(ctx context.Context, rawOrigin string) (bool, error) {
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
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM application_allowed_origins WHERE canonical_origin = $1
		)`, canonical,
	).Scan(&exists); err != nil {
		return false, applicationinstance.ErrIntegrationPersistence
	}
	return exists, nil
}
