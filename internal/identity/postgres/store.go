package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
)

// Store persists application-scoped users through the process-owned
// PostgreSQL pool. It creates short-lived database/sql adapters only and does
// not own another connection pool.
type Store struct {
	pool *database.Pool
}

func New(pool *database.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
) (identity.User, error) {
	if !applicationInstanceID.Valid() {
		return identity.User{}, identity.ErrInvalidApplicationInstanceScope
	}
	if err := ctx.Err(); err != nil {
		return identity.User{}, err
	}
	if s == nil || s.pool == nil {
		return identity.User{}, identity.ErrPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	var user identity.User
	var internalID int64
	var storedApplicationInstanceID int64
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO users (application_instance_id)
		 VALUES ($1)
		 RETURNING id, application_instance_id, created_at`,
		int64(applicationInstanceID),
	).Scan(&internalID, &storedApplicationInstanceID, &user.CreatedAt); err != nil {
		return identity.User{}, classifyError(ctx, err)
	}

	user.InternalID = identity.InternalID(internalID)
	user.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationInstanceID)
	user.CreatedAt = user.CreatedAt.UTC()
	return user, nil
}

// Resolve returns a user only when both the trusted application-instance scope
// and storage-internal user identity match. Possession of an internal user ID
// alone never selects scope and there is no unscoped fallback.
func (s *Store) Resolve(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	userID identity.InternalID,
) (identity.User, error) {
	if !applicationInstanceID.Valid() {
		return identity.User{}, identity.ErrInvalidApplicationInstanceScope
	}
	if !userID.Valid() {
		return identity.User{}, identity.ErrInvalidInternalID
	}
	if err := ctx.Err(); err != nil {
		return identity.User{}, err
	}
	if s == nil || s.pool == nil {
		return identity.User{}, identity.ErrPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	var user identity.User
	var storedID int64
	var storedApplicationInstanceID int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, application_instance_id, created_at
		 FROM users
		 WHERE application_instance_id = $1 AND id = $2`,
		int64(applicationInstanceID),
		int64(userID),
	).Scan(&storedID, &storedApplicationInstanceID, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return identity.User{}, identity.ErrNotFound
		}
		return identity.User{}, classifyError(ctx, err)
	}

	user.InternalID = identity.InternalID(storedID)
	user.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationInstanceID)
	user.CreatedAt = user.CreatedAt.UTC()
	return user, nil
}

func classifyError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return identity.ErrPersistence
}
