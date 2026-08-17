package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
)

// Store persists application_instance roots through the process-owned PostgreSQL pool.
type Store struct {
	pool *database.Pool
}

func New(pool *database.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(ctx context.Context) (applicationinstance.Instance, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.Instance{}, err
	}
	if s == nil || s.pool == nil {
		return applicationinstance.Instance{}, applicationinstance.ErrPersistence
	}
	publicID, err := applicationinstance.NewPublicID()
	if err != nil {
		return applicationinstance.Instance{}, applicationinstance.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var instance applicationinstance.Instance
	var internalID int64
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO application_instances (public_id)
		 VALUES ($1)
		 RETURNING id, public_id, created_at`,
		string(publicID),
	).Scan(&internalID, &instance.PublicID, &instance.CreatedAt); err != nil {
		return applicationinstance.Instance{}, classifyError(ctx, err)
	}
	instance.InternalID = applicationinstance.InternalID(internalID)
	instance.CreatedAt = instance.CreatedAt.UTC()
	return instance, nil
}

func (s *Store) Resolve(ctx context.Context, internalID applicationinstance.InternalID) (applicationinstance.Instance, error) {
	if !internalID.Valid() {
		return applicationinstance.Instance{}, applicationinstance.ErrInvalidInternalID
	}
	if err := ctx.Err(); err != nil {
		return applicationinstance.Instance{}, err
	}
	if s == nil || s.pool == nil {
		return applicationinstance.Instance{}, applicationinstance.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var instance applicationinstance.Instance
	var storedID int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, public_id, created_at
		 FROM application_instances
		 WHERE id = $1`,
		int64(internalID),
	).Scan(&storedID, &instance.PublicID, &instance.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return applicationinstance.Instance{}, applicationinstance.ErrNotFound
		}
		return applicationinstance.Instance{}, classifyError(ctx, err)
	}
	instance.InternalID = applicationinstance.InternalID(storedID)
	instance.CreatedAt = instance.CreatedAt.UTC()
	return instance, nil
}

func (s *Store) ResolveByPublicID(ctx context.Context, publicID applicationinstance.PublicID) (applicationinstance.Instance, error) {
	if !publicID.Valid() {
		return applicationinstance.Instance{}, applicationinstance.ErrInvalidPublicID
	}
	if err := ctx.Err(); err != nil {
		return applicationinstance.Instance{}, err
	}
	if s == nil || s.pool == nil {
		return applicationinstance.Instance{}, applicationinstance.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var instance applicationinstance.Instance
	var storedID int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, public_id, created_at
		 FROM application_instances
		 WHERE public_id = $1`,
		string(publicID),
	).Scan(&storedID, &instance.PublicID, &instance.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return applicationinstance.Instance{}, applicationinstance.ErrNotFound
		}
		return applicationinstance.Instance{}, classifyError(ctx, err)
	}
	instance.InternalID = applicationinstance.InternalID(storedID)
	instance.CreatedAt = instance.CreatedAt.UTC()
	return instance, nil
}

func classifyError(ctx context.Context, _ error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return applicationinstance.ErrPersistence
}
