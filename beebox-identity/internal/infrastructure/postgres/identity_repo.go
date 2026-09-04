package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IdentityRepository struct {
	pool *pgxpool.Pool
}

func NewIdentityRepository(pool *pgxpool.Pool) *IdentityRepository {
	return &IdentityRepository{pool: pool}
}

func (r *IdentityRepository) Create(ctx context.Context, identity domain.Identity) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO identity.identities (id, user_id, project_id, env, provider, subject, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, identity.ID, identity.UserID, identity.ProjectID, identity.Env, identity.Provider, identity.Subject, identity.CreatedAt)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

func (r *IdentityRepository) FindBySubject(ctx context.Context, projectID uuid.UUID, env, provider, subject string) (domain.Identity, error) {
	var item domain.Identity
	err := r.pool.QueryRow(ctx, `
SELECT id, user_id, project_id, env, provider, subject, created_at
FROM identity.identities
WHERE project_id = $1 AND env = $2 AND provider = $3 AND subject = $4
`, projectID, env, provider, subject).Scan(
		&item.ID, &item.UserID, &item.ProjectID, &item.Env, &item.Provider, &item.Subject, &item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Identity{}, domain.ErrNotFound
	}
	return item, err
}

func (r *IdentityRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.Identity, error) {
	rows, err := r.pool.Query(ctx, `
SELECT id, user_id, project_id, env, provider, subject, created_at
FROM identity.identities
WHERE user_id = $1
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Identity
	for rows.Next() {
		var item domain.Identity
		if err := rows.Scan(&item.ID, &item.UserID, &item.ProjectID, &item.Env, &item.Provider, &item.Subject, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

type OAuthStateRepository struct {
	pool *pgxpool.Pool
}

func NewOAuthStateRepository(pool *pgxpool.Pool) *OAuthStateRepository {
	return &OAuthStateRepository{pool: pool}
}

func (r *OAuthStateRepository) Create(ctx context.Context, state domain.OAuthState) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO identity.oauth_states (state_hash, project_id, env, slug, verifier, redirect, nonce, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`, state.StateHash, state.ProjectID, state.Env, state.Slug, state.Verifier, state.Redirect, state.Nonce, state.ExpiresAt, state.CreatedAt)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

func (r *OAuthStateRepository) TakeByHash(ctx context.Context, stateHash string) (domain.OAuthState, error) {
	var item domain.OAuthState
	err := r.pool.QueryRow(ctx, `
DELETE FROM identity.oauth_states
WHERE state_hash = $1
RETURNING state_hash, project_id, env, slug, verifier, redirect, nonce, expires_at, created_at
`, stateHash).Scan(
		&item.StateHash, &item.ProjectID, &item.Env, &item.Slug, &item.Verifier, &item.Redirect, &item.Nonce, &item.ExpiresAt, &item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OAuthState{}, domain.ErrNotFound
	}
	return item, err
}
