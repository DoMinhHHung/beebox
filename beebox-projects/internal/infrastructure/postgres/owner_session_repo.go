package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OwnerSessionRepository struct {
	pool *pgxpool.Pool
}

func NewOwnerSessionRepository(pool *pgxpool.Pool) *OwnerSessionRepository {
	return &OwnerSessionRepository{pool: pool}
}

func (r *OwnerSessionRepository) Create(ctx context.Context, session domain.OwnerSession) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO project.owner_sessions (id, account_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, session.ID, session.AccountID, session.TokenHash, session.ExpiresAt, session.CreatedAt)
	return mapWriteErr(err)
}

func (r *OwnerSessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (domain.OwnerSession, error) {
	var session domain.OwnerSession
	err := r.pool.QueryRow(ctx, `
		SELECT id, account_id, token_hash, expires_at, created_at
		FROM project.owner_sessions
		WHERE token_hash = $1
	`, tokenHash).Scan(&session.ID, &session.AccountID, &session.TokenHash, &session.ExpiresAt, &session.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OwnerSession{}, domain.ErrNotFound
	}
	return session, err
}

func (r *OwnerSessionRepository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM project.owner_sessions
		WHERE token_hash = $1
	`, tokenHash)
	return err
}
