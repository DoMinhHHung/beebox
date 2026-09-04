package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Create(ctx context.Context, session domain.Session) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO identity.sessions (id, user_id, project_id, env, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, session.ID, session.UserID, session.ProjectID, session.Env, session.TokenHash, session.ExpiresAt, session.CreatedAt)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

func (r *SessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (domain.Session, error) {
	row := r.pool.QueryRow(ctx, `
SELECT id, user_id, project_id, env, token_hash, expires_at, created_at
FROM identity.sessions
WHERE token_hash = $1
`, tokenHash)
	var session domain.Session
	err := row.Scan(&session.ID, &session.UserID, &session.ProjectID, &session.Env, &session.TokenHash, &session.ExpiresAt, &session.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Session{}, err
	}
	return session, nil
}

func (r *SessionRepository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM identity.sessions WHERE token_hash = $1`, tokenHash)
	return err
}
