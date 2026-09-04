package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, user domain.User) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO identity.users (id, project_id, env, email, password_hash, needs_email, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`, user.ID, user.ProjectID, user.Env, user.Email, user.PasswordHash, user.NeedsEmail, user.CreatedAt, user.UpdatedAt)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

func (r *UserRepository) FindByEmail(ctx context.Context, projectID uuid.UUID, env, email string) (domain.User, error) {
	row := r.pool.QueryRow(ctx, `
SELECT id, project_id, env, email, password_hash, needs_email, created_at, updated_at
FROM identity.users
WHERE project_id = $1 AND env = $2 AND email = $3
`, projectID, env, email)
	return scanUser(row)
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	row := r.pool.QueryRow(ctx, `
SELECT id, project_id, env, email, password_hash, needs_email, created_at, updated_at
FROM identity.users
WHERE id = $1
`, id)
	return scanUser(row)
}

func scanUser(row pgx.Row) (domain.User, error) {
	var user domain.User
	err := row.Scan(&user.ID, &user.ProjectID, &user.Env, &user.Email, &user.PasswordHash, &user.NeedsEmail, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
