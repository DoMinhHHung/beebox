package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AccountRepository struct {
	pool *pgxpool.Pool
}

func NewAccountRepository(pool *pgxpool.Pool) *AccountRepository {
	return &AccountRepository{pool: pool}
}

func (r *AccountRepository) Create(ctx context.Context, account domain.Account) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO project.accounts (id, email, password_hash)
		VALUES ($1, $2, $3)
	`, account.ID, account.Email, account.PasswordHash)
	return mapWriteErr(err)
}

func (r *AccountRepository) FindByID(ctx context.Context, id uuid.UUID) (domain.Account, error) {
	var account domain.Account
	err := r.pool.QueryRow(ctx, `
		SELECT id, email, password_hash
		FROM project.accounts
		WHERE id = $1
	`, id).Scan(&account.ID, &account.Email, &account.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Account{}, domain.ErrNotFound
	}
	return account, err
}

func (r *AccountRepository) FindByEmail(ctx context.Context, email string) (domain.Account, error) {
	var account domain.Account
	err := r.pool.QueryRow(ctx, `
		SELECT id, email, password_hash
		FROM project.accounts
		WHERE email = $1
	`, email).Scan(&account.ID, &account.Email, &account.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Account{}, domain.ErrNotFound
	}
	return account, err
}
