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
		INSERT INTO project.accounts (id, email)
		VALUES ($1, $2)
	`, account.ID, account.Email)
	return mapWriteErr(err)
}

func (r *AccountRepository) FindByID(ctx context.Context, id uuid.UUID) (domain.Account, error) {
	var account domain.Account
	err := r.pool.QueryRow(ctx, `
		SELECT id, email
		FROM project.accounts
		WHERE id = $1
	`, id).Scan(&account.ID, &account.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Account{}, domain.ErrNotFound
	}
	return account, err
}
