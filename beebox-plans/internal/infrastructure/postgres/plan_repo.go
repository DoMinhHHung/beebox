package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PlanRepository struct {
	pool *pgxpool.Pool
}

func NewPlanRepository(pool *pgxpool.Pool) *PlanRepository {
	return &PlanRepository{pool: pool}
}

func (r *PlanRepository) FindBySlug(ctx context.Context, slug string) (domain.Plan, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, slug, name, limits
		FROM plan.plans
		WHERE slug = $1
	`, slug)
	plan, err := scanPlan(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Plan{}, domain.ErrNotFound
	}
	return plan, err
}

func (r *PlanRepository) List(ctx context.Context) ([]domain.Plan, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, slug, name, limits
		FROM plan.plans
		ORDER BY slug
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Plan
	for rows.Next() {
		plan, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, plan)
	}
	return out, rows.Err()
}

func (r *PlanRepository) Create(ctx context.Context, plan domain.Plan) error {
	limits, err := json.Marshal(plan.Limits)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO plan.plans (id, slug, name, limits)
		VALUES ($1, $2, $3, $4)
	`, plan.ID, plan.Slug, plan.Name, limits)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanPlan(s scanner) (domain.Plan, error) {
	var plan domain.Plan
	var raw []byte
	if err := s.Scan(&plan.ID, &plan.Slug, &plan.Name, &raw); err != nil {
		return domain.Plan{}, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &plan.Limits); err != nil {
			return domain.Plan{}, err
		}
	}
	return plan, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
