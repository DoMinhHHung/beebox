package postgres

import (
	"context"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OriginRepository struct {
	pool *pgxpool.Pool
}

func NewOriginRepository(pool *pgxpool.Pool) *OriginRepository {
	return &OriginRepository{pool: pool}
}

func (r *OriginRepository) Create(ctx context.Context, ownerID uuid.UUID, origin domain.Origin) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO project.origins (id, project_id, origin)
			VALUES ($1, $2, $3)
		`, origin.ID, origin.ProjectID, origin.Origin)
		return mapWriteErr(err)
	})
}

func (r *OriginRepository) ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.Origin, error) {
	var out []domain.Origin
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, project_id, origin, created_at
			FROM project.origins
			WHERE project_id = $1
			ORDER BY origin
		`, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item domain.Origin
			if err := rows.Scan(&item.ID, &item.ProjectID, &item.Origin, &item.CreatedAt); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if out == nil && err == nil {
		out = []domain.Origin{}
	}
	return out, err
}

func (r *OriginRepository) Delete(ctx context.Context, ownerID, projectID, originID uuid.UUID) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			DELETE FROM project.origins WHERE id = $1 AND project_id = $2
		`, originID, projectID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *OriginRepository) ListByProjectID(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	var out []string
	err := withInternal(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT origin FROM project.origins WHERE project_id = $1 ORDER BY origin
		`, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var origin string
			if err := rows.Scan(&origin); err != nil {
				return err
			}
			out = append(out, origin)
		}
		return rows.Err()
	})
	if out == nil && err == nil {
		out = []string{}
	}
	return out, err
}
