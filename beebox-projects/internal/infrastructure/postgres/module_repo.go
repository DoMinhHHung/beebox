package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ModuleRepository struct {
	pool *pgxpool.Pool
}

func NewModuleRepository(pool *pgxpool.Pool) *ModuleRepository {
	return &ModuleRepository{pool: pool}
}

func (r *ModuleRepository) Replace(ctx context.Context, ownerID, projectID uuid.UUID, names []string) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM project.modules WHERE project_id = $1`, projectID); err != nil {
			return err
		}
		return insertModules(ctx, tx, projectID, names)
	})
}

func insertModules(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, names []string) error {
	for _, name := range names {
		if _, err := tx.Exec(ctx, `
			INSERT INTO project.modules (project_id, name) VALUES ($1, $2)
		`, projectID, name); err != nil {
			return mapWriteErr(err)
		}
	}
	return nil
}

func (r *ModuleRepository) ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]string, error) {
	var out []string
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		return scanModuleNames(ctx, tx, projectID, &out)
	})
	if out == nil && err == nil {
		out = []string{}
	}
	return out, err
}

func (r *ModuleRepository) ListByProjectID(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	var out []string
	err := withInternal(ctx, r.pool, func(tx pgx.Tx) error {
		return scanModuleNames(ctx, tx, projectID, &out)
	})
	if out == nil && err == nil {
		out = []string{}
	}
	return out, err
}

func scanModuleNames(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, out *[]string) error {
	rows, err := tx.Query(ctx, `
		SELECT name FROM project.modules WHERE project_id = $1 ORDER BY name
	`, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		*out = append(*out, name)
	}
	return rows.Err()
}
