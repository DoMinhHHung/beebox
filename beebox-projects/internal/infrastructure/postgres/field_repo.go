package postgres

import (
	"context"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FieldRepository struct {
	pool *pgxpool.Pool
}

func NewFieldRepository(pool *pgxpool.Pool) *FieldRepository {
	return &FieldRepository{pool: pool}
}

func (r *FieldRepository) Replace(ctx context.Context, ownerID, projectID uuid.UUID, fields []domain.Field) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM project.fields WHERE project_id = $1`, projectID); err != nil {
			return err
		}
		for _, field := range fields {
			if _, err := tx.Exec(ctx, `
INSERT INTO project.fields (id, project_id, name, type, required, unique_per_project, sort_order)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, field.ID, projectID, field.Name, field.Type, field.Required, field.UniquePerProject, field.SortOrder); err != nil {
				return mapWriteErr(err)
			}
		}
		return nil
	})
}

func (r *FieldRepository) ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.Field, error) {
	var out []domain.Field
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		return scanFields(ctx, tx, projectID, &out)
	})
	if out == nil && err == nil {
		out = []domain.Field{}
	}
	return out, err
}

func (r *FieldRepository) ListByProjectID(ctx context.Context, projectID uuid.UUID) ([]domain.Field, error) {
	var out []domain.Field
	err := withInternal(ctx, r.pool, func(tx pgx.Tx) error {
		return scanFields(ctx, tx, projectID, &out)
	})
	if out == nil && err == nil {
		out = []domain.Field{}
	}
	return out, err
}

func scanFields(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, out *[]domain.Field) error {
	rows, err := tx.Query(ctx, `
SELECT id, project_id, name, type, required, unique_per_project, sort_order
FROM project.fields
WHERE project_id = $1
ORDER BY sort_order, name
`, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var field domain.Field
		if err := rows.Scan(&field.ID, &field.ProjectID, &field.Name, &field.Type, &field.Required, &field.UniquePerProject, &field.SortOrder); err != nil {
			return err
		}
		*out = append(*out, field)
	}
	return rows.Err()
}
