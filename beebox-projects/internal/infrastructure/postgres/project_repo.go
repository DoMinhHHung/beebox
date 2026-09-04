package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProjectRepository struct {
	pool *pgxpool.Pool
}

func NewProjectRepository(pool *pgxpool.Pool) *ProjectRepository {
	return &ProjectRepository{pool: pool}
}

func (r *ProjectRepository) Create(ctx context.Context, ownerID uuid.UUID, project domain.Project) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO project.projects (id, owner_id, plan_id, plan_slug, name, slug, env, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, project.ID, project.OwnerID, project.PlanID, project.PlanSlug, project.Name, project.Slug, project.Env, project.Status)
		return mapWriteErr(err)
	})
}

func (r *ProjectRepository) List(ctx context.Context, ownerID uuid.UUID) ([]domain.Project, error) {
	var out []domain.Project
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, owner_id, plan_id, plan_slug, name, slug, env, status
			FROM project.projects
			ORDER BY slug
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanProject(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if out == nil && err == nil {
		out = []domain.Project{}
	}
	return out, err
}

func (r *ProjectRepository) FindByID(ctx context.Context, ownerID, id uuid.UUID) (domain.Project, error) {
	var project domain.Project
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT id, owner_id, plan_id, plan_slug, name, slug, env, status
			FROM project.projects
			WHERE id = $1
		`, id)
		p, err := scanProject(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		project = p
		return err
	})
	return project, err
}

func (r *ProjectRepository) Update(ctx context.Context, ownerID uuid.UUID, project domain.Project) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE project.projects
			SET plan_id = $2,
			    plan_slug = $3,
			    name = $4,
			    slug = $5,
			    status = $6,
			    updated_at = now()
			WHERE id = $1
		`, project.ID, project.PlanID, project.PlanSlug, project.Name, project.Slug, project.Status)
		if err != nil {
			return mapWriteErr(err)
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *ProjectRepository) Delete(ctx context.Context, ownerID, id uuid.UUID) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM project.projects WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

type scanner interface {
	Scan(dest ...any) error
}

func scanProject(s scanner) (domain.Project, error) {
	var p domain.Project
	err := s.Scan(&p.ID, &p.OwnerID, &p.PlanID, &p.PlanSlug, &p.Name, &p.Slug, &p.Env, &p.Status)
	return p, err
}
