package postgres

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type APIKeyRepository struct {
	pool *pgxpool.Pool
}

func NewAPIKeyRepository(pool *pgxpool.Pool) *APIKeyRepository {
	return &APIKeyRepository{pool: pool}
}

func (r *APIKeyRepository) Create(ctx context.Context, ownerID uuid.UUID, key domain.APIKey) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		return insertAPIKey(ctx, tx, key)
	})
}

func insertAPIKey(ctx context.Context, tx pgx.Tx, key domain.APIKey) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO project.api_keys (id, project_id, prefix, secret_hash, kind, env)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, key.ID, key.ProjectID, key.Prefix, key.SecretHash, key.Kind, key.Env)
	return mapWriteErr(err)
}

func (r *APIKeyRepository) ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.APIKey, error) {
	var out []domain.APIKey
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, project_id, prefix, secret_hash, kind, env, created_at, revoked_at
			FROM project.api_keys
			WHERE project_id = $1
			ORDER BY created_at
		`, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			k, err := scanAPIKey(rows)
			if err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	if out == nil && err == nil {
		out = []domain.APIKey{}
	}
	return out, err
}

func (r *APIKeyRepository) Revoke(ctx context.Context, ownerID, projectID, keyID uuid.UUID) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE project.api_keys
			SET revoked_at = now()
			WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL
		`, keyID, projectID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *APIKeyRepository) FindActiveByHash(ctx context.Context, secretHash string) (domain.APIKey, domain.Project, error) {
	var key domain.APIKey
	var project domain.Project
	err := withInternal(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT
				k.id, k.project_id, k.prefix, k.secret_hash, k.kind, k.env, k.created_at, k.revoked_at,
				p.id, p.owner_id, p.plan_id, p.plan_slug, p.name, p.slug, p.env, p.status, p.updated_at
			FROM project.api_keys k
			JOIN project.projects p ON p.id = k.project_id
			WHERE k.secret_hash = $1 AND k.revoked_at IS NULL
		`, secretHash)
		err := row.Scan(
			&key.ID, &key.ProjectID, &key.Prefix, &key.SecretHash, &key.Kind, &key.Env, &key.CreatedAt, &key.RevokedAt,
			&project.ID, &project.OwnerID, &project.PlanID, &project.PlanSlug, &project.Name, &project.Slug, &project.Env, &project.Status, &project.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	})
	return key, project, err
}

func scanAPIKey(s scanner) (domain.APIKey, error) {
	var k domain.APIKey
	err := s.Scan(&k.ID, &k.ProjectID, &k.Prefix, &k.SecretHash, &k.Kind, &k.Env, &k.CreatedAt, &k.RevokedAt)
	return k, err
}
