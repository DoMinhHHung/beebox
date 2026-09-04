package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OAuthProviderRepository struct {
	pool *pgxpool.Pool
}

func NewOAuthProviderRepository(pool *pgxpool.Pool) *OAuthProviderRepository {
	return &OAuthProviderRepository{pool: pool}
}

func (r *OAuthProviderRepository) Upsert(ctx context.Context, ownerID uuid.UUID, provider domain.OAuthProvider) error {
	extra, err := json.Marshal(provider.Extra)
	if extra == nil || err != nil {
		extra = []byte("{}")
	}
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project.oauth_providers (id, project_id, slug, client_id, client_secret_enc, extra, redirect_uri, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (project_id, slug) DO UPDATE SET
  client_id = EXCLUDED.client_id,
  client_secret_enc = CASE WHEN EXCLUDED.client_secret_enc = '' THEN project.oauth_providers.client_secret_enc ELSE EXCLUDED.client_secret_enc END,
  extra = EXCLUDED.extra,
  redirect_uri = EXCLUDED.redirect_uri,
  enabled = EXCLUDED.enabled
`, provider.ID, provider.ProjectID, provider.Slug, provider.ClientID, provider.SecretEnc, extra, provider.RedirectURI, provider.Enabled)
		return mapWriteErr(err)
	})
}

func (r *OAuthProviderRepository) Find(ctx context.Context, ownerID, projectID uuid.UUID, slug string) (domain.OAuthProvider, error) {
	var item domain.OAuthProvider
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		return scanOAuth(ctx, tx, projectID, slug, &item)
	})
	return item, err
}

func (r *OAuthProviderRepository) FindByProject(ctx context.Context, projectID uuid.UUID, slug string) (domain.OAuthProvider, error) {
	var item domain.OAuthProvider
	err := withInternal(ctx, r.pool, func(tx pgx.Tx) error {
		return scanOAuth(ctx, tx, projectID, slug, &item)
	})
	return item, err
}

func scanOAuth(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, slug string, item *domain.OAuthProvider) error {
	var extra []byte
	err := tx.QueryRow(ctx, `
SELECT id, project_id, slug, client_id, client_secret_enc, extra, redirect_uri, enabled
FROM project.oauth_providers
WHERE project_id = $1 AND slug = $2
`, projectID, slug).Scan(&item.ID, &item.ProjectID, &item.Slug, &item.ClientID, &item.SecretEnc, &extra, &item.RedirectURI, &item.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	item.SecretConfigured = item.SecretEnc != ""
	item.Extra = map[string]string{}
	if len(extra) > 0 {
		_ = json.Unmarshal(extra, &item.Extra)
	}
	return nil
}
