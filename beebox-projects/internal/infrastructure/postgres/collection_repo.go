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

type CollectionRepository struct{ pool *pgxpool.Pool }

func NewCollectionRepository(pool *pgxpool.Pool) *CollectionRepository {
	return &CollectionRepository{pool: pool}
}

func (r *CollectionRepository) Create(ctx context.Context, ownerID uuid.UUID, collection domain.Collection) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project.collections (id, project_id, name, slug, created_at)
VALUES ($1, $2, $3, $4, $5)
`, collection.ID, collection.ProjectID, collection.Name, collection.Slug, collection.CreatedAt)
		return mapWriteErr(err)
	})
}

func (r *CollectionRepository) ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]domain.Collection, error) {
	var out []domain.Collection
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT id, project_id, name, slug, created_at
FROM project.collections WHERE project_id = $1 ORDER BY created_at, name
`, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item domain.Collection
			if err := rows.Scan(&item.ID, &item.ProjectID, &item.Name, &item.Slug, &item.CreatedAt); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if out == nil && err == nil {
		out = []domain.Collection{}
	}
	return out, err
}

func (r *CollectionRepository) Find(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) (domain.Collection, error) {
	var item domain.Collection
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
SELECT id, project_id, name, slug, created_at
FROM project.collections WHERE project_id = $1 AND id = $2
`, projectID, collectionID).Scan(&item.ID, &item.ProjectID, &item.Name, &item.Slug, &item.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	})
	return item, err
}

func (r *CollectionRepository) CountByProject(ctx context.Context, ownerID, projectID uuid.UUID) (int, error) {
	var n int
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM project.collections WHERE project_id = $1`, projectID).Scan(&n)
	})
	return n, err
}

type DocumentRepository struct{ pool *pgxpool.Pool }

func NewDocumentRepository(pool *pgxpool.Pool) *DocumentRepository {
	return &DocumentRepository{pool: pool}
}

type rowScanner interface{ Scan(dest ...any) error }

func scanDocument(row rowScanner) (domain.Document, error) {
	var doc domain.Document
	var raw []byte
	if err := row.Scan(&doc.ID, &doc.ProjectID, &doc.CollectionID, &raw, &doc.CreatedAt, &doc.UpdatedAt); err != nil {
		return domain.Document{}, err
	}
	if len(raw) == 0 {
		doc.Data = map[string]any{}
		return doc, nil
	}
	if err := json.Unmarshal(raw, &doc.Data); err != nil {
		return domain.Document{}, err
	}
	if doc.Data == nil {
		doc.Data = map[string]any{}
	}
	return doc, nil
}

func (r *DocumentRepository) Create(ctx context.Context, ownerID uuid.UUID, doc domain.Document) error {
	raw, err := json.Marshal(doc.Data)
	if err != nil {
		return domain.ErrInvalidInput
	}
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project.documents (id, project_id, collection_id, data, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
`, doc.ID, doc.ProjectID, doc.CollectionID, raw, doc.CreatedAt, doc.UpdatedAt)
		return mapWriteErr(err)
	})
}

func (r *DocumentRepository) ListByCollection(ctx context.Context, ownerID, projectID, collectionID uuid.UUID) ([]domain.Document, error) {
	var out []domain.Document
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT id, project_id, collection_id, data, created_at, updated_at
FROM project.documents WHERE project_id = $1 AND collection_id = $2 ORDER BY created_at
`, projectID, collectionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			doc, err := scanDocument(rows)
			if err != nil {
				return err
			}
			out = append(out, doc)
		}
		return rows.Err()
	})
	if out == nil && err == nil {
		out = []domain.Document{}
	}
	return out, err
}

func (r *DocumentRepository) Find(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID) (domain.Document, error) {
	var doc domain.Document
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		item, err := scanDocument(tx.QueryRow(ctx, `
SELECT id, project_id, collection_id, data, created_at, updated_at
FROM project.documents WHERE project_id = $1 AND collection_id = $2 AND id = $3
`, projectID, collectionID, documentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		doc = item
		return nil
	})
	return doc, err
}

func (r *DocumentRepository) Update(ctx context.Context, ownerID uuid.UUID, doc domain.Document) error {
	raw, err := json.Marshal(doc.Data)
	if err != nil {
		return domain.ErrInvalidInput
	}
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
UPDATE project.documents SET data = $1, updated_at = $2
WHERE project_id = $3 AND collection_id = $4 AND id = $5
`, raw, doc.UpdatedAt, doc.ProjectID, doc.CollectionID, doc.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *DocumentRepository) Delete(ctx context.Context, ownerID, projectID, collectionID, documentID uuid.UUID) error {
	return withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
DELETE FROM project.documents WHERE project_id = $1 AND collection_id = $2 AND id = $3
`, projectID, collectionID, documentID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *DocumentRepository) CountByProject(ctx context.Context, ownerID, projectID uuid.UUID) (int, error) {
	var n int
	err := withOwner(ctx, r.pool, ownerID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM project.documents WHERE project_id = $1`, projectID).Scan(&n)
	})
	return n, err
}
