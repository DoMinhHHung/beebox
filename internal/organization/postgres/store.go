package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/organization"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/jackc/pgx/v5/pgconn"
)

const organizationSlugConstraint = "organizations_application_slug_key"

type Store struct {
	pool *database.Pool
}

func New(pool *database.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(ctx context.Context, current organization.MutationContext, name, slug string) (organization.Organization, error) {
	if err := ctx.Err(); err != nil {
		return organization.Organization{}, err
	}
	if s == nil || s.pool == nil || !current.Valid() || name == "" || slug == "" {
		return organization.Organization{}, organization.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	item, err := insertOrganization(ctx, tx, current.ApplicationInstanceID, name, slug)
	if err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	if err := insertAudit(ctx, tx, current, audit.ActionOrganizationCreated, item.ID); err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	return item, nil
}

func (s *Store) Get(ctx context.Context, applicationID applicationinstance.InternalID, id organization.ID) (organization.Organization, error) {
	if err := ctx.Err(); err != nil {
		return organization.Organization{}, err
	}
	if s == nil || s.pool == nil || !applicationID.Valid() || !id.Valid() {
		return organization.Organization{}, organization.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	item, err := scanOrganization(db.QueryRowContext(ctx, `
		SELECT opaque_id::text,application_instance_id,name,slug,created_at,updated_at
		FROM organizations
		WHERE application_instance_id=$1 AND opaque_id=$2::uuid`, int64(applicationID), string(id)))
	if err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	return item, nil
}

func (s *Store) List(ctx context.Context, applicationID applicationinstance.InternalID, limit int, after *organization.ListPosition) ([]organization.Organization, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.pool == nil || !applicationID.Valid() || limit < 1 || limit > organization.ListMaxLimit+1 {
		return nil, organization.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()

	query := `SELECT opaque_id::text,application_instance_id,name,slug,created_at,updated_at
		FROM organizations WHERE application_instance_id=$1`
	args := []any{int64(applicationID)}
	if after != nil {
		if !after.ID.Valid() || after.CreatedAt.IsZero() {
			return nil, organization.ErrPersistence
		}
		query += ` AND (created_at,opaque_id)>($2,$3::uuid) ORDER BY created_at ASC,opaque_id ASC LIMIT $4`
		args = append(args, after.CreatedAt.UTC(), string(after.ID), limit)
	} else {
		query += ` ORDER BY created_at ASC,opaque_id ASC LIMIT $2`
		args = append(args, limit)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, classifyError(ctx, err)
	}
	defer rows.Close()
	items := make([]organization.Organization, 0, limit)
	for rows.Next() {
		item, err := scanOrganization(rows)
		if err != nil {
			return nil, classifyError(ctx, err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyError(ctx, err)
	}
	return items, nil
}

func (s *Store) Update(ctx context.Context, current organization.MutationContext, id organization.ID, name, slug string) (organization.Organization, error) {
	if err := ctx.Err(); err != nil {
		return organization.Organization{}, err
	}
	if s == nil || s.pool == nil || !current.Valid() || !id.Valid() || name == "" || slug == "" {
		return organization.Organization{}, organization.ErrPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	item, err := scanOrganization(tx.QueryRowContext(ctx, `
		UPDATE organizations
		SET name=$3,slug=$4,updated_at=CURRENT_TIMESTAMP
		WHERE application_instance_id=$1 AND opaque_id=$2::uuid
		RETURNING opaque_id::text,application_instance_id,name,slug,created_at,updated_at`,
		int64(current.ApplicationInstanceID), string(id), name, slug))
	if err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	if err := insertAudit(ctx, tx, current, audit.ActionOrganizationUpdated, item.ID); err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return organization.Organization{}, classifyError(ctx, err)
	}
	return item, nil
}

func insertOrganization(ctx context.Context, tx *sql.Tx, applicationID applicationinstance.InternalID, name, slug string) (organization.Organization, error) {
	return scanOrganization(tx.QueryRowContext(ctx, `
		INSERT INTO organizations(application_instance_id,name,slug)
		VALUES($1,$2,$3)
		RETURNING opaque_id::text,application_instance_id,name,slug,created_at,updated_at`,
		int64(applicationID), name, slug))
}

func insertAudit(ctx context.Context, tx *sql.Tx, current organization.MutationContext, action string, organizationID organization.ID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			application_instance_id,actor_kind,actor_user_id,subject_user_id,
			action,resource_category,resource_reference,outcome,correlation_id,source
		) VALUES($1,$2,$3,NULL,$4,$5,$6,$7,$8,$9)`,
		int64(current.ApplicationInstanceID), audit.ActorKindUser, int64(current.ActorUserID),
		action, audit.ResourceCategoryOrganization, string(organizationID), audit.OutcomeSuccess,
		current.CorrelationID[:], audit.SourceInternalOrganization)
	return err
}

type rowScanner interface {
	Scan(...any) error
}

func scanOrganization(row rowScanner) (organization.Organization, error) {
	var item organization.Organization
	var applicationID int64
	if err := row.Scan(&item.ID, &applicationID, &item.Name, &item.Slug, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return organization.Organization{}, err
	}
	item.ApplicationInstanceID = applicationinstance.InternalID(applicationID)
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	if !item.ApplicationInstanceID.Valid() || !item.ID.Valid() || item.Name == "" || item.Slug == "" {
		return organization.Organization{}, organization.ErrPersistence
	}
	return item, nil
}

func classifyError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, sql.ErrNoRows) {
		return organization.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == organizationSlugConstraint {
		return organization.ErrSlugUnavailable
	}
	if errors.Is(err, organization.ErrNotFound) || errors.Is(err, organization.ErrSlugUnavailable) {
		return err
	}
	return organization.ErrPersistence
}
