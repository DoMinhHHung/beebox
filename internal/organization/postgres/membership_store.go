package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/organization"
	"github.com/jackc/pgx/v5/pgconn"
)

const membershipTupleConstraint = "organization_memberships_application_organization_user_key"

func (s *Store) CreateMembership(ctx context.Context, current organization.MutationContext, organizationID organization.ID, userPublicID identity.PublicID) (organization.Membership, error) {
	if err := ctx.Err(); err != nil {
		return organization.Membership{}, err
	}
	if s == nil || s.pool == nil || !current.Valid() || !organizationID.Valid() || !userPublicID.Valid() {
		return organization.Membership{}, organization.ErrPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return organization.Membership{}, classifyMembershipError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var item organization.Membership
	var applicationID, targetUserID int64
	err = tx.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT o.id AS organization_id,u.id AS user_id
			FROM organizations o
			JOIN users u ON u.application_instance_id=$1 AND u.public_id=$3
			WHERE o.application_instance_id=$1 AND o.opaque_id=$2::uuid
		), inserted AS (
			INSERT INTO organization_memberships(application_instance_id,organization_id,user_id)
			SELECT $1,organization_id,user_id FROM candidate
			RETURNING opaque_id::text,application_instance_id,user_id,created_at
		)
		SELECT opaque_id,application_instance_id,user_id,created_at FROM inserted`,
		int64(current.ApplicationInstanceID), string(organizationID), string(userPublicID),
	).Scan(&item.ID, &applicationID, &targetUserID, &item.CreatedAt)
	if err != nil {
		return organization.Membership{}, classifyMembershipError(ctx, err)
	}
	item.ApplicationInstanceID = applicationinstance.InternalID(applicationID)
	item.OrganizationID = organizationID
	item.UserPublicID = userPublicID
	item.CreatedAt = item.CreatedAt.UTC()
	if !item.ID.Valid() || item.ApplicationInstanceID != current.ApplicationInstanceID || !identity.InternalID(targetUserID).Valid() {
		return organization.Membership{}, organization.ErrPersistence
	}

	if err := insertMembershipAudit(ctx, tx, current, identity.InternalID(targetUserID), audit.ActionOrganizationMembershipCreated, organizationID); err != nil {
		return organization.Membership{}, classifyMembershipError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return organization.Membership{}, classifyMembershipError(ctx, err)
	}
	return item, nil
}

func (s *Store) GetMembership(ctx context.Context, applicationID applicationinstance.InternalID, membershipID organization.MembershipID) (organization.Membership, error) {
	if err := ctx.Err(); err != nil {
		return organization.Membership{}, err
	}
	if s == nil || s.pool == nil || !applicationID.Valid() || !membershipID.Valid() {
		return organization.Membership{}, organization.ErrPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	var item organization.Membership
	var storedApplicationID int64
	err := db.QueryRowContext(ctx, `
		SELECT m.opaque_id::text,m.application_instance_id,o.opaque_id::text,u.public_id,m.created_at
		FROM organization_memberships m
		JOIN organizations o
		  ON o.application_instance_id=m.application_instance_id AND o.id=m.organization_id
		JOIN users u
		  ON u.application_instance_id=m.application_instance_id AND u.id=m.user_id
		WHERE m.application_instance_id=$1 AND m.opaque_id=$2::uuid`,
		int64(applicationID), string(membershipID),
	).Scan(&item.ID, &storedApplicationID, &item.OrganizationID, &item.UserPublicID, &item.CreatedAt)
	if err != nil {
		return organization.Membership{}, classifyMembershipError(ctx, err)
	}
	item.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationID)
	item.CreatedAt = item.CreatedAt.UTC()
	if item.ApplicationInstanceID != applicationID || !item.ID.Valid() || !item.OrganizationID.Valid() || !item.UserPublicID.Valid() {
		return organization.Membership{}, organization.ErrPersistence
	}
	return item, nil
}

func (s *Store) RemoveMembership(ctx context.Context, current organization.MutationContext, membershipID organization.MembershipID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil || !current.Valid() || !membershipID.Valid() {
		return organization.ErrPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyMembershipError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var membershipInternalID int64
	var organizationID organization.ID
	var targetUserID int64
	err = tx.QueryRowContext(ctx, `
		SELECT m.id,o.opaque_id::text,m.user_id
		FROM organization_memberships m
		JOIN organizations o
		  ON o.application_instance_id=m.application_instance_id AND o.id=m.organization_id
		WHERE m.application_instance_id=$1 AND m.opaque_id=$2::uuid
		FOR UPDATE OF m`,
		int64(current.ApplicationInstanceID), string(membershipID),
	).Scan(&membershipInternalID, &organizationID, &targetUserID)
	if err != nil {
		return classifyMembershipError(ctx, err)
	}
	if membershipInternalID <= 0 || !organizationID.Valid() || !identity.InternalID(targetUserID).Valid() {
		return organization.ErrPersistence
	}

	// Role assignment is subordinate current membership authority. P3.3 keeps
	// the FK restrictive (NO ACTION) and removes the assignment explicitly in
	// this same transaction rather than introducing cascade lifecycle semantics.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM organization_membership_role_assignments
		WHERE application_instance_id=$1 AND membership_id=$2`,
		int64(current.ApplicationInstanceID), membershipInternalID); err != nil {
		return classifyMembershipError(ctx, err)
	}

	result, err := tx.ExecContext(ctx, `
		DELETE FROM organization_memberships
		WHERE application_instance_id=$1 AND id=$2`,
		int64(current.ApplicationInstanceID), membershipInternalID)
	if err != nil {
		return classifyMembershipError(ctx, err)
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return organization.ErrPersistence
	}
	if err := insertMembershipAudit(ctx, tx, current, identity.InternalID(targetUserID), audit.ActionOrganizationMembershipRemoved, organizationID); err != nil {
		return classifyMembershipError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyMembershipError(ctx, err)
	}
	return nil
}

func (s *Store) ResolveActiveOrganization(ctx context.Context, applicationID applicationinstance.InternalID, userPublicID identity.PublicID, organizationID organization.ID) (organization.ActiveOrganization, error) {
	if err := ctx.Err(); err != nil {
		return organization.ActiveOrganization{}, err
	}
	if s == nil || s.pool == nil || !applicationID.Valid() || !userPublicID.Valid() || !organizationID.Valid() {
		return organization.ActiveOrganization{}, organization.ErrPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	var active organization.ActiveOrganization
	var storedApplicationID int64
	err := db.QueryRowContext(ctx, `
		SELECT o.opaque_id::text,o.application_instance_id,o.name,o.slug,o.created_at,o.updated_at,
		       m.opaque_id::text,u.public_id
		FROM organization_memberships m
		JOIN organizations o
		  ON o.application_instance_id=m.application_instance_id AND o.id=m.organization_id
		JOIN users u
		  ON u.application_instance_id=m.application_instance_id AND u.id=m.user_id
		WHERE m.application_instance_id=$1
		  AND o.opaque_id=$2::uuid
		  AND u.public_id=$3`,
		int64(applicationID), string(organizationID), string(userPublicID),
	).Scan(
		&active.Organization.ID,
		&storedApplicationID,
		&active.Organization.Name,
		&active.Organization.Slug,
		&active.Organization.CreatedAt,
		&active.Organization.UpdatedAt,
		&active.MembershipID,
		&active.UserPublicID,
	)
	if err != nil {
		return organization.ActiveOrganization{}, classifyMembershipError(ctx, err)
	}
	active.Organization.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationID)
	active.Organization.CreatedAt = active.Organization.CreatedAt.UTC()
	active.Organization.UpdatedAt = active.Organization.UpdatedAt.UTC()
	if active.Organization.ApplicationInstanceID != applicationID || active.Organization.ID != organizationID || active.UserPublicID != userPublicID || !active.MembershipID.Valid() {
		return organization.ActiveOrganization{}, organization.ErrPersistence
	}
	return active, nil
}

func insertMembershipAudit(ctx context.Context, tx *sql.Tx, current organization.MutationContext, targetUserID identity.InternalID, action string, organizationID organization.ID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			application_instance_id,actor_kind,actor_user_id,subject_user_id,
			action,resource_category,resource_reference,outcome,correlation_id,source
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		int64(current.ApplicationInstanceID), audit.ActorKindUser, int64(current.ActorUserID), int64(targetUserID),
		action, audit.ResourceCategoryOrganizationMembership, string(organizationID), audit.OutcomeSuccess,
		current.CorrelationID[:], audit.SourceInternalOrganization)
	return err
}

func classifyMembershipError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, sql.ErrNoRows) {
		return organization.ErrMembershipNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == membershipTupleConstraint {
		return organization.ErrMembershipUnavailable
	}
	if errors.Is(err, organization.ErrMembershipNotFound) || errors.Is(err, organization.ErrMembershipUnavailable) {
		return err
	}
	return organization.ErrPersistence
}
