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

const (
	roleKeyConstraint             = "organization_role_definitions_application_key_key"
	permissionKeyConstraint       = "organization_permission_definitions_application_key_key"
	permissionResourceConstraint  = "organization_permission_definitions_app_resource_action_key"
	rolePermissionGrantConstraint = "organization_role_permission_grants_pkey"
)

func (s *Store) CreateRoleDefinition(ctx context.Context, current organization.MutationContext, key string) (organization.RoleDefinition, error) {
	if err := ctx.Err(); err != nil {
		return organization.RoleDefinition{}, err
	}
	if s == nil || s.pool == nil || !current.Valid() || key == "" {
		return organization.RoleDefinition{}, organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return organization.RoleDefinition{}, classifyAuthorizationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var item organization.RoleDefinition
	var appID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO organization_role_definitions(application_instance_id,role_key)
		VALUES($1,$2)
		RETURNING opaque_id::text,application_instance_id,role_key,created_at`,
		int64(current.ApplicationInstanceID), key,
	).Scan(&item.ID, &appID, &item.Key, &item.CreatedAt)
	if err != nil {
		if isConstraint(err, roleKeyConstraint) {
			return organization.RoleDefinition{}, organization.ErrRoleUnavailable
		}
		return organization.RoleDefinition{}, classifyAuthorizationError(ctx, err)
	}
	item.ApplicationInstanceID = applicationinstance.InternalID(appID)
	item.CreatedAt = item.CreatedAt.UTC()
	if !item.ID.Valid() || item.ApplicationInstanceID != current.ApplicationInstanceID || item.Key != key {
		return organization.RoleDefinition{}, organization.ErrAuthorizationPersistence
	}
	if err := insertAuthorizationAudit(ctx, tx, current, nil, audit.ActionOrganizationRoleDefinitionCreated, audit.ResourceCategoryOrganizationRoleDefinition, string(item.ID), "", ""); err != nil {
		return organization.RoleDefinition{}, classifyAuthorizationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return organization.RoleDefinition{}, classifyAuthorizationError(ctx, err)
	}
	return item, nil
}

func (s *Store) CreatePermissionDefinition(ctx context.Context, current organization.MutationContext, key, resource, action string) (organization.PermissionDefinition, error) {
	if err := ctx.Err(); err != nil {
		return organization.PermissionDefinition{}, err
	}
	if s == nil || s.pool == nil || !current.Valid() || key == "" || resource == "" || action == "" {
		return organization.PermissionDefinition{}, organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return organization.PermissionDefinition{}, classifyAuthorizationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var item organization.PermissionDefinition
	var appID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO organization_permission_definitions(application_instance_id,permission_key,resource_key,action_key)
		VALUES($1,$2,$3,$4)
		RETURNING opaque_id::text,application_instance_id,permission_key,resource_key,action_key,created_at`,
		int64(current.ApplicationInstanceID), key, resource, action,
	).Scan(&item.ID, &appID, &item.Key, &item.Resource, &item.Action, &item.CreatedAt)
	if err != nil {
		if isConstraint(err, permissionKeyConstraint) || isConstraint(err, permissionResourceConstraint) {
			return organization.PermissionDefinition{}, organization.ErrPermissionUnavailable
		}
		return organization.PermissionDefinition{}, classifyAuthorizationError(ctx, err)
	}
	item.ApplicationInstanceID = applicationinstance.InternalID(appID)
	item.CreatedAt = item.CreatedAt.UTC()
	if !item.ID.Valid() || item.ApplicationInstanceID != current.ApplicationInstanceID || item.Key != key || item.Resource != resource || item.Action != action {
		return organization.PermissionDefinition{}, organization.ErrAuthorizationPersistence
	}
	if err := insertAuthorizationAudit(ctx, tx, current, nil, audit.ActionOrganizationPermissionDefinitionCreated, audit.ResourceCategoryOrganizationPermission, string(item.ID), "", ""); err != nil {
		return organization.PermissionDefinition{}, classifyAuthorizationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return organization.PermissionDefinition{}, classifyAuthorizationError(ctx, err)
	}
	return item, nil
}

func (s *Store) GrantPermissionToRole(ctx context.Context, current organization.MutationContext, roleID organization.RoleID, permissionID organization.PermissionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil || !current.Valid() || !roleID.Valid() || !permissionID.Valid() {
		return organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var roleInternalID, permissionInternalID int64
	var roleReference, permissionReference string
	err = tx.QueryRowContext(ctx, `
		SELECT r.id,r.opaque_id::text,p.id,p.opaque_id::text
		FROM organization_role_definitions r
		JOIN organization_permission_definitions p ON p.application_instance_id=$1 AND p.opaque_id=$3::uuid
		WHERE r.application_instance_id=$1 AND r.opaque_id=$2::uuid`,
		int64(current.ApplicationInstanceID), string(roleID), string(permissionID),
	).Scan(&roleInternalID, &roleReference, &permissionInternalID, &permissionReference)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return organization.ErrGrantNotFound
		}
		return classifyAuthorizationError(ctx, err)
	}
	if roleReference != string(roleID) || permissionReference != string(permissionID) {
		return organization.ErrAuthorizationPersistence
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO organization_role_permission_grants(application_instance_id,role_definition_id,permission_definition_id)
		VALUES($1,$2,$3)`, int64(current.ApplicationInstanceID), roleInternalID, permissionInternalID)
	if err != nil {
		if isConstraint(err, rolePermissionGrantConstraint) {
			return organization.ErrGrantUnavailable
		}
		return classifyAuthorizationError(ctx, err)
	}
	if err := insertAuthorizationAudit(ctx, tx, current, nil, audit.ActionOrganizationRolePermissionGranted, audit.ResourceCategoryOrganizationRolePermission, roleReference, "", permissionReference); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	return nil
}

func (s *Store) RevokePermissionFromRole(ctx context.Context, current organization.MutationContext, roleID organization.RoleID, permissionID organization.PermissionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil || !current.Valid() || !roleID.Valid() || !permissionID.Valid() {
		return organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var roleInternalID, permissionInternalID int64
	err = tx.QueryRowContext(ctx, `
		SELECT r.id,p.id
		FROM organization_role_definitions r
		JOIN organization_permission_definitions p ON p.application_instance_id=$1 AND p.opaque_id=$3::uuid
		JOIN organization_role_permission_grants g
		  ON g.application_instance_id=$1 AND g.role_definition_id=r.id AND g.permission_definition_id=p.id
		WHERE r.application_instance_id=$1 AND r.opaque_id=$2::uuid`,
		int64(current.ApplicationInstanceID), string(roleID), string(permissionID),
	).Scan(&roleInternalID, &permissionInternalID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return organization.ErrGrantNotFound
		}
		return classifyAuthorizationError(ctx, err)
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM organization_role_permission_grants
		WHERE application_instance_id=$1 AND role_definition_id=$2 AND permission_definition_id=$3`,
		int64(current.ApplicationInstanceID), roleInternalID, permissionInternalID)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return organization.ErrAuthorizationPersistence
	}
	if err := insertAuthorizationAudit(ctx, tx, current, nil, audit.ActionOrganizationRolePermissionRevoked, audit.ResourceCategoryOrganizationRolePermission, string(roleID), "", string(permissionID)); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	return nil
}

func (s *Store) SetMembershipRole(ctx context.Context, current organization.MutationContext, membershipID organization.MembershipID, roleID organization.RoleID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil || !current.Valid() || !membershipID.Valid() || !roleID.Valid() {
		return organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var membershipInternalID, targetUserID, roleInternalID int64
	var organizationReference string
	err = tx.QueryRowContext(ctx, `
		SELECT m.id,m.user_id,o.opaque_id::text,r.id
		FROM organization_memberships m
		JOIN organizations o
		  ON o.application_instance_id=m.application_instance_id AND o.id=m.organization_id
		JOIN organization_role_definitions r
		  ON r.application_instance_id=$1 AND r.opaque_id=$3::uuid
		WHERE m.application_instance_id=$1 AND m.opaque_id=$2::uuid
		FOR UPDATE OF m`, int64(current.ApplicationInstanceID), string(membershipID), string(roleID),
	).Scan(&membershipInternalID, &targetUserID, &organizationReference, &roleInternalID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return organization.ErrAssignmentNotFound
		}
		return classifyAuthorizationError(ctx, err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO organization_membership_role_assignments(application_instance_id,membership_id,role_definition_id)
		VALUES($1,$2,$3)
		ON CONFLICT (application_instance_id,membership_id)
		DO UPDATE SET role_definition_id=EXCLUDED.role_definition_id,updated_at=CURRENT_TIMESTAMP`,
		int64(current.ApplicationInstanceID), membershipInternalID, roleInternalID)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	if err := insertAuthorizationAudit(ctx, tx, current, ptrInternalID(identity.InternalID(targetUserID)), audit.ActionOrganizationMembershipRoleSet, audit.ResourceCategoryOrganizationMembershipRole, string(membershipID), organizationReference, string(roleID)); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	return nil
}

func (s *Store) ClearMembershipRole(ctx context.Context, current organization.MutationContext, membershipID organization.MembershipID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil || !current.Valid() || !membershipID.Valid() {
		return organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var membershipInternalID, targetUserID int64
	var organizationReference, roleReference string
	err = tx.QueryRowContext(ctx, `
		SELECT m.id,m.user_id,o.opaque_id::text,r.opaque_id::text
		FROM organization_memberships m
		JOIN organizations o
		  ON o.application_instance_id=m.application_instance_id AND o.id=m.organization_id
		JOIN organization_membership_role_assignments a
		  ON a.application_instance_id=m.application_instance_id AND a.membership_id=m.id
		JOIN organization_role_definitions r
		  ON r.application_instance_id=a.application_instance_id AND r.id=a.role_definition_id
		WHERE m.application_instance_id=$1 AND m.opaque_id=$2::uuid
		FOR UPDATE OF m`, int64(current.ApplicationInstanceID), string(membershipID),
	).Scan(&membershipInternalID, &targetUserID, &organizationReference, &roleReference)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return organization.ErrAssignmentNotFound
		}
		return classifyAuthorizationError(ctx, err)
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM organization_membership_role_assignments
		WHERE application_instance_id=$1 AND membership_id=$2`, int64(current.ApplicationInstanceID), membershipInternalID)
	if err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return organization.ErrAuthorizationPersistence
	}
	if err := insertAuthorizationAudit(ctx, tx, current, ptrInternalID(identity.InternalID(targetUserID)), audit.ActionOrganizationMembershipRoleCleared, audit.ResourceCategoryOrganizationMembershipRole, string(membershipID), organizationReference, roleReference); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyAuthorizationError(ctx, err)
	}
	return nil
}

func (s *Store) CheckOrganizationAuthorization(ctx context.Context, applicationID applicationinstance.InternalID, userPublicID identity.PublicID, organizationID organization.ID, resource, action string) (organization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return organization.DecisionDeny, err
	}
	if s == nil || s.pool == nil || !applicationID.Valid() || !userPublicID.Valid() || !organizationID.Valid() || resource == "" || action == "" {
		return organization.DecisionDeny, organization.ErrAuthorizationPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var allowed bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM organizations o
			JOIN users u ON u.application_instance_id=$1 AND u.public_id=$3
			JOIN organization_memberships m
			  ON m.application_instance_id=$1 AND m.organization_id=o.id AND m.user_id=u.id
			JOIN organization_membership_role_assignments a
			  ON a.application_instance_id=m.application_instance_id AND a.membership_id=m.id
			JOIN organization_role_definitions r
			  ON r.application_instance_id=a.application_instance_id AND r.id=a.role_definition_id
			JOIN organization_role_permission_grants g
			  ON g.application_instance_id=r.application_instance_id AND g.role_definition_id=r.id
			JOIN organization_permission_definitions p
			  ON p.application_instance_id=g.application_instance_id AND p.id=g.permission_definition_id
			WHERE o.application_instance_id=$1
			  AND o.opaque_id=$2::uuid
			  AND p.resource_key=$4
			  AND p.action_key=$5
		)`, int64(applicationID), string(organizationID), string(userPublicID), resource, action,
	).Scan(&allowed)
	if err != nil {
		return organization.DecisionDeny, classifyAuthorizationError(ctx, err)
	}
	if allowed {
		return organization.DecisionAllow, nil
	}
	return organization.DecisionDeny, nil
}

func insertAuthorizationAudit(ctx context.Context, tx *sql.Tx, current organization.MutationContext, subjectUserID *identity.InternalID, action, category, resourceReference, organizationReference, relatedReference string) error {
	var subject any
	if subjectUserID != nil {
		subject = int64(*subjectUserID)
	}
	var organizationValue, relatedValue any
	if organizationReference != "" {
		organizationValue = organizationReference
	}
	if relatedReference != "" {
		relatedValue = relatedReference
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			application_instance_id,actor_kind,actor_user_id,subject_user_id,
			action,resource_category,resource_reference,organization_reference,
			related_resource_reference,outcome,correlation_id,source
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		int64(current.ApplicationInstanceID), audit.ActorKindUser, int64(current.ActorUserID), subject,
		action, category, resourceReference, organizationValue, relatedValue, audit.OutcomeSuccess,
		current.CorrelationID[:], audit.SourceInternalOrganization)
	return err
}

func classifyAuthorizationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return organization.ErrAuthorizationPersistence
}

func isConstraint(err error, name string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == name
}

func ptrInternalID(value identity.InternalID) *identity.InternalID { return &value }
