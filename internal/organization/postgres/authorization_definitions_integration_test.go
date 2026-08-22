//go:build integration

package postgres

import (
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/organization"
)

func TestOrganizationAuthorizationDefinitionsAreScopedUniqueAndDatabaseEnforced(t *testing.T) {
	f := newAuthorizationFixture(t)

	roleContext := mutationContext(t, f.appA.InternalID, f.actorA)
	adminA, err := f.authorization.CreateRoleDefinition(f.ctx, roleContext, " Admin ")
	if err != nil {
		t.Fatal(err)
	}
	if !adminA.ID.Valid() || adminA.Key != "admin" || adminA.ApplicationInstanceID != f.appA.InternalID {
		t.Fatalf("admin role=%#v", adminA)
	}
	adminB, err := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appB.InternalID, f.actorB), "admin")
	if err != nil {
		t.Fatalf("same role key in another application: %v", err)
	}
	if adminA.ID == adminB.ID {
		t.Fatal("independent applications reused role locator")
	}
	if _, err := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "ADMIN"); !errors.Is(err, organization.ErrRoleUnavailable) {
		t.Fatalf("same-app duplicate role error=%v", err)
	}
	assertConcurrentRoleCreation(t, f)

	permissionContext := mutationContext(t, f.appA.InternalID, f.actorA)
	readA, err := f.authorization.CreatePermissionDefinition(f.ctx, permissionContext, "organization.read", "organization", "read")
	if err != nil {
		t.Fatal(err)
	}
	writeA, err := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "organization.write", "organization", "write")
	if err != nil {
		t.Fatal(err)
	}
	readB, err := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appB.InternalID, f.actorB), "organization.read", "organization", "read")
	if err != nil {
		t.Fatalf("same permission vocabulary in another application: %v", err)
	}
	if readA.ID == readB.ID || !readA.ID.Valid() || readA.Resource != "organization" || readA.Action != "read" {
		t.Fatalf("permission definitions A=%#v B=%#v", readA, readB)
	}
	if _, err := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "organization.read", "organization", "inspect"); !errors.Is(err, organization.ErrPermissionUnavailable) {
		t.Fatalf("duplicate permission key error=%v", err)
	}
	if _, err := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "organization.observe", "organization", "read"); !errors.Is(err, organization.ErrPermissionUnavailable) {
		t.Fatalf("ambiguous resource/action error=%v", err)
	}

	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), adminA.ID, readA.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), adminA.ID, readA.ID); !errors.Is(err, organization.ErrGrantUnavailable) {
		t.Fatalf("duplicate grant error=%v", err)
	}
	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), adminA.ID, readB.ID); !errors.Is(err, organization.ErrGrantNotFound) {
		t.Fatalf("app-A role accepted app-B permission: %v", err)
	}
	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appB.InternalID, f.actorB), adminA.ID, readB.ID); !errors.Is(err, organization.ErrGrantNotFound) {
		t.Fatalf("app-B scope accepted app-A role: %v", err)
	}

	assertDatabaseRejectsAuthorizationCrossScope(t, f, adminA.ID, adminB.ID, readA.ID, readB.ID)
	assertAuthorizationAudit(t, f, roleContext, "organization.authorization.role.created", "organization_role_definition", string(adminA.ID), "", "", nil)
	assertAuthorizationAudit(t, f, permissionContext, "organization.authorization.permission.created", "organization_permission_definition", string(readA.ID), "", "", nil)
	_ = writeA
}

func assertDatabaseRejectsAuthorizationCrossScope(t *testing.T, f authorizationFixture, roleA, roleB organization.RoleID, permissionA, permissionB organization.PermissionID) {
	t.Helper()
	db := f.pool.OpenSQLDB()
	defer db.Close()
	var membershipInternal, roleAInternal, roleBInternal, permissionAInternal, permissionBInternal int64
	if err := db.QueryRowContext(f.ctx, `SELECT id FROM organization_memberships WHERE application_instance_id=$1 AND opaque_id=$2::uuid`, int64(f.appA.InternalID), string(f.membershipOther.ID)).Scan(&membershipInternal); err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		query string
		arg   string
		out   *int64
	}{
		{`SELECT id FROM organization_role_definitions WHERE opaque_id=$1::uuid`, string(roleA), &roleAInternal},
		{`SELECT id FROM organization_role_definitions WHERE opaque_id=$1::uuid`, string(roleB), &roleBInternal},
		{`SELECT id FROM organization_permission_definitions WHERE opaque_id=$1::uuid`, string(permissionA), &permissionAInternal},
		{`SELECT id FROM organization_permission_definitions WHERE opaque_id=$1::uuid`, string(permissionB), &permissionBInternal},
	}
	for _, q := range queries {
		if err := db.QueryRowContext(f.ctx, q.query, q.arg).Scan(q.out); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(f.ctx, `INSERT INTO organization_membership_role_assignments(application_instance_id,membership_id,role_definition_id) VALUES($1,$2,$3)`, int64(f.appA.InternalID), membershipInternal, roleBInternal); err == nil {
		t.Fatal("database accepted app-A membership -> app-B role")
	}
	if _, err := db.ExecContext(f.ctx, `INSERT INTO organization_role_permission_grants(application_instance_id,role_definition_id,permission_definition_id) VALUES($1,$2,$3)`, int64(f.appA.InternalID), roleAInternal, permissionBInternal); err == nil {
		t.Fatal("database accepted app-A role -> app-B permission")
	}
	if _, err := db.ExecContext(f.ctx, `INSERT INTO organization_role_permission_grants(application_instance_id,role_definition_id,permission_definition_id) VALUES($1,$2,$3)`, int64(f.appA.InternalID), roleBInternal, permissionAInternal); err == nil {
		t.Fatal("database accepted app-B role through app-A scope")
	}
}
