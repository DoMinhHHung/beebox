//go:build integration

package migration

import (
	"context"
	"testing"
	"time"
)

func TestOrganizationAuthorizationMigrationUpgradesExactVersion26(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_organization_authorization_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesThrough(t, 26)); err != nil {
		t.Fatalf("apply exact version 26 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 26)
	db := pool.OpenSQLDB()
	defer db.Close()
	for _, table := range []string{
		"organization_role_definitions",
		"organization_permission_definitions",
		"organization_role_permission_grants",
		"organization_membership_role_assignments",
	} {
		var before *string
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, table).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if before != nil {
			t.Fatalf("version 26 unexpectedly contains %s", table)
		}
	}

	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("upgrade exact 26 -> 27: %v", err)
	}
	assertMigrationState(t, ctx, pool, 27)

	for _, table := range []string{
		"organization_role_definitions",
		"organization_permission_definitions",
		"organization_role_permission_grants",
		"organization_membership_role_assignments",
	} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, table).Scan(&got); err != nil || got != table {
			t.Fatalf("table %s = %q err=%v", table, got, err)
		}
	}

	constraints := []string{
		"organization_memberships_application_instance_id_id_key",
		"organization_role_definitions_application_key_key",
		"organization_role_definitions_application_instance_id_id_key",
		"organization_permission_definitions_application_key_key",
		"organization_permission_definitions_app_resource_action_key",
		"organization_permission_definitions_application_instance_id_id_key",
		"organization_role_permission_grants_role_scope_fk",
		"organization_role_permission_grants_permission_scope_fk",
		"organization_membership_role_assignments_pkey",
		"organization_membership_role_assignments_membership_scope_fk",
		"organization_membership_role_assignments_role_scope_fk",
		"audit_events_organization_reference_check",
		"audit_events_related_resource_reference_check",
	}
	for _, constraint := range constraints {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace AND conname=$1`, constraint).Scan(&count); err != nil || count != 1 {
			t.Fatalf("constraint %s count=%d err=%v", constraint, count, err)
		}
	}

	var auditColumns int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='audit_events'
		  AND column_name IN ('organization_reference','related_resource_reference')`).Scan(&auditColumns); err != nil || auditColumns != 2 {
		t.Fatalf("authorization audit columns=%d err=%v", auditColumns, err)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT conname,confdeltype::text
		FROM pg_constraint
		WHERE connamespace=current_schema()::regnamespace
		  AND conname IN (
			'organization_role_permission_grants_role_scope_fk',
			'organization_role_permission_grants_permission_scope_fk',
			'organization_membership_role_assignments_membership_scope_fk',
			'organization_membership_role_assignments_role_scope_fk'
		  )
		ORDER BY conname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name, deleteAction string
		if err := rows.Scan(&name, &deleteAction); err != nil {
			t.Fatal(err)
		}
		if deleteAction != "a" {
			t.Fatalf("%s delete action=%q, want PostgreSQL NO ACTION", name, deleteAction)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 4 {
		t.Fatalf("authorization scoped FK rows=%d, want 4", seen)
	}
}
