//go:build integration

package migration

import (
	"context"
	"testing"
	"time"
)

func TestOrganizationMembershipMigrationUpgradesExactVersion25(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_organization_membership_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesThrough(t, 25)); err != nil {
		t.Fatalf("apply exact version 25 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 25)
	db := pool.OpenSQLDB()
	defer db.Close()
	var before *string
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('organization_memberships')::text`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != nil {
		t.Fatalf("version 25 unexpectedly contains organization_memberships: %q", *before)
	}

	if err := upWithSources(ctx, pool.OpenSQLDB(), migrationSourcesRange(t, 26, 26)); err != nil {
		t.Fatalf("upgrade exact 25 -> 26: %v", err)
	}
	assertMigrationState(t, ctx, pool, 26)

	var tableName string
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('organization_memberships')::text`).Scan(&tableName); err != nil || tableName != "organization_memberships" {
		t.Fatalf("organization_memberships table=%q err=%v", tableName, err)
	}
	var compositeOrganizationKey, scopedOrganizationFK, scopedUserFK, tupleUnique int
	if err := db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (WHERE conname='organizations_application_instance_id_id_key'),
			count(*) FILTER (WHERE conname='organization_memberships_organization_scope_fk'),
			count(*) FILTER (WHERE conname='organization_memberships_user_scope_fk'),
			count(*) FILTER (WHERE conname='organization_memberships_application_organization_user_key')
		FROM pg_constraint
		WHERE connamespace=current_schema()::regnamespace`).Scan(&compositeOrganizationKey, &scopedOrganizationFK, &scopedUserFK, &tupleUnique); err != nil {
		t.Fatal(err)
	}
	if compositeOrganizationKey != 1 || scopedOrganizationFK != 1 || scopedUserFK != 1 || tupleUnique != 1 {
		t.Fatalf("membership constraints organization-key=%d organization-fk=%d user-fk=%d tuple-unique=%d", compositeOrganizationKey, scopedOrganizationFK, scopedUserFK, tupleUnique)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT conname,confdeltype::text
		FROM pg_constraint
		WHERE connamespace=current_schema()::regnamespace
		  AND conname IN ('organization_memberships_organization_scope_fk','organization_memberships_user_scope_fk')
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
			t.Fatalf("%s delete action = %q, want PostgreSQL NO ACTION", name, deleteAction)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("scoped membership FK rows = %d, want 2", seen)
	}

	var scopedLocatorIndex int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM pg_indexes
		WHERE schemaname=current_schema()
		  AND indexname='organization_memberships_application_opaque_id_idx'`).Scan(&scopedLocatorIndex); err != nil || scopedLocatorIndex != 1 {
		t.Fatalf("membership scoped locator index count=%d err=%v", scopedLocatorIndex, err)
	}
}
