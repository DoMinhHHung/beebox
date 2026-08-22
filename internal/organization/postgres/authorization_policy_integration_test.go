//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/organization"
)

func TestOrganizationAuthorizationDefaultDenyNoMagicRolesAndImmediateFreshness(t *testing.T) {
	f := newAuthorizationFixture(t)
	admin, _ := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "admin")
	owner, _ := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "owner")
	viewer, _ := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "viewer")
	read, _ := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "organization.read", "organization", "read")
	write, _ := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "organization.write", "organization", "write")
	adminB, _ := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appB.InternalID, f.actorB), "admin")

	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	// The literal admin key does not grant anything.
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA2.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	// The literal owner key is equally non-magic.
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA2.ID, "organization", "read", organization.DecisionDeny)

	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), admin.ID, read.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionAllow)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "write", organization.DecisionDeny)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "other", "read", organization.DecisionDeny)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "other", organization.DecisionDeny)

	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), owner.ID, write.ID); err != nil {
		t.Fatal(err)
	}
	// One user can hold different organization-local roles without global role state.
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA2.ID, "organization", "write", organization.DecisionAllow)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA2.ID, "organization", "read", organization.DecisionDeny)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "write", organization.DecisionDeny)

	// Locators alone do not grant authority and all missing/cross-scope prerequisites deny.
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA2.PublicID, f.orgA2.ID, "organization", "read", organization.DecisionDeny)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userB.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgB.ID, "organization", "read", organization.DecisionDeny)
	assertAuthorizationDecision(t, f, f.appB.InternalID, f.userA.PublicID, f.orgB.ID, "organization", "read", organization.DecisionDeny)
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, adminB.ID); !errors.Is(err, organization.ErrRoleAssignmentNotFound) {
		t.Fatalf("cross-app role assignment error=%v, want ErrRoleAssignmentNotFound", err)
	}
	// The scoped lookup intentionally does not reveal which candidate object was foreign.
	// A denied substitution must leave the prior valid assignment and its authority intact.
	assertAssignmentRole(t, f, f.membershipA.ID, admin.ID)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionAllow)
	assertCrossApplicationRoleConstraint(t, f, f.membershipA.ID, adminB.ID)
	assertAssignmentRole(t, f, f.membershipA.ID, admin.ID)

	if err := f.authorization.RevokePermissionFromRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), admin.ID, read.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)
	if err := f.authorization.GrantPermissionToRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), admin.ID, read.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionAllow)

	if err := f.authorization.ClearMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionAllow)
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, viewer.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)

	assertConcurrentRoleReplacement(t, f, admin.ID, owner.ID)

	// Parent membership removal explicitly clears the subordinate role assignment
	// in the same transaction and the next authoritative check denies.
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.membership.RemoveMembership(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID); err != nil {
		t.Fatalf("RemoveMembership(with assignment) error=%v", err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "organization", "read", organization.DecisionDeny)
	assertAssignmentCount(t, f, f.membershipA.ID, 0)
}

func assertAssignmentRole(t *testing.T, f authorizationFixture, membershipID organization.MembershipID, want organization.RoleID) {
	t.Helper()
	db := f.pool.OpenSQLDB()
	defer db.Close()
	var got string
	if err := db.QueryRowContext(f.ctx, `
		SELECT r.opaque_id::text
		FROM organization_membership_role_assignments a
		JOIN organization_memberships m
		  ON m.application_instance_id=a.application_instance_id AND m.id=a.membership_id
		JOIN organization_role_definitions r
		  ON r.application_instance_id=a.application_instance_id AND r.id=a.role_definition_id
		WHERE a.application_instance_id=$1 AND m.opaque_id=$2::uuid`,
		int64(f.appA.InternalID), string(membershipID)).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if organization.RoleID(got) != want {
		t.Fatalf("assignment role=%s, want %s", got, want)
	}
}

func assertCrossApplicationRoleConstraint(t *testing.T, f authorizationFixture, membershipID organization.MembershipID, foreignRoleID organization.RoleID) {
	t.Helper()
	db := f.pool.OpenSQLDB()
	defer db.Close()
	_, err := db.ExecContext(f.ctx, `
		UPDATE organization_membership_role_assignments a
		SET role_definition_id=(
			SELECT id FROM organization_role_definitions
			WHERE application_instance_id=$2 AND opaque_id=$4::uuid
		)
		WHERE a.application_instance_id=$1
		  AND a.membership_id=(
			SELECT id FROM organization_memberships
			WHERE application_instance_id=$1 AND opaque_id=$3::uuid
		  )`,
		int64(f.appA.InternalID), int64(f.appB.InternalID), string(membershipID), string(foreignRoleID))
	if err == nil {
		t.Fatal("cross-application direct role substitution unexpectedly bypassed database constraints")
	}
}

func assertConcurrentRoleReplacement(t *testing.T, f authorizationFixture, first, second organization.RoleID) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, roleID := range []organization.RoleID{first, second} {
		roleID := roleID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results <- f.authorization.SetMembershipRole(ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipOther.ID, roleID)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent role replacement error=%v", err)
		}
	}
	assertAssignmentCount(t, f, f.membershipOther.ID, 1)
}
