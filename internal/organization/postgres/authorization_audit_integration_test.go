//go:build integration

package postgres

import (
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/organization"
)

func TestOrganizationAuthorizationMutationsRollbackWhenRequiredAuditFails(t *testing.T) {
	f := newAuthorizationFixture(t)
	badActor := mutationContext(t, f.appA.InternalID, f.actorB)

	if _, err := f.authorization.CreateRoleDefinition(f.ctx, badActor, "audit-role"); !errors.Is(err, organization.ErrAuthorizationPersistence) {
		t.Fatalf("role audit failure error=%v", err)
	}
	role, err := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "audit-role")
	if err != nil {
		t.Fatalf("role insert was not rolled back: %v", err)
	}
	if _, err := f.authorization.CreatePermissionDefinition(f.ctx, badActor, "audit.read", "audit", "read"); !errors.Is(err, organization.ErrAuthorizationPersistence) {
		t.Fatalf("permission audit failure error=%v", err)
	}
	permission, err := f.authorization.CreatePermissionDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "audit.read", "audit", "read")
	if err != nil {
		t.Fatalf("permission insert was not rolled back: %v", err)
	}

	if err := f.authorization.GrantPermissionToRole(f.ctx, badActor, role.ID, permission.ID); !errors.Is(err, organization.ErrAuthorizationPersistence) {
		t.Fatalf("grant audit failure error=%v", err)
	}
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "audit", "read", organization.DecisionDeny)

	grantContext := mutationContext(t, f.appA.InternalID, f.actorA)
	if err := f.authorization.GrantPermissionToRole(f.ctx, grantContext, role.ID, permission.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "audit", "read", organization.DecisionAllow)
	if err := f.authorization.RevokePermissionFromRole(f.ctx, badActor, role.ID, permission.ID); !errors.Is(err, organization.ErrAuthorizationPersistence) {
		t.Fatalf("revoke audit failure error=%v", err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "audit", "read", organization.DecisionAllow)

	otherRole, err := f.authorization.CreateRoleDefinition(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), "other-role")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorization.SetMembershipRole(f.ctx, badActor, f.membershipA.ID, otherRole.ID); !errors.Is(err, organization.ErrAuthorizationPersistence) {
		t.Fatalf("assignment audit failure error=%v", err)
	}
	// Original role and its explicit permission remain current after rollback.
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "audit", "read", organization.DecisionAllow)

	clearBad := mutationContext(t, f.appA.InternalID, f.actorB)
	if err := f.authorization.ClearMembershipRole(f.ctx, clearBad, f.membershipA.ID); !errors.Is(err, organization.ErrAuthorizationPersistence) {
		t.Fatalf("clear audit failure error=%v", err)
	}
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "audit", "read", organization.DecisionAllow)

	// Membership removal now explicitly deletes the subordinate assignment before
	// deleting the membership. If its required membership audit fails, both
	// deletes must roll back together so the previous authority remains intact.
	if err := f.membership.RemoveMembership(f.ctx, badActor, f.membershipA.ID); !errors.Is(err, organization.ErrPersistence) {
		t.Fatalf("membership removal audit failure error=%v", err)
	}
	if _, err := f.membership.GetMembership(f.ctx, f.appA.InternalID, f.membershipA.ID); err != nil {
		t.Fatalf("membership removal audit failure did not roll membership back: %v", err)
	}
	assertAssignmentCount(t, f, f.membershipA.ID, 1)
	assertAuthorizationDecision(t, f, f.appA.InternalID, f.userA.PublicID, f.orgA.ID, "audit", "read", organization.DecisionAllow)

	assertAuthorizationAudit(t, f, grantContext, audit.ActionOrganizationRolePermissionGranted, audit.ResourceCategoryOrganizationRolePermission, string(role.ID), "", string(permission.ID), nil)
	setContext := mutationContext(t, f.appA.InternalID, f.actorA)
	if err := f.authorization.SetMembershipRole(f.ctx, setContext, f.membershipA2.ID, otherRole.ID); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationAudit(t, f, setContext, audit.ActionOrganizationMembershipRoleSet, audit.ResourceCategoryOrganizationMembershipRole, string(f.membershipA2.ID), string(f.orgA2.ID), string(otherRole.ID), &f.userA.InternalID)
}
