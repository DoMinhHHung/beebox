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
	if err := f.authorization.SetMembershipRole(f.ctx, mutationContext(t, f.appA.InternalID, f.actorA), f.membershipA.ID, adminB.ID); !errors.Is(err, organization.ErrRoleNotFound) {
		t.Fatalf("cross-app role assignment error=%v", err)
	}

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
