//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/organization"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestOrganizationMembershipPersistenceActiveResolutionAndAudit(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_organization_membership")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applicationStore := applicationpostgres.New(pool)
	appA := createApplication(t, ctx, applicationStore)
	appB := createApplication(t, ctx, applicationStore)
	actorA := createActorUser(t, ctx, pool, appA.InternalID)
	actorB := createActorUser(t, ctx, pool, appB.InternalID)
	userA1 := createMembershipUser(t, ctx, pool, appA.InternalID)
	userA2 := createMembershipUser(t, ctx, pool, appA.InternalID)
	userA3 := createMembershipUser(t, ctx, pool, appA.InternalID)
	userB := createMembershipUser(t, ctx, pool, appB.InternalID)

	organizationService := newService(t, New(pool))
	orgA := createOrganization(t, ctx, organizationService, appA.InternalID, actorA, "Alpha", "alpha")
	orgA2 := createOrganization(t, ctx, organizationService, appA.InternalID, actorA, "Beta", "beta")
	orgConcurrent := createOrganization(t, ctx, organizationService, appA.InternalID, actorA, "Concurrent", "concurrent-members")
	orgB := createOrganization(t, ctx, organizationService, appB.InternalID, actorB, "Foreign", "foreign")

	membershipService, err := organization.NewMembershipService(New(pool))
	if err != nil {
		t.Fatal(err)
	}

	createA1 := mutationContext(t, appA.InternalID, actorA)
	membershipA1, err := membershipService.CreateMembership(ctx, createA1, orgA.ID, userA1.PublicID)
	if err != nil {
		t.Fatalf("CreateMembership(app A) error = %v", err)
	}
	if !membershipA1.ID.Valid() || membershipA1.ApplicationInstanceID != appA.InternalID || membershipA1.OrganizationID != orgA.ID || membershipA1.UserPublicID != userA1.PublicID || membershipA1.CreatedAt.IsZero() || membershipA1.CreatedAt.Location() != time.UTC {
		t.Fatalf("membership = %#v", membershipA1)
	}
	if len(string(membershipA1.ID)) != 36 {
		t.Fatalf("membership locator %q is not opaque UUID storage identity", membershipA1.ID)
	}
	resolvedMembership, err := membershipService.GetMembership(ctx, appA.InternalID, membershipA1.ID)
	if err != nil || resolvedMembership.ID != membershipA1.ID || resolvedMembership.OrganizationID != orgA.ID || resolvedMembership.UserPublicID != userA1.PublicID {
		t.Fatalf("GetMembership() = %#v, %v", resolvedMembership, err)
	}
	assertMembershipAudit(t, ctx, pool, createA1, userA1.InternalID, audit.ActionOrganizationMembershipCreated, orgA.ID)

	membershipA1SecondOrg, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA2.ID, userA1.PublicID)
	if err != nil {
		t.Fatalf("same user second organization error = %v", err)
	}
	membershipA2SameOrg, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA.ID, userA2.PublicID)
	if err != nil {
		t.Fatalf("second user same organization error = %v", err)
	}
	if membershipA1SecondOrg.ID == membershipA1.ID || membershipA2SameOrg.ID == membershipA1.ID {
		t.Fatal("distinct membership resources reused a locator")
	}

	if _, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA.ID, userA1.PublicID); !errors.Is(err, organization.ErrMembershipUnavailable) {
		t.Fatalf("duplicate membership error = %v, want ErrMembershipUnavailable", err)
	}
	assertMembershipTupleCount(t, ctx, pool, appA.InternalID, orgA.ID, userA1.PublicID, 1)

	if _, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgB.ID, userA1.PublicID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("cross-app organization CreateMembership() error = %v", err)
	}
	if _, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA.ID, userB.PublicID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("cross-app user CreateMembership() error = %v", err)
	}
	assertDatabaseRejectsCrossApplicationMemberships(t, ctx, pool, appA.InternalID, orgA.ID, orgB.ID, userA1, userB)

	if _, err := membershipService.GetMembership(ctx, appB.InternalID, membershipA1.ID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("cross-app GetMembership() error = %v", err)
	}

	activeA, err := membershipService.ResolveActiveOrganization(ctx, appA.InternalID, userA1.PublicID, orgA.ID)
	if err != nil || activeA.Organization.ID != orgA.ID || activeA.MembershipID != membershipA1.ID || activeA.UserPublicID != userA1.PublicID {
		t.Fatalf("ResolveActiveOrganization(org A) = %#v, %v", activeA, err)
	}
	activeA2, err := membershipService.ResolveActiveOrganization(ctx, appA.InternalID, userA1.PublicID, orgA2.ID)
	if err != nil || activeA2.Organization.ID != orgA2.ID || activeA2.MembershipID != membershipA1SecondOrg.ID {
		t.Fatalf("ResolveActiveOrganization(org A2) = %#v, %v", activeA2, err)
	}
	if _, err := membershipService.ResolveActiveOrganization(ctx, appA.InternalID, userA2.PublicID, orgA2.ID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("non-member active organization error = %v", err)
	}
	if _, err := membershipService.ResolveActiveOrganization(ctx, appA.InternalID, userA3.PublicID, orgA.ID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("organization/user locators without membership granted authority: %v", err)
	}

	badActorContext := mutationContext(t, appA.InternalID, actorB)
	if _, err := membershipService.CreateMembership(ctx, badActorContext, orgA2.ID, userA2.PublicID); !errors.Is(err, organization.ErrPersistence) {
		t.Fatalf("cross-app audit actor CreateMembership() error = %v, want ErrPersistence", err)
	}
	assertMembershipTupleCount(t, ctx, pool, appA.InternalID, orgA2.ID, userA2.PublicID, 0)

	badRemoveContext := mutationContext(t, appA.InternalID, identity.InternalID(9_999_999))
	if err := membershipService.RemoveMembership(ctx, badRemoveContext, membershipA2SameOrg.ID); !errors.Is(err, organization.ErrPersistence) {
		t.Fatalf("audit failure RemoveMembership() error = %v, want ErrPersistence", err)
	}
	if _, err := membershipService.GetMembership(ctx, appA.InternalID, membershipA2SameOrg.ID); err != nil {
		t.Fatalf("audit failure committed membership deletion: %v", err)
	}

	if err := membershipService.RemoveMembership(ctx, mutationContext(t, appB.InternalID, actorB), membershipA1.ID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("cross-app RemoveMembership() error = %v", err)
	}
	removeA1 := mutationContext(t, appA.InternalID, actorA)
	if err := membershipService.RemoveMembership(ctx, removeA1, membershipA1.ID); err != nil {
		t.Fatalf("RemoveMembership() error = %v", err)
	}
	assertMembershipAudit(t, ctx, pool, removeA1, userA1.InternalID, audit.ActionOrganizationMembershipRemoved, orgA.ID)
	if _, err := membershipService.GetMembership(ctx, appA.InternalID, membershipA1.ID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("removed membership GetMembership() error = %v", err)
	}
	if _, err := membershipService.ResolveActiveOrganization(ctx, appA.InternalID, userA1.PublicID, orgA.ID); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Fatalf("stale organization hint remained authoritative after removal commit: %v", err)
	}

	recreated, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA.ID, userA1.PublicID)
	if err != nil {
		t.Fatalf("recreate membership error = %v", err)
	}
	if recreated.ID == membershipA1.ID {
		t.Fatalf("recreated membership reused removed locator %q", recreated.ID)
	}

	const creators = 8
	contexts := make([]organization.MutationContext, creators)
	for i := range contexts {
		contexts[i] = mutationContext(t, appA.InternalID, actorA)
	}
	results := make(chan error, creators)
	var wg sync.WaitGroup
	for i := range creators {
		wg.Add(1)
		current := contexts[i]
		go func() {
			defer wg.Done()
			callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer callCancel()
			_, err := membershipService.CreateMembership(callCtx, current, orgConcurrent.ID, userA3.PublicID)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, organization.ErrMembershipUnavailable):
			conflicts++
		default:
			t.Fatalf("concurrent CreateMembership() error = %v", err)
		}
	}
	if successes != 1 || conflicts != creators-1 {
		t.Fatalf("concurrent membership results success=%d conflicts=%d, want 1/%d", successes, conflicts, creators-1)
	}
	assertMembershipTupleCount(t, ctx, pool, appA.InternalID, orgConcurrent.ID, userA3.PublicID, 1)

	assertNoGlobalActiveOrganizationColumns(t, ctx, pool)
}

type membershipUser struct {
	InternalID identity.InternalID
	PublicID   identity.PublicID
}

func createMembershipUser(t *testing.T, ctx context.Context, pool *database.Pool, applicationID applicationinstance.InternalID) membershipUser {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var item membershipUser
	var internalID int64
	if err := db.QueryRowContext(ctx, `
		INSERT INTO users(application_instance_id)
		VALUES($1)
		RETURNING id,public_id`, int64(applicationID)).Scan(&internalID, &item.PublicID); err != nil {
		t.Fatalf("create membership user error = %v", err)
	}
	item.InternalID = identity.InternalID(internalID)
	if !item.InternalID.Valid() || !item.PublicID.Valid() {
		t.Fatalf("created membership user = %#v", item)
	}
	return item
}

func createOrganization(t *testing.T, ctx context.Context, service *organization.Service, applicationID applicationinstance.InternalID, actorID identity.InternalID, name, slug string) organization.Organization {
	t.Helper()
	item, err := service.Create(ctx, mutationContext(t, applicationID, actorID), name, slug)
	if err != nil {
		t.Fatalf("create organization %q error = %v", slug, err)
	}
	return item
}

func assertDatabaseRejectsCrossApplicationMemberships(t *testing.T, ctx context.Context, pool *database.Pool, applicationID applicationinstance.InternalID, orgA, orgB organization.ID, userA, userB membershipUser) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var orgAInternal, orgBInternal int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM organizations WHERE application_instance_id=$1 AND opaque_id=$2::uuid`, int64(applicationID), string(orgA)).Scan(&orgAInternal); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT id FROM organizations WHERE opaque_id=$1::uuid`, string(orgB)).Scan(&orgBInternal); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO organization_memberships(application_instance_id,organization_id,user_id) VALUES($1,$2,$3)`, int64(applicationID), orgBInternal, int64(userA.InternalID)); err == nil {
		t.Fatal("database accepted app-A membership pointing at app-B organization")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO organization_memberships(application_instance_id,organization_id,user_id) VALUES($1,$2,$3)`, int64(applicationID), orgAInternal, int64(userB.InternalID)); err == nil {
		t.Fatal("database accepted app-A organization with app-B user")
	}
}

func assertMembershipTupleCount(t *testing.T, ctx context.Context, pool *database.Pool, applicationID applicationinstance.InternalID, organizationID organization.ID, userPublicID identity.PublicID, want int) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM organization_memberships m
		JOIN organizations o ON o.application_instance_id=m.application_instance_id AND o.id=m.organization_id
		JOIN users u ON u.application_instance_id=m.application_instance_id AND u.id=m.user_id
		WHERE m.application_instance_id=$1 AND o.opaque_id=$2::uuid AND u.public_id=$3`,
		int64(applicationID), string(organizationID), string(userPublicID)).Scan(&count); err != nil {
		t.Fatalf("membership tuple count error = %v", err)
	}
	if count != want {
		t.Fatalf("membership tuple count = %d, want %d", count, want)
	}
}

func assertMembershipAudit(t *testing.T, ctx context.Context, pool *database.Pool, current organization.MutationContext, targetUserID identity.InternalID, action string, organizationID organization.ID) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var actorID, subjectID int64
	var actorKind, storedAction, category, reference, outcome, source string
	var correlation []byte
	var occurredAt time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source,occurred_at
		FROM audit_events
		WHERE application_instance_id=$1 AND action=$2 AND resource_reference=$3 AND correlation_id=$4`,
		int64(current.ApplicationInstanceID), action, string(organizationID), current.CorrelationID[:],
	).Scan(&actorKind, &actorID, &subjectID, &storedAction, &category, &reference, &outcome, &correlation, &source, &occurredAt); err != nil {
		t.Fatalf("query membership audit error = %v", err)
	}
	if actorKind != audit.ActorKindUser || actorID != int64(current.ActorUserID) || subjectID != int64(targetUserID) || storedAction != action || category != audit.ResourceCategoryOrganizationMembership || reference != string(organizationID) || outcome != audit.OutcomeSuccess || source != audit.SourceInternalOrganization {
		t.Fatalf("membership audit actor=%s/%d subject=%d action=%s category=%s ref=%s outcome=%s source=%s", actorKind, actorID, subjectID, storedAction, category, reference, outcome, source)
	}
	if !bytes.Equal(correlation, current.CorrelationID[:]) || occurredAt.IsZero() {
		t.Fatalf("membership audit correlation/time = %x/%v", correlation, occurredAt)
	}
}

func assertNoGlobalActiveOrganizationColumns(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	for _, table := range []string{"users", "sessions"} {
		var count int
		if err := db.QueryRowContext(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name='active_organization_id'`, table).Scan(&count); err != nil {
			t.Fatalf("active organization column query for %s error = %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s.active_organization_id unexpectedly exists", table)
		}
	}
}
