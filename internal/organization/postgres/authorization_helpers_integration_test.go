//go:build integration

package postgres

import (
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

type authorizationFixture struct {
	ctx               context.Context
	pool              *database.Pool
	authorization     *organization.AuthorizationService
	membership        *organization.MembershipService
	appA, appB        applicationinstance.Instance
	actorA, actorB    identity.InternalID
	userA, userA2     membershipUser
	userB             membershipUser
	orgA, orgA2, orgB organization.Organization
	membershipA       organization.Membership
	membershipA2      organization.Membership
	membershipOther   organization.Membership
}

func newAuthorizationFixture(t *testing.T) authorizationFixture {
	t.Helper()
	databaseURL := isolatedDatabaseURL(t, "beebox_authorization_"+safeTestSuffix(t.Name()))
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	appStore := applicationpostgres.New(pool)
	appA := createApplication(t, ctx, appStore)
	appB := createApplication(t, ctx, appStore)
	actorA := createActorUser(t, ctx, pool, appA.InternalID)
	actorB := createActorUser(t, ctx, pool, appB.InternalID)
	userA := createMembershipUser(t, ctx, pool, appA.InternalID)
	userA2 := createMembershipUser(t, ctx, pool, appA.InternalID)
	userB := createMembershipUser(t, ctx, pool, appB.InternalID)
	orgService := newService(t, New(pool))
	orgA := createOrganization(t, ctx, orgService, appA.InternalID, actorA, "Alpha", "alpha-authz")
	orgA2 := createOrganization(t, ctx, orgService, appA.InternalID, actorA, "Beta", "beta-authz")
	orgB := createOrganization(t, ctx, orgService, appB.InternalID, actorB, "Foreign", "foreign-authz")
	membershipService, err := organization.NewMembershipService(New(pool))
	if err != nil {
		t.Fatal(err)
	}
	membershipA, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA.ID, userA.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	membershipA2, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA2.ID, userA.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	membershipOther, err := membershipService.CreateMembership(ctx, mutationContext(t, appA.InternalID, actorA), orgA.ID, userA2.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	authorizationService, err := organization.NewAuthorizationService(New(pool))
	if err != nil {
		t.Fatal(err)
	}
	return authorizationFixture{
		ctx: ctx, pool: pool, authorization: authorizationService, membership: membershipService,
		appA: appA, appB: appB, actorA: actorA, actorB: actorB,
		userA: userA, userA2: userA2, userB: userB,
		orgA: orgA, orgA2: orgA2, orgB: orgB,
		membershipA: membershipA, membershipA2: membershipA2, membershipOther: membershipOther,
	}
}

func safeTestSuffix(name string) string {
	result := make([]byte, 0, len(name))
	for i := range len(name) {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result = append(result, c)
		}
	}
	if len(result) > 32 {
		result = result[:32]
	}
	return string(result)
}

func assertAuthorizationDecision(t *testing.T, f authorizationFixture, appID applicationinstance.InternalID, user identity.PublicID, orgID organization.ID, resource, action string, want organization.Decision) {
	t.Helper()
	got, err := f.authorization.CheckOrganizationAuthorization(f.ctx, appID, user, orgID, resource, action)
	if err != nil {
		t.Fatalf("authorization %s/%s error = %v", resource, action, err)
	}
	if got != want {
		t.Fatalf("authorization %s/%s = %v, want %v", resource, action, got, want)
	}
}

func assertAssignmentCount(t *testing.T, f authorizationFixture, membershipID organization.MembershipID, want int) {
	t.Helper()
	db := f.pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(f.ctx, `
		SELECT count(*)
		FROM organization_membership_role_assignments a
		JOIN organization_memberships m
		  ON m.application_instance_id=a.application_instance_id AND m.id=a.membership_id
		WHERE a.application_instance_id=$1 AND m.opaque_id=$2::uuid`,
		int64(f.appA.InternalID), string(membershipID)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("assignment count=%d, want %d", count, want)
	}
}

func assertConcurrentRoleCreation(t *testing.T, f authorizationFixture) {
	t.Helper()
	const workers = 8
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			callCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := f.authorization.CreateRoleDefinition(callCtx, mutationContext(t, f.appA.InternalID, f.actorA), "concurrent-role")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, organization.ErrRoleUnavailable):
			conflicts++
		default:
			t.Fatalf("concurrent role create error = %v", err)
		}
	}
	if successes != 1 || conflicts != workers-1 {
		t.Fatalf("concurrent role create success=%d conflicts=%d", successes, conflicts)
	}
}

func assertAuthorizationAudit(t *testing.T, f authorizationFixture, current organization.MutationContext, action, category, resource, orgRef, related string, subject *identity.InternalID) {
	t.Helper()
	db := f.pool.OpenSQLDB()
	defer db.Close()
	var actorID int64
	var subjectID *int64
	var gotAction, gotCategory, gotResource, outcome, source string
	var gotOrg, gotRelated *string
	var occurredAt time.Time
	if err := db.QueryRowContext(f.ctx, `
		SELECT actor_user_id,subject_user_id,action,resource_category,resource_reference,
		       organization_reference,related_resource_reference,outcome,source,occurred_at
		FROM audit_events
		WHERE application_instance_id=$1 AND correlation_id=$2 AND action=$3`,
		int64(current.ApplicationInstanceID), current.CorrelationID[:], action,
	).Scan(&actorID, &subjectID, &gotAction, &gotCategory, &gotResource, &gotOrg, &gotRelated, &outcome, &source, &occurredAt); err != nil {
		t.Fatal(err)
	}
	if actorID != int64(current.ActorUserID) || gotAction != action || gotCategory != category || gotResource != resource || outcome != audit.OutcomeSuccess || source != audit.SourceInternalOrganization || occurredAt.IsZero() {
		t.Fatalf("unexpected authorization audit fact")
	}
	if nullableString(gotOrg) != orgRef || nullableString(gotRelated) != related {
		t.Fatalf("audit refs org=%q related=%q, want %q/%q", nullableString(gotOrg), nullableString(gotRelated), orgRef, related)
	}
	if subject == nil && subjectID != nil {
		t.Fatal("audit unexpectedly contains subject")
	}
	if subject != nil && (subjectID == nil || *subjectID != int64(*subject)) {
		t.Fatalf("audit subject=%v, want %d", subjectID, *subject)
	}
}

func nullableString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
