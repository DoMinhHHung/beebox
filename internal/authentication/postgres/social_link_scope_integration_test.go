//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestSocialLinkSameProviderSubjectMayBeOwnedIndependentlyAcrossApplications(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_cross_app")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identities := identitypostgres.New(pool)
	userA, err := identities.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := identities.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionA, createdA := insertSocialLinkSession(t, ctx, db, appA.InternalID, userA.InternalID, time.Minute)
	sessionB, createdB := insertSocialLinkSession(t, ctx, db, appB.InternalID, userB.InternalID, time.Minute)
	store := New(pool)
	attemptA := createConsumedSocialLinkAttempt(t, ctx, store, appA.InternalID, userA.InternalID, sessionA, createdA, authentication.ProviderGitLab, "cross-app-a")
	attemptB := createConsumedSocialLinkAttempt(t, ctx, store, appB.InternalID, userB.InternalID, sessionB, createdB, authentication.ProviderGitLab, "cross-app-b")
	for _, attempt := range []authentication.SocialLinkAttemptSnapshot{attemptA, attemptB} {
		correlation, _ := audit.NewCorrelationID()
		if err := store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attempt.AttemptID, ProviderSubject: "same-provider-subject", CorrelationID: correlation}); err != nil {
			t.Fatalf("FinalizeSocialLink(app=%d) error = %v", attempt.ApplicationInstanceID, err)
		}
	}
	assertExternalIdentityOwner(t, ctx, db, appA.InternalID, authentication.ProviderGitLab, "same-provider-subject", userA.InternalID)
	assertExternalIdentityOwner(t, ctx, db, appB.InternalID, authentication.ProviderGitLab, "same-provider-subject", userB.InternalID)
}

func TestSocialLinkAttemptAdmissionIsBoundedPerUserAndProvider(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_admission")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	for i := 0; i < authentication.SocialLinkAttemptUserProviderLimit; i++ {
		if err := store.AllowSocialLinkAttempt(ctx, app.InternalID, user.InternalID, authentication.ProviderDiscord); err != nil {
			t.Fatalf("admission %d error = %v", i+1, err)
		}
	}
	if err := store.AllowSocialLinkAttempt(ctx, app.InternalID, user.InternalID, authentication.ProviderDiscord); !errors.Is(err, authentication.ErrPublicRateLimited) {
		t.Fatalf("admission beyond user/provider limit = %v, want rate limited", err)
	}
	// A different provider has a distinct fixed-vocabulary subject bucket.
	if err := store.AllowSocialLinkAttempt(ctx, app.InternalID, user.InternalID, authentication.ProviderGitHub); err != nil {
		t.Fatalf("different provider unexpectedly rate limited: %v", err)
	}
}
