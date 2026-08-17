//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestPublicTrustCredentialsOriginsAndPublicIDs(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_public_trust")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() = %v", err)
	}

	apps := New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !appA.PublicID.Valid() || !appB.PublicID.Valid() || appA.PublicID == appB.PublicID {
		t.Fatal("application public IDs invalid or duplicate")
	}
	resolved, err := apps.ResolveByPublicID(ctx, appA.PublicID)
	if err != nil || resolved.InternalID != appA.InternalID || resolved.PublicID != appA.PublicID {
		t.Fatalf("public resolve = %#v err = %v", resolved, err)
	}

	service := applicationinstance.NewIntegrationService(NewIntegrationStore(pool))
	publishableCredential, publishableKey, err := service.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}
	secretCredential, secretKey, err := service.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindSecret)
	if err != nil {
		t.Fatal(err)
	}
	if publishableCredential.ApplicationInstanceID != appA.InternalID || secretCredential.ApplicationInstanceID != appA.InternalID {
		t.Fatal("credential scope mismatch")
	}
	if got, err := service.ResolvePublishable(ctx, publishableKey); err != nil || got.InternalID != appA.InternalID {
		t.Fatalf("publishable resolve = %#v err = %v", got, err)
	}
	if _, err := service.AuthenticateSecret(ctx, publishableKey); !errors.Is(err, applicationinstance.ErrInvalidCredential) {
		t.Fatalf("publishable key gained backend authority: %v", err)
	}
	if got, err := service.AuthenticateSecret(ctx, secretKey); err != nil || got.InternalID != appA.InternalID {
		t.Fatalf("secret auth = %#v err = %v", got, err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var secretHash []byte
	var publishableStored sql.NullString
	var lastUsedAt sql.NullTime
	if err := db.QueryRowContext(
		ctx,
		`SELECT secret_hash, publishable_key, last_used_at
		 FROM application_credentials
		 WHERE public_id = $1`,
		string(secretCredential.PublicID),
	).Scan(&secretHash, &publishableStored, &lastUsedAt); err != nil {
		t.Fatal(err)
	}
	if len(secretHash) != 32 || strings.Contains(string(secretHash), secretKey) || publishableStored.Valid || !lastUsedAt.Valid {
		t.Fatal("secret credential was persisted or used unsafely")
	}

	rotatedCredential, rotatedSecret, err := service.RotateCredential(
		ctx,
		appA.InternalID,
		secretCredential.PublicID,
		applicationinstance.CredentialKindSecret,
	)
	if err != nil {
		t.Fatalf("RotateCredential() = %v", err)
	}
	if rotatedCredential.PublicID == secretCredential.PublicID || rotatedSecret == secretKey {
		t.Fatal("rotation reused credential identity or secret")
	}
	if _, err := service.AuthenticateSecret(ctx, secretKey); !errors.Is(err, applicationinstance.ErrCredentialRevoked) {
		t.Fatalf("old rotated secret error = %v, want revoked", err)
	}
	if got, err := service.AuthenticateSecret(ctx, rotatedSecret); err != nil || got.InternalID != appA.InternalID {
		t.Fatalf("rotated secret auth = %#v err = %v", got, err)
	}

	publishableB, keyB, err := service.CreateCredential(ctx, appB.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.RotateCredential(ctx, appA.InternalID, publishableB.PublicID, applicationinstance.CredentialKindPublishable); !errors.Is(err, applicationinstance.ErrCredentialNotFound) {
		t.Fatalf("cross-app rotation error = %v, want not found", err)
	}
	if err := service.RevokeCredential(ctx, appA.InternalID, publishableB.PublicID); !errors.Is(err, applicationinstance.ErrCredentialNotFound) {
		t.Fatalf("cross-app revoke error = %v, want not found", err)
	}
	if got, err := service.ResolvePublishable(ctx, keyB); err != nil || got.InternalID != appB.InternalID {
		t.Fatalf("app B publishable resolve = %#v err = %v", got, err)
	}

	origin, err := service.AddAllowedOrigin(ctx, appA.InternalID, "HTTPS://Example.TEST:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if origin.CanonicalOrigin != "https://example.test:8443" {
		t.Fatalf("origin = %q", origin.CanonicalOrigin)
	}
	if _, err := service.AddAllowedOrigin(ctx, appA.InternalID, "https://example.test:8443"); err == nil {
		t.Fatal("duplicate origin unexpectedly succeeded")
	}

	var credentialCreateAudits int
	var credentialRevokeAudits int
	var originAudits int
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			count(*) FILTER (WHERE action = $2),
			count(*) FILTER (WHERE action = $3),
			count(*) FILTER (WHERE action = $4)
		 FROM audit_events
		 WHERE application_instance_id = $1`,
		int64(appA.InternalID),
		applicationinstance.AuditActionCredentialCreated,
		applicationinstance.AuditActionCredentialRevoked,
		applicationinstance.AuditActionOriginAdded,
	).Scan(&credentialCreateAudits, &credentialRevokeAudits, &originAudits); err != nil {
		t.Fatalf("query integration audits = %v", err)
	}
	if credentialCreateAudits != 3 || credentialRevokeAudits != 1 || originAudits != 1 {
		t.Fatalf("audit counts create=%d revoke=%d origin=%d, want 3/1/1", credentialCreateAudits, credentialRevokeAudits, originAudits)
	}
}
