//go:build integration

package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/jackc/pgx/v5"
)

func TestPasswordCredentialsAreApplicationScopedAndSecretDerived(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_password_scope")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applicationStore := applicationpostgres.New(pool)
	appA, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}

	userStore := identitypostgres.New(pool)
	userA, err := userStore.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}
	userA2, err := userStore.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A2) error = %v", err)
	}
	userB, err := userStore.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}

	rawA := []byte(" synthetic password A ")
	hashA, err := authentication.HashPassword(rawA)
	if err != nil {
		t.Fatalf("HashPassword(A) error = %v", err)
	}

	store := New(pool)
	credentialA, err := store.CreatePasswordCredential(ctx, appA.InternalID, userA.InternalID, hashA)
	if err != nil {
		t.Fatalf("CreatePasswordCredential(A) error = %v", err)
	}
	if credentialA.ApplicationInstanceID != appA.InternalID || credentialA.UserID != userA.InternalID {
		t.Fatalf("credential A scope/owner = %d/%d, want %d/%d", credentialA.ApplicationInstanceID, credentialA.UserID, appA.InternalID, userA.InternalID)
	}
	if credentialA.CreatedAt.Location() != time.UTC {
		t.Fatalf("credential A CreatedAt location = %v, want UTC", credentialA.CreatedAt.Location())
	}
	if err := authentication.VerifyPassword(credentialA.PasswordHash, rawA); err != nil {
		t.Fatalf("VerifyPassword(created A) error = %v", err)
	}

	resolvedA, err := store.ResolvePasswordCredential(ctx, appA.InternalID, userA.InternalID)
	if err != nil {
		t.Fatalf("ResolvePasswordCredential(A,userA) error = %v", err)
	}
	if err := authentication.VerifyPassword(resolvedA.PasswordHash, rawA); err != nil {
		t.Fatalf("VerifyPassword(resolved A) error = %v", err)
	}
	if err := authentication.VerifyPassword(resolvedA.PasswordHash, []byte("wrong candidate")); !errors.Is(err, authentication.ErrPasswordMismatch) {
		t.Fatalf("VerifyPassword(wrong) error = %v, want ErrPasswordMismatch", err)
	}

	if _, err := store.ResolvePasswordCredential(ctx, appB.InternalID, userA.InternalID); !errors.Is(err, authentication.ErrPasswordCredentialNotFound) {
		t.Fatalf("ResolvePasswordCredential(B,userA) error = %v, want not found", err)
	}
	if _, err := store.CreatePasswordCredential(ctx, appA.InternalID, userB.InternalID, hashA); !errors.Is(err, authentication.ErrPasswordCredentialPersistence) {
		t.Fatalf("CreatePasswordCredential(A,userB) error = %v, want persistence failure", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var crossScopeCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT count(*) FROM password_credentials WHERE application_instance_id = $1 AND user_id = $2`,
		int64(appA.InternalID),
		int64(userB.InternalID),
	).Scan(&crossScopeCount); err != nil {
		t.Fatalf("count cross-scope credentials error = %v", err)
	}
	if crossScopeCount != 0 {
		t.Fatalf("cross-scope credential rows = %d, want 0", crossScopeCount)
	}

	rawA2 := []byte("synthetic password A2")
	hashA2, err := authentication.HashPassword(rawA2)
	if err != nil {
		t.Fatalf("HashPassword(A2) error = %v", err)
	}
	if _, err := store.CreatePasswordCredential(ctx, appA.InternalID, userA2.InternalID, hashA2); err != nil {
		t.Fatalf("CreatePasswordCredential(A,userA2) error = %v", err)
	}
	if _, err := store.CreatePasswordCredential(ctx, appA.InternalID, userA.InternalID, hashA2); !errors.Is(err, authentication.ErrPasswordCredentialConflict) {
		t.Fatalf("duplicate CreatePasswordCredential(A,userA) error = %v, want conflict", err)
	}

	var storedHash string
	if err := db.QueryRowContext(
		ctx,
		`SELECT password_hash FROM password_credentials WHERE application_instance_id = $1 AND user_id = $2`,
		int64(appA.InternalID),
		int64(userA.InternalID),
	).Scan(&storedHash); err != nil {
		t.Fatalf("query stored password hash error = %v", err)
	}
	if storedHash == string(rawA) || !strings.HasPrefix(storedHash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatal("database password value is not a BeeBox Argon2id derived encoding")
	}
	parsed, err := authentication.ParsePasswordHash(storedHash)
	if err != nil || authentication.VerifyPassword(parsed, rawA) != nil {
		t.Fatalf("stored password hash does not verify synthetic candidate: parse error = %v", err)
	}
}

func TestPasswordCredentialValidatesTrustedIdentifiers(t *testing.T) {
	store := New(nil)
	hash, err := authentication.HashPassword([]byte("identifier fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	ctx := context.Background()
	if _, err := store.CreatePasswordCredential(ctx, applicationinstance.InternalID(0), identity.InternalID(1), hash); !errors.Is(err, authentication.ErrInvalidApplicationInstanceScope) {
		t.Fatalf("invalid app scope error = %v", err)
	}
	if _, err := store.CreatePasswordCredential(ctx, applicationinstance.InternalID(1), identity.InternalID(0), hash); !errors.Is(err, authentication.ErrInvalidUserInternalID) {
		t.Fatalf("invalid user ID error = %v", err)
	}
	if _, err := store.CreatePasswordCredential(ctx, applicationinstance.InternalID(1), identity.InternalID(1), authentication.PasswordHash{}); !errors.Is(err, authentication.ErrInvalidPasswordHash) {
		t.Fatalf("invalid password hash error = %v", err)
	}
}

func TestConcurrentPasswordCredentialCreateCommitsExactlyOnce(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_password_concurrent")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user) error = %v", err)
	}
	hash, err := authentication.HashPassword([]byte("precomputed persistence race password"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	store := New(pool)
	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.CreatePasswordCredential(ctx, app.InternalID, user.InternalID, hash)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, authentication.ErrPasswordCredentialConflict):
			conflicts++
		default:
			t.Fatalf("concurrent CreatePasswordCredential() error = %v", err)
		}
	}
	if successes != 1 || conflicts != attempts-1 {
		t.Fatalf("concurrent results successes=%d conflicts=%d, want 1/%d", successes, conflicts, attempts-1)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT count(*) FROM password_credentials WHERE application_instance_id = $1 AND user_id = $2`,
		int64(app.InternalID), int64(user.InternalID),
	).Scan(&count); err != nil {
		t.Fatalf("count password credentials error = %v", err)
	}
	if count != 1 {
		t.Fatalf("password credential rows = %d, want 1", count)
	}
}

func TestPasswordCredentialFailureUsesSafeStableError(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_password_failure")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user) error = %v", err)
	}
	hash, err := authentication.HashPassword([]byte("safe error fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, "DROP TABLE password_credentials"); err != nil {
		db.Close()
		t.Fatalf("drop password_credentials error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test adapter error = %v", err)
	}

	_, err = New(pool).CreatePasswordCredential(ctx, app.InternalID, user.InternalID, hash)
	if !errors.Is(err, authentication.ErrPasswordCredentialPersistence) || err.Error() != "password credential persistence failure" {
		t.Fatalf("CreatePasswordCredential() error = %v, want stable persistence failure", err)
	}
	if strings.Contains(err.Error(), hash.StorageEncoding()) {
		t.Fatal("persistence error contains password hash")
	}
}

func isolatedDatabaseURL(t *testing.T, schema string) string {
	t.Helper()
	databaseURL := os.Getenv("BEEBOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("BEEBOX_TEST_DATABASE_URL is required for integration tests")
	}

	adminPool := openPool(t, databaseURL)
	adminDB := adminPool.OpenSQLDB()
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := adminDB.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
		adminDB.Close()
		t.Fatalf("drop test schema error = %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminDB.Close()
		t.Fatalf("create test schema error = %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		_ = adminDB.Close()
	})

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal("BEEBOX_TEST_DATABASE_URL must be a valid URI")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func openPool(t *testing.T, databaseURL string) *database.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping() error = %v", err)
	}
	return pool
}
