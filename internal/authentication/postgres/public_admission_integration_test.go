//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestPreKDFLimiterConcurrentFirstUseIsAtomic(t *testing.T) {
	tests := []struct {
		name  string
		admit func(context.Context, *Store, int64, [32]byte) error
	}{
		{
			name: "signup",
			admit: func(ctx context.Context, store *Store, appID int64, subject [32]byte) error {
				keyHash := sha256.Sum256([]byte("concurrent-signup-key"))
				requestHash := sha256.Sum256([]byte("concurrent-signup-request"))
				_, err := store.AdmitPublicSignup(ctx, internalID(appID), keyHash, requestHash, subject)
				return err
			},
		},
		{
			name: "verification confirm",
			admit: func(ctx context.Context, store *Store, appID int64, subject [32]byte) error {
				return store.AllowPublicVerificationConfirm(ctx, internalID(appID), subject)
			},
		},
		{
			name: "password reset issue",
			admit: func(ctx context.Context, store *Store, appID int64, subject [32]byte) error {
				return store.AllowPasswordResetIssue(ctx, internalID(appID), subject)
			},
		},
		{
			name: "password reset confirm",
			admit: func(ctx context.Context, store *Store, appID int64, subject [32]byte) error {
				return store.AllowPasswordResetConfirm(ctx, internalID(appID), subject)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			databaseURL := isolatedDatabaseURL(t, "beebox_pre_kdf_"+sanitizeTestName(tt.name))
			pool := openPool(t, databaseURL)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
				t.Fatalf("migration.Up() error = %v", err)
			}
			app, err := applicationpostgres.New(pool).Create(ctx)
			if err != nil {
				t.Fatalf("Create(application) error = %v", err)
			}
			store := New(pool)
			subject := sha256.Sum256([]byte("same-first-use-identifier"))

			const attempts = 8
			start := make(chan struct{})
			results := make(chan error, attempts)
			var wg sync.WaitGroup
			for i := 0; i < attempts; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					results <- tt.admit(ctx, store, int64(app.InternalID), subject)
				}()
			}
			close(start)
			wg.Wait()
			close(results)

			allowed := 0
			limited := 0
			for err := range results {
				switch {
				case err == nil:
					allowed++
				case errors.Is(err, authentication.ErrPublicRateLimited):
					limited++
				default:
					t.Fatalf("concurrent admission returned persistence/other error: %v", err)
				}
			}
			if allowed != 5 || limited != attempts-5 {
				t.Fatalf("allowed/limited = %d/%d, want 5/%d", allowed, limited, attempts-5)
			}
		})
	}
}

func TestPreKDFGlobalDenialStopsIdentifierCardinalityGrowth(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_pre_kdf_cardinality")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(application) error = %v", err)
	}
	store := New(pool)

	for i := 0; i < 100; i++ {
		fingerprint := sha256.Sum256([]byte(fmt.Sprintf("allowed-%d", i)))
		if err := store.AllowPasswordResetIssue(ctx, app.InternalID, fingerprint); err != nil {
			t.Fatalf("allowed admission %d error = %v", i, err)
		}
	}
	before := countLimiterRows(t, ctx, pool.OpenSQLDB(), int64(app.InternalID), "password_reset_issue_pre_kdf_identifier")
	if before != 100 {
		t.Fatalf("identifier rows before global denial = %d, want 100", before)
	}

	for i := 0; i < 20; i++ {
		fingerprint := sha256.Sum256([]byte(fmt.Sprintf("denied-%d", i)))
		err := store.AllowPasswordResetIssue(ctx, app.InternalID, fingerprint)
		if !errors.Is(err, authentication.ErrPublicRateLimited) {
			t.Fatalf("post-global admission %d error = %v, want rate limited", i, err)
		}
	}
	after := countLimiterRows(t, ctx, pool.OpenSQLDB(), int64(app.InternalID), "password_reset_issue_pre_kdf_identifier")
	if after != before {
		t.Fatalf("identifier rows grew after global denial: before=%d after=%d", before, after)
	}
}

func TestPreKDFLimiterIsIndependentAcrossApplications(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_pre_kdf_cross_application")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	apps := applicationpostgres.New(pool)
	first, err := apps.Create(ctx)
	if err != nil {
		t.Fatalf("Create(first application) error = %v", err)
	}
	second, err := apps.Create(ctx)
	if err != nil {
		t.Fatalf("Create(second application) error = %v", err)
	}
	store := New(pool)
	fingerprint := sha256.Sum256([]byte("shared-identifier"))
	for i := 0; i < 5; i++ {
		if err := store.AllowPublicVerificationConfirm(ctx, first.InternalID, fingerprint); err != nil {
			t.Fatalf("first application admission %d error = %v", i, err)
		}
	}
	if err := store.AllowPublicVerificationConfirm(ctx, first.InternalID, fingerprint); !errors.Is(err, authentication.ErrPublicRateLimited) {
		t.Fatalf("first application overflow error = %v, want rate limited", err)
	}
	if err := store.AllowPublicVerificationConfirm(ctx, second.InternalID, fingerprint); err != nil {
		t.Fatalf("second application first admission error = %v", err)
	}
}

func countLimiterRows(t *testing.T, ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	Close() error
}, appID int64, operation string) int {
	t.Helper()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation=$2`, appID, operation).Scan(&count); err != nil {
		t.Fatalf("count limiter rows error = %v", err)
	}
	return count
}

func sanitizeTestName(value string) string {
	result := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

func internalID(value int64) applicationinstance.InternalID {
	return applicationinstance.InternalID(value)
}
