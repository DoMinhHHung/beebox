package migration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io/fs"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
)

const validMigration = "-- +goose Up\nSELECT 1;\n"

func TestEmbeddedSourcesAreValidAndOrdered(t *testing.T) {
	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatalf("fs.Sub() error = %v", err)
	}
	if err := validateSources(sources); err != nil {
		t.Fatalf("validateSources() error = %v", err)
	}
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		t.Fatalf("fs.ReadDir() error = %v", err)
	}
	want := []string{
		"00001_runtime_baseline.sql",
		"00002_application_instances.sql",
		"00003_users.sql",
		"00004_email_identifiers.sql",
		"00005_password_credentials.sql",
		"00006_audit_events.sql",
		"00007_email_verification_challenges.sql",
		"00008_phase1_public_integration.sql",
		"00009_public_auth_controls.sql",
		"00010_sessions.sql",
	}
	if len(entries) != len(want) {
		t.Fatalf("embedded migration count = %d, want %d", len(entries), len(want))
	}
	for i, name := range want {
		if entries[i].Name() != name {
			t.Fatalf("migration[%d] = %q, want %q", i, entries[i].Name(), name)
		}
	}
}

func TestValidateSourcesRejectsUnsafeOrInvalidSources(t *testing.T) {
	tests := []struct {
		name    string
		sources fs.FS
	}{
		{name: "empty", sources: fstest.MapFS{}},
		{name: "invalid name", sources: fstest.MapFS{"1_bad.sql": {Data: []byte(validMigration)}}},
		{name: "duplicate version", sources: fstest.MapFS{
			"00001_one.sql": {Data: []byte(validMigration)},
			"00001_two.sql": {Data: []byte(validMigration)},
		}},
		{name: "down directive", sources: fstest.MapFS{
			"00001_bad.sql": {Data: []byte(validMigration + "-- +goose Down\nSELECT 1;\n")},
		}},
		{name: "non-transactional directive", sources: fstest.MapFS{
			"00001_bad.sql": {Data: []byte("-- +goose NO TRANSACTION\n" + validMigration)},
		}},
		{name: "environment substitution", sources: fstest.MapFS{
			"00001_bad.sql": {Data: []byte("-- +goose Up\n-- +goose ENVSUB ON\nSELECT '${SECRET}';\n")},
		}},
		{name: "missing up directive", sources: fstest.MapFS{
			"00001_bad.sql": {Data: []byte("SELECT 1;\n")},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSources(tc.sources); !errors.Is(err, errInvalidSources) {
				t.Fatalf("validateSources() error = %v, want %v", err, errInvalidSources)
			}
		})
	}
}

func TestUpRejectsMissingDeadlineAndClosesAdapter(t *testing.T) {
	registerTestDriverOnce()
	db, err := sql.Open(testDriverName, "deadline")
	if err != nil {
		t.Fatal(err)
	}
	if err := upWithSources(context.Background(), db, fstest.MapFS{"00001_test.sql": {Data: []byte(validMigration)}}); !errors.Is(err, errDeadlineRequired) {
		t.Fatalf("upWithSources() error = %v, want %v", err, errDeadlineRequired)
	}
	if err := db.Ping(); err == nil || !strings.Contains(err.Error(), "database is closed") {
		t.Fatalf("db.Ping() after Up = %v, want closed database", err)
	}
}

const testDriverName = "beebox_migration_test"

var registered atomic.Bool

func registerTestDriverOnce() {
	if registered.CompareAndSwap(false, true) {
		sql.Register(testDriverName, testDriver{})
	}
}

type testDriver struct{}

func (testDriver) Open(string) (driver.Conn, error) { return testConn{}, nil }

type testConn struct{}

func (testConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unsupported") }
func (testConn) Close() error                        { return nil }
func (testConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsupported") }
