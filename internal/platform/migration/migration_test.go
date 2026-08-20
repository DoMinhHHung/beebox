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
		"00011_password_resets.sql",
		"00012_production_hardening.sql",
		"00013_email_otp_signin.sql",
		"00014_phone_sms.sql",
		"00015_social_oauth.sql",
		"00016_social_account_linking.sql",
		"00017_social_account_management.sql",
		"00018_passkeys.sql",
		"00019_totp_mfa.sql",
		"00020_recovery_codes.sql",
		"00021_reverification.sql",
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
		{name: "duplicate version", sources: fstest.MapFS{"00001_one.sql": {Data: []byte(validMigration)}, "00001_two.sql": {Data: []byte(validMigration)}}},
		{name: "down directive", sources: fstest.MapFS{"00001_bad.sql": {Data: []byte(validMigration + "-- +goose Down\nSELECT 1;\n")}}},
		{name: "non-transactional directive", sources: fstest.MapFS{"00001_bad.sql": {Data: []byte("-- +goose NO TRANSACTION\n" + validMigration)}}},
		{name: "environment substitution", sources: fstest.MapFS{"00001_bad.sql": {Data: []byte("-- +goose Up\n-- +goose ENVSUB ON\nSELECT '${SECRET}';\n")}}},
		{name: "missing up directive", sources: fstest.MapFS{"00001_bad.sql": {Data: []byte("SELECT 1;\n")}}},
		{name: "out of order", sources: unsortedFS{MapFS: fstest.MapFS{"00001_one.sql": {Data: []byte(validMigration)}, "00002_two.sql": {Data: []byte(validMigration)}}, order: []string{"00002_two.sql", "00001_one.sql"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSources(tt.sources)
			if !errors.Is(err, errInvalidSources) {
				t.Fatalf("validateSources() error = %v, want stable invalid-sources error", err)
			}
		})
	}
}

func TestUpRequiresDeadlineAndClosesAdapterWithSafeError(t *testing.T) {
	db, closed := openTestDB(t)
	if err := db.Ping(); err != nil {
		t.Fatalf("test db Ping() error = %v", err)
	}
	err := upWithSources(context.Background(), db, fstest.MapFS{"00001_baseline.sql": {Data: []byte(validMigration)}})
	if !errors.Is(err, errDeadlineRequired) {
		t.Fatalf("upWithSources() error = %v, want deadline-required error", err)
	}
	if strings.Contains(err.Error(), "provider") || strings.Contains(err.Error(), "dsn") {
		t.Fatalf("upWithSources() error leaks provider detail: %q", err)
	}
	if err := db.Ping(); err == nil || err.Error() != "sql: database is closed" {
		t.Fatalf("db.Ping() after Up = %v, want closed adapter", err)
	}
	if got := closed.Load(); got != 1 {
		t.Fatalf("underlying adapter Close() calls = %d, want 1", got)
	}
}

type unsortedFS struct {
	fstest.MapFS
	order []string
}

func (u unsortedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, fs.ErrNotExist
	}
	entries := make([]fs.DirEntry, 0, len(u.order))
	for _, path := range u.order {
		info, err := fs.Stat(u.MapFS, path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, fs.FileInfoToDirEntry(info))
	}
	return entries, nil
}

func openTestDB(t *testing.T) (*sql.DB, *atomic.Int32) {
	t.Helper()
	closed := &atomic.Int32{}
	return sql.OpenDB(testConnector{closed: closed}), closed
}

type testDriver struct {
	closed *atomic.Int32
}

func (d testDriver) Open(string) (driver.Conn, error) { return testConn{closed: d.closed}, nil }

type testConnector struct {
	closed *atomic.Int32
}

func (c testConnector) Connect(context.Context) (driver.Conn, error) {
	return testConn{closed: c.closed}, nil
}
func (c testConnector) Driver() driver.Driver { return testDriver{closed: c.closed} }

type testConn struct {
	closed *atomic.Int32
}

func (testConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not implemented") }
func (c testConn) Close() error                      { c.closed.Add(1); return nil }
func (testConn) Begin() (driver.Tx, error)           { return nil, errors.New("not implemented") }
