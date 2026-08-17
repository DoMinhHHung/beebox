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
	if len(entries) != 6 ||
		entries[0].Name() != "00001_runtime_baseline.sql" ||
		entries[1].Name() != "00002_application_instances.sql" ||
		entries[2].Name() != "00003_users.sql" ||
		entries[3].Name() != "00004_email_identifiers.sql" ||
		entries[4].Name() != "00005_password_credentials.sql" ||
		entries[5].Name() != "00006_audit_events.sql" {
		t.Fatalf("embedded migration sources = %v, want ordered versions 1 through 6", entries)
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

type unsortedFS struct { fstest.MapFS; order []string }
func (u unsortedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." { return nil, fs.ErrNotExist }
	entries := make([]fs.DirEntry, 0, len(u.order))
	for _, path := range u.order {
		info, err := fs.Stat(u.MapFS, path); if err != nil { return nil, err }
		entries = append(entries, fs.FileInfoToDirEntry(info))
	}
	return entries, nil
}

func openTestDB(t *testing.T) (*sql.DB, *atomic.Int32) { t.Helper(); closed := &atomic.Int32{}; return sql.OpenDB(testConnector{closed: closed}), closed }
type testDriver struct { closed *atomic.Int32 }
func (d testDriver) Open(string) (driver.Conn, error) { return testConn{closed: d.closed}, nil }
type testConnector struct { closed *atomic.Int32 }
func (c testConnector) Connect(context.Context) (driver.Conn, error) { return testConn{closed: c.closed}, nil }
func (c testConnector) Driver() driver.Driver { return testDriver{closed: c.closed} }
type testConn struct { closed *atomic.Int32 }
func (testConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not implemented") }
func (c testConn) Close() error { c.closed.Add(1); return nil }
func (testConn) Begin() (driver.Tx, error) { return nil, errors.New("not implemented") }
