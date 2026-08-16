package database

import (
	"context"
	"strings"
	"testing"
)

func TestOpenRejectsInvalidPoolConfigurationWithoutLeakingURL(t *testing.T) {
	const secretMarker = "super-secret"

	pool, err := Open(
		context.Background(),
		"postgres://user:"+secretMarker+"@localhost/beebox?pool_max_conns=invalid",
	)
	if pool != nil {
		pool.Close()
		t.Fatal("Open() pool is non-nil for invalid configuration")
	}
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}
	if err.Error() != "invalid PostgreSQL pool configuration" {
		t.Fatalf("Open() error = %q, want stable safe error", err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("Open() error leaks credential marker: %q", err)
	}
}
