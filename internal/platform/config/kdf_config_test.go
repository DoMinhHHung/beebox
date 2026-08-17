package config

import (
	"strings"
	"testing"
)

func TestLoadKDFConcurrencyDefaultsAndOverrides(t *testing.T) {
	cfg, err := Load(mapLookup(map[string]string{"BEEBOX_DATABASE_URL": testDatabaseURL}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KDFConcurrency != 2 {
		t.Fatalf("KDFConcurrency = %d, want 2", cfg.KDFConcurrency)
	}
	cfg, err = Load(mapLookup(map[string]string{"BEEBOX_DATABASE_URL": testDatabaseURL, "BEEBOX_KDF_CONCURRENCY": "4"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KDFConcurrency != 4 {
		t.Fatalf("KDFConcurrency = %d, want 4", cfg.KDFConcurrency)
	}
}

func TestLoadRejectsInvalidKDFConcurrency(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "65", "many"} {
		_, err := Load(mapLookup(map[string]string{"BEEBOX_DATABASE_URL": testDatabaseURL, "BEEBOX_KDF_CONCURRENCY": value}))
		if err == nil || !strings.Contains(err.Error(), "BEEBOX_KDF_CONCURRENCY") {
			t.Fatalf("value %q error = %v, want bounded KDF configuration error", value, err)
		}
	}
}
