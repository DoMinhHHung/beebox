package beeboxid

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewVersion7(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if id.Version() != 7 {
		t.Fatalf("version=%d want 7", id.Version())
	}
	if id == uuid.Nil {
		t.Fatalf("nil uuid")
	}
}

func TestNewUnique(t *testing.T) {
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		id, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if id.Version() != 7 {
			t.Fatalf("version=%d want 7", id.Version())
		}
		s := id.String()
		if _, ok := seen[s]; ok {
			t.Fatalf("duplicate %s", s)
		}
		seen[s] = struct{}{}
	}
}
