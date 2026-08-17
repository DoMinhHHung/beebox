package identity

import "testing"

func TestInternalIDValid(t *testing.T) {
	tests := []struct {
		id   InternalID
		want bool
	}{
		{id: -1, want: false},
		{id: 0, want: false},
		{id: 1, want: true},
	}

	for _, tt := range tests {
		if got := tt.id.Valid(); got != tt.want {
			t.Fatalf("InternalID(%d).Valid() = %v, want %v", tt.id, got, tt.want)
		}
	}
}
