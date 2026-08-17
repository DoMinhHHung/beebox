package applicationinstance

import "testing"

func TestInternalIDValidation(t *testing.T) {
	tests := []struct {
		name string
		id   InternalID
		want bool
	}{
		{name: "zero", id: 0, want: false},
		{name: "negative", id: -1, want: false},
		{name: "positive", id: 1, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.Valid(); got != tt.want {
				t.Fatalf("InternalID(%d).Valid() = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
