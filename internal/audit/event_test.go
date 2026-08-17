package audit

import "testing"

func TestNewCorrelationIDProducesBoundedInternalIdentifier(t *testing.T) {
	first, err := NewCorrelationID()
	if err != nil {
		t.Fatalf("NewCorrelationID() error = %v", err)
	}
	second, err := NewCorrelationID()
	if err != nil {
		t.Fatalf("NewCorrelationID() second error = %v", err)
	}
	if len(first) != CorrelationIDBytes || len(second) != CorrelationIDBytes {
		t.Fatalf("correlation lengths = %d/%d, want %d", len(first), len(second), CorrelationIDBytes)
	}
	if first == second {
		t.Fatal("independent correlation identifiers unexpectedly match")
	}
}
