package publicid

import "testing"

func TestNewUUIDv4IsTypedUniqueAndValid(t *testing.T) {
	first, err := NewUUIDv4("app")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewUUIDv4("app")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("random public identifiers unexpectedly match")
	}
	if !IsUUIDv4(first, "app") || !IsUUIDv4(second, "app") {
		t.Fatal("generated public identifier is not valid UUIDv4")
	}
	if IsUUIDv4(first, "usr") {
		t.Fatal("resource prefix was not enforced")
	}
	body, ok := UUIDBody(first, "app")
	if !ok || len(body) != 36 {
		t.Fatal("UUIDBody failed")
	}
}

func TestIsUUIDv4RejectsMalformedOrWrongVersion(t *testing.T) {
	for _, value := range []string{"", "app_123", "app_00000000-0000-1000-8000-000000000000", "app_00000000-0000-4000-0000-000000000000"} {
		if IsUUIDv4(value, "app") {
			t.Fatalf("accepted invalid public ID %q", value)
		}
	}
}
