package crypto

import "testing"

func TestArgon2idRoundTrip(t *testing.T) {
	h := Argon2id{}
	encoded, err := h.Hash("password1")
	if err != nil {
		t.Fatal(err)
	}
	if !h.Verify("password1", encoded) {
		t.Fatal("expected match")
	}
	if h.Verify("password2", encoded) {
		t.Fatal("expected mismatch")
	}
}
