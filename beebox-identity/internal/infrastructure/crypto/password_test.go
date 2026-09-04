package crypto

import "testing"

func TestArgon2idHashAndVerify(t *testing.T) {
	h := Argon2id{}
	encoded, err := h.Hash("password1")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if encoded == "password1" || encoded == "" {
		t.Fatalf("stored plaintext")
	}
	if !h.Verify("password1", encoded) {
		t.Fatalf("verify true password")
	}
	if h.Verify("password2", encoded) {
		t.Fatalf("verify wrong password")
	}
	if h.Verify("password1", "not-a-hash") {
		t.Fatalf("verify garbage")
	}
}
