package signingkey

import "testing"

func TestGenerateProducesValidDistinctEd25519Material(t *testing.T) {
	first, err := Generate()
	if err != nil { t.Fatal(err) }
	second, err := Generate()
	if err != nil { t.Fatal(err) }
	if err := Parse(first); err != nil { t.Fatalf("Parse(first) = %v", err) }
	if err := Parse(second); err != nil { t.Fatalf("Parse(second) = %v", err) }
	if first.KeyID == second.KeyID || first.PrivateKey == second.PrivateKey { t.Fatal("generated key material unexpectedly repeated") }
}
