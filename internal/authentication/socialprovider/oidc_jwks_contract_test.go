package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestOIDCJWKSRotationAndUnknownKidsAreBounded(t *testing.T) {
	t.Parallel()
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[rsa.PublicKey]
	var kid atomic.Value
	current.Store(&keyA.PublicKey)
	kid.Store("key-a")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeContractJWKS(w, kid.Load().(string), current.Load())
	}))
	defer server.Close()
	client := server.Client()
	verifier := oidc.NewVerifier("https://issuer.example.test", oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL), &oidc.Config{ClientID: "fake-client", SupportedSigningAlgs: []string{"RS256"}})
	verify := func(key *rsa.PrivateKey, tokenKid string) error {
		raw, err := signContractJWT(key, tokenKid, map[string]any{"iss": "https://issuer.example.test", "aud": "fake-client", "sub": "stable-subject", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()})
		if err != nil {
			return err
		}
		_, err = verifier.Verify(oidc.ClientContext(context.Background(), client), raw)
		return err
	}
	if err := verify(keyA, "key-a"); err != nil {
		t.Fatal(err)
	}
	current.Store(&keyB.PublicKey)
	kid.Store("key-b")
	if err := verify(keyB, "key-b"); err != nil {
		t.Fatalf("rotated key was not accepted: %v", err)
	}
	before := calls.Load()
	for i := 0; i < 3; i++ {
		unknown, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(unknown, "unknown-kid"); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if delta := calls.Load() - before; delta > 3 {
		t.Fatalf("unknown kid caused unbounded JWKS requests: %d", delta)
	}
}
