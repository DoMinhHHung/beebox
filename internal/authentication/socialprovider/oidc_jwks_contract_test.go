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
	if got := calls.Load(); got != 1 {
		t.Fatalf("initial JWKS fetches=%d want=1", got)
	}

	current.Store(&keyB.PublicKey)
	kid.Store("key-b")
	beforeRotation := calls.Load()
	const maxRotationSettleAttempts = 32
	var rotationErr error
	for attempt := 1; attempt <= maxRotationSettleAttempts; attempt++ {
		rotationErr = verify(keyB, "key-b")
		after := calls.Load()
		if rotationErr == nil {
			if after <= beforeRotation {
				t.Fatal("rotated key was accepted without an observable post-rotation JWKS refresh")
			}
			if delta := after - beforeRotation; delta != 1 {
				t.Fatalf("rotation JWKS fetches=%d want=1", delta)
			}
			break
		}
		if after > beforeRotation {
			t.Fatalf("post-rotation JWKS refresh did not accept key B: %v", rotationErr)
		}
		if attempt == maxRotationSettleAttempts {
			t.Fatalf("rotated key was not accepted after bounded inflight-settle attempts: %v", rotationErr)
		}
		// go-oidc v3.20.0 signals a completed inflight fetch before its owner
		// reacquires the cache mutex and clears the inflight pointer. Yield only
		// inside this contract test so a back-to-back rotation cannot reuse the
		// just-completed key-A result. A permanently broken refresh still fails:
		// success requires exactly one observable post-rotation JWKS request.
		time.Sleep(time.Millisecond)
	}

	beforeUnknown := calls.Load()
	for i := 0; i < 3; i++ {
		unknown, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(unknown, "unknown-kid"); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if delta := calls.Load() - beforeUnknown; delta > 3 {
		t.Fatalf("unknown kid caused unbounded JWKS requests: %d", delta)
	}
}
