package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestSlackOIDCSubjectRejectsInvalidSubAndProfileFallback(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		subject any
		present bool
	}{
		{name: "missing"},
		{name: "empty", subject: "", present: true},
		{name: "wrong type", subject: 12345, present: true},
		{name: "oversized", subject: strings.Repeat("s", 513), present: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			const clientID = "fake-client"
			const nonce = "fake-nonce"
			nonceHash := sha256.Sum256([]byte(nonce))
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				writeContractJWKS(w, "key-a", &key.PublicKey)
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				claims := map[string]any{
					"iss":            server.URL,
					"aud":            clientID,
					"nonce":          nonce,
					"iat":            time.Now().Add(-time.Minute).Unix(),
					"exp":            time.Now().Add(5 * time.Minute).Unix(),
					"email":          "fallback@example.test",
					"email_verified": true,
					"name":           "Fallback",
					"team_id":        "T-fallback",
					"user_id":        "U-fallback",
				}
				if tc.present {
					claims["sub"] = tc.subject
				}
				raw, signErr := signContractJWT(key, "key-a", claims)
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "access_token": "fake-access", "token_type": "Bearer", "id_token": raw})
			})
			client := server.Client()
			a := &adapter{
				provider:     authentication.ProviderSlack,
				clientID:     clientID,
				clientSecret: "fake-secret",
				redirectURL:  server.URL + "/callback",
				tokenURL:     server.URL + "/token",
				authStyle:    oauth2.AuthStyleInHeader,
				useNonce:     true,
				mode:         subjectOIDC,
				verifier: oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{
					ClientID:             clientID,
					SupportedSigningAlgs: []string{"RS256"},
				}),
				httpClient: client,
			}
			if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", nonceHash); err != authentication.ErrSocialProviderProof {
				t.Fatalf("Slack accepted invalid subject %#v: %v", tc.subject, err)
			}
		})
	}
}
