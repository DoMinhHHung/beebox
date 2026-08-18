package socialprovider

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func assertContractTokenRequest(t *testing.T, r *http.Request, redirect string, authStyle oauth2.AuthStyle, pkce bool) {
	t.Helper()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("token request method=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
	}
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "fake-code" || r.Form.Get("redirect_uri") != redirect {
		t.Fatalf("token form = %v", r.Form)
	}
	if pkce {
		if r.Form.Get("code_verifier") != strings.Repeat("p", 43) {
			t.Fatalf("code_verifier = %q", r.Form.Get("code_verifier"))
		}
	} else if r.Form.Get("code_verifier") != "" {
		t.Fatalf("unexpected code_verifier = %q", r.Form.Get("code_verifier"))
	}
	switch authStyle {
	case oauth2.AuthStyleInParams:
		if r.Form.Get("client_id") != "fake-client" || r.Form.Get("client_secret") == "" || r.Header.Get("Authorization") != "" {
			t.Fatalf("parameter client auth form=%v header=%q", r.Form, r.Header.Get("Authorization"))
		}
	case oauth2.AuthStyleInHeader:
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fake-client" || pass != "fake-secret" || r.Form.Get("client_id") != "" || r.Form.Get("client_secret") != "" {
			t.Fatalf("Basic client auth user=%q ok=%v form=%v", user, ok, r.Form)
		}
	}
}

func signContractJWT(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func writeContractJWKS(w http.ResponseWriter, kid string, key *rsa.PublicKey) {
	w.Header().Set("Content-Type", "application/json")
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e}}})
}
