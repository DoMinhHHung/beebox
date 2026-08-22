package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/httpapi"
	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

func TestGatewayIdentityAuthenticatedCorrelationProvenance(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1")
	seen := make(chan string, 1)
	identity := httpapi.WithTrustedRequestCorrelation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(httpapi.RequestIDHeader)
		w.Header().Add(httpapi.RequestIDHeader, "identity-duplicate-attempt")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.Header.Get(httpapi.RequestIDHeader)))
	}), cfg.CorrelationKey)
	identityServer := httptest.NewServer(identity)
	defer identityServer.Close()
	cfg.IdentityBaseURL = testConfig(t, identityServer.URL).IdentityBaseURL

	const spoofed = "00112233445566778899aabbccddeeff"
	req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
	req.Header.Set(requestcorrelation.PublicHeader, spoofed)
	req.Header.Set(requestcorrelation.InternalIDHeader, spoofed)
	req.Header.Set(requestcorrelation.InternalSignatureHeader, requestcorrelation.Sign(cfg.CorrelationKey, requestcorrelation.ID{}))
	resp := httptest.NewRecorder()
	NewHandler(cfg, nil).ServeHTTP(resp, req)

	identityID := <-seen
	if identityID == "" || identityID == spoofed || len(identityID) != 32 {
		t.Fatalf("identity accepted spoofed correlation: %q", identityID)
	}
	body, err := io.ReadAll(resp.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != identityID {
		t.Fatalf("identity body request ID = %q want %q", body, identityID)
	}
	values := resp.Header().Values(requestIDHeader)
	if len(values) != 1 || values[0] != identityID {
		t.Fatalf("public response request IDs = %#v want exactly %q", values, identityID)
	}
	if resp.Header().Get(requestcorrelation.InternalIDHeader) != "" || resp.Header().Get(requestcorrelation.InternalSignatureHeader) != "" {
		t.Fatal("internal correlation proof leaked to public response")
	}
}
