package gateway

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/httpapi"
	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

type gatewayCorrelationApps struct {
	app applicationinstance.Instance
}

func (f gatewayCorrelationApps) ResolvePublishable(_ context.Context, key string) (applicationinstance.Instance, error) {
	if key != "key" {
		return applicationinstance.Instance{}, applicationinstance.ErrCredentialNotFound
	}
	return f.app, nil
}

type gatewayCorrelationOrigins struct{}

func (gatewayCorrelationOrigins) IsAllowedOrigin(context.Context, applicationinstance.InternalID, string) (bool, error) {
	return true, nil
}
func (gatewayCorrelationOrigins) AnyAllowedOrigin(context.Context, string) (bool, error) {
	return true, nil
}

type gatewayCorrelationSignup struct {
	correlations chan audit.CorrelationID
}

func (f *gatewayCorrelationSignup) SignUpWithCorrelation(
	_ context.Context,
	_ applicationinstance.InternalID,
	_ string,
	_ string,
	_ string,
	correlation audit.CorrelationID,
) error {
	f.correlations <- correlation
	return authentication.ErrPublicIdempotencyConflict
}

type gatewayCorrelationVerification struct{}

func (gatewayCorrelationVerification) RequestWithCorrelation(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error {
	return nil
}
func (gatewayCorrelationVerification) ConfirmWithCorrelation(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error {
	return nil
}

func gatewayCorrelationKey(t *testing.T, material string) requestcorrelation.Key {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString([]byte(material))
	key, err := requestcorrelation.LoadKey(func(name string) (string, bool) {
		if name == requestcorrelation.KeyEnvironmentVariable {
			return encoded, true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newGatewayCorrelationIdentityServer(t *testing.T, key requestcorrelation.Key, signup *gatewayCorrelationSignup) *httptest.Server {
	t.Helper()
	base := httpapi.New(
		http.NotFoundHandler(),
		gatewayCorrelationApps{app: applicationinstance.Instance{InternalID: 42}},
		gatewayCorrelationOrigins{},
		signup,
		gatewayCorrelationVerification{},
	)
	return httptest.NewServer(httpapi.WithTrustedRequestCorrelation(base, key))
}

func gatewayCorrelationSignupRequest(publishableKey string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://public.test/v1/sign-ups", strings.NewReader(`{"email":"user@example.com","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpapi.PublishableKeyHeader, publishableKey)
	req.Header.Set(httpapi.IdempotencyKeyHeader, "correlation-test")
	req.Header.Set(requestcorrelation.PublicHeader, "00112233445566778899aabbccddeeff")
	req.Header.Set(requestcorrelation.InternalIDHeader, "00112233445566778899aabbccddeeff")
	req.Header.Set(requestcorrelation.InternalSignatureHeader, "client-spoof")
	return req
}

func assertIdentityCanonicalError(t *testing.T, resp *httptest.ResponseRecorder, status int, code string) gatewayErrorEnvelope {
	t.Helper()
	if resp.Code != status {
		t.Fatalf("status=%d want=%d body=%s", resp.Code, status, resp.Body.String())
	}
	var envelope gatewayErrorEnvelope
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode canonical Identity error: %v body=%s", err, resp.Body.String())
	}
	publicIDs := resp.Header().Values(requestIDHeader)
	if len(publicIDs) != 1 || publicIDs[0] == "" || envelope.Error.RequestID != publicIDs[0] {
		t.Fatalf("public IDs=%#v body request_id=%q", publicIDs, envelope.Error.RequestID)
	}
	if envelope.Error.Code != code || envelope.Error.Message == "" {
		t.Fatalf("canonical error=%+v", envelope.Error)
	}
	if resp.Header().Get(requestcorrelation.InternalIDHeader) != "" || resp.Header().Get(requestcorrelation.InternalSignatureHeader) != "" {
		t.Fatal("internal correlation proof leaked to public response")
	}
	return envelope
}

func TestGatewayIdentityMatchingKeyKeepsPublicAndAuditCorrelationTogether(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1")
	signup := &gatewayCorrelationSignup{correlations: make(chan audit.CorrelationID, 1)}
	identity := newGatewayCorrelationIdentityServer(t, cfg.CorrelationKey, signup)
	defer identity.Close()
	cfg = testConfig(t, identity.URL)

	resp := httptest.NewRecorder()
	NewHandler(cfg, nil).ServeHTTP(resp, gatewayCorrelationSignupRequest("key"))
	envelope := assertIdentityCanonicalError(t, resp, http.StatusConflict, "idempotency_conflict")

	select {
	case auditID := <-signup.correlations:
		if got := hex.EncodeToString(auditID[:]); got != envelope.Error.RequestID {
			t.Fatalf("matching-key audit=%q public=%q", got, envelope.Error.RequestID)
		}
	case <-time.After(time.Second):
		t.Fatal("Identity did not receive audit correlation")
	}
}

func TestGatewayIdentityMixedKeysKeepPublicErrorIDAndSplitAuditCorrelation(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1")
	identityKey := gatewayCorrelationKey(t, "fedcba9876543210fedcba9876543210")
	if identityKey == cfg.CorrelationKey {
		t.Fatal("test requires distinct Gateway and Identity keys")
	}
	signup := &gatewayCorrelationSignup{correlations: make(chan audit.CorrelationID, 2)}
	identity := newGatewayCorrelationIdentityServer(t, identityKey, signup)
	defer identity.Close()
	cfg.IdentityBaseURL = testConfig(t, identity.URL).IdentityBaseURL

	resp := httptest.NewRecorder()
	NewHandler(cfg, nil).ServeHTTP(resp, gatewayCorrelationSignupRequest("key"))
	envelope := assertIdentityCanonicalError(t, resp, http.StatusConflict, "idempotency_conflict")
	gatewayID := envelope.Error.RequestID
	if gatewayID == "00112233445566778899aabbccddeeff" {
		t.Fatal("Gateway accepted client-selected public request ID")
	}

	select {
	case auditID := <-signup.correlations:
		auditValue := hex.EncodeToString(auditID[:])
		if auditValue == gatewayID || len(auditValue) != 32 {
			t.Fatalf("mixed-key audit did not split: public=%q audit=%q", gatewayID, auditValue)
		}
	case <-time.After(time.Second):
		t.Fatal("Identity did not receive fresh audit correlation")
	}

	unauthorized := httptest.NewRecorder()
	NewHandler(cfg, nil).ServeHTTP(unauthorized, gatewayCorrelationSignupRequest("wrong-key"))
	assertIdentityCanonicalError(t, unauthorized, http.StatusUnauthorized, "invalid_application")
	select {
	case unexpected := <-signup.correlations:
		t.Fatalf("correlation metadata changed authorization outcome; signup received audit=%q", hex.EncodeToString(unexpected[:]))
	default:
	}
}
