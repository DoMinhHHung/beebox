//go:build integration

package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/httpapi"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
	sessionpostgres "github.com/DoMinhHHung/beebox/internal/session/postgres"
	"github.com/jackc/pgx/v5"
)

type gatewayDelivery struct {
	mu               sync.Mutex
	verificationCode string
	signInCode       string
}

func (d *gatewayDelivery) DeliverVerificationCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	d.verificationCode = code
	d.mu.Unlock()
	return nil
}

func (d *gatewayDelivery) DeliverPasswordResetCode(context.Context, string, string, time.Time) error {
	return nil
}

func (d *gatewayDelivery) DeliverSignInCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	d.signInCode = code
	d.mu.Unlock()
	return nil
}

func (d *gatewayDelivery) DeliverSignInLink(context.Context, string, string, time.Time) error {
	return nil
}

func (d *gatewayDelivery) verification() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.verificationCode
}

func (d *gatewayDelivery) signIn() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signInCode
}

func TestGatewayIdentityPostgreSQLCriticalJourney(t *testing.T) {
	pool := gatewayPool(t, "beebox_gateway_e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	integrationStore := applicationpostgres.NewIntegrationStore(pool)
	integrations := applicationinstance.NewIntegrationService(integrationStore)
	if _, err := integrations.AddAllowedOrigin(ctx, appA.InternalID, "http://public.example.test"); err != nil {
		t.Fatal(err)
	}
	_, publishableA, err := integrations.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}
	_, secretA, err := integrations.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindSecret)
	if err != nil {
		t.Fatal(err)
	}
	_, secretB, err := integrations.CreateCredential(ctx, appB.InternalID, applicationinstance.CredentialKindSecret)
	if err != nil {
		t.Fatal(err)
	}

	delivery := &gatewayDelivery{}
	authStore := authpostgres.New(pool)
	verificationCore := authentication.NewEmailVerificationService(authStore, delivery)
	verification := authentication.NewPublicVerificationService(identitypostgres.New(pool), authStore, verificationCore)
	signup := authentication.NewPublicSignupService(authStore, delivery)
	emailOTP := authentication.NewEmailOTPService(authStore, delivery)
	identityHandler := httpapi.New(http.NotFoundHandler(), integrations, integrationStore, signup, verification)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := session.NewKeyRing("https://auth.example.test", "gateway-e2e", privateKey, map[string]ed25519.PublicKey{"gateway-e2e": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	sessionStore := sessionpostgres.New(pool)
	sessions := session.NewService(sessionStore, sessionStore, ring)
	emailOTPSessions := session.NewEmailOTPService(authStore, ring)
	identityHandler = httpapi.WithSessions(identityHandler, integrations, integrationStore, sessions, ring)
	identityHandler = httpapi.WithEmailOTP(identityHandler, integrations, integrationStore, emailOTP, emailOTPSessions)
	identityHandler = httpapi.WithSessionManagement(identityHandler, integrations, integrations, sessions)
	accountCore := authentication.NewAccountManagementService(authStore, verificationCore, nil)
	identityHandler = httpapi.WithAccountManagement(identityHandler, integrations, integrationStore, sessions, accountCore)

	identityServer := httptest.NewServer(identityHandler)
	t.Cleanup(identityServer.Close)
	identityURL, err := url.Parse(identityServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	gatewayHandler := NewHandler(Config{
		IdentityBaseURL:       identityURL,
		ConnectTimeout:        time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		RequestTimeout:        10 * time.Second,
		ReadinessTimeout:      time.Second,
		ShutdownTimeout:       time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxBodyBytes:          1 << 20,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	gatewayRequest(t, gatewayHandler, "", http.MethodGet, "/health/live", "", nil, http.StatusOK, nil)

	const email = "gateway-alice@example.test"
	const password = "correct horse battery staple"
	gatewayRequest(t, gatewayHandler, publishableA, http.MethodPost, "/v1/sign-ups", `{"email":"`+email+`","password":"`+password+`"}`, map[string]string{"Idempotency-Key": "gateway-e2e-signup"}, http.StatusAccepted, nil)
	code := delivery.verification()
	if code == "" {
		t.Fatal("signup did not deliver verification code")
	}
	gatewayRequest(t, gatewayHandler, publishableA, http.MethodPost, "/v1/email-verifications/confirm", `{"email":"`+email+`","code":"`+code+`"}`, nil, http.StatusOK, nil)

	var passwordSession gatewaySessionResponse
	passwordResponse := gatewayRequest(t, gatewayHandler, publishableA, http.MethodPost, "/v1/sign-ins", `{"email":"`+email+`","password":"`+password+`"}`, nil, http.StatusOK, &passwordSession)
	passwordSession.requireBrowserComplete(t, passwordResponse)
	gatewayRequest(t, gatewayHandler, publishableA, http.MethodGet, "/v1/sessions/current", "", map[string]string{"Authorization": "Bearer " + passwordSession.AccessToken}, http.StatusOK, nil)
	gatewayRequest(t, gatewayHandler, publishableA, http.MethodGet, "/v1/profile", "", map[string]string{"Authorization": "Bearer " + passwordSession.AccessToken}, http.StatusOK, nil)
	gatewayRequest(t, gatewayHandler, "", http.MethodGet, "/.well-known/jwks.json", "", nil, http.StatusOK, nil)

	// A session public ID is a locator only. Another application's backend
	// credential cannot inspect app A's session through the public gateway.
	gatewayBackendRequest(t, gatewayHandler, secretB, "/v1/backend/sessions/"+passwordSession.SessionID, http.StatusNotFound)
	gatewayBackendRequest(t, gatewayHandler, secretA, "/v1/backend/sessions/"+passwordSession.SessionID, http.StatusOK)

	// Exercise a passwordless primary proof through the exact same network
	// boundary and verify it yields ordinary session authority only after its
	// one-time proof completes.
	gatewayRequest(t, gatewayHandler, publishableA, http.MethodPost, "/v1/sign-ins/email-otp", `{"email":"`+email+`"}`, nil, http.StatusAccepted, nil)
	otp := delivery.signIn()
	if otp == "" {
		t.Fatal("email OTP did not deliver code")
	}
	var otpSession gatewaySessionResponse
	otpResponse := gatewayRequest(t, gatewayHandler, publishableA, http.MethodPost, "/v1/sign-ins/email-otp/confirm", `{"email":"`+email+`","code":"`+otp+`"}`, nil, http.StatusOK, &otpSession)
	otpSession.requireBrowserComplete(t, otpResponse)
	gatewayRequest(t, gatewayHandler, publishableA, http.MethodGet, "/v1/profile", "", map[string]string{"Authorization": "Bearer " + otpSession.AccessToken}, http.StatusOK, nil)
}

type gatewaySessionResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
}

func (r gatewaySessionResponse) requireBrowserComplete(t *testing.T, res *httptest.ResponseRecorder) {
	t.Helper()
	if r.AccessToken == "" || r.SessionID == "" {
		t.Fatalf("incomplete browser session response: %#v", r)
	}
	if r.RefreshToken != "" {
		t.Fatal("browser session response exposed refresh token in JSON")
	}
	cookies := res.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("refresh cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !strings.HasPrefix(cookie.Name, "__Host-beebox-refresh-") || cookie.Value == "" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("gateway refresh cookie = %#v", cookie)
	}
	if strings.Contains(res.Body.String(), cookie.Value) {
		t.Fatal("browser response JSON contained refresh cookie secret")
	}
}

func gatewayRequest(t *testing.T, handler http.Handler, publishable, method, path, body string, headers map[string]string, want int, output any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://public.example.test"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if publishable != "" {
		req.Header.Set(httpapi.PublishableKeyHeader, publishable)
		req.Header.Set("Origin", "http://public.example.test")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != want {
		t.Fatalf("%s %s status = %d want %d body=%s", method, path, res.Code, want, res.Body.String())
	}
	if res.Header().Get(requestIDHeader) == "" {
		t.Fatalf("%s %s missing gateway request ID", method, path)
	}
	if output != nil {
		if err := json.Unmarshal(res.Body.Bytes(), output); err != nil {
			t.Fatalf("decode %s %s response: %v", method, path, err)
		}
	}
	return res
}

func gatewayBackendRequest(t *testing.T, handler http.Handler, secret, path string, want int) {
	t.Helper()
	gatewayRequest(t, handler, "", http.MethodGet, path, "", map[string]string{"Authorization": "Bearer " + secret}, want, nil)
}

func gatewayPool(t *testing.T, schema string) *database.Pool {
	t.Helper()
	databaseURL := os.Getenv("BEEBOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("BEEBOX_TEST_DATABASE_URL is required")
	}
	admin, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	db := admin.OpenSQLDB()
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + quoted + " CASCADE"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE SCHEMA " + quoted); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP SCHEMA IF EXISTS " + quoted + " CASCADE")
		_ = db.Close()
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(context.Background(), parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
