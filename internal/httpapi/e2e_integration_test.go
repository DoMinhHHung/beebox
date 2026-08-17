//go:build integration

package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
	sessionpostgres "github.com/DoMinhHHung/beebox/internal/session/postgres"
	"github.com/jackc/pgx/v5"
)

type exitDelivery struct {
	mu               sync.Mutex
	verificationCode string
	resetCode        string
}

func (d *exitDelivery) DeliverVerificationCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	d.verificationCode = code
	d.mu.Unlock()
	return nil
}

func (d *exitDelivery) DeliverPasswordResetCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	d.resetCode = code
	d.mu.Unlock()
	return nil
}

func (d *exitDelivery) verification() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.verificationCode
}

func (d *exitDelivery) reset() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.resetCode
}

func TestPhase1HTTPLifecycleOverPostgreSQL(t *testing.T) {
	pool := exitPool(t, "beebox_phase1_exit")
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
	_, publishable, err := integrations.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindPublishable)
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

	delivery := &exitDelivery{}
	authStore := authpostgres.New(pool)
	verificationCore := authentication.NewEmailVerificationService(authStore, delivery)
	verification := authentication.NewPublicVerificationService(identitypostgres.New(pool), authStore, verificationCore)
	signup := authentication.NewPublicSignupService(authStore, delivery)
	reset := authentication.NewPasswordResetService(authStore, delivery)
	base := New(http.NotFoundHandler(), integrations, integrationStore, signup, verification)
	base = WithPasswordReset(base, integrations, integrationStore, reset)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := session.NewKeyRing("https://auth.example.test", "active", privateKey, map[string]ed25519.PublicKey{"active": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	sessionStore := sessionpostgres.New(pool)
	sessions := session.NewService(sessionStore, sessionStore, ring)
	base = WithSessions(base, integrations, integrationStore, sessions, ring)
	base = WithSessionManagement(base, integrations, integrations, sessions)

	const email = "alice@example.test"
	const oldPassword = "correct horse battery staple"
	const newPassword = "different horse battery staple"

	exitRequest(t, base, publishable, http.MethodPost, "/v1/sign-ups", `{"email":"`+email+`","password":"`+oldPassword+`"}`, map[string]string{"Idempotency-Key": "phase1-exit-signup"}, http.StatusAccepted, nil)
	code := delivery.verification()
	if code == "" {
		t.Fatal("signup did not deliver verification code")
	}
	exitRequest(t, base, publishable, http.MethodPost, "/v1/email-verifications/confirm", `{"email":"`+email+`","code":"`+code+`"}`, nil, http.StatusOK, nil)

	var signedIn struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		SessionID    string `json:"session_id"`
	}
	exitRequest(t, base, publishable, http.MethodPost, "/v1/sign-ins", `{"email":"`+email+`","password":"`+oldPassword+`"}`, nil, http.StatusOK, &signedIn)
	if signedIn.AccessToken == "" || signedIn.RefreshToken == "" || signedIn.SessionID == "" {
		t.Fatalf("signin returned incomplete session material: %#v", signedIn)
	}
	exitRequest(t, base, publishable, http.MethodGet, "/v1/sessions/current", "", map[string]string{"Authorization": "Bearer " + signedIn.AccessToken}, http.StatusOK, nil)

	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		SessionID    string `json:"session_id"`
	}
	exitRequest(t, base, publishable, http.MethodPost, "/v1/sessions/refresh", `{"refresh_token":"`+signedIn.RefreshToken+`"}`, nil, http.StatusOK, &rotated)
	if rotated.RefreshToken == "" || rotated.RefreshToken == signedIn.RefreshToken || rotated.SessionID != signedIn.SessionID {
		t.Fatalf("refresh did not rotate exactly one credential: %#v", rotated)
	}

	// Backend authority is application scoped: app B cannot inspect app A's session.
	exitBackendRequest(t, base, secretB, http.MethodGet, "/v1/backend/sessions/"+signedIn.SessionID, http.StatusNotFound)
	exitBackendRequest(t, base, secretA, http.MethodGet, "/v1/backend/sessions/"+signedIn.SessionID, http.StatusOK)

	exitRequest(t, base, publishable, http.MethodPost, "/v1/sessions/sign-out", "", map[string]string{"Authorization": "Bearer " + rotated.AccessToken}, http.StatusOK, nil)
	exitRequest(t, base, publishable, http.MethodPost, "/v1/sessions/refresh", `{"refresh_token":"`+rotated.RefreshToken+`"}`, nil, http.StatusUnauthorized, nil)

	exitRequest(t, base, publishable, http.MethodPost, "/v1/password-resets", `{"email":"`+email+`"}`, nil, http.StatusAccepted, nil)
	resetCode := delivery.reset()
	if resetCode == "" {
		t.Fatal("password reset did not deliver reset code")
	}
	exitRequest(t, base, publishable, http.MethodPost, "/v1/password-resets/confirm", `{"email":"`+email+`","code":"`+resetCode+`","new_password":"`+newPassword+`"}`, nil, http.StatusOK, nil)

	exitRequest(t, base, publishable, http.MethodPost, "/v1/sign-ins", `{"email":"`+email+`","password":"`+oldPassword+`"}`, nil, http.StatusUnauthorized, nil)
	exitRequest(t, base, publishable, http.MethodPost, "/v1/sign-ins", `{"email":"`+email+`","password":"`+newPassword+`"}`, nil, http.StatusOK, nil)
}

func exitRequest(t *testing.T, handler http.Handler, publishable, method, path, body string, headers map[string]string, want int, output any) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if publishable != "" {
		req.Header.Set(PublishableKeyHeader, publishable)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != want {
		t.Fatalf("%s %s status = %d want %d body=%s", method, path, res.Code, want, res.Body.String())
	}
	if output != nil {
		if err := json.Unmarshal(res.Body.Bytes(), output); err != nil {
			t.Fatalf("decode %s %s response: %v", method, path, err)
		}
	}
}

func exitBackendRequest(t *testing.T, handler http.Handler, secret, method, path string, want int) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != want {
		t.Fatalf("backend %s %s status = %d want %d body=%s", method, path, res.Code, want, res.Body.String())
	}
}

func exitPool(t *testing.T, schema string) *database.Pool {
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
