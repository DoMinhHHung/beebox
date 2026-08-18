//go:build integration

package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
	sessionpostgres "github.com/DoMinhHHung/beebox/internal/session/postgres"
)

type phoneExitDelivery struct {
	mu      sync.Mutex
	signup  string
	signin  string
}

func (d *phoneExitDelivery) DeliverPhoneSignupCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signup = code
	return nil
}

func (d *phoneExitDelivery) DeliverPhoneSignInCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signin = code
	return nil
}

func (d *phoneExitDelivery) signupCode() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signup
}

func (d *phoneExitDelivery) signinCode() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signin
}

func TestPhoneSignupAndSignInHTTPLifecycleOverPostgreSQL(t *testing.T) {
	pool := exitPool(t, "beebox_phone_exit")
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
	_, publishableA, err := integrations.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}
	_, publishableB, err := integrations.CreateCredential(ctx, appB.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}

	delivery := &phoneExitDelivery{}
	authStore := authpostgres.New(pool)
	signupIssuer := authentication.NewPhoneSignupService(authStore, delivery)
	signinIssuer := authentication.NewPhoneOTPService(authStore, delivery)
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
	signupConfirmer := session.NewPhoneSignupService(authStore, ring)
	signinConfirmer := session.NewPhoneOTPService(authStore, ring)
	var handler http.Handler = http.NotFoundHandler()
	handler = WithSessions(handler, integrations, integrationStore, sessions, ring)
	handler = WithPhoneSMS(handler, integrations, integrationStore, signupIssuer, signupConfirmer, signinIssuer, signinConfirmer)
	handler = WithSessionManagement(handler, integrations, integrations, sessions)

	const phone = "+84901234567"
	db := pool.OpenSQLDB()
	defer db.Close()
	var users, phones int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(appA.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("users before phone signup = %d, want 0", users)
	}

	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ups/phone", `{"phone":"`+phone+`"}`, nil, http.StatusAccepted, nil)
	if code := delivery.signupCode(); code == "" {
		t.Fatal("phone signup did not deliver a code")
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(appA.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE application_instance_id=$1`, int64(appA.InternalID)).Scan(&phones); err != nil {
		t.Fatal(err)
	}
	if users != 0 || phones != 0 {
		t.Fatalf("phone issue created principal state users=%d phones=%d", users, phones)
	}

	// A different application cannot redeem app A's pending challenge.
	exitRequest(t, handler, publishableB, http.MethodPost, "/v1/sign-ups/phone/confirm", `{"phone":"`+phone+`","code":"`+delivery.signupCode()+`"}`, nil, http.StatusUnauthorized, nil)

	var signedUp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		SessionID    string `json:"session_id"`
	}
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ups/phone/confirm", `{"phone":"`+phone+`","code":"`+delivery.signupCode()+`"}`, nil, http.StatusOK, &signedUp)
	if signedUp.AccessToken == "" || signedUp.RefreshToken == "" || signedUp.SessionID == "" {
		t.Fatalf("phone signup returned incomplete session: %#v", signedUp)
	}
	exitRequest(t, handler, publishableA, http.MethodGet, "/v1/sessions/current", "", map[string]string{"Authorization": "Bearer " + signedUp.AccessToken}, http.StatusOK, nil)

	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		SessionID    string `json:"session_id"`
	}
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sessions/refresh", `{"refresh_token":"`+signedUp.RefreshToken+`"}`, nil, http.StatusOK, &rotated)
	if rotated.RefreshToken == "" || rotated.RefreshToken == signedUp.RefreshToken || rotated.SessionID != signedUp.SessionID {
		t.Fatalf("phone signup refresh did not rotate: %#v", rotated)
	}
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sessions/sign-out", "", map[string]string{"Authorization": "Bearer " + rotated.AccessToken}, http.StatusOK, nil)
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ups/phone/confirm", `{"phone":"`+phone+`","code":"`+delivery.signupCode()+`"}`, nil, http.StatusUnauthorized, nil)

	// Unknown phone issue is indistinguishable and does not create a session.
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ins/phone-otp", `{"phone":"+84909999999"}`, nil, http.StatusAccepted, nil)

	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ins/phone-otp", `{"phone":"`+phone+`"}`, nil, http.StatusAccepted, nil)
	if code := delivery.signinCode(); code == "" {
		t.Fatal("phone sign-in did not deliver a code")
	}
	// Same canonical phone in app B remains an independent scope and cannot redeem app A's code.
	exitRequest(t, handler, publishableB, http.MethodPost, "/v1/sign-ins/phone-otp/confirm", `{"phone":"`+phone+`","code":"`+delivery.signinCode()+`"}`, nil, http.StatusUnauthorized, nil)

	var signedIn struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		SessionID    string `json:"session_id"`
	}
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ins/phone-otp/confirm", `{"phone":"`+phone+`","code":"`+delivery.signinCode()+`"}`, nil, http.StatusOK, &signedIn)
	if signedIn.AccessToken == "" || signedIn.RefreshToken == "" || signedIn.SessionID == "" {
		t.Fatalf("phone sign-in returned incomplete session: %#v", signedIn)
	}
	exitRequest(t, handler, publishableA, http.MethodGet, "/v1/sessions/current", "", map[string]string{"Authorization": "Bearer " + signedIn.AccessToken}, http.StatusOK, nil)
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sessions/refresh", `{"refresh_token":"`+signedIn.RefreshToken+`"}`, nil, http.StatusOK, &rotated)
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sessions/sign-out", "", map[string]string{"Authorization": "Bearer " + rotated.AccessToken}, http.StatusOK, nil)
	exitRequest(t, handler, publishableA, http.MethodPost, "/v1/sign-ins/phone-otp/confirm", `{"phone":"`+phone+`","code":"`+delivery.signinCode()+`"}`, nil, http.StatusUnauthorized, nil)
}
