//go:build integration

package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/identity"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
	sessionpostgres "github.com/DoMinhHHung/beebox/internal/session/postgres"
)

func TestSocialLinkHTTPLifecycleOverPostgreSQL(t *testing.T) {
	pool := exitPool(t, "beebox_social_link_http_exit")
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

	const originA = "https://app-a.example"
	const originB = "https://app-b.example"
	const redirectA = "https://app-a.example/account/link-complete"
	const foreignRedirect = "https://app-a.example/foreign-link-complete"
	if _, err := integrations.AddAllowedOrigin(ctx, appA.InternalID, originA); err != nil {
		t.Fatal(err)
	}
	if _, err := integrations.AddAllowedOrigin(ctx, appB.InternalID, originB); err != nil {
		t.Fatal(err)
	}
	if _, err := integrations.AddAllowedRedirectURL(ctx, appA.InternalID, redirectA); err != nil {
		t.Fatal(err)
	}
	if _, err := integrations.AddAllowedRedirectURL(ctx, appB.InternalID, foreignRedirect); err != nil {
		t.Fatal(err)
	}

	identityStore := identitypostgres.New(pool)
	userA, err := identityStore.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := identityStore.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := session.NewKeyRing("https://auth.example.test", "active", privateKey, map[string]ed25519.PublicKey{"active": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	now := time.Now().UTC()
	sessionA := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userA.InternalID, now.Add(-time.Minute), now.Add(time.Hour))
	sessionB := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userB.InternalID, now.Add(-time.Minute), now.Add(time.Hour))
	tokenA, err := ring.Sign(string(userA.PublicID), string(appA.PublicID), sessionA, now)
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := ring.Sign(string(userB.PublicID), string(appA.PublicID), sessionB, now)
	if err != nil {
		t.Fatal(err)
	}

	authStore := authpostgres.New(pool)
	sessionStore := sessionpostgres.New(pool)
	sessionService := session.NewService(sessionStore, sessionStore, ring)
	provider := &socialHTTPE2EProvider{provider: authentication.ProviderGitHub}
	registry := socialHTTPE2ERegistry{appID: appA.PublicID, provider: provider}
	linkCore := authentication.NewSocialLinkService(authStore, integrationStore, authStore, registry, nil)
	socialCore := authentication.NewSocialService(authStore, integrationStore, authStore, registry, nil)
	socialCompletion := session.NewSocialCompletionService(authStore, authStore, ring)
	reverificationCore := authentication.NewReverificationService(authStore)
	base := WithSocialAuth(http.NotFoundHandler(), integrations, integrationStore, socialCore, socialCompletion)
	base = WithSocialLinks(base, integrations, integrationStore, sessionService, linkCore)
	handler := WithReverification(base, integrations, integrationStore, sessionService, reverificationCore)

	t.Run("session switch callback stays bound to initiating principal", func(t *testing.T) {
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, tokenA, redirectA, "github")
		callback := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&user_id="+url.QueryEscape(string(userB.PublicID))+"&session_id="+url.QueryEscape(sessionB)+"&redirect_url=https%3A%2F%2Fevil.example", nil)
		req.Header.Set("Authorization", "Bearer "+tokenB)
		handler.ServeHTTP(callback, req)
		if callback.Code != http.StatusSeeOther {
			t.Fatalf("callback status/body = %d %s", callback.Code, callback.Body.String())
		}
		assertSocialStoredRedirect(t, callback, redirectA, "beebox_link", "success")
		assertSocialLinkOwner(t, ctx, db, appA.InternalID, authentication.ProviderGitHub, "social-http-provider-subject", userA.InternalID)
		assertSocialLinkCounts(t, ctx, db, appA.InternalID, 2, 2, 0)

		replay := httptest.NewRecorder()
		handler.ServeHTTP(replay, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&redirect_url=https%3A%2F%2Fevil.example", nil))
		assertSocialError(t, replay, http.StatusBadRequest, "invalid_social_state")
		if replay.Header().Get("Location") != "" {
			t.Fatalf("replay redirected to %q", replay.Header().Get("Location"))
		}
	})

	t.Run("separate fresh proof authorizes an older active target session", func(t *testing.T) {
		staleSession := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userA.InternalID, now.Add(-11*time.Minute), now.Add(time.Hour))
		proofSession := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userA.InternalID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		staleToken, err := ring.Sign(string(userA.PublicID), string(appA.PublicID), staleSession, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		proofToken, err := ring.Sign(string(userA.PublicID), string(appA.PublicID), proofSession, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		grant := createSocialLinkHTTPReverification(t, handler, publishableA, originA, staleToken, proofToken)
		res := socialLinkE2EPost(t, handler, publishableA, originA, staleToken, grant, `{"provider":"github","redirect_url":"`+redirectA+`"}`)
		if res.Code != http.StatusCreated {
			t.Fatalf("older target with fresh proof status/body = %d %s", res.Code, res.Body.String())
		}
	})

	t.Run("initiation rejects untrusted application origin redirect provider and principal input", func(t *testing.T) {
		cases := []struct {
			name                string
			publishable         string
			origin              string
			token               string
			body                string
			needsReverification bool
			status              int
			code                string
		}{
			{name: "wrong audience", publishable: publishableB, origin: originB, token: tokenA, body: `{"provider":"github","redirect_url":"https://app-b.example/link"}`, status: http.StatusUnauthorized, code: "invalid_session"},
			{name: "wrong origin", publishable: publishableA, origin: originB, token: tokenA, body: `{"provider":"github","redirect_url":"` + redirectA + `"}`, status: http.StatusForbidden, code: "origin_not_allowed"},
			{name: "foreign redirect", publishable: publishableA, origin: originA, token: tokenA, body: `{"provider":"github","redirect_url":"` + foreignRedirect + `"}`, needsReverification: true, status: http.StatusUnprocessableEntity, code: "invalid_redirect"},
			{name: "unsupported provider", publishable: publishableA, origin: originA, token: tokenA, body: `{"provider":"custom","redirect_url":"` + redirectA + `"}`, needsReverification: true, status: http.StatusUnprocessableEntity, code: "unsupported_provider"},
			{name: "chosen principal", publishable: publishableA, origin: originA, token: tokenA, body: `{"provider":"github","redirect_url":"` + redirectA + `","user_id":"` + string(userB.PublicID) + `","session_id":"` + sessionB + `"}`, needsReverification: true, status: http.StatusBadRequest, code: "invalid_request"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				grant := ""
				if tc.needsReverification {
					grant = createSocialLinkHTTPReverification(t, handler, publishableA, originA, tokenA, tokenA)
				}
				res := socialLinkE2EPost(t, handler, tc.publishable, tc.origin, tc.token, grant, tc.body)
				assertSocialError(t, res, tc.status, tc.code)
			})
		}
	})

	t.Run("purpose and provider substitution fail closed", func(t *testing.T) {
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, tokenA, redirectA, "github")
		wrongProvider := httptest.NewRecorder()
		handler.ServeHTTP(wrongProvider, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/gitlab?state="+url.QueryEscape(state)+"&code=provider-code", nil))
		assertSocialError(t, wrongProvider, http.StatusBadRequest, "invalid_social_state")

		stripped := httptest.NewRecorder()
		handler.ServeHTTP(stripped, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(strings.TrimPrefix(state, authentication.SocialLinkStatePrefix))+"&code=provider-code", nil))
		assertSocialError(t, stripped, http.StatusBadRequest, "invalid_social_state")

		verifier := strings.Repeat("v", 43)
		challenge, ok := authentication.S256Challenge(verifier)
		if !ok {
			t.Fatal("failed to build P2.3 code challenge")
		}
		authAttempt := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"`+redirectA+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		if authAttempt.Code != http.StatusCreated {
			t.Fatalf("P2.3 attempt status/body = %d %s", authAttempt.Code, authAttempt.Body.String())
		}
		var payload socialAttemptResponse
		if err := json.Unmarshal(authAttempt.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		authorization, err := url.Parse(payload.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		prefixed := httptest.NewRecorder()
		handler.ServeHTTP(prefixed, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(authentication.SocialLinkStatePrefix+authorization.Query().Get("state"))+"&code=provider-code", nil))
		assertSocialError(t, prefixed, http.StatusBadRequest, "invalid_social_state")
	})

	t.Run("provider denial skips proof and uses generic stored redirect", func(t *testing.T) {
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, tokenA, redirectA, "github")
		before := provider.exchangeCalls
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&error=access_denied&error_description=provider-secret", nil))
		if res.Code != http.StatusSeeOther {
			t.Fatalf("denial status/body = %d %s", res.Code, res.Body.String())
		}
		assertSocialStoredRedirect(t, res, redirectA, "beebox_error", "social_link_failed")
		if provider.exchangeCalls != before {
			t.Fatalf("provider denial called proof: before=%d after=%d", before, provider.exchangeCalls)
		}
	})

	t.Run("revoked initiating session cannot be replaced at callback", func(t *testing.T) {
		revocable := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userA.InternalID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		revocableToken, err := ring.Sign(string(userA.PublicID), string(appA.PublicID), revocable, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, revocableToken, revocableToken, redirectA, "github")
		if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND public_id=$2`, int64(appA.InternalID), revocable); err != nil {
			t.Fatal(err)
		}
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&session_id="+url.QueryEscape(sessionB), nil)
		req.Header.Set("Authorization", "Bearer "+tokenB)
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusSeeOther {
			t.Fatalf("revoked callback status/body = %d %s", res.Code, res.Body.String())
		}
		assertSocialStoredRedirect(t, res, redirectA, "beebox_error", "social_link_failed")
	})

	t.Run("other owner conflict is generic and never transfers ownership", func(t *testing.T) {
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenB, tokenB, redirectA, "github")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code", nil))
		if res.Code != http.StatusSeeOther {
			t.Fatalf("conflict callback status/body = %d %s", res.Code, res.Body.String())
		}
		assertSocialStoredRedirect(t, res, redirectA, "beebox_error", "social_link_failed")
		assertSocialLinkOwner(t, ctx, db, appA.InternalID, authentication.ProviderGitHub, "social-http-provider-subject", userA.InternalID)
	})
}

func createSocialLinkHTTPAttempt(t *testing.T, handler http.Handler, publishable, origin, targetAccessToken, proofAccessToken, redirect, provider string) string {
	t.Helper()
	grant := createSocialLinkHTTPReverification(t, handler, publishable, origin, targetAccessToken, proofAccessToken)
	res := socialLinkE2EPost(t, handler, publishable, origin, targetAccessToken, grant, `{"provider":"`+provider+`","redirect_url":"`+redirect+`"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("create social link attempt status/body = %d %s", res.Code, res.Body.String())
	}
	assertSocialSecurityHeaders(t, res, origin)
	var payload socialLinkAttemptResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ExpiresIn <= 0 || payload.ExpiresIn > 600 {
		t.Fatalf("expires_in = %d", payload.ExpiresIn)
	}
	authorization, err := url.Parse(payload.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := authorization.Query().Get("state")
	if !strings.HasPrefix(state, authentication.SocialLinkStatePrefix) {
		t.Fatalf("authorization state = %q", state)
	}
	return state
}

func createSocialLinkHTTPReverification(t *testing.T, handler http.Handler, publishable, origin, targetAccessToken, proofAccessToken string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"purpose":            authentication.ReverificationPurposeSocialLink,
		"proof_access_token": proofAccessToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/reverifications", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, publishable)
	req.Header.Set("Origin", origin)
	req.Header.Set("Authorization", "Bearer "+targetAccessToken)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create reverification status/body = %d %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("reverification Cache-Control=%q want no-store", got)
	}
	var grant authentication.ReverificationGrant
	if err := json.Unmarshal(res.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.Token == "" || grant.ExpiresAt.IsZero() {
		t.Fatalf("invalid reverification response: %#v", grant)
	}
	return grant.Token
}

func socialLinkE2EPost(t *testing.T, handler http.Handler, publishable, origin, accessToken, reverificationToken, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/social-links/attempts", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if publishable != "" {
		req.Header.Set(PublishableKeyHeader, publishable)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if reverificationToken != "" {
		req.Header.Set(ReverificationHeader, reverificationToken)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func insertSocialLinkHTTPSession(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, userID identity.InternalID, createdAt, expiresAt time.Time) string {
	t.Helper()
	publicID, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,created_at,last_seen_at,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$4,$5,$5)`, publicID, int64(appID), int64(userID), createdAt.UTC(), expiresAt.UTC()); err != nil {
		t.Fatal(err)
	}
	return publicID
}

func assertSocialLinkOwner(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, provider authentication.Provider, subject string, want identity.InternalID) {
	t.Helper()
	var got int64
	if err := db.QueryRowContext(ctx, `SELECT user_id FROM external_identities WHERE application_instance_id=$1 AND provider=$2 AND provider_subject=$3`, int64(appID), string(provider), subject).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != int64(want) {
		t.Fatalf("social link owner = %d want %d", got, want)
	}
}

func assertSocialLinkCounts(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, wantUsers, wantSessions, wantGrants int) {
	t.Helper()
	var users, sessions, grants int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(appID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(appID)).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_auth_completion_grants WHERE application_instance_id=$1`, int64(appID)).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if users != wantUsers || sessions != wantSessions || grants != wantGrants {
		t.Fatalf("users/sessions/grants = %d/%d/%d want %d/%d/%d", users, sessions, grants, wantUsers, wantSessions, wantGrants)
	}
}
