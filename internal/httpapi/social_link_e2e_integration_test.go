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

type socialLinkE2EProvider struct {
	provider      authentication.Provider
	subject       string
	exchangeCalls int
}

func (p *socialLinkE2EProvider) Provider() authentication.Provider { return p.provider }
func (*socialLinkE2EProvider) UsesPKCE() bool                       { return false }
func (*socialLinkE2EProvider) UsesNonce() bool                      { return false }
func (*socialLinkE2EProvider) AuthorizationURL(state, _, _ string) (string, error) {
	u := &url.URL{Scheme: "https", Host: "provider.example.test", Path: "/authorize"}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (p *socialLinkE2EProvider) ExchangeIdentity(_ context.Context, code, _ string, _ [32]byte) (authentication.ExternalIdentityProof, error) {
	p.exchangeCalls++
	if code == "" || p.subject == "" {
		return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
	}
	return authentication.ExternalIdentityProof{Provider: p.provider, Subject: p.subject}, nil
}

type socialLinkE2ERegistry struct {
	appID    applicationinstance.PublicID
	provider *socialLinkE2EProvider
}

func (r socialLinkE2ERegistry) Resolve(appID applicationinstance.PublicID, provider authentication.Provider) (authentication.SocialProvider, bool) {
	if r.provider == nil || appID != r.appID || provider != r.provider.provider {
		return nil, false
	}
	return r.provider, true
}

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
	provider := &socialLinkE2EProvider{provider: authentication.ProviderGitHub, subject: "link-subject-a"}
	registry := socialLinkE2ERegistry{appID: appA.PublicID, provider: provider}
	linkCore := authentication.NewSocialLinkService(authStore, integrationStore, authStore, registry, nil)
	socialCore := authentication.NewSocialService(authStore, integrationStore, authStore, registry, nil)
	socialCompletion := session.NewSocialCompletionService(authStore, authStore, ring)
	base := WithSocialAuth(http.NotFoundHandler(), integrations, integrationStore, socialCore, socialCompletion)
	handler := WithSocialLinks(base, integrations, integrationStore, sessionService, linkCore)

	t.Run("fresh authenticated initiation and session switch callback stay bound to user A", func(t *testing.T) {
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, redirectA, "github")
		if !strings.HasPrefix(state, authentication.SocialLinkStatePrefix) {
			t.Fatalf("link state = %q", state)
		}

		callback := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&user_id="+url.QueryEscape(string(userB.PublicID))+"&session_id="+url.QueryEscape(sessionB)+"&redirect_url=https%3A%2F%2Fevil.example%2Fsteal", nil)
		req.Header.Set("Authorization", "Bearer "+tokenB)
		handler.ServeHTTP(callback, req)
		if callback.Code != http.StatusSeeOther {
			t.Fatalf("callback status/body = %d %s", callback.Code, callback.Body.String())
		}
		assertSocialStoredRedirect(t, callback, redirectA, "beebox_link", "success")
		assertSocialLinkOwner(t, ctx, db, appA.InternalID, authentication.ProviderGitHub, "link-subject-a", userA.InternalID)
		assertSocialLinkCounts(t, ctx, db, appA.InternalID, 2, 2, 0)

		replay := httptest.NewRecorder()
		handler.ServeHTTP(replay, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&redirect_url=https%3A%2F%2Fevil.example", nil))
		assertSocialError(t, replay, http.StatusBadRequest, "invalid_social_state")
		if replay.Header().Get("Location") != "" {
			t.Fatalf("replay redirected to %q", replay.Header().Get("Location"))
		}
	})

	t.Run("stale session with newly signed access token still requires reverification", func(t *testing.T) {
		staleSession := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userA.InternalID, now.Add(-11*time.Minute), now.Add(time.Hour))
		freshCredentialForOldSession, err := ring.Sign(string(userA.PublicID), string(appA.PublicID), staleSession, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		res := socialLinkE2EPost(t, handler, publishableA, originA, freshCredentialForOldSession, "/v1/social-links/attempts", `{"provider":"github","redirect_url":"`+redirectA+`"}`)
		assertSocialError(t, res, http.StatusForbidden, "reverification_required")
	})

	t.Run("invalid audience origin redirect provider and client principal are rejected", func(t *testing.T) {
		wrongAudience := socialLinkE2EPost(t, handler, publishableB, originB, tokenA, "/v1/social-links/attempts", `{"provider":"github","redirect_url":"https://app-b.example/link"}`)
		assertSocialError(t, wrongAudience, http.StatusUnauthorized, "invalid_session")

		wrongOrigin := socialLinkE2EPost(t, handler, publishableA, originB, tokenA, "/v1/social-links/attempts", `{"provider":"github","redirect_url":"`+redirectA+`"}`)
		assertSocialError(t, wrongOrigin, http.StatusForbidden, "origin_not_allowed")

		crossAppRedirect := socialLinkE2EPost(t, handler, publishableA, originA, tokenA, "/v1/social-links/attempts", `{"provider":"github","redirect_url":"`+foreignRedirect+`"}`)
		assertSocialError(t, crossAppRedirect, http.StatusUnprocessableEntity, "invalid_redirect")

		unsupported := socialLinkE2EPost(t, handler, publishableA, originA, tokenA, "/v1/social-links/attempts", `{"provider":"custom","redirect_url":"`+redirectA+`"}`)
		assertSocialError(t, unsupported, http.StatusUnprocessableEntity, "unsupported_provider")

		chosenPrincipal := socialLinkE2EPost(t, handler, publishableA, originA, tokenA, "/v1/social-links/attempts", `{"provider":"github","redirect_url":"`+redirectA+`","user_id":"`+string(userB.PublicID)+`","session_id":"`+sessionB+`"}`)
		assertSocialError(t, chosenPrincipal, http.StatusBadRequest, "invalid_request")
	})

	t.Run("provider mismatch and purpose substitution fail without consuming valid authority", func(t *testing.T) {
		provider.subject = "link-subject-purpose"
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, redirectA, "github")
		wrongProvider := httptest.NewRecorder()
		handler.ServeHTTP(wrongProvider, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/gitlab?state="+url.QueryEscape(state)+"&code=provider-code", nil))
		assertSocialError(t, wrongProvider, http.StatusBadRequest, "invalid_social_state")

		stripped := strings.TrimPrefix(state, authentication.SocialLinkStatePrefix)
		strippedCallback := httptest.NewRecorder()
		handler.ServeHTTP(strippedCallback, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(stripped)+"&code=provider-code", nil))
		assertSocialError(t, strippedCallback, http.StatusBadRequest, "invalid_social_state")

		valid := httptest.NewRecorder()
		handler.ServeHTTP(valid, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code", nil))
		if valid.Code != http.StatusSeeOther {
			t.Fatalf("valid link callback after substitution probes = %d %s", valid.Code, valid.Body.String())
		}
		assertSocialLinkOwner(t, ctx, db, appA.InternalID, authentication.ProviderGitHub, "link-subject-purpose", userA.InternalID)

		verifier := strings.Repeat("v", 43)
		challenge, ok := authentication.S256Challenge(verifier)
		if !ok {
			t.Fatal("failed to create P2.3 challenge")
		}
		authAttempt := socialE2EPost(t, handler, publishableA, originA, "", "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"`+redirectA+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		if authAttempt.Code != http.StatusCreated {
			t.Fatalf("P2.3 attempt status/body = %d %s", authAttempt.Code, authAttempt.Body.String())
		}
		var authPayload socialAttemptResponse
		if err := json.Unmarshal(authAttempt.Body.Bytes(), &authPayload); err != nil {
			t.Fatal(err)
		}
		authorization, err := url.Parse(authPayload.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		authState := authorization.Query().Get("state")
		prefixedAuth := httptest.NewRecorder()
		handler.ServeHTTP(prefixedAuth, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(authentication.SocialLinkStatePrefix+authState)+"&code=provider-code", nil))
		assertSocialError(t, prefixedAuth, http.StatusBadRequest, "invalid_social_state")
	})

	t.Run("provider denial is generic and does not call provider proof", func(t *testing.T) {
		provider.subject = "link-subject-denial"
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, redirectA, "github")
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

	t.Run("revoked initiating session fails instead of substituting replacement session", func(t *testing.T) {
		provider.subject = "link-subject-revoked"
		revocable := insertSocialLinkHTTPSession(t, ctx, db, appA.InternalID, userA.InternalID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		revocableToken, err := ring.Sign(string(userA.PublicID), string(appA.PublicID), revocable, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, revocableToken, redirectA, "github")
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
		assertSocialLinkMissing(t, ctx, db, appA.InternalID, authentication.ProviderGitHub, "link-subject-revoked")
	})

	t.Run("other owner subject fails generically without transfer", func(t *testing.T) {
		const subject = "link-subject-conflict"
		if _, err := db.ExecContext(ctx, `INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject) VALUES($1,$2,'github',$3)`, int64(appA.InternalID), int64(userB.InternalID), subject); err != nil {
			t.Fatal(err)
		}
		provider.subject = subject
		state := createSocialLinkHTTPAttempt(t, handler, publishableA, originA, tokenA, redirectA, "github")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code", nil))
		if res.Code != http.StatusSeeOther {
			t.Fatalf("conflict callback status/body = %d %s", res.Code, res.Body.String())
		}
		assertSocialStoredRedirect(t, res, redirectA, "beebox_error", "social_link_failed")
		assertSocialLinkOwner(t, ctx, db, appA.InternalID, authentication.ProviderGitHub, subject, userB.InternalID)
	})
}

func createSocialLinkHTTPAttempt(t *testing.T, handler http.Handler, publishable, origin, accessToken, redirect, provider string) string {
	t.Helper()
	res := socialLinkE2EPost(t, handler, publishable, origin, accessToken, "/v1/social-links/attempts", `{"provider":"`+provider+`","redirect_url":"`+redirect+`"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("create social link attempt status/body = %d %s", res.Code, res.Body.String())
	}
	assertSocialSecurityHeaders(t, res, origin)
	var payload socialLinkAttemptResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ExpiresIn <= 0 || payload.ExpiresIn > 600 {
		t.Fatalf("social link expires_in = %d", payload.ExpiresIn)
	}
	authorization, err := url.Parse(payload.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := authorization.Query().Get("state")
	if state == "" {
		t.Fatalf("authorization URL omitted state: %q", payload.AuthorizationURL)
	}
	return state
}

func socialLinkE2EPost(t *testing.T, handler http.Handler, publishable, origin, accessToken, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
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

func assertSocialLinkMissing(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, provider authentication.Provider, subject string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND provider=$2 AND provider_subject=$3`, int64(appID), string(provider), subject).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unexpected social link rows = %d", count)
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
