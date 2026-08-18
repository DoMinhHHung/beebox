package socialprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	providerHTTPTimeout = 5 * time.Second
	providerBodyLimit   = 1 << 20
)

type subjectMode uint8

const (
	subjectOIDC subjectMode = iota + 1
	subjectTopLevelID
	subjectNestedDataID
	subjectTikTokOpenID
)

type adapterConfig struct {
	provider        authentication.Provider
	clientID        string
	clientSecret    string
	microsoftTenant string
	redirectURL     string
}

type adapter struct {
	provider     authentication.Provider
	clientID     string
	clientSecret string
	redirectURL  string
	authURL      string
	tokenURL     string
	userInfoURL  string
	scopes       []string
	authStyle    oauth2.AuthStyle
	usePKCE      bool
	useNonce     bool
	mode         subjectMode
	verifier     *oidc.IDTokenVerifier
	httpClient   *http.Client
	tikTok       bool
}

type providerSpec struct {
	authURL     string
	tokenURL    string
	userInfoURL string
	scopes      []string
	authStyle   oauth2.AuthStyle
	usePKCE     bool
	useNonce    bool
	mode        subjectMode
	issuer      string
	jwksURL     string
}

func newAdapter(cfg adapterConfig) (*adapter, error) {
	spec, err := specFor(cfg.provider, cfg.microsoftTenant)
	if err != nil {
		return nil, ErrConfig
	}
	client := &http.Client{
		Timeout:       providerHTTPTimeout,
		Transport:     &boundedTransport{base: http.DefaultTransport, max: providerBodyLimit},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	a := &adapter{
		provider:     cfg.provider,
		clientID:     cfg.clientID,
		clientSecret: cfg.clientSecret,
		redirectURL:  cfg.redirectURL,
		authURL:      spec.authURL,
		tokenURL:     spec.tokenURL,
		userInfoURL:  spec.userInfoURL,
		scopes:       append([]string(nil), spec.scopes...),
		authStyle:    spec.authStyle,
		usePKCE:      spec.usePKCE,
		useNonce:     spec.useNonce,
		mode:         spec.mode,
		httpClient:   client,
		tikTok:       cfg.provider == authentication.ProviderTikTok,
	}
	if spec.mode == subjectOIDC {
		keyCtx := oidc.ClientContext(context.Background(), client)
		keySet := oidc.NewRemoteKeySet(keyCtx, spec.jwksURL)
		a.verifier = oidc.NewVerifier(spec.issuer, keySet, &oidc.Config{
			ClientID:             cfg.clientID,
			SupportedSigningAlgs: []string{"RS256"},
		})
	}
	return a, nil
}

func (a *adapter) Provider() authentication.Provider { return a.provider }
func (a *adapter) UsesPKCE() bool                    { return a.usePKCE }
func (a *adapter) UsesNonce() bool                   { return a.useNonce }

func (a *adapter) AuthorizationURL(state, nonce, providerCodeChallenge string) (string, error) {
	if a == nil || state == "" || a.authURL == "" || a.clientID == "" || a.redirectURL == "" {
		return "", authentication.ErrSocialProviderProof
	}
	if a.usePKCE && !authentication.ValidS256Challenge(providerCodeChallenge) {
		return "", authentication.ErrSocialProviderProof
	}
	if a.useNonce && nonce == "" {
		return "", authentication.ErrSocialProviderProof
	}
	if a.tikTok {
		u, err := url.Parse(a.authURL)
		if err != nil {
			return "", authentication.ErrSocialProviderProof
		}
		q := u.Query()
		q.Set("client_key", a.clientID)
		q.Set("response_type", "code")
		q.Set("redirect_uri", a.redirectURL)
		q.Set("scope", strings.Join(a.scopes, ","))
		q.Set("state", state)
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	oauthCfg := a.oauthConfig()
	opts := make([]oauth2.AuthCodeOption, 0, 4)
	if a.usePKCE {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", providerCodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	if a.useNonce {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	return oauthCfg.AuthCodeURL(state, opts...), nil
}

func (a *adapter) ExchangeIdentity(ctx context.Context, code, providerVerifier string, expectedNonce [32]byte) (authentication.ExternalIdentityProof, error) {
	if a == nil || code == "" || a.httpClient == nil {
		return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
	}
	if a.usePKCE && !authentication.ValidPKCEVerifier(providerVerifier) {
		return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
	}
	if a.useNonce && expectedNonce == ([32]byte{}) {
		return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
	}
	var subject string
	var err error
	if a.tikTok {
		subject, err = a.exchangeTikTok(ctx, code)
	} else {
		token, exchangeErr := a.exchangeStandard(ctx, code, providerVerifier)
		if exchangeErr != nil {
			return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
		}
		switch a.mode {
		case subjectOIDC:
			subject, err = a.subjectFromIDToken(ctx, token, expectedNonce)
		case subjectTopLevelID, subjectNestedDataID:
			subject, err = a.subjectFromUserInfo(ctx, token.AccessToken)
		default:
			err = authentication.ErrSocialProviderProof
		}
	}
	if err != nil || subject == "" || len(subject) > 512 {
		return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
	}
	return authentication.ExternalIdentityProof{Provider: a.provider, Subject: subject}, nil
}

func (a *adapter) oauthConfig() oauth2.Config {
	return oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		RedirectURL:  a.redirectURL,
		Scopes:       append([]string(nil), a.scopes...),
		Endpoint:     oauth2.Endpoint{AuthURL: a.authURL, TokenURL: a.tokenURL, AuthStyle: a.authStyle},
	}
}

func (a *adapter) exchangeStandard(ctx context.Context, code, providerVerifier string) (*oauth2.Token, error) {
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if a.usePKCE {
		opts = append(opts, oauth2.VerifierOption(providerVerifier))
	}
	token, err := a.oauthConfig().Exchange(exchangeCtx, code, opts...)
	if err != nil || token == nil || token.AccessToken == "" {
		return nil, authentication.ErrSocialProviderProof
	}
	return token, nil
}

func (a *adapter) subjectFromIDToken(ctx context.Context, token *oauth2.Token, expectedNonce [32]byte) (string, error) {
	if a.verifier == nil || token == nil {
		return "", authentication.ErrSocialProviderProof
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", authentication.ErrSocialProviderProof
	}
	verifyCtx := oidc.ClientContext(ctx, a.httpClient)
	idToken, err := a.verifier.Verify(verifyCtx, raw)
	if err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	var claims struct {
		Subject   string          `json:"sub"`
		Nonce     string          `json:"nonce"`
		NotBefore int64           `json:"nbf"`
		Email     json.RawMessage `json:"email"`
		Name      json.RawMessage `json:"name"`
		Picture   json.RawMessage `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" {
		return "", authentication.ErrSocialProviderProof
	}
	if a.useNonce && !authentication.CompareNonceHash(expectedNonce, claims.Nonce) {
		return "", authentication.ErrSocialProviderProof
	}
	if claims.NotBefore != 0 && time.Now().UTC().Add(time.Minute).Before(time.Unix(claims.NotBefore, 0).UTC()) {
		return "", authentication.ErrSocialProviderProof
	}
	return claims.Subject, nil
}

func (a *adapter) subjectFromUserInfo(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" || a.userInfoURL == "" {
		return "", authentication.ErrSocialProviderProof
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.userInfoURL, nil)
	if err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", authentication.ErrSocialProviderProof
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, providerBodyLimit+1))
	decoder.UseNumber()
	var payload struct {
		ID   json.RawMessage `json:"id"`
		Data struct {
			ID json.RawMessage `json:"id"`
		} `json:"data"`
		Email  json.RawMessage `json:"email"`
		Name   json.RawMessage `json:"name"`
		Avatar json.RawMessage `json:"avatar"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	if a.mode == subjectNestedDataID {
		return rawID(payload.Data.ID)
	}
	return rawID(payload.ID)
}

func rawID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", authentication.ErrSocialProviderProof
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return "", authentication.ErrSocialProviderProof
		}
		return s, nil
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	value := number.String()
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	return value, nil
}

func (a *adapter) exchangeTikTok(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_key", a.clientID)
	form.Set("client_secret", a.clientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", a.redirectURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", authentication.ErrSocialProviderProof
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", authentication.ErrSocialProviderProof
	}
	var payload struct {
		AccessToken  string          `json:"access_token"`
		OpenID       string          `json:"open_id"`
		RefreshToken json.RawMessage `json:"refresh_token"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, providerBodyLimit+1))
	if err := decoder.Decode(&payload); err != nil || payload.AccessToken == "" || payload.OpenID == "" {
		return "", authentication.ErrSocialProviderProof
	}
	return payload.OpenID, nil
}

type boundedTransport struct {
	base http.RoundTripper
	max  int64
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || t.max <= 0 {
		return nil, errors.New("social provider transport unavailable")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > t.max {
		_ = resp.Body.Close()
		return nil, errors.New("social provider response too large")
	}
	resp.Body = &boundedReadCloser{reader: io.LimitReader(resp.Body, t.max+1), closer: resp.Body}
	return resp, nil
}

type boundedReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (r *boundedReadCloser) Read(p []byte) (int, error) { return r.reader.Read(p) }
func (r *boundedReadCloser) Close() error               { return r.closer.Close() }

func specFor(provider authentication.Provider, microsoftTenant string) (providerSpec, error) {
	switch provider {
	case authentication.ProviderGoogle:
		return providerSpec{
			authURL:   "https://accounts.google.com/o/oauth2/v2/auth",
			tokenURL:  "https://oauth2.googleapis.com/token",
			scopes:    []string{"openid"},
			authStyle: oauth2.AuthStyleInParams,
			usePKCE:   true,
			useNonce:  true,
			mode:      subjectOIDC,
			issuer:    "https://accounts.google.com",
			jwksURL:   "https://www.googleapis.com/oauth2/v3/certs",
		}, nil
	case authentication.ProviderApple:
		return providerSpec{
			authURL:   "https://appleid.apple.com/auth/authorize",
			tokenURL:  "https://appleid.apple.com/auth/token",
			authStyle: oauth2.AuthStyleInParams,
			useNonce:  true,
			mode:      subjectOIDC,
			issuer:    "https://appleid.apple.com",
			jwksURL:   "https://appleid.apple.com/auth/keys",
		}, nil
	case authentication.ProviderMicrosoft:
		base := "https://login.microsoftonline.com/" + microsoftTenant
		issuer := base + "/v2.0"
		return providerSpec{
			authURL:   base + "/oauth2/v2.0/authorize",
			tokenURL:  base + "/oauth2/v2.0/token",
			scopes:    []string{"openid"},
			authStyle: oauth2.AuthStyleInParams,
			usePKCE:   true,
			useNonce:  true,
			mode:      subjectOIDC,
			issuer:    issuer,
			jwksURL:   base + "/discovery/v2.0/keys",
		}, nil
	case authentication.ProviderGitHub:
		return providerSpec{
			authURL:     "https://github.com/login/oauth/authorize",
			tokenURL:    "https://github.com/login/oauth/access_token",
			userInfoURL: "https://api.github.com/user",
			authStyle:   oauth2.AuthStyleInParams,
			usePKCE:     true,
			mode:        subjectTopLevelID,
		}, nil
	case authentication.ProviderGitLab:
		return providerSpec{
			authURL:     "https://gitlab.com/oauth/authorize",
			tokenURL:    "https://gitlab.com/oauth/token",
			userInfoURL: "https://gitlab.com/api/v4/user",
			scopes:      []string{"read_user"},
			authStyle:   oauth2.AuthStyleInParams,
			usePKCE:     true,
			mode:        subjectTopLevelID,
		}, nil
	case authentication.ProviderFacebook:
		return providerSpec{
			authURL:     "https://www.facebook.com/dialog/oauth",
			tokenURL:    "https://graph.facebook.com/oauth/access_token",
			userInfoURL: "https://graph.facebook.com/me?fields=id",
			authStyle:   oauth2.AuthStyleInParams,
			mode:        subjectTopLevelID,
		}, nil
	case authentication.ProviderDiscord:
		return providerSpec{
			authURL:     "https://discord.com/oauth2/authorize",
			tokenURL:    "https://discord.com/api/v10/oauth2/token",
			userInfoURL: "https://discord.com/api/v10/users/@me",
			scopes:      []string{"identify"},
			authStyle:   oauth2.AuthStyleInParams,
			mode:        subjectTopLevelID,
		}, nil
	case authentication.ProviderLinkedIn:
		return providerSpec{
			authURL:   "https://www.linkedin.com/oauth/v2/authorization",
			tokenURL:  "https://www.linkedin.com/oauth/v2/accessToken",
			scopes:    []string{"openid"},
			authStyle: oauth2.AuthStyleInParams,
			useNonce:  true,
			mode:      subjectOIDC,
			issuer:    "https://www.linkedin.com",
			jwksURL:   "https://www.linkedin.com/oauth/openid/jwks",
		}, nil
	case authentication.ProviderX:
		return providerSpec{
			authURL:     "https://x.com/i/oauth2/authorize",
			tokenURL:    "https://api.x.com/2/oauth2/token",
			userInfoURL: "https://api.x.com/2/users/me",
			scopes:      []string{"users.read"},
			authStyle:   oauth2.AuthStyleInHeader,
			usePKCE:     true,
			mode:        subjectNestedDataID,
		}, nil
	case authentication.ProviderTikTok:
		return providerSpec{
			authURL:  "https://www.tiktok.com/v2/auth/authorize/",
			tokenURL: "https://open.tiktokapis.com/v2/oauth/token/",
			scopes:   []string{"user.info.basic"},
			mode:     subjectTikTokOpenID,
		}, nil
	default:
		return providerSpec{}, fmt.Errorf("%w: provider", ErrConfig)
	}
}
