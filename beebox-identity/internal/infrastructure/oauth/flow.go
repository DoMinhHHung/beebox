package oauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

func (p specProvider) AuthURL(in AuthRequest) (string, string, error) {
	state := strings.TrimSpace(in.State)
	if state == "" {
		var err error
		state, err = NewState()
		if err != nil {
			return "", "", err
		}
	}
	verifier := in.Verifier
	challenge := ""
	if verifier == "" {
		var err error
		verifier, challenge, err = NewPKCE()
		if err != nil {
			return "", "", err
		}
	} else {
		sum := sha256Sum(verifier)
		challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	_ = verifier
	cfg, err := p.endpoints(in.Extra)
	if err != nil {
		return "", "", err
	}
	if cfg.authURL == "" && cfg.issuer != "" {
		cfg, err = p.resolveOIDC(context.Background(), cfg)
		if err != nil {
			return "", "", err
		}
	}
	if cfg.authURL == "" {
		return "", "", fmt.Errorf("missing authorization endpoint")
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", in.ClientID)
	q.Set("redirect_uri", in.RedirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(cfg.scopes) > 0 {
		q.Set("scope", strings.Join(cfg.scopes, " "))
	}
	if in.Nonce != "" {
		q.Set("nonce", in.Nonce)
	}
	for k, v := range cfg.authExtra {
		q.Set(k, v)
	}
	return cfg.authURL + "?" + q.Encode(), state, nil
}

func (p specProvider) Exchange(ctx context.Context, code, verifier, redirectURI string, creds Credentials) (Profile, error) {
	if strings.TrimSpace(code) == "" {
		return Profile{}, fmt.Errorf("missing code")
	}
	cfg, err := p.endpoints(creds.Extra)
	if err != nil {
		return Profile{}, err
	}
	if cfg.tokenURL == "" && cfg.issuer != "" {
		cfg, err = p.resolveOIDC(ctx, cfg)
		if err != nil {
			return Profile{}, err
		}
	}
	secret := creds.ClientSecret
	if p.slug == SlugApple {
		secret, err = appleClientSecret(creds, zeroTime())
		if err != nil {
			return Profile{}, err
		}
	}
	vals := url.Values{}
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", code)
	vals.Set("redirect_uri", redirectURI)
	vals.Set("client_id", creds.ClientID)
	vals.Set("code_verifier", verifier)
	headers := map[string]string{}
	switch p.slug {
	case SlugX:
		basic := base64.StdEncoding.EncodeToString([]byte(creds.ClientID + ":" + creds.ClientSecret))
		headers["Authorization"] = "Basic " + basic
	case SlugGitHub:
		headers["Accept"] = "application/json"
		vals.Set("client_secret", secret)
	default:
		vals.Set("client_secret", secret)
	}
	if p.slug == SlugOIDC && strings.EqualFold(creds.Extra["token_auth"], "basic") {
		delete(vals, "client_secret")
		basic := base64.StdEncoding.EncodeToString([]byte(creds.ClientID + ":" + creds.ClientSecret))
		headers["Authorization"] = "Basic " + basic
	}
	body, status, err := postForm(ctx, p.client(), cfg.tokenURL, vals, headers)
	if err != nil {
		return Profile{}, err
	}
	if status >= 400 {
		return Profile{}, fmt.Errorf("token status %d", status)
	}
	token, err := decodeMap(body)
	if err != nil {
		return Profile{}, err
	}
	access := asString(token["access_token"])
	idToken := asString(token["id_token"])
	return p.profile(ctx, cfg, creds, access, idToken)
}

type endpoints struct {
	issuer    string
	authURL   string
	tokenURL  string
	userURL   string
	jwksURL   string
	scopes    []string
	authExtra map[string]string
}

func (p specProvider) endpoints(extra map[string]string) (endpoints, error) {
	if extra == nil {
		extra = map[string]string{}
	}
	switch p.slug {
	case SlugGoogle:
		return endpoints{
			issuer:   "https://accounts.google.com",
			authURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			tokenURL: "https://oauth2.googleapis.com/token",
			userURL:  "https://openidconnect.googleapis.com/v1/userinfo",
			jwksURL:  "https://www.googleapis.com/oauth2/v3/certs",
			scopes:   []string{"openid", "email", "profile"},
		}, nil
	case SlugMicrosoft:
		tenant := strings.TrimSpace(extra["tenant"])
		if tenant == "" {
			tenant = "common"
		}
		base := "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0"
		return endpoints{
			issuer:   "https://login.microsoftonline.com/" + tenant + "/v2.0",
			authURL:  base + "/authorize",
			tokenURL: base + "/token",
			scopes:   []string{"openid", "profile", "email"},
		}, nil
	case SlugApple:
		return endpoints{
			issuer:    "https://appleid.apple.com",
			authURL:   "https://appleid.apple.com/auth/authorize",
			tokenURL:  "https://appleid.apple.com/auth/token",
			jwksURL:   "https://appleid.apple.com/auth/keys",
			scopes:    []string{"name", "email"},
			authExtra: map[string]string{"response_mode": "form_post"},
		}, nil
	case SlugGitHub:
		return endpoints{
			authURL:  "https://github.com/login/oauth/authorize",
			tokenURL: "https://github.com/login/oauth/access_token",
			userURL:  "https://api.github.com/user",
			scopes:   []string{"user:email"},
		}, nil
	case SlugX:
		return endpoints{
			authURL:  "https://x.com/i/oauth2/authorize",
			tokenURL: "https://api.x.com/2/oauth2/token",
			userURL:  "https://api.x.com/2/users/me",
			scopes:   []string{"users.read", "offline.access", "tweet.read"},
		}, nil
	case SlugLinkedIn:
		return endpoints{
			issuer:   "https://www.linkedin.com",
			authURL:  "https://www.linkedin.com/oauth/v2/authorization",
			tokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
			userURL:  "https://api.linkedin.com/v2/userinfo",
			jwksURL:  "https://www.linkedin.com/oauth/openid/jwks",
			scopes:   []string{"openid", "profile", "email"},
		}, nil
	case SlugSlack:
		return endpoints{
			issuer:   "https://slack.com",
			authURL:  "https://slack.com/openid/connect/authorize",
			tokenURL: "https://slack.com/api/openid.connect.token",
			userURL:  "https://slack.com/api/openid.connect.userInfo",
			jwksURL:  "https://slack.com/openid/connect/keys",
			scopes:   []string{"openid", "email", "profile"},
		}, nil
	case SlugTwitch:
		return endpoints{
			issuer:   "https://id.twitch.tv/oauth2",
			authURL:  "https://id.twitch.tv/oauth2/authorize",
			tokenURL: "https://id.twitch.tv/oauth2/token",
			userURL:  "https://api.twitch.tv/helix/users",
			scopes:   []string{"user:read:email", "openid"},
		}, nil
	case SlugGitLab:
		base := strings.TrimRight(strings.TrimSpace(extra["base_url"]), "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		return endpoints{
			issuer:   base,
			authURL:  base + "/oauth/authorize",
			tokenURL: base + "/oauth/token",
			userURL:  base + "/oauth/userinfo",
			scopes:   []string{"openid", "email", "profile"},
		}, nil
	case SlugFacebook:
		return endpoints{
			authURL:  "https://www.facebook.com/v21.0/dialog/oauth",
			tokenURL: "https://graph.facebook.com/v21.0/oauth/access_token",
			userURL:  "https://graph.facebook.com/v21.0/me?fields=id,name,email",
			scopes:   []string{"public_profile", "email"},
		}, nil
	case SlugOIDC:
		issuer := strings.TrimRight(strings.TrimSpace(extra["issuer"]), "/")
		if issuer == "" {
			return endpoints{}, fmt.Errorf("issuer required")
		}
		if !strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://localhost") && !strings.HasPrefix(issuer, "http://127.0.0.1") {
			return endpoints{}, fmt.Errorf("issuer must be https")
		}
		return endpoints{issuer: issuer, scopes: []string{"openid", "email", "profile"}}, nil
	default:
		return endpoints{}, fmt.Errorf("unknown provider")
	}
}

func (p specProvider) profile(ctx context.Context, cfg endpoints, creds Credentials, access, idToken string) (Profile, error) {
	if p.slug == SlugOIDC || (cfg.issuer != "" && (p.slug == SlugGoogle || p.slug == SlugApple || p.slug == SlugLinkedIn || p.slug == SlugSlack || p.slug == SlugMicrosoft || p.slug == SlugGitLab)) {
		resolved, err := p.resolveOIDC(ctx, cfg)
		if err == nil {
			cfg = resolved
		} else if p.slug == SlugOIDC {
			return Profile{}, err
		}
	}
	switch p.slug {
	case SlugGitHub:
		return githubProfile(ctx, p.client(), cfg, access)
	case SlugX:
		return xProfile(ctx, p.client(), cfg, access)
	case SlugFacebook:
		return facebookProfile(ctx, p.client(), cfg, access)
	case SlugTwitch:
		return twitchProfile(ctx, p.client(), cfg, access, creds.ClientID)
	case SlugMicrosoft:
		return microsoftProfile(idToken)
	case SlugApple:
		return appleProfile(idToken, creds.ClientID, creds.Extra["nonce"])
	default:
		return oidcProfile(ctx, p.client(), cfg, creds.ClientID, access, idToken, creds.Extra["nonce"])
	}
}
