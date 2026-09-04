package oauth

import (
	"context"
	"strings"
)

type Profile struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	NeedsEmail    bool
	Raw           map[string]any
}

type AuthRequest struct {
	ClientID    string
	RedirectURI string
	State       string
	Verifier    string
	Nonce       string
	Extra       map[string]string
}

type Credentials struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Extra        map[string]string
}

type Provider interface {
	Slug() string
	AuthURL(in AuthRequest) (authURL, state string, err error)
	Exchange(ctx context.Context, code, verifier, redirectURI string, creds Credentials) (Profile, error)
}

func ModuleName(slug string) string {
	return "auth.oauth." + strings.TrimSpace(slug)
}

func discoveryURL(issuer string) string {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	return issuer + "/.well-known/openid-configuration"
}
