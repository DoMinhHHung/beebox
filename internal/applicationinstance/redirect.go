package applicationinstance

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

const (
	AuditActionRedirectAdded = "application.allowed_redirect.added"
	AuditResourceRedirect    = "application_allowed_redirect"
)

var (
	ErrInvalidRedirect  = errors.New("invalid application redirect URL")
	ErrRedirectConflict = errors.New("application redirect URL conflict")
)

type AllowedRedirectURL struct {
	InternalID            int64
	ApplicationInstanceID InternalID
	CanonicalURL          string
	CreatedAt             time.Time
}

// RedirectPersistence is a narrow capability added after the original
// integration persistence contract. It keeps redirect ownership separate from
// browser CORS origin policy while sharing the application integration service.
type RedirectPersistence interface {
	AddAllowedRedirectURL(context.Context, InternalID, string, CorrelationID) (AllowedRedirectURL, error)
}

func (s *IntegrationService) AddAllowedRedirectURL(ctx context.Context, appID InternalID, raw string) (AllowedRedirectURL, error) {
	if s == nil || !appID.Valid() {
		return AllowedRedirectURL{}, ErrIntegrationPersistence
	}
	persistence, ok := s.persistence.(RedirectPersistence)
	if !ok || persistence == nil {
		return AllowedRedirectURL{}, ErrIntegrationPersistence
	}
	canonical, err := CanonicalizeRedirectURL(raw)
	if err != nil {
		return AllowedRedirectURL{}, err
	}
	correlation, err := newCorrelationID()
	if err != nil {
		return AllowedRedirectURL{}, ErrIntegrationPersistence
	}
	if err := ctx.Err(); err != nil {
		return AllowedRedirectURL{}, err
	}
	return persistence.AddAllowedRedirectURL(ctx, appID, canonical, correlation)
}

// CanonicalizeRedirectURL returns the exact URL form used by both operator
// configuration and social-auth initiation. P2.3 intentionally rejects query
// strings so BeeBox owns the completion query parameters.
func CanonicalizeRedirectURL(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > 2048 {
		return "", ErrInvalidRedirect
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Scheme == "" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", ErrInvalidRedirect
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.Contains(u.Host, "*") {
		return "", ErrInvalidRedirect
	}
	// Reject alternate escaped-path spellings. This keeps configured and
	// requested redirect equality byte-stable after canonicalization.
	if u.RawPath != "" {
		return "", ErrInvalidRedirect
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch scheme {
	case "https":
	case "http":
		if strings.ToLower(u.Hostname()) != "localhost" {
			return "", ErrInvalidRedirect
		}
	default:
		return "", ErrInvalidRedirect
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	canonical := (&url.URL{Scheme: scheme, Host: host, Path: path}).String()
	if len(canonical) > 2048 {
		return "", ErrInvalidRedirect
	}
	return canonical, nil
}

func RedirectOrigin(canonicalRedirect string) (string, error) {
	canonical, err := CanonicalizeRedirectURL(canonicalRedirect)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(canonical)
	if err != nil {
		return "", ErrInvalidRedirect
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}
