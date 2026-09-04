package resolve

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

const (
	HeaderPublishableKey = "X-BeeBox-Publishable-Key"
	HeaderProjectSlug    = "X-BeeBox-Project-Slug"
	HeaderInternalToken  = "X-BeeBox-Internal-Token"
	hostSuffix           = ".api.beebox.dev"
)

type Project struct {
	ProjectID string   `json:"project_id"`
	Slug      string   `json:"slug"`
	PlanSlug  string   `json:"plan_slug"`
	Env       string   `json:"env"`
	Origins   []string `json:"origins"`
	Modules   []string `json:"modules"`
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *Client) Resolve(ctx context.Context, pk, slug string) (Project, error) {
	if c == nil || c.BaseURL == "" {
		return Project{}, apperror.New(apperror.CodeInternal, "resolve is not configured")
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + "/internal/resolve")
	if err != nil {
		return Project{}, apperror.New(apperror.CodeInternal, "invalid projects base url")
	}
	q := u.Query()
	switch {
	case pk != "":
		q.Set("pk", pk)
	case slug != "":
		q.Set("slug", slug)
	default:
		return Project{}, apperror.New(apperror.CodeUnauthorized, "project not resolved")
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Project{}, apperror.New(apperror.CodeInternal, "internal error")
	}
	req.Header.Set(HeaderInternalToken, c.Token)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Project{}, apperror.Wrap(err, apperror.CodeInternal, "internal error")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return Project{}, apperror.New(apperror.CodeUnauthorized, "unauthorized")
	case http.StatusNotFound:
		return Project{}, apperror.New(apperror.CodeNotFound, "not found")
	case http.StatusBadRequest:
		return Project{}, apperror.New(apperror.CodeInvalidInput, "invalid input")
	}
	if resp.StatusCode >= 400 {
		return Project{}, apperror.New(apperror.CodeInternal, "internal error")
	}
	var project Project
	if err := json.Unmarshal(body, &project); err != nil {
		return Project{}, apperror.New(apperror.CodeInternal, "internal error")
	}
	if project.Origins == nil {
		project.Origins = []string{}
	}
	if project.Modules == nil {
		project.Modules = []string{}
	}
	return project, nil
}

func bearerPublishableKey(auth string) string {
	auth = strings.TrimSpace(auth)
	const scheme = "bearer "
	if len(auth) < len(scheme) {
		return ""
	}
	if !strings.EqualFold(auth[:len(scheme)], scheme) {
		return ""
	}
	tok := strings.TrimSpace(auth[len(scheme):])
	if strings.HasPrefix(tok, "pk_") {
		return tok
	}
	return ""
}

func IdentityFrom(r *http.Request) (pk, slug string) {
	if r == nil {
		return "", ""
	}
	if pk = strings.TrimSpace(r.Header.Get(HeaderPublishableKey)); pk != "" {
		return pk, ""
	}
	if pk = bearerPublishableKey(r.Header.Get("Authorization")); pk != "" {
		return pk, ""
	}
	if slug = strings.TrimSpace(r.Header.Get(HeaderProjectSlug)); slug != "" {
		return "", slug
	}
	return "", SlugFromHost(r.Host)
}

func SlugFromHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.HasSuffix(host, hostSuffix) {
		return ""
	}
	slug := strings.TrimSuffix(host, hostSuffix)
	if slug == "" || strings.Contains(slug, ".") {
		return ""
	}
	return slug
}

func OriginAllowed(origin string, origins []string) bool {
	origin = canonicalizeOrigin(origin)
	if origin == "" {
		return true
	}
	for _, item := range origins {
		if canonicalizeOrigin(item) == origin {
			return true
		}
	}
	return false
}

func canonicalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + strings.ToLower(u.Host)
}
