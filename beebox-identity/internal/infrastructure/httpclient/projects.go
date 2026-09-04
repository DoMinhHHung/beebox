package httpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/google/uuid"
)

type Projects struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type resolveBody struct {
	ProjectID string   `json:"project_id"`
	Env       string   `json:"env"`
	Modules   []string `json:"modules"`
	Status    string   `json:"status"`
}

func (c *Projects) Resolve(ctx context.Context, pk, slug string) (domain.Scope, error) {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" {
		return domain.Scope{}, domain.ErrUnauthorized
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + "/internal/resolve")
	if err != nil {
		return domain.Scope{}, err
	}
	q := u.Query()
	switch {
	case pk != "":
		q.Set("pk", pk)
	case slug != "":
		q.Set("slug", slug)
	default:
		return domain.Scope{}, domain.ErrUnauthorized
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return domain.Scope{}, err
	}
	req.Header.Set("X-BeeBox-Internal-Token", c.Token)
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return domain.Scope{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return domain.Scope{}, domain.ErrUnauthorized
	case http.StatusForbidden:
		return domain.Scope{}, domain.ErrProjectDisabled
	case http.StatusNotFound:
		return domain.Scope{}, domain.ErrUnauthorized
	}
	if resp.StatusCode >= 400 {
		return domain.Scope{}, domain.ErrUnauthorized
	}
	var parsed resolveBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return domain.Scope{}, err
	}
	projectID, err := uuid.Parse(parsed.ProjectID)
	if err != nil || projectID == uuid.Nil {
		return domain.Scope{}, domain.ErrUnauthorized
	}
	if parsed.Modules == nil {
		parsed.Modules = []string{}
	}
	disabled := parsed.Status == "disabled"
	return domain.Scope{
		ProjectID: projectID,
		Env:       parsed.Env,
		Modules:   parsed.Modules,
		Disabled:  disabled,
	}, nil
}
