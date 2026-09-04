package httpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/oauth"
	"github.com/google/uuid"
)

type OAuthCreds struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *OAuthCreds) Get(ctx context.Context, projectID uuid.UUID, slug string) (oauth.Credentials, error) {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" {
		return oauth.Credentials{}, domain.ErrUnauthorized
	}
	raw := strings.TrimRight(c.BaseURL, "/") + "/internal/oauth/" + projectID.String() + "/" + slug
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return oauth.Credentials{}, err
	}
	req.Header.Set("X-BeeBox-Internal-Token", c.Token)
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return oauth.Credentials{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return oauth.Credentials{}, domain.ErrUnauthorized
	}
	var parsed struct {
		ClientID     string            `json:"client_id"`
		ClientSecret string            `json:"client_secret"`
		RedirectURI  string            `json:"redirect_uri"`
		Enabled      bool              `json:"enabled"`
		Extra        map[string]string `json:"extra"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return oauth.Credentials{}, err
	}
	if !parsed.Enabled {
		return oauth.Credentials{}, domain.ErrUnauthorized
	}
	if parsed.Extra == nil {
		parsed.Extra = map[string]string{}
	}
	return oauth.Credentials{
		ClientID:     parsed.ClientID,
		ClientSecret: parsed.ClientSecret,
		RedirectURI:  parsed.RedirectURI,
		Extra:        parsed.Extra,
	}, nil
}
