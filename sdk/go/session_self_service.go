package beebox

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type UserSession struct {
	ID            string `json:"id"`
	CreatedAt     string `json:"created_at"`
	LastSeenAt    string `json:"last_seen_at"`
	IdleExpiresAt string `json:"idle_expires_at"`
	ExpiresAt     string `json:"expires_at"`
	Revoked       bool   `json:"revoked"`
	Current       bool   `json:"current"`
}

type SessionPage struct {
	Items      []UserSession `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

func (c *Client) ListSessions(ctx context.Context, accessToken string, limit int, cursor string) (SessionPage, error) {
	var out SessionPage
	if limit < 0 || limit > 100 {
		return out, ErrInvalidClient
	}
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	path := "/v1/sessions"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out, map[string]string{"Authorization": "Bearer " + accessToken}, false)
	return out, err
}

func (c *Client) RevokeOwnSession(ctx context.Context, origin, accessToken, reverificationToken, sessionID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(sessionID)+"/revoke", nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) RevokeOtherSessions(ctx context.Context, origin, accessToken, reverificationToken string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/revoke-others", nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) SignOutEverywhere(ctx context.Context, origin, accessToken, reverificationToken string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/sign-out-everywhere", nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}
