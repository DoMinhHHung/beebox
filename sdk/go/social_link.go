package beebox

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

type SocialLinkAttemptRequest struct {
	Provider    SocialProvider `json:"provider"`
	RedirectURL string         `json:"redirect_url"`
}

type SocialLinkAttempt struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int64  `json:"expires_in"`
}

type LinkedSocialAccount struct {
	ID        string         `json:"id"`
	Provider  SocialProvider `json:"provider"`
	CreatedAt time.Time      `json:"created_at"`
}

type LinkedSocialAccountPage struct {
	Items      []LinkedSocialAccount `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type ListSocialLinksOptions struct {
	Limit  int
	Cursor string
}

// CreateSocialLinkAttempt starts explicit social linking for an already
// authenticated BeeBox target session after a one-time social_link
// reverification grant has been consumed. The SDK neither opens a browser nor
// retries the security mutation.
func (c *Client) CreateSocialLinkAttempt(ctx context.Context, accessToken, origin, reverificationToken string, input SocialLinkAttemptRequest) (SocialLinkAttempt, error) {
	var out SocialLinkAttempt
	err := c.doJSON(ctx, "POST", "/v1/social-links/attempts", input, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
	return out, err
}

func (c *Client) ListSocialLinks(ctx context.Context, accessToken, origin string, options ListSocialLinksOptions) (LinkedSocialAccountPage, error) {
	values := url.Values{}
	if options.Limit != 0 {
		values.Set("limit", strconv.Itoa(options.Limit))
	}
	if options.Cursor != "" {
		values.Set("cursor", options.Cursor)
	}
	path := "/v1/social-links"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out LinkedSocialAccountPage
	err := c.doJSON(ctx, "GET", path, nil, &out, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Origin":        origin,
	}, false)
	return out, err
}

// UnlinkSocialLink removes one BeeBox-owned social identity association after
// a one-time social_unlink reverification grant has been consumed. The server
// operation is idempotent for a valid absent/not-owned opaque ID; the SDK
// performs exactly one request and does not revoke provider-side consent.
func (c *Client) UnlinkSocialLink(ctx context.Context, accessToken, origin, reverificationToken, socialLinkID string) error {
	return c.doJSON(ctx, "DELETE", "/v1/social-links/"+url.PathEscape(socialLinkID), nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}
