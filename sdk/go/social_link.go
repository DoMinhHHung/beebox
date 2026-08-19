package beebox

import "context"

type SocialLinkAttemptRequest struct {
	Provider    SocialProvider `json:"provider"`
	RedirectURL string         `json:"redirect_url"`
}

type SocialLinkAttempt struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int64  `json:"expires_in"`
}

// CreateSocialLinkAttempt starts explicit social linking for an already
// authenticated BeeBox session. The access token and Origin are caller-owned
// existing BeeBox context; the SDK neither opens a browser nor retries.
func (c *Client) CreateSocialLinkAttempt(ctx context.Context, accessToken, origin string, input SocialLinkAttemptRequest) (SocialLinkAttempt, error) {
	var out SocialLinkAttempt
	err := c.doJSON(ctx, "POST", "/v1/social-links/attempts", input, &out, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Origin":        origin,
	}, false)
	return out, err
}
