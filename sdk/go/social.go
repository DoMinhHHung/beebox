package beebox

import "context"

type SocialProvider string

const (
	SocialProviderGoogle    SocialProvider = "google"
	SocialProviderApple     SocialProvider = "apple"
	SocialProviderMicrosoft SocialProvider = "microsoft"
	SocialProviderGitHub    SocialProvider = "github"
	SocialProviderGitLab    SocialProvider = "gitlab"
	SocialProviderFacebook  SocialProvider = "facebook"
	SocialProviderSlack     SocialProvider = "slack"
	SocialProviderDiscord   SocialProvider = "discord"
	SocialProviderLinkedIn  SocialProvider = "linkedin"
	SocialProviderX         SocialProvider = "x"
	SocialProviderTikTok    SocialProvider = "tiktok"
)

type SocialAuthAttemptRequest struct {
	Provider            SocialProvider `json:"provider"`
	RedirectURL         string         `json:"redirect_url"`
	CodeChallenge       string         `json:"code_challenge"`
	CodeChallengeMethod string         `json:"code_challenge_method"`
}

type SocialAuthAttempt struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int64  `json:"expires_in"`
}

type socialAuthExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// CreateSocialAuthAttempt starts the headless social-auth flow. The caller owns
// the S256 PKCE verifier and must retain it locally across the provider redirect.
// BeeBox receives only the challenge at this step.
func (c *Client) CreateSocialAuthAttempt(ctx context.Context, origin string, input SocialAuthAttemptRequest) (SocialAuthAttempt, error) {
	var out SocialAuthAttempt
	err := c.doJSON(ctx, "POST", "/v1/social-auth/attempts", input, &out, map[string]string{"Origin": origin}, false)
	return out, err
}

// ExchangeSocialAuthCode exchanges the one-time BeeBox completion code with
// the original client PKCE verifier. The SDK performs exactly one HTTP request;
// callers decide whether and how to recover from transport ambiguity.
func (c *Client) ExchangeSocialAuthCode(ctx context.Context, origin, code, codeVerifier string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, "POST", "/v1/social-auth/exchange", socialAuthExchangeRequest{Code: code, CodeVerifier: codeVerifier}, &out, map[string]string{"Origin": origin}, false)
	return out, err
}
