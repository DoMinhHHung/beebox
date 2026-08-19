package socialprovider

import (
	"reflect"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"golang.org/x/oauth2"
)

type verifiedProductionContract struct {
	provider      authentication.Provider
	tenant        string
	authURL       string
	tokenURL      string
	userinfo      string
	scopes        []string
	auth          oauth2.AuthStyle
	pkce          bool
	nonce         bool
	mode          subjectMode
	tokenExchange tokenExchangeMode
	issuer        string
	jwks          string
}

// These literals are intentionally independent of specFor. They are copied
// from the provider-owned protocol evidence cited in PR #22. The Facebook row
// records the selected base manual Website flow plus its dedicated GET/query
// token exchange; dedicated wire tests cover details not represented here.
func TestVerifiedProductionProviderContracts(t *testing.T) {
	t.Parallel()
	contracts := []verifiedProductionContract{
		{authentication.ProviderGoogle, "", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "", []string{"openid", "profile"}, oauth2.AuthStyleInParams, true, true, subjectOIDC, tokenExchangeStandard, "https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs"},
		{authentication.ProviderApple, "", "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token", "", nil, oauth2.AuthStyleInParams, false, true, subjectOIDC, tokenExchangeStandard, "https://appleid.apple.com", "https://appleid.apple.com/auth/keys"},
		{authentication.ProviderMicrosoft, "11111111-1111-4111-8111-111111111111", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/authorize", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/token", "", []string{"openid"}, oauth2.AuthStyleInParams, true, true, subjectOIDC, tokenExchangeStandard, "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/discovery/v2.0/keys"},
		{authentication.ProviderGitHub, "", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "https://api.github.com/user", nil, oauth2.AuthStyleInParams, true, false, subjectTopLevelNumericID, tokenExchangeStandard, "", ""},
		{authentication.ProviderGitLab, "", "https://gitlab.com/oauth/authorize", "https://gitlab.com/oauth/token", "https://gitlab.com/api/v4/user", []string{"read_user"}, oauth2.AuthStyleInParams, true, false, subjectTopLevelNumericID, tokenExchangeStandard, "", ""},
		{authentication.ProviderFacebook, "", "https://www.facebook.com/v25.0/dialog/oauth", "https://graph.facebook.com/v25.0/oauth/access_token", "https://graph.facebook.com/me?fields=id", nil, oauth2.AuthStyle(0), false, false, subjectTopLevelStringID, tokenExchangeFacebookGETQuery, "", ""},
		{authentication.ProviderSlack, "", "https://slack.com/openid/connect/authorize", "https://slack.com/api/openid.connect.token", "", []string{"openid"}, oauth2.AuthStyleInHeader, false, true, subjectOIDC, tokenExchangeStandard, "https://slack.com", "https://slack.com/openid/connect/keys"},
		{authentication.ProviderDiscord, "", "https://discord.com/oauth2/authorize", "https://discord.com/api/v10/oauth2/token", "https://discord.com/api/v10/users/@me", []string{"identify"}, oauth2.AuthStyleInParams, false, false, subjectTopLevelStringID, tokenExchangeStandard, "", ""},
		{authentication.ProviderLinkedIn, "", "https://www.linkedin.com/oauth/v2/authorization", "https://www.linkedin.com/oauth/v2/accessToken", "", []string{"openid"}, oauth2.AuthStyleInParams, false, true, subjectOIDC, tokenExchangeStandard, "https://www.linkedin.com", "https://www.linkedin.com/oauth/openid/jwks"},
		{authentication.ProviderX, "", "https://x.com/i/oauth2/authorize", "https://api.x.com/2/oauth2/token", "https://api.x.com/2/users/me", []string{"tweet.read", "users.read"}, oauth2.AuthStyleInHeader, true, false, subjectNestedStringID, tokenExchangeStandard, "", ""},
		{authentication.ProviderTikTok, "", "https://www.tiktok.com/v2/auth/authorize/", "https://open.tiktokapis.com/v2/oauth/token/", "", []string{"user.info.basic"}, oauth2.AuthStyle(0), false, false, subjectTikTokOpenID, tokenExchangeStandard, "", ""},
	}
	if len(contracts) != len(authentication.Providers) {
		t.Fatalf("verified production contracts = %d, providers = %d", len(contracts), len(authentication.Providers))
	}
	for _, contract := range contracts {
		contract := contract
		t.Run(string(contract.provider), func(t *testing.T) {
			t.Parallel()
			spec, err := specFor(contract.provider, contract.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if spec.authURL != contract.authURL ||
				spec.tokenURL != contract.tokenURL ||
				spec.userInfoURL != contract.userinfo ||
				spec.authStyle != contract.auth ||
				spec.usePKCE != contract.pkce ||
				spec.useNonce != contract.nonce ||
				spec.mode != contract.mode ||
				spec.tokenExchange != contract.tokenExchange ||
				spec.issuer != contract.issuer ||
				spec.jwksURL != contract.jwks ||
				!reflect.DeepEqual(spec.scopes, contract.scopes) {
				t.Fatalf("production contract drift for %s: %#v", contract.provider, spec)
			}
		})
	}
}
