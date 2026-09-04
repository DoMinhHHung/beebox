package oauth

import (
	"fmt"
	"strings"
)

const (
	SlugApple     = "apple"
	SlugGitLab    = "gitlab"
	SlugLinkedIn  = "linkedin"
	SlugSlack     = "slack"
	SlugTwitch    = "twitch"
	SlugFacebook  = "facebook"
	SlugGoogle    = "google"
	SlugMicrosoft = "microsoft"
	SlugGitHub    = "github"
	SlugX         = "x"
	SlugOIDC      = "oidc"
)

var BuiltInSlugs = []string{
	SlugApple, SlugGitLab, SlugLinkedIn, SlugSlack, SlugTwitch,
	SlugFacebook, SlugGoogle, SlugMicrosoft, SlugGitHub, SlugX, SlugOIDC,
}

func ValidSlug(slug string) bool {
	slug = strings.ToLower(strings.TrimSpace(slug))
	for _, item := range BuiltInSlugs {
		if item == slug {
			return true
		}
	}
	return false
}

func Lookup(slug string) (Provider, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !ValidSlug(slug) {
		return nil, fmt.Errorf("unknown provider")
	}
	return specProvider{slug: slug}, nil
}

type specProvider struct {
	slug string
	http HTTPDoer
}

func (p specProvider) Slug() string { return p.slug }

func (p specProvider) client() HTTPDoer {
	if p.http != nil {
		return p.http
	}
	return defaultHTTP()
}
