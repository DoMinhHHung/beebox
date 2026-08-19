package beebox

import (
	"reflect"
	"testing"
)

func TestSocialProviderVocabulary(t *testing.T) {
	t.Parallel()
	got := []SocialProvider{
		SocialProviderGoogle,
		SocialProviderApple,
		SocialProviderMicrosoft,
		SocialProviderGitHub,
		SocialProviderGitLab,
		SocialProviderFacebook,
		SocialProviderSlack,
		SocialProviderDiscord,
		SocialProviderLinkedIn,
		SocialProviderX,
		SocialProviderTikTok,
	}
	want := []SocialProvider{"google", "apple", "microsoft", "github", "gitlab", "facebook", "slack", "discord", "linkedin", "x", "tiktok"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("social provider vocabulary = %v, want %v", got, want)
	}
}
