package migration

import (
	"strings"
	"testing"
)

func TestSocialOAuthMigrationContainsExactElevenProviderVocabulary(t *testing.T) {
	t.Parallel()
	content, err := embeddedSQL.ReadFile("sql/00015_social_oauth.sql")
	if err != nil {
		t.Fatal(err)
	}
	const providers = "('google','apple','microsoft','github','gitlab','facebook','slack','discord','linkedin','x','tiktok')"
	if got := strings.Count(string(content), providers); got != 2 {
		t.Fatalf("social provider CHECK vocabulary occurrences = %d, want 2", got)
	}
}
