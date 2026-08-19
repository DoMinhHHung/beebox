package socialprovider

import (
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func TestLoadSlackUsesOrdinaryClientCredentialsWithoutProviderPKCEStateKey(t *testing.T) {
	t.Parallel()
	appID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	registry, protector, err := Load(mapLookup(map[string]string{
		connectionsEnv: `[{"application_id":"` + string(appID) + `","provider":"slack","client_id":"client","client_secret":"fake-secret"}]`,
		issuerEnv:      "https://beebox.example.test",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if protector != nil {
		t.Fatal("Slack-only registry unexpectedly required provider PKCE state protection")
	}
	provider, ok := registry.Resolve(appID, authentication.ProviderSlack)
	if !ok || provider == nil || provider.Provider() != authentication.ProviderSlack {
		t.Fatal("Slack connection was not resolved")
	}
	if provider.UsesPKCE() || !provider.UsesNonce() {
		t.Fatalf("Slack PKCE=%v nonce=%v", provider.UsesPKCE(), provider.UsesNonce())
	}
}
