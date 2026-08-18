package socialprovider

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func TestLoadAbsentSocialConfigIsOptional(t *testing.T) {
	t.Parallel()
	registry, protector, err := Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if registry == nil || registry.Enabled() || protector != nil {
		t.Fatalf("registry=%#v protector=%#v", registry, protector)
	}
}

func TestLoadRejectsMalformedConnectionWithoutLeakingSecret(t *testing.T) {
	t.Parallel()
	const secret = "super-secret-must-not-leak"
	lookup := mapLookup(map[string]string{
		connectionsEnv: `[{"application_id":"bad","provider":"google","client_id":"client","client_secret":"` + secret + `"}]`,
		issuerEnv:      "https://beebox.example.test",
	})
	_, _, err := Load(lookup)
	if err == nil {
		t.Fatal("expected configuration error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestLoadRejectsDuplicateApplicationProvider(t *testing.T) {
	t.Parallel()
	appID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	entry := `{"application_id":"` + string(appID) + `","provider":"google","client_id":"client","client_secret":"fake-secret"}`
	lookup := mapLookup(map[string]string{
		connectionsEnv: `[` + entry + `,` + entry + `]`,
		issuerEnv:      "https://beebox.example.test",
		stateKeyEnv:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if _, _, err := Load(lookup); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestLoadRejectsMissingOrMalformedSocialStateKeyWhenPKCEEnabled(t *testing.T) {
	t.Parallel()
	appID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	connections := `[{"application_id":"` + string(appID) + `","provider":"github","client_id":"client","client_secret":"fake-secret"}]`
	for _, key := range []string{"", "not-base64", base64.RawURLEncoding.EncodeToString(make([]byte, 31))} {
		lookup := mapLookup(map[string]string{
			connectionsEnv: connections,
			issuerEnv:      "https://beebox.example.test",
			stateKeyEnv:    key,
		})
		if _, _, err := Load(lookup); err == nil {
			t.Fatalf("accepted invalid social state key %q", key)
		}
	}
}

func TestLoadResolvesCredentialsByApplicationAndProvider(t *testing.T) {
	t.Parallel()
	appA, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	appB, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	connections := `[` +
		`{"application_id":"` + string(appA) + `","provider":"github","client_id":"client-a","client_secret":"fake-secret-a"},` +
		`{"application_id":"` + string(appB) + `","provider":"discord","client_id":"client-b","client_secret":"fake-secret-b"}` +
		`]`
	registry, protector, err := Load(mapLookup(map[string]string{
		connectionsEnv: connections,
		issuerEnv:      "https://beebox.example.test",
		stateKeyEnv:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Enabled() || protector == nil {
		t.Fatal("expected enabled social registry and PKCE protector")
	}
	if provider, ok := registry.Resolve(appA, authentication.ProviderGitHub); !ok || provider.Provider() != authentication.ProviderGitHub {
		t.Fatal("github connection not resolved for application A")
	}
	if _, ok := registry.Resolve(appA, authentication.ProviderDiscord); ok {
		t.Fatal("cross-application provider configuration leaked")
	}
	if provider, ok := registry.Resolve(appB, authentication.ProviderDiscord); !ok || provider.Provider() != authentication.ProviderDiscord {
		t.Fatal("discord connection not resolved for application B")
	}
}

func TestLoadRejectsMicrosoftWithoutExplicitTenant(t *testing.T) {
	t.Parallel()
	appID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	lookup := mapLookup(map[string]string{
		connectionsEnv: `[{"application_id":"` + string(appID) + `","provider":"microsoft","client_id":"client","client_secret":"fake-secret"}]`,
		issuerEnv:      "https://beebox.example.test",
		stateKeyEnv:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if _, _, err := Load(lookup); err == nil {
		t.Fatal("expected explicit Microsoft tenant requirement")
	}
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
