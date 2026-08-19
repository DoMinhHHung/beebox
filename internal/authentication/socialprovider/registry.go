package socialprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

const (
	connectionsEnv = "BEEBOX_SOCIAL_CONNECTIONS"
	stateKeyEnv    = "BEEBOX_SOCIAL_STATE_KEY"
	issuerEnv      = "BEEBOX_ISSUER"
)

var ErrConfig = errors.New("invalid social provider configuration")
var microsoftTenantPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type LookupEnv func(string) (string, bool)

type connectionInput struct {
	ApplicationID   string                  `json:"application_id"`
	Provider        authentication.Provider `json:"provider"`
	ClientID        string                  `json:"client_id"`
	ClientSecret    string                  `json:"client_secret"`
	MicrosoftTenant string                  `json:"microsoft_tenant,omitempty"`
}

type Registry struct {
	providers map[string]authentication.SocialProvider
}

func EmptyRegistry() *Registry {
	return &Registry{providers: make(map[string]authentication.SocialProvider)}
}

func Load(lookup LookupEnv) (*Registry, *authentication.SocialStateProtector, error) {
	if lookup == nil {
		return nil, nil, ErrConfig
	}
	raw, ok := lookup(connectionsEnv)
	if !ok || strings.TrimSpace(raw) == "" {
		return EmptyRegistry(), nil, nil
	}
	issuer, ok := lookup(issuerEnv)
	if !ok || issuer == "" {
		return nil, nil, ErrConfig
	}
	callbackBase, err := canonicalCallbackBase(issuer)
	if err != nil {
		return nil, nil, ErrConfig
	}
	inputs, err := decodeConnections(raw)
	if err != nil || len(inputs) == 0 {
		return nil, nil, ErrConfig
	}

	registry := EmptyRegistry()
	needsStateKey := false
	for _, input := range inputs {
		appID := applicationinstance.PublicID(input.ApplicationID)
		if !appID.Valid() || !input.Provider.Valid() || strings.TrimSpace(input.ClientID) != input.ClientID || input.ClientID == "" || len(input.ClientID) > 1024 || input.ClientSecret == "" || len(input.ClientSecret) > 16<<10 {
			return nil, nil, ErrConfig
		}
		if input.Provider == authentication.ProviderMicrosoft {
			if !microsoftTenantPattern.MatchString(input.MicrosoftTenant) {
				return nil, nil, ErrConfig
			}
		} else if input.MicrosoftTenant != "" {
			return nil, nil, ErrConfig
		}
		key := registryKey(appID, input.Provider)
		if _, duplicate := registry.providers[key]; duplicate {
			return nil, nil, ErrConfig
		}
		adapter, err := newAdapter(adapterConfig{
			provider:        input.Provider,
			clientID:        input.ClientID,
			clientSecret:    input.ClientSecret,
			microsoftTenant: input.MicrosoftTenant,
			redirectURL:     callbackBase + "/v1/social-auth/callback/" + string(input.Provider),
		})
		if err != nil {
			return nil, nil, ErrConfig
		}
		registry.providers[key] = adapter
		needsStateKey = needsStateKey || adapter.UsesPKCE()
	}

	var protector *authentication.SocialStateProtector
	if needsStateKey {
		encoded, ok := lookup(stateKeyEnv)
		if !ok || encoded == "" {
			return nil, nil, ErrConfig
		}
		key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return nil, nil, ErrConfig
		}
		protector, err = authentication.NewSocialStateProtector(key)
		if err != nil {
			return nil, nil, ErrConfig
		}
	}
	return registry, protector, nil
}

func (r *Registry) Resolve(appID applicationinstance.PublicID, provider authentication.Provider) (authentication.SocialProvider, bool) {
	if r == nil || !appID.Valid() || !provider.Valid() {
		return nil, false
	}
	p, ok := r.providers[registryKey(appID, provider)]
	return p, ok
}

func (r *Registry) Enabled() bool {
	return r != nil && len(r.providers) > 0
}

func registryKey(appID applicationinstance.PublicID, provider authentication.Provider) string {
	return string(appID) + "\x00" + string(provider)
}

func decodeConnections(raw string) ([]connectionInput, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var inputs []connectionInput
	if err := decoder.Decode(&inputs); err != nil {
		return nil, ErrConfig
	}
	if decoder.More() {
		return nil, ErrConfig
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return nil, ErrConfig
	}
	return inputs, nil
}

func canonicalCallbackBase(raw string) (string, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return "", ErrConfig
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", ErrConfig
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(scheme == "http" && strings.EqualFold(u.Hostname(), "localhost")) {
		return "", ErrConfig
	}
	path := strings.TrimSuffix(u.Path, "/")
	if path != "" {
		return "", fmt.Errorf("%w: issuer path is not supported for provider callbacks", ErrConfig)
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}
