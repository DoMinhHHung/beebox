package passkeywebauthn

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

type Protocol struct{}

func New() *Protocol { return &Protocol{} }

type user struct {
	snapshot authentication.PasskeyProtocolUser
	creds    []webauthn.Credential
}

func (u *user) WebAuthnID() []byte { return []byte(u.snapshot.PublicID) }
func (u *user) WebAuthnName() string { return string(u.snapshot.PublicID) }
func (u *user) WebAuthnDisplayName() string { return string(u.snapshot.PublicID) }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func makeUser(snapshot authentication.PasskeyProtocolUser) (*user, error) {
	if !snapshot.UserID.Valid() || !snapshot.PublicID.Valid() {
		return nil, authentication.ErrPasskeyProof
	}
	out := &user{snapshot: snapshot, creds: make([]webauthn.Credential, 0, len(snapshot.Credentials))}
	for _, stored := range snapshot.Credentials {
		var credential webauthn.Credential
		if len(stored.CredentialJSON) == 0 || json.Unmarshal(stored.CredentialJSON, &credential) != nil || len(credential.ID) == 0 {
			return nil, authentication.ErrPasskeyProof
		}
		out.creds = append(out.creds, credential)
	}
	return out, nil
}

func newWebAuthn(rpID, origin string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "BeeBox",
		RPID:          rpID,
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: authentication.PasskeyAttemptTTL},
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: authentication.PasskeyAttemptTTL},
		},
	})
}

func (p *Protocol) BeginRegistration(snapshot authentication.PasskeyProtocolUser, rpID, origin string) (json.RawMessage, json.RawMessage, string, error) {
	u, err := makeUser(snapshot)
	if err != nil {
		return nil, nil, "", err
	}
	wa, err := newWebAuthn(rpID, origin)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	creation, sessionData, err := wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()),
	)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	options, err := json.Marshal(creation.Response)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	return options, sessionJSON, sessionData.Challenge, nil
}

func (p *Protocol) FinishRegistration(snapshot authentication.PasskeyProtocolUser, rpID, origin string, sessionJSON, response json.RawMessage) (authentication.PasskeyCredential, error) {
	u, err := makeUser(snapshot)
	if err != nil {
		return authentication.PasskeyCredential{}, err
	}
	wa, err := newWebAuthn(rpID, origin)
	if err != nil {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	var sessionData webauthn.SessionData
	if json.Unmarshal(sessionJSON, &sessionData) != nil || sessionData.RelyingPartyID != rpID {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	credential, err := wa.CreateCredential(u, sessionData, parsed)
	if err != nil || credential == nil || len(credential.ID) == 0 {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	return authentication.PasskeyCredential{RPID: rpID, CredentialID: append([]byte(nil), credential.ID...), CredentialJSON: encoded}, nil
}

func (p *Protocol) BeginAuthentication(rpID, origin string) (json.RawMessage, json.RawMessage, string, error) {
	wa, err := newWebAuthn(rpID, origin)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	assertion, sessionData, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	options, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, "", authentication.ErrPasskeyUnavailable
	}
	return options, sessionJSON, sessionData.Challenge, nil
}

func (p *Protocol) FinishAuthentication(ctx context.Context, rpID, origin string, sessionJSON, response json.RawMessage, loader func(context.Context, []byte, []byte) (authentication.PasskeyProtocolUser, error)) (authentication.PasskeyProtocolUser, authentication.PasskeyCredential, error) {
	if loader == nil {
		return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	wa, err := newWebAuthn(rpID, origin)
	if err != nil {
		return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	var sessionData webauthn.SessionData
	if json.Unmarshal(sessionJSON, &sessionData) != nil || sessionData.RelyingPartyID != rpID {
		return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	var loaded authentication.PasskeyProtocolUser
	found, credential, err := wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, loadErr := loader(ctx, rawID, userHandle)
		if loadErr != nil {
			return nil, loadErr
		}
		loaded = snapshot
		return makeUser(snapshot)
	}, sessionData, parsed)
	if err != nil || found == nil || credential == nil || !loaded.UserID.Valid() {
		return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	updated, err := json.Marshal(credential)
	if err != nil {
		return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, authentication.ErrPasskeyProof
	}
	for _, item := range loaded.Credentials {
		if string(item.CredentialID) == string(credential.ID) {
			item.CredentialJSON = updated
			return loaded, item, nil
		}
	}
	return authentication.PasskeyProtocolUser{}, authentication.PasskeyCredential{}, errors.New("validated passkey credential was not loaded")
}
