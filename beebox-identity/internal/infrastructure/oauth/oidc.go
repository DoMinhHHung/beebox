package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func sha256Sum(v string) [32]byte {
	return sha256.Sum256([]byte(v))
}

func zeroTime() time.Time { return time.Time{} }

func (p specProvider) resolveOIDC(ctx context.Context, cfg endpoints) (endpoints, error) {
	if cfg.issuer == "" {
		return cfg, nil
	}
	body, status, err := getJSON(ctx, p.client(), discoveryURL(cfg.issuer), nil)
	if err != nil {
		return endpoints{}, err
	}
	if status >= 400 {
		return endpoints{}, fmt.Errorf("discovery status %d", status)
	}
	doc, err := decodeMap(body)
	if err != nil {
		return endpoints{}, err
	}
	issuer := asString(doc["issuer"])
	if issuer != "" && strings.TrimRight(issuer, "/") != strings.TrimRight(cfg.issuer, "/") {
		return endpoints{}, fmt.Errorf("issuer mismatch")
	}
	if v := asString(doc["authorization_endpoint"]); v != "" {
		cfg.authURL = v
	}
	if v := asString(doc["token_endpoint"]); v != "" {
		cfg.tokenURL = v
	}
	if v := asString(doc["userinfo_endpoint"]); v != "" {
		cfg.userURL = v
	}
	if v := asString(doc["jwks_uri"]); v != "" {
		cfg.jwksURL = v
	}
	if cfg.authURL == "" || cfg.tokenURL == "" {
		return endpoints{}, fmt.Errorf("discovery incomplete")
	}
	return cfg, nil
}

func oidcProfile(ctx context.Context, client HTTPDoer, cfg endpoints, clientID, access, idToken, nonce string) (Profile, error) {
	var claims map[string]any
	if idToken != "" {
		parsed, err := decodeJWTClaimsUnverified(idToken)
		if err != nil {
			return Profile{}, err
		}
		if err := validateIDToken(parsed, cfg.issuer, clientID, nonce); err != nil {
			return Profile{}, err
		}
		claims = parsed
	}
	if cfg.userURL != "" && access != "" {
		body, status, err := getJSON(ctx, client, cfg.userURL, map[string]string{"Authorization": "Bearer " + access})
		if err == nil && status < 400 {
			if info, err := decodeMap(body); err == nil {
				if claims == nil {
					claims = map[string]any{}
				}
				for k, v := range info {
					if _, ok := claims[k]; !ok {
						claims[k] = v
					}
				}
			}
		}
	}
	if claims == nil {
		return Profile{}, fmt.Errorf("no profile")
	}
	email := strings.ToLower(strings.TrimSpace(asString(claims["email"])))
	prof := Profile{
		Subject:       asString(claims["sub"]),
		Email:         email,
		EmailVerified: asBool(claims["email_verified"]) || email != "",
		Name:          asString(claims["name"]),
		GivenName:     asString(claims["given_name"]),
		FamilyName:    asString(claims["family_name"]),
		Picture:       asString(claims["picture"]),
		Raw:           claims,
	}
	if prof.Subject == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	if prof.Email == "" {
		prof.NeedsEmail = true
	}
	return prof, nil
}

func validateIDToken(claims map[string]any, issuer, clientID, nonce string) error {
	iss := asString(claims["iss"])
	if issuer != "" {
		a := strings.TrimRight(iss, "/")
		b := strings.TrimRight(issuer, "/")
		if a != b && a != strings.TrimPrefix(b, "https://") && "https://"+a != b {
			if !(issuer == "https://accounts.google.com" && (iss == "https://accounts.google.com" || iss == "accounts.google.com")) {
				return fmt.Errorf("iss mismatch")
			}
		}
	}
	audOK := false
	switch t := claims["aud"].(type) {
	case string:
		audOK = t == clientID
	case []any:
		for _, item := range t {
			if asString(item) == clientID {
				audOK = true
				break
			}
		}
	}
	if clientID != "" && !audOK {
		return fmt.Errorf("aud mismatch")
	}
	if raw, ok := claims["exp"]; ok {
		var exp int64
		switch v := raw.(type) {
		case float64:
			exp = int64(v)
		case json.Number:
			exp, _ = v.Int64()
		}
		if exp > 0 && time.Now().UTC().Unix() > exp {
			return fmt.Errorf("token expired")
		}
	}
	if nonce != "" {
		got := asString(claims["nonce"])
		if got != nonce {
			return fmt.Errorf("nonce mismatch")
		}
	}
	return nil
}

func microsoftProfile(idToken string) (Profile, error) {
	if idToken == "" {
		return Profile{}, fmt.Errorf("missing id_token")
	}
	claims, err := decodeJWTClaimsUnverified(idToken)
	if err != nil {
		return Profile{}, err
	}
	oid := asString(claims["oid"])
	tid := asString(claims["tid"])
	sub := asString(claims["sub"])
	if oid != "" && tid != "" {
		sub = tid + "." + oid
	}
	email := strings.ToLower(strings.TrimSpace(asString(claims["email"])))
	if email == "" {
		email = strings.ToLower(strings.TrimSpace(asString(claims["preferred_username"])))
	}
	if sub == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	return Profile{
		Subject:       sub,
		Email:         email,
		EmailVerified: email != "",
		Name:          asString(claims["name"]),
		NeedsEmail:    email == "",
		Raw:           claims,
	}, nil
}

func appleProfile(idToken, clientID, nonce string) (Profile, error) {
	if idToken == "" {
		return Profile{}, fmt.Errorf("missing id_token")
	}
	claims, err := decodeJWTClaimsUnverified(idToken)
	if err != nil {
		return Profile{}, err
	}
	if err := validateIDToken(claims, "https://appleid.apple.com", clientID, nonce); err != nil {
		return Profile{}, err
	}
	email := strings.ToLower(strings.TrimSpace(asString(claims["email"])))
	sub := asString(claims["sub"])
	if sub == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	return Profile{
		Subject:       sub,
		Email:         email,
		EmailVerified: asBool(claims["email_verified"]) || email != "",
		NeedsEmail:    email == "",
		Raw:           claims,
	}, nil
}

func githubProfile(ctx context.Context, client HTTPDoer, cfg endpoints, access string) (Profile, error) {
	body, status, err := getJSON(ctx, client, cfg.userURL, map[string]string{
		"Authorization": "Bearer " + access,
		"Accept":        "application/vnd.github+json",
	})
	if err != nil {
		return Profile{}, err
	}
	if status >= 400 {
		return Profile{}, fmt.Errorf("github user status %d", status)
	}
	user, err := decodeMap(body)
	if err != nil {
		return Profile{}, err
	}
	email := strings.ToLower(strings.TrimSpace(asString(user["email"])))
	verified := false
	ebody, estatus, eerr := getJSON(ctx, client, "https://api.github.com/user/emails", map[string]string{
		"Authorization": "Bearer " + access,
		"Accept":        "application/vnd.github+json",
	})
	if eerr == nil && estatus < 400 {
		var emails []map[string]any
		if json.Unmarshal(ebody, &emails) == nil {
			for _, item := range emails {
				if asBool(item["primary"]) && asBool(item["verified"]) {
					email = strings.ToLower(strings.TrimSpace(asString(item["email"])))
					verified = true
					break
				}
			}
		}
	}
	sub := asString(user["id"])
	if sub == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	return Profile{
		Subject:       sub,
		Email:         email,
		EmailVerified: verified || email != "",
		Name:          asString(user["name"]),
		Picture:       asString(user["avatar_url"]),
		NeedsEmail:    email == "",
		Raw:           user,
	}, nil
}

func xProfile(ctx context.Context, client HTTPDoer, cfg endpoints, access string) (Profile, error) {
	body, status, err := getJSON(ctx, client, cfg.userURL, map[string]string{"Authorization": "Bearer " + access})
	if err != nil {
		return Profile{}, err
	}
	if status >= 400 {
		return Profile{}, fmt.Errorf("x user status %d", status)
	}
	doc, err := decodeMap(body)
	if err != nil {
		return Profile{}, err
	}
	data, _ := doc["data"].(map[string]any)
	if data == nil {
		data = doc
	}
	sub := asString(data["id"])
	if sub == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	return Profile{
		Subject:    sub,
		Name:       asString(data["name"]),
		NeedsEmail: true,
		Raw:        doc,
	}, nil
}

func facebookProfile(ctx context.Context, client HTTPDoer, cfg endpoints, access string) (Profile, error) {
	u, _ := url.Parse(cfg.userURL)
	q := u.Query()
	q.Set("access_token", access)
	u.RawQuery = q.Encode()
	body, status, err := getJSON(ctx, client, u.String(), nil)
	if err != nil {
		return Profile{}, err
	}
	if status >= 400 {
		return Profile{}, fmt.Errorf("facebook user status %d", status)
	}
	user, err := decodeMap(body)
	if err != nil {
		return Profile{}, err
	}
	email := strings.ToLower(strings.TrimSpace(asString(user["email"])))
	sub := asString(user["id"])
	if sub == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	return Profile{
		Subject:       sub,
		Email:         email,
		EmailVerified: email != "",
		Name:          asString(user["name"]),
		NeedsEmail:    email == "",
		Raw:           user,
	}, nil
}

func twitchProfile(ctx context.Context, client HTTPDoer, cfg endpoints, access, clientID string) (Profile, error) {
	body, status, err := getJSON(ctx, client, cfg.userURL, map[string]string{
		"Authorization": "Bearer " + access,
		"Client-Id":     clientID,
	})
	if err != nil {
		return Profile{}, err
	}
	if status >= 400 {
		return Profile{}, fmt.Errorf("twitch user status %d", status)
	}
	doc, err := decodeMap(body)
	if err != nil {
		return Profile{}, err
	}
	var first map[string]any
	if arr, ok := doc["data"].([]any); ok && len(arr) > 0 {
		first, _ = arr[0].(map[string]any)
	}
	if first == nil {
		first = doc
	}
	email := strings.ToLower(strings.TrimSpace(asString(first["email"])))
	sub := asString(first["id"])
	if sub == "" {
		return Profile{}, fmt.Errorf("missing subject")
	}
	return Profile{
		Subject:       sub,
		Email:         email,
		EmailVerified: email != "",
		Name:          asString(first["display_name"]),
		Picture:       asString(first["profile_image_url"]),
		NeedsEmail:    email == "",
		Raw:           doc,
	}, nil
}
