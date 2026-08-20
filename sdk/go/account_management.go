package beebox

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type EmailIdentifier struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Verified  bool   `json:"verified"`
	Primary   bool   `json:"primary"`
	CreatedAt string `json:"created_at"`
}

type PhoneIdentifier struct {
	ID        string `json:"id"`
	Phone     string `json:"phone"`
	Verified  bool   `json:"verified"`
	Primary   bool   `json:"primary"`
	CreatedAt string `json:"created_at"`
}

type EmailIdentifierPage struct {
	Items      []EmailIdentifier `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type PhoneIdentifierPage struct {
	Items      []PhoneIdentifier `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type Profile struct {
	DisplayName *string `json:"display_name"`
	GivenName   *string `json:"given_name"`
	FamilyName  *string `json:"family_name"`
	Locale      *string `json:"locale"`
}

type ProfilePatch struct {
	DisplayName **string `json:"display_name,omitempty"`
	GivenName   **string `json:"given_name,omitempty"`
	FamilyName  **string `json:"family_name,omitempty"`
	Locale      **string `json:"locale,omitempty"`
}

func (c *Client) ListEmailIdentifiers(ctx context.Context, origin, accessToken string, limit int, cursor string) (EmailIdentifierPage, error) {
	var out EmailIdentifierPage
	path, err := accountIdentifierListPath("emails", limit, cursor)
	if err != nil {
		return out, err
	}
	err = c.doJSON(ctx, http.MethodGet, path, nil, &out, accountHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) AddEmailIdentifier(ctx context.Context, origin, accessToken, reverificationToken, email string) (EmailIdentifier, error) {
	var out EmailIdentifier
	err := c.doJSON(ctx, http.MethodPost, "/v1/identifiers/emails", map[string]string{"email": email}, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
	return out, err
}

func (c *Client) RequestEmailIdentifierVerification(ctx context.Context, origin, accessToken, identifierID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/identifiers/emails/"+url.PathEscape(identifierID)+"/verification", nil, nil, accountHeaders(origin, accessToken), false)
}

func (c *Client) ConfirmEmailIdentifierVerification(ctx context.Context, origin, accessToken, identifierID, code string) (EmailIdentifier, error) {
	var out EmailIdentifier
	err := c.doJSON(ctx, http.MethodPost, "/v1/identifiers/emails/"+url.PathEscape(identifierID)+"/verification/confirm", map[string]string{"code": code}, &out, accountHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) SetPrimaryEmailIdentifier(ctx context.Context, origin, accessToken, reverificationToken, identifierID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/identifiers/emails/"+url.PathEscape(identifierID)+"/primary", nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) RemoveEmailIdentifier(ctx context.Context, origin, accessToken, reverificationToken, identifierID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/identifiers/emails/"+url.PathEscape(identifierID), nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) ListPhoneIdentifiers(ctx context.Context, origin, accessToken string, limit int, cursor string) (PhoneIdentifierPage, error) {
	var out PhoneIdentifierPage
	path, err := accountIdentifierListPath("phones", limit, cursor)
	if err != nil {
		return out, err
	}
	err = c.doJSON(ctx, http.MethodGet, path, nil, &out, accountHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) AddPhoneIdentifier(ctx context.Context, origin, accessToken, reverificationToken, phone string) (PhoneIdentifier, error) {
	var out PhoneIdentifier
	err := c.doJSON(ctx, http.MethodPost, "/v1/identifiers/phones", map[string]string{"phone": phone}, &out, reverificationHeaders(origin, accessToken, reverificationToken), false)
	return out, err
}

func (c *Client) RequestPhoneIdentifierVerification(ctx context.Context, origin, accessToken, identifierID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/identifiers/phones/"+url.PathEscape(identifierID)+"/verification", nil, nil, accountHeaders(origin, accessToken), false)
}

func (c *Client) ConfirmPhoneIdentifierVerification(ctx context.Context, origin, accessToken, identifierID, code string) (PhoneIdentifier, error) {
	var out PhoneIdentifier
	err := c.doJSON(ctx, http.MethodPost, "/v1/identifiers/phones/"+url.PathEscape(identifierID)+"/verification/confirm", map[string]string{"code": code}, &out, accountHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) SetPrimaryPhoneIdentifier(ctx context.Context, origin, accessToken, reverificationToken, identifierID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/identifiers/phones/"+url.PathEscape(identifierID)+"/primary", nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) RemovePhoneIdentifier(ctx context.Context, origin, accessToken, reverificationToken, identifierID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/identifiers/phones/"+url.PathEscape(identifierID), nil, nil, reverificationHeaders(origin, accessToken, reverificationToken), false)
}

func (c *Client) GetProfile(ctx context.Context, origin, accessToken string) (Profile, error) {
	var out Profile
	err := c.doJSON(ctx, http.MethodGet, "/v1/profile", nil, &out, accountHeaders(origin, accessToken), false)
	return out, err
}

func (c *Client) PatchProfile(ctx context.Context, origin, accessToken string, patch ProfilePatch) (Profile, error) {
	var out Profile
	err := c.doJSON(ctx, http.MethodPatch, "/v1/profile", patch, &out, accountHeaders(origin, accessToken), false)
	return out, err
}

func accountIdentifierListPath(kind string, limit int, cursor string) (string, error) {
	if (kind != "emails" && kind != "phones") || limit < 0 || limit > 100 {
		return "", ErrInvalidClient
	}
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	path := "/v1/identifiers/" + kind
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return path, nil
}

func accountHeaders(origin, accessToken string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Origin":        origin,
	}
}
