package beebox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 10 * time.Second

var ErrInvalidClient = errors.New("invalid BeeBox client configuration")

type Error struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *Error) Error() string {
	if e == nil {
		return "BeeBox request failed"
	}
	return fmt.Sprintf("BeeBox request failed: %s", e.Code)
}

type Client struct {
	baseURL        *url.URL
	publishableKey string
	secretKey      string
	httpClient     *http.Client
}

type Option func(*Client) error

func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) error {
		if client == nil {
			return ErrInvalidClient
		}
		c.httpClient = client
		return nil
	}
}

func WithSecretKey(secret string) Option {
	return func(c *Client) error {
		c.secretKey = secret
		return nil
	}
}

func NewClient(baseURL, publishableKey string, options ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" || publishableKey == "" {
		return nil, ErrInvalidClient
	}
	c := &Client{baseURL: u, publishableKey: publishableKey, httpClient: &http.Client{Timeout: defaultTimeout}}
	for _, option := range options {
		if option != nil {
			if err := option(c); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

type StatusResponse struct {
	Status string `json:"status"`
}

type PendingMFA struct {
	Factor    string `json:"factor"`
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

type TokenResponse struct {
	Status       string      `json:"status,omitempty"`
	AccessToken  string      `json:"access_token,omitempty"`
	TokenType    string      `json:"token_type,omitempty"`
	ExpiresIn    int64       `json:"expires_in,omitempty"`
	SessionID    string      `json:"session_id,omitempty"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	PendingMFA   *PendingMFA `json:"pending_mfa,omitempty"`
}

type Session struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
}

func (c *Client) SignUp(ctx context.Context, email, password, idempotencyKey string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ups", map[string]string{"email": email, "password": password}, &out, map[string]string{"Idempotency-Key": idempotencyKey}, false)
	return out, err
}

func (c *Client) RequestEmailVerification(ctx context.Context, email string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/email-verifications", map[string]string{"email": email}, &out, nil, false)
	return out, err
}

func (c *Client) ResendEmailVerification(ctx context.Context, email string) (StatusResponse, error) {
	return c.RequestEmailVerification(ctx, email)
}

func (c *Client) ConfirmEmailVerification(ctx context.Context, email, code string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/email-verifications/confirm", map[string]string{"email": email, "code": code}, &out, nil, false)
	return out, err
}

func (c *Client) SignIn(ctx context.Context, email, password string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sign-ins", map[string]string{"email": email, "password": password}, &out, nil, false)
	return out, err
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (TokenResponse, error) {
	var out TokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/sessions/refresh", map[string]string{"refresh_token": refreshToken}, &out, nil, false)
	return out, err
}

func (c *Client) CurrentSession(ctx context.Context, accessToken string) (Session, error) {
	var out Session
	err := c.doJSON(ctx, http.MethodGet, "/v1/sessions/current", nil, &out, map[string]string{"Authorization": "Bearer " + accessToken}, false)
	return out, err
}

func (c *Client) SignOut(ctx context.Context, accessToken string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/sign-out", nil, nil, map[string]string{"Authorization": "Bearer " + accessToken}, false)
}

func (c *Client) RequestPasswordReset(ctx context.Context, email string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/password-resets", map[string]string{"email": email}, &out, nil, false)
	return out, err
}

func (c *Client) ConfirmPasswordReset(ctx context.Context, email, code, newPassword string) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/password-resets/confirm", map[string]string{"email": email, "code": code, "new_password": newPassword}, &out, nil, false)
	return out, err
}

func (c *Client) GetSession(ctx context.Context, sessionID string) (Session, error) {
	var out Session
	err := c.doJSON(ctx, http.MethodGet, "/v1/backend/sessions/"+url.PathEscape(sessionID), nil, &out, nil, true)
	return out, err
}

func (c *Client) RevokeSession(ctx context.Context, sessionID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/backend/sessions/"+url.PathEscape(sessionID)+"/revoke", nil, nil, nil, true)
}

func (c *Client) doJSON(ctx context.Context, method, path string, input, output any, headers map[string]string, backend bool) error {
	if c == nil || c.baseURL == nil || c.httpClient == nil {
		return ErrInvalidClient
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.Fragment != "" || !strings.HasPrefix(relative.Path, "/") {
		return ErrInvalidClient
	}
	u := *c.baseURL
	u.Path = strings.TrimSuffix(u.Path, "/") + relative.Path
	u.RawPath = ""
	u.RawQuery = relative.RawQuery
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if backend {
		if c.secretKey == "" {
			return ErrInvalidClient
		}
		req.Header.Set("Authorization", "Bearer "+c.secretKey)
	} else {
		req.Header.Set("X-BeeBox-Publishable-Key", c.publishableKey)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&envelope)
		return &Error{StatusCode: res.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: envelope.Error.RequestID}
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(output)
}
