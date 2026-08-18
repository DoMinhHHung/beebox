package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPhoneSMSOperations(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		confirm bool
		call    func(*Client) error
	}{
		{name: "signup issue", path: "/v1/sign-ups/phone", call: func(c *Client) error {
			_, err := c.RequestPhoneSignUpOTP(context.Background(), "+84901234567")
			return err
		}},
		{name: "signup confirm", path: "/v1/sign-ups/phone/confirm", confirm: true, call: func(c *Client) error {
			_, err := c.ConfirmPhoneSignUpOTP(context.Background(), "+84901234567", "123456")
			return err
		}},
		{name: "signin issue", path: "/v1/sign-ins/phone-otp", call: func(c *Client) error {
			_, err := c.RequestPhoneOTPSignIn(context.Background(), "+84901234567")
			return err
		}},
		{name: "signin confirm", path: "/v1/sign-ins/phone-otp/confirm", confirm: true, call: func(c *Client) error {
			_, err := c.ConfirmPhoneOTPSignIn(context.Background(), "+84901234567", "123456")
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost || r.URL.Path != tt.path {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["phone"] != "+84901234567" {
					t.Fatalf("phone = %q", body["phone"])
				}
				if tt.confirm && body["code"] != "123456" {
					t.Fatalf("code = %q", body["code"])
				}
				if tt.confirm {
					_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", TokenType: "Bearer", ExpiresIn: 300, SessionID: "ses_test", RefreshToken: "refresh"})
					return
				}
				_ = json.NewEncoder(w).Encode(StatusResponse{Status: "accepted"})
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "pk_test")
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.call(client); err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want exactly one", requests)
			}
		})
	}
}
