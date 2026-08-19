package applicationinstance

import "testing"

func TestCanonicalizeRedirectURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "https exact path", raw: "https://App.Example.test/auth/callback", want: "https://app.example.test/auth/callback", ok: true},
		{name: "https root", raw: "https://app.example.test", want: "https://app.example.test/", ok: true},
		{name: "localhost http", raw: "http://localhost:3000/callback", want: "http://localhost:3000/callback", ok: true},
		{name: "production http", raw: "http://app.example.test/callback"},
		{name: "loopback ip is not localhost exception", raw: "http://127.0.0.1:3000/callback"},
		{name: "query", raw: "https://app.example.test/callback?next=x"},
		{name: "fragment", raw: "https://app.example.test/callback#fragment"},
		{name: "userinfo", raw: "https://user@app.example.test/callback"},
		{name: "wildcard", raw: "https://*.example.test/callback"},
		{name: "relative", raw: "/callback"},
		{name: "javascript", raw: "javascript://app.example.test/callback"},
		{name: "leading whitespace", raw: " https://app.example.test/callback"},
		{name: "escaped alternate path", raw: "https://app.example.test/auth/%63allback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeRedirectURL(tt.raw)
			if tt.ok {
				if err != nil {
					t.Fatalf("CanonicalizeRedirectURL() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("CanonicalizeRedirectURL() = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("CanonicalizeRedirectURL() = %q, want rejection", got)
			}
		})
	}
}

func TestRedirectOriginPreservesPortAndRejectsInvalid(t *testing.T) {
	t.Parallel()
	got, err := RedirectOrigin("https://app.example.test:8443/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://app.example.test:8443" {
		t.Fatalf("origin = %q", got)
	}
	if _, err := RedirectOrigin("https://app.example.test/callback?x=1"); err == nil {
		t.Fatal("expected invalid redirect")
	}
}
