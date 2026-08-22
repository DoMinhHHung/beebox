package main

import "testing"

func TestConfigureIdentityHTTPAddress(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "internal default", env: map[string]string{}, want: defaultIdentityHTTPAddress},
		{name: "legacy compatibility", env: map[string]string{"BEEBOX_HTTP_ADDR": ":9000"}, want: ":9000"},
		{name: "identity override", env: map[string]string{"BEEBOX_HTTP_ADDR": ":9000", "BEEBOX_IDENTITY_HTTP_ADDR": "0.0.0.0:8081"}, want: "0.0.0.0:8081"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for key, value := range tc.env {
				env[key] = value
			}
			lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
			set := func(key, value string) error { env[key] = value; return nil }
			if err := configureIdentityHTTPAddress(lookup, set); err != nil {
				t.Fatal(err)
			}
			if got := env["BEEBOX_HTTP_ADDR"]; got != tc.want {
				t.Fatalf("BEEBOX_HTTP_ADDR = %q want %q", got, tc.want)
			}
		})
	}
}
