package main

import "os"

const defaultIdentityHTTPAddress = "127.0.0.1:8081"

// configureIdentityHTTPAddress preserves BEEBOX_HTTP_ADDR compatibility while
// giving the independently runnable Identity Service an internal-only default.
// BEEBOX_IDENTITY_HTTP_ADDR wins when explicitly configured.
func configureIdentityHTTPAddress(lookup func(string) (string, bool), set func(string, string) error) error {
	if value, ok := lookup("BEEBOX_IDENTITY_HTTP_ADDR"); ok {
		return set("BEEBOX_HTTP_ADDR", value)
	}
	if _, ok := lookup("BEEBOX_HTTP_ADDR"); !ok {
		return set("BEEBOX_HTTP_ADDR", defaultIdentityHTTPAddress)
	}
	return nil
}

func init() {
	if err := configureIdentityHTTPAddress(os.LookupEnv, os.Setenv); err != nil {
		panic("configure BeeBox Identity HTTP address")
	}
}
