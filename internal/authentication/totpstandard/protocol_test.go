package totpstandard

import (
	"net/url"
	"testing"
	"time"
)

func TestGenerateUsesRatifiedParameters(t *testing.T) {
	p := New()
	enrollment, err := p.Generate("app_test", "usr_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(enrollment.SecretRaw) != int(SecretBytes) || enrollment.Secret == "" || enrollment.URI == "" {
		t.Fatalf("invalid enrollment: raw=%d secret=%t uri=%t", len(enrollment.SecretRaw), enrollment.Secret != "", enrollment.URI != "")
	}
	u, err := url.Parse(enrollment.URI)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("algorithm") != "SHA1" || u.Query().Get("digits") != "6" || u.Query().Get("period") != "30" {
		t.Fatalf("unexpected otpauth URI parameters: %s", enrollment.URI)
	}
}

func TestVerifyAcceptsOnlyAdjacentWindowAndReturnsMatchedTimestep(t *testing.T) {
	p := New()
	enrollment, err := p.Generate("app_test", "usr_test")
	if err != nil {
		t.Fatal(err)
	}
	serverTime := time.Unix(1_800_000_015, 0).UTC()
	current := serverTime.Unix() / int64(PeriodSeconds)
	for _, offset := range []int64{-1, 0, 1} {
		at := time.Unix((current+offset)*int64(PeriodSeconds), 0).UTC()
		code, err := p.CodeForTest(enrollment.SecretRaw, at)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := p.Verify(enrollment.SecretRaw, code, serverTime)
		if err != nil || !ok || got != current+offset {
			t.Fatalf("offset %d verification = timestep %d ok=%v err=%v", offset, got, ok, err)
		}
	}
	for _, offset := range []int64{-2, 2} {
		at := time.Unix((current+offset)*int64(PeriodSeconds), 0).UTC()
		code, err := p.CodeForTest(enrollment.SecretRaw, at)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, err := p.Verify(enrollment.SecretRaw, code, serverTime); err != nil || ok {
			t.Fatalf("offset %d accepted: ok=%v err=%v", offset, ok, err)
		}
	}
}

func TestVerifyRejectsMalformedCode(t *testing.T) {
	p := New()
	if _, _, err := p.Verify([]byte("synthetic-secret"), "12345a", time.Now()); err == nil {
		t.Fatal("malformed code accepted")
	}
}
