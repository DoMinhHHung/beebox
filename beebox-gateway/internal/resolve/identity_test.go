package resolve

import (
	"net/http"
	"testing"
)

func TestIdentityFromBearerCaseInsensitive(t *testing.T) {
	req := &http.Request{Header: http.Header{}}
	req.Header.Set("Authorization", "bEaReR pk_test_abc")
	pk, slug := IdentityFrom(req)
	if pk != "pk_test_abc" || slug != "" {
		t.Fatalf("pk=%q slug=%q", pk, slug)
	}
}
