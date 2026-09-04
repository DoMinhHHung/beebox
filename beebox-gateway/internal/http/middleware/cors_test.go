package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/resolve"
)

type stubResolver struct {
	project resolve.Project
}

func (s stubResolver) Resolve(*http.Request) (resolve.Project, error) {
	return s.project, nil
}

func TestPreflightAllowsIdentityHeaders(t *testing.T) {
	project := resolve.Project{
		ProjectID: "01800000-0000-7000-8000-000000000001",
		Slug:      "shop",
		Origins:   []string{"http://localhost:3000"},
	}
	h := ResolveAndCORS(stubResolver{project: project}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cases := []struct {
		header string
		value  string
	}{
		{"X-BeeBox-Publishable-Key", "pk_test_ok"},
		{"Authorization", "Bearer pk_test_ok"},
		{"X-BeeBox-Project-Slug", "shop"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodOptions, "/v1/client/config", nil)
		req.Header.Set(tc.header, tc.value)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", tc.header)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s status=%d", tc.header, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
			t.Fatalf("%s acao=%q", tc.header, rec.Header().Get("Access-Control-Allow-Origin"))
		}
	}
}
