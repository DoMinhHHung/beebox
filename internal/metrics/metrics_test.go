package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecorderExportsBoundedCounters(t *testing.T) {
	r := New()
	r.Observe("signup", "success")
	r.Observe("signup", "success")
	r.Observe("signin", "denied")
	r.Observe("user@example.test", "denied")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)
	body := res.Body.String()
	if !strings.Contains(body, `beebox_auth_operations_total{operation="signup",outcome="success"} 2`) {
		t.Fatalf("missing signup counter: %s", body)
	}
	if !strings.Contains(body, `beebox_auth_operations_total{operation="signin",outcome="denied"} 1`) {
		t.Fatalf("missing signin counter: %s", body)
	}
	if strings.Contains(body, "example.test") {
		t.Fatal("unsafe/high-cardinality label was exported")
	}
}

func TestRecorderRejectsNonGET(t *testing.T) {
	res := httptest.NewRecorder()
	New().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", res.Code)
	}
}
