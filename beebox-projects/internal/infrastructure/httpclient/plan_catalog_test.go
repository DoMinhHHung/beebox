package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

func TestPlanCatalogFindBySlug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/plans/free" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"01800000-0000-7000-8000-0000000000aa","slug":"free","name":"Free"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := NewPlanCatalog(srv.URL, srv.Client())
	got, err := c.FindBySlug(context.Background(), "free")
	if err != nil {
		t.Fatalf("free: %v", err)
	}
	if got.Slug != "free" || got.ID.String() != "01800000-0000-7000-8000-0000000000aa" {
		t.Fatalf("got=%+v", got)
	}
	_, err = c.FindBySlug(context.Background(), "missing")
	if err != domain.ErrNotFound {
		t.Fatalf("missing err=%v", err)
	}
}
