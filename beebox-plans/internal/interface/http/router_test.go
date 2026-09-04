package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
	"github.com/google/uuid"
)

type memPlans struct {
	items map[string]domain.Plan
}

func (m memPlans) FindBySlug(_ context.Context, slug string) (domain.Plan, error) {
	p, ok := m.items[slug]
	if !ok {
		return domain.Plan{}, domain.ErrNotFound
	}
	return p, nil
}

func (m memPlans) List(context.Context) ([]domain.Plan, error) {
	out := make([]domain.Plan, 0, len(m.items))
	for _, p := range m.items {
		out = append(out, p)
	}
	return out, nil
}

func (m memPlans) Create(context.Context, domain.Plan) error { return nil }

type okPing struct{}

func (okPing) Ping(context.Context) error { return nil }

func TestPlansHTTP(t *testing.T) {
	id := uuid.MustParse("01800000-0000-7000-8000-000000000001")
	repo := memPlans{items: map[string]domain.Plan{
		"free": {ID: id, Slug: "free", Name: "Free", Limits: domain.Limits{UserFields: 3, Collections: 1}},
	}}
	h := New(application.ListPlans{Plans: repo}, application.GetPlan{Plans: repo}, okPing{})

	live := httptest.NewRecorder()
	h.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("live=%d", live.Code)
	}

	ready := httptest.NewRecorder()
	h.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("ready=%d", ready.Code)
	}

	list := httptest.NewRecorder()
	h.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/v1/plans", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list=%d body=%s", list.Code, list.Body.String())
	}

	got := httptest.NewRecorder()
	h.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/v1/plans/free", nil))
	if got.Code != http.StatusOK {
		t.Fatalf("get=%d body=%s", got.Code, got.Body.String())
	}
	var body planDTO
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body.Slug != "free" || body.Limits.UserFields != 3 {
		t.Fatalf("body=%+v", body)
	}

	missing := httptest.NewRecorder()
	h.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/v1/plans/nope", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing=%d", missing.Code)
	}
}
