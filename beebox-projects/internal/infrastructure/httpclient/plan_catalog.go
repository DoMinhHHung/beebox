package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

type PlanCatalog struct {
	base   string
	client *http.Client
}

func NewPlanCatalog(baseURL string, client *http.Client) *PlanCatalog {
	if client == nil {
		client = http.DefaultClient
	}
	return &PlanCatalog{base: strings.TrimRight(baseURL, "/"), client: client}
}

type planBody struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

func (c *PlanCatalog) FindBySlug(ctx context.Context, slug string) (domain.CatalogPlan, error) {
	u := c.base + "/v1/plans/" + url.PathEscape(slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return domain.CatalogPlan{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return domain.CatalogPlan{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return domain.CatalogPlan{}, domain.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return domain.CatalogPlan{}, fmt.Errorf("plans status %d", resp.StatusCode)
	}
	var body planBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.CatalogPlan{}, err
	}
	id, err := uuid.Parse(body.ID)
	if err != nil {
		return domain.CatalogPlan{}, err
	}
	if body.Slug == "" {
		return domain.CatalogPlan{}, domain.ErrNotFound
	}
	return domain.CatalogPlan{ID: id, Slug: body.Slug}, nil
}
