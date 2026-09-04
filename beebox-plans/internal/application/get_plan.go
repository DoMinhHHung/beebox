package application

import (
	"context"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
)

type GetPlan struct {
	Plans domain.PlanRepository
}

func (u GetPlan) Execute(ctx context.Context, slug string) (domain.Plan, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return domain.Plan{}, domain.ErrInvalidInput
	}
	return u.Plans.FindBySlug(ctx, slug)
}
