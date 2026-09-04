package application

import (
	"context"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
)

type ListPlans struct {
	Plans domain.PlanRepository
}

func (u ListPlans) Execute(ctx context.Context) ([]domain.Plan, error) {
	return u.Plans.List(ctx)
}
