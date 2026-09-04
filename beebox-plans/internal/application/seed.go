package application

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
)

func Seed(ctx context.Context, plans domain.PlanRepository) error {
	wanted := []domain.Plan{
		{
			Slug: "free",
			Name: "Free",
			Limits: domain.Limits{
				UserFields:  3,
				Collections: 1,
			},
		},
		{
			Slug: "pro",
			Name: "Pro",
			Limits: domain.Limits{
				UserFields:  20,
				Collections: 20,
				OAuth:       true,
				OTP:         true,
				Realtime:    true,
			},
		},
	}
	for _, plan := range wanted {
		_, err := plans.FindBySlug(ctx, plan.Slug)
		if err == nil {
			continue
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		newID, err := id.New()
		if err != nil {
			return err
		}
		plan.ID = newID
		if err := plans.Create(ctx, plan); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				continue
			}
			return err
		}
	}
	return nil
}
