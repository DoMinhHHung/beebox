package domain

import (
	"context"

	"github.com/google/uuid"
)

type Limits struct {
	UserFields  int  `json:"user_fields"`
	Collections int  `json:"collections"`
	OAuth       bool `json:"oauth"`
	OTP         bool `json:"otp"`
	Realtime    bool `json:"realtime"`
}

type Plan struct {
	ID     uuid.UUID
	Slug   string
	Name   string
	Limits Limits
}

type PlanRepository interface {
	FindBySlug(ctx context.Context, slug string) (Plan, error)
	List(ctx context.Context) ([]Plan, error)
	Create(ctx context.Context, plan Plan) error
}
