package application

import (
	"context"
	"sync"

	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
)

type fakePlanRepo struct {
	mu     sync.Mutex
	bySlug map[string]domain.Plan
}

func newFakePlanRepo(plans ...domain.Plan) *fakePlanRepo {
	r := &fakePlanRepo{bySlug: map[string]domain.Plan{}}
	for _, p := range plans {
		r.bySlug[p.Slug] = p
	}
	return r
}

func (f *fakePlanRepo) FindBySlug(_ context.Context, slug string) (domain.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.bySlug[slug]
	if !ok {
		return domain.Plan{}, domain.ErrNotFound
	}
	return p, nil
}

func (f *fakePlanRepo) List(context.Context) ([]domain.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]domain.Plan, 0, len(f.bySlug))
	for _, p := range f.bySlug {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakePlanRepo) Create(_ context.Context, plan domain.Plan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.bySlug[plan.Slug]; ok {
		return domain.ErrConflict
	}
	f.bySlug[plan.Slug] = plan
	return nil
}
