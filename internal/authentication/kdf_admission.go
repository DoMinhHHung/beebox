package authentication

import (
	"context"
	"errors"
	"sync"
)

const DefaultKDFConcurrency = 2

var (
	ErrKDFAdmissionLimited = errors.New("KDF admission limited")

	processKDFMu   sync.RWMutex
	processKDFGate = NewKDFGate(DefaultKDFConcurrency)
)

// KDFGate bounds both concurrent expensive KDF work and the number of callers
// waiting for a KDF slot. It is resource admission only; database-backed abuse
// controls remain the distributed correctness authority.
type KDFGate struct {
	running chan struct{}
	waiting chan struct{}
}

func NewKDFGate(limit int) *KDFGate {
	if limit <= 0 {
		limit = DefaultKDFConcurrency
	}
	return &KDFGate{
		running: make(chan struct{}, limit),
		waiting: make(chan struct{}, limit),
	}
}

func (g *KDFGate) Limit() int {
	if g == nil {
		return 0
	}
	return cap(g.running)
}

// Do executes fn after bounded, context-aware admission. At most limit callers
// run and at most limit additional callers wait. Further callers fail fast.
func (g *KDFGate) Do(ctx context.Context, fn func() error) error {
	if g == nil || g.Limit() <= 0 || fn == nil {
		return ErrKDFAdmissionLimited
	}

	select {
	case g.waiting <- struct{}{}:
	default:
		return ErrKDFAdmissionLimited
	}

	select {
	case g.running <- struct{}{}:
		<-g.waiting
		defer func() { <-g.running }()
	case <-ctx.Done():
		<-g.waiting
		return ctx.Err()
	}

	return fn()
}

// ConfigureProcessKDFConcurrency replaces the process-wide resource gate. It is
// intended to be called during process startup before serving requests.
func ConfigureProcessKDFConcurrency(limit int) error {
	if limit <= 0 || limit > 64 {
		return ErrKDFAdmissionLimited
	}
	processKDFMu.Lock()
	processKDFGate = NewKDFGate(limit)
	processKDFMu.Unlock()
	return nil
}

func withProcessKDF(ctx context.Context, fn func() error) error {
	processKDFMu.RLock()
	gate := processKDFGate
	processKDFMu.RUnlock()
	return gate.Do(ctx, fn)
}
