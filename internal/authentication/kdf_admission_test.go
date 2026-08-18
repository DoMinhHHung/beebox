package authentication

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestKDFGateBoundsConcurrencyAndWaiting(t *testing.T) {
	gate := NewKDFGate(2)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32

	work := func() error {
		n := active.Add(1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return nil
	}

	errs := make(chan error, 5)
	for range 4 {
		go func() { errs <- gate.Do(context.Background(), work) }()
	}
	<-started
	<-started

	// Wait for both remaining callers to actually occupy the bounded waiting
	// set before probing the fifth caller. Merely observing two running workers
	// does not guarantee the scheduler has run the other goroutines yet.
	deadline := time.Now().Add(time.Second)
	for len(gate.waiting) < gate.Limit() {
		if time.Now().After(deadline) {
			t.Fatalf("waiting admissions = %d, want %d", len(gate.waiting), gate.Limit())
		}
		runtime.Gosched()
	}

	// Two callers are running and two are in the bounded waiting set. A fifth
	// caller is rejected rather than extending an unbounded queue.
	if err := gate.Do(context.Background(), func() error { return nil }); !errors.Is(err, ErrKDFAdmissionLimited) {
		t.Fatalf("expected saturated admission error, got %v", err)
	}
	close(release)
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatalf("KDF work failed: %v", err)
		}
	}
	if got := maxActive.Load(); got > 2 {
		t.Fatalf("observed %d concurrent KDF operations, want <= 2", got)
	}
}

func TestKDFGateCancellationReleasesWaitingAdmission(t *testing.T) {
	gate := NewKDFGate(1)
	entered := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = gate.Do(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := gate.Do(ctx, func() error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	close(release)

	// A canceled waiter must release its bounded waiting token.
	if err := gate.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("admission token leaked after cancellation: %v", err)
	}
}
