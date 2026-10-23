package workspaceclock

import (
	"errors"
	"testing"
)

func TestElapsedFailureWithdrawsWithoutAnotherCheck(t *testing.T) {
	o, b, closed := clockFixture(t)
	if _, err := o.Measure(); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	previous := b.elapsed
	b.elapsed = -1
	b.mu.Unlock()
	if _, err := o.Measure(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong failure: %v", err)
	}
	o.mu.Lock()
	stillReady := o.ready
	o.mu.Unlock()
	b.mu.Lock()
	b.elapsed = previous
	b.mu.Unlock()
	afterErr := o.Check(0)
	if stillReady || closed.Load() != 1 || afterErr == nil {
		t.Fatal("elapsed failure left readiness published; recovery of Elapsed reused old measurement without correction")
	}
}
