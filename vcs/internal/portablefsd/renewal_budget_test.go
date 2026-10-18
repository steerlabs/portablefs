//go:build darwin || linux

package portablefsd

import (
	"sync"
	"testing"
	"time"
)

func TestP4ContinuousRenewalBudgetExpires(t *testing.T) {
	expired := make(chan struct{})
	stop, err := startV3RenewalBudget(time.Millisecond, func() { close(expired) })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case <-expired:
	case <-time.After(5 * time.Second):
		t.Fatal("native continuous deadline did not end waiting")
	}
	// Stopping after expiration must not address a reused native descriptor.
	var joined sync.WaitGroup
	for range 8 {
		joined.Go(stop)
	}
	joined.Wait()
}

func TestP4ContinuousRenewalBudgetStopRetiresOwner(t *testing.T) {
	expired := make(chan struct{})
	stop, err := startV3RenewalBudget(time.Hour, func() { close(expired) })
	if err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for range 8 {
		joined.Go(stop)
	}
	joined.Wait()
	select {
	case <-expired:
		t.Fatal("stopped native deadline canceled the completed call")
	default:
	}
}
