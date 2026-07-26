package clientcore

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeRenewer struct {
	mu      sync.Mutex
	orphans [][]uint64
	opens   [][]uint64
}

func (f *fakeRenewer) RenewOrphanLeases(inos []uint64) (int32, error) {
	f.mu.Lock()
	f.orphans = append(f.orphans, append([]uint64(nil), inos...))
	f.mu.Unlock()
	return 0, nil
}

func (f *fakeRenewer) RenewOpenInodes(inos []uint64) (int32, error) {
	f.mu.Lock()
	f.opens = append(f.opens, append([]uint64(nil), inos...))
	f.mu.Unlock()
	return 0, nil
}

func TestRenewOpenLeases(t *testing.T) {
	orphans := NewInodeSet()
	opens := NewInodeSet()
	orphans.Add(11)
	opens.Add(22)
	auth := &fakeRenewer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RenewOpenLeases(ctx, auth, orphans, opens, time.Millisecond, nil)

	deadline := time.Now().Add(time.Second)
	for {
		auth.mu.Lock()
		got := len(auth.orphans) > 0 && len(auth.opens) > 0
		auth.mu.Unlock()
		if got {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("renewals did not arrive")
		}
		time.Sleep(time.Millisecond)
	}
}
