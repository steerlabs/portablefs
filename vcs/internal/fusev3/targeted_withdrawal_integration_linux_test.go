//go:build linux

package fusev3

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestNamespaceWithdrawalWaitsOnlyForAffectedCacheHolders(t *testing.T) {
	for _, kind := range []string{"unrelated-directory", "cached-parent", "new-directory-completeness"} {
		t.Run(kind, func(t *testing.T) {
			var listener *controlFaultListener
			f := newIntegrationFixture(t, integrationConfig{Mounts: 2, wrapListener: func(l net.Listener) net.Listener { listener = &controlFaultListener{Listener: l}; return listener }})
			defer listener.heal()
			if err := os.Mkdir(f.join(0, "a"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.join(0, "b"), 0700); err != nil {
				t.Fatal(err)
			}
			writer, peer := 0, 1
			switch kind {
			case "unrelated-directory":
				if _, err := os.Stat(f.join(peer, "b")); err != nil {
					t.Fatal(err)
				}
			case "cached-parent":
				if _, err := os.Stat(f.join(peer, "a")); err != nil {
					t.Fatal(err)
				}
			case "new-directory-completeness":
				// Mount 0 has only MKDIR's post-state/empty-directory proof for a; it
				// has not performed a later LOOKUP or READDIR of that directory.
				writer, peer = 1, 0
			}
			listener.partition(t, peer)
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- os.Mkdir(f.join(writer, "a", "child"), 0700) }()
			if kind == "unrelated-directory" {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					listener.heal()
					<-done
					t.Fatal("unrelated cache holder delayed namespace reply")
				}
				t.Logf("unrelated partitioned subscriber: mkdir completed in %s", time.Since(start))
				return
			}
			select {
			case err := <-done:
				t.Fatalf("affected cache holder was not withdrawn before reply: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			listener.heal()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(12 * time.Second):
				t.Fatal("mutation did not complete after peer healed/horizon")
			}
		})
	}
}

// These fixture hooks delay application delivery after the real CONTROL RPC
// returns. Renewal remains on the real connection and is never faulted.
func (t *integrationTransport) NextControlEvent(ctx context.Context, incarnation, after, completed uint64) (*authoritypb.ControlEvent, error) {
	event, err := t.Client.NextControlEvent(ctx, incarnation, after, completed)
	t.hookMu.Lock()
	hook := t.afterControlEvent
	t.hookMu.Unlock()
	if err == nil && hook != nil {
		err = hook(ctx, event)
	}
	return event, err
}

func (t *integrationTransport) RenewSubscription(ctx context.Context, incarnation uint64) (time.Time, error) {
	horizon, err := t.Client.RenewSubscription(ctx, incarnation)
	t.hookMu.Lock()
	hook := t.afterSubscriptionRenewal
	t.hookMu.Unlock()
	if hook != nil {
		hook(horizon, err)
	}
	return horizon, err
}

func TestNamespaceWithdrawalHonorsRenewalsWhileControlDeliveryStalls(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	if err := os.Mkdir(f.join(0, "metadata"), 0700); err != nil {
		t.Fatal(err)
	}
	reader := mustOpenFile(t, f.join(1, "metadata"), os.O_RDONLY, 0)
	defer reader.Close()
	if info, err := reader.Stat(); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("warm GETATTR: %v %v", info, err)
	}
	if _, err := os.Stat(f.join(1, "new-name")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm negative LOOKUP: %v", err)
	}
	raw := f.mounts[1].raw
	waitUntil(t, time.Second, "negative and attribute cache settlement", func() bool {
		raw.mu.RLock()
		defer raw.mu.RUnlock()
		parent := raw.nodesByID[1].key.inode
		record := raw.cachedNames[nameKey{parent: parent, name: "metadata"}]
		return raw.cachedNegatives[nameKey{parent: parent, name: "new-name"}] == "new-name" && record != nil && raw.cachedAttrs[record.identity] == record
	})
	healed := make(chan struct{})
	var healOnce sync.Once
	heal := func() { healOnce.Do(func() { close(healed) }) }
	defer heal()
	delayed := make(chan struct{}, 1)
	var renewals atomic.Uint64
	transport := f.transports[1]
	transport.hookMu.Lock()
	transport.afterControlEvent = func(ctx context.Context, event *authoritypb.ControlEvent) error {
		if event.GetChangeBatch() == nil {
			return nil
		}
		select {
		case delayed <- struct{}{}:
		default:
		}
		select {
		case <-healed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	transport.afterSubscriptionRenewal = func(_ time.Time, err error) {
		if err == nil {
			renewals.Add(1)
		}
	}
	transport.hookMu.Unlock()
	written := make(chan error, 2)
	go func() { written <- os.Mkdir(f.join(0, "new-name"), 0700) }()
	go func() { written <- os.Chmod(f.join(0, "metadata"), 0755) }()
	select {
	case <-delayed:
	case <-time.After(2 * time.Second):
		t.Fatal("no change reply reached the delivery fault")
	}
	for range 2 {
		select {
		case err := <-written:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("unacknowledged renewing reader prevented bounded writer progress")
		}
	}
	if renewals.Load() < 2 {
		t.Fatalf("writer did not exercise outstanding withdrawal across repeated accepted renewals: %d", renewals.Load())
	}
	// The daemon remains live and runs real syscalls after both writer replies.
	// Refusal while recovering is allowed; an old negative name or old attributes
	// are not. Keep CONTROL delivery stalled throughout these probes.
	checked := make(chan error, 1)
	go func() {
		if _, err := os.Stat(f.join(1, "new-name")); errors.Is(err, os.ErrNotExist) {
			checked <- errors.New("live reader served stale negative LOOKUP after writer visibility")
			return
		}
		if info, err := reader.Stat(); err == nil && info.Mode().Perm() != 0755 {
			checked <- errors.New("live reader served stale GETATTR after writer visibility")
			return
		}
		checked <- nil
	}()
	select {
	case err := <-checked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		heal()
		select {
		case err := <-checked:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cache probes did not recover after delivery resumed")
		}
	}
	heal()
	waitUntil(t, 5*time.Second, "fresh namespace and attributes after recovery", func() bool {
		_, lookupErr := os.Stat(f.join(1, "new-name"))
		info, attrErr := reader.Stat()
		return lookupErr == nil && attrErr == nil && info.Mode().Perm() == 0755
	})
}
