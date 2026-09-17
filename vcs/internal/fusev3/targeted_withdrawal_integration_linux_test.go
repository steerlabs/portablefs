//go:build linux

package fusev3

import (
	"net"
	"os"
	"testing"
	"time"
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
