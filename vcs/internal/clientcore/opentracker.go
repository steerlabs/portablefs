package clientcore

import (
	"strings"
	"sync"
)

// OpenTracker counts open file handles per path so the write-back idle sweeper
// never hands off a subtree while a file under it is still open. A time-based
// release that fires mid-workflow can flush a transient state; gating release on
// "nothing under the subtree is open" confines handoff to clean close boundaries.
type OpenTracker struct {
	mu sync.Mutex
	m  map[string]int
}

func NewOpenTracker() *OpenTracker { return &OpenTracker{m: map[string]int{}} }

func (t *OpenTracker) Inc(p string) {
	t.mu.Lock()
	t.m[p]++
	t.mu.Unlock()
}

func (t *OpenTracker) Dec(p string) {
	t.mu.Lock()
	if t.m[p] <= 1 {
		delete(t.m, p)
	} else {
		t.m[p]--
	}
	t.mu.Unlock()
}

// BusyUnder reports whether any open handle is at or under subtree root (root
// "" = the whole volume). The session sweeper uses it to skip a still-in-use
// subtree.
func (t *OpenTracker) BusyUnder(root string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for p := range t.m {
		if root == "" || p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}
