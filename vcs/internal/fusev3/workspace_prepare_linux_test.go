//go:build linux

package fusev3

import (
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// A managed arena entry that is not finalized at registration (ESTALE GETATTR)
// reaches PrepareReplyPayload's unlocked tail. Connection-gone terminal
// settlement then claims the finalized-but-unreported owner and recycles the
// arena slot. Observing originalFinalized under raw.mu orders preparation up
// to its unlock; it does not order an unlocked tail read before recycling.
func TestWorkspacePrepareTailRacesTerminalRecycle(t *testing.T) {
	f := newStockFixture(t)
	f.lookup(t, 1, "cached")
	bindWorkspaceTestGate(t, f.mount)
	r := f.raw
	u := f.unique.Add(2)
	node := uint64(1 << 40)
	st := testEntryFileSystem(r).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}}, &fuse.AttrOut{})
	r.mu.RLock()
	p := r.replyPublications[u]
	r.mu.RUnlock()
	if p == nil || !p.cachedArena || p.originalFinalized {
		t.Fatalf("want an unfinalized arena entry, status=%v", st)
	}
	writerDone := make(chan struct{})
	physical := make(chan struct{})
	go func() {
		defer close(writerDone)
		// Physical writer: prepare (finalize, unlock, unlocked tail), then a
		// parked device write; it reports only after the connection loss.
		r.PrepareReplyPayload(u, node, 3, make([]byte, 128), nil, 0)
		<-physical
		r.ReplyWritten(u, fuse.Status(19)) // ENODEV
	}()
	defer func() { close(physical); <-writerDone }()
	waitUntil(t, time.Second, "reply preparation finalized", func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return p.originalFinalized
	})
	if r.terminalizeReplyCacheOwnership(time.Now()) {
		t.Fatal("finalized writer unexpectedly joined")
	}
	r.terminalizeReplyCacheOwnershipAfterConnectionGone()
	r.mu.RLock()
	defer r.mu.RUnlock()
	free := 0
	seen := make(map[*replyPublication]bool)
	for p := r.cachedReplyFree; p != nil; p = p.cachedNext {
		if seen[p] {
			t.Fatal("duplicate arena slot")
		}
		seen[p] = true
		free++
	}
	if free != len(r.cachedReplyArena) || len(r.replyPublications) != 0 {
		t.Fatal("prepare/terminal recycle leaked an owner", free)
	}
}
