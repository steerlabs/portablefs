package clientcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

type failingOpenRegistrar struct {
	status int32
	gen    uint64
	err    error
}

func (r failingOpenRegistrar) MarkOpenGen(uint64) (int32, uint64, error) {
	return r.status, r.gen, r.err
}

func (failingOpenRegistrar) UnmarkOpen(uint64) (int32, error) {
	return fsproto.OK, nil
}

func (failingOpenRegistrar) UnmarkOpenBatch([]uint64) (int32, error) {
	return fsproto.OK, nil
}

func TestDelegationReleaseBlocksWhenPreparedPinsAreUnconfirmed(t *testing.T) {
	ctx := context.Background()
	v := dialCore(t, serveCore(t), Options{
		Owner: "pin-prepare-failure", VolumeID: "pin-prepare-failure",
		Branch: "main", WALDir: t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !v.wb.Covers("d/held") {
		t.Fatal("precondition: create did not acquire a delegation")
	}
	n := NewNodeState(InoOf("d/held"), a.Ino != 0)
	if st := v.Open(ctx, "d/held", n, true); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	t.Cleanup(func() { v.CloseHandle("d/held", n) })
	if _, st := v.Write(ctx, "d/held", n, 0, []byte("held")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	realPrepare := v.prepareDelegationRelease
	v.prepareDelegationRelease = func(string, string, []string) ([]uint64, uint64, error) {
		return nil, 0, errors.New("injected prepare failure")
	}
	err := v.wb.ReleaseFor(ctx, "d/held")
	v.prepareDelegationRelease = realPrepare
	if err == nil {
		t.Fatal("delegation release succeeded without confirmed prepared pins")
	}

	status := v.wb.Status()
	if len(status.Delegations) != 1 || status.Delegations[0].Scope != "d" || !status.Delegations[0].Draining {
		t.Fatalf("failed prepare did not keep the delegation held and draining: %+v", status.Delegations)
	}
	if ino := n.AuthorityIno(); ino != 0 {
		t.Fatalf("failed prepare bound authority inode %d", ino)
	}

	retryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := v.wb.ReleaseFor(retryCtx, "d/held"); err != nil {
		t.Fatalf("release did not recover after restoring prepare: %v", err)
	}
}

func TestDirectoryRenameWhileOpenRekeysPinOwnership(t *testing.T) {
	ctx := context.Background()
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner: "rename-pin-writer", VolumeID: "rename-pin", Branch: "main",
		WALDir: t.TempDir(),
	})
	watchInvalidationsForTest(t, v)
	peer := dialCore(t, addr, Options{Owner: "rename-pin-peer"})

	if _, st := v.Mkdir(ctx, "root", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir root: %d", st)
	}
	dirAttr, st := v.Mkdir(ctx, "root/old", 0o755)
	if st != fsproto.OK {
		t.Fatalf("mkdir delegated directory: %d", st)
	}
	a, st := v.Create(ctx, "root/old/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !v.wb.Covers("root/old/held") {
		t.Fatal("precondition: nested create was not delegated")
	}
	n := NewNodeState(InoOf("root/old/held"), a.Ino != 0)
	if st := v.Open(ctx, "root/old/held", n, true); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	if _, st := v.Write(ctx, "root/old/held", n, 0, []byte("renamed")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	dirNode := NewNodeState(dirAttr.Ino, dirAttr.Ino != 0)
	if st := v.Rename(ctx, "root/old", "root/new", dirNode, nil); st != fsproto.OK {
		t.Fatalf("rename directory: %d", st)
	}
	if v.opens.BusyUnder("root/old") || !v.opens.BusyUnder("root/new") {
		t.Fatalf("open tracker was not prefix-rekeyed: old=%v new=%v", v.opens.BusyUnder("root/old"), v.opens.BusyUnder("root/new"))
	}

	// The peer operation recalls the still-held "root" delegation. Release
	// must resolve the handle at its NEW descendant path, pin that inode, and
	// only then let the peer unlink proceed.
	if st := peer.Remove(ctx, "root/new/held", nil); st != fsproto.OK {
		t.Fatalf("peer remove renamed file: %d", st)
	}
	pinIno := n.AuthorityIno()
	if pinIno == 0 {
		t.Fatal("recall did not bind the renamed open node to its authority inode")
	}
	if _, st, err := v.client.GetattrOrphan(pinIno); err != nil || st != fsproto.OK {
		t.Fatalf("renamed open inode was not parked: status=%d err=%v", st, err)
	}
	if !n.MarkOrphan(pinIno, v.OpenOrphans()) {
		t.Fatal("failed to attach parked inode to live handle")
	}
	data, st := v.Read(ctx, "root/new/held", n, 0, 64)
	if st != fsproto.OK || string(data) != "renamed" {
		t.Fatalf("open-after-rename/unlink read = %q status=%d", data, st)
	}

	v.CloseHandle("root/new/held", n)
	awaitOrphanGone(t, v.client, pinIno, "renamed open inode was not reaped after last close")
}

func TestOpenTrackerRenameUsesPathBoundaries(t *testing.T) {
	tracker := NewOpenTracker()
	moved := NewNodeState(1, true)
	neighbor := NewNodeState(2, true)
	if _, err := tracker.Inc(context.Background(), "old/child", moved); err != nil {
		t.Fatalf("track moved open: %v", err)
	}
	if _, err := tracker.Inc(context.Background(), "older/child", neighbor); err != nil {
		t.Fatalf("track neighbor open: %v", err)
	}
	registry := newOpenRegistry(
		failingOpenRegistrar{status: fsproto.OK, gen: 1},
		func() uint64 { return 1 },
		NewInodeSet(),
		1,
		nil,
	)
	if st := registry.Open("old/child", 10); st != fsproto.OK {
		t.Fatalf("seed live registry entry: %d", st)
	}
	volume := &Volume{
		opens:   tracker,
		openReg: registry,
	}
	if ok := tracker.seedReleasePin(openOwnerFor("old/child", moved), releasePin{ino: 10, path: "old/child"}); !ok {
		t.Fatal("seed release pin")
	}

	volume.noteOpenRename("old", "new", moved, nil)

	if tracker.BusyUnder("old") || !tracker.BusyUnder("new") {
		t.Fatalf("renamed subtree tracking is wrong: old=%v new=%v", tracker.BusyUnder("old"), tracker.BusyUnder("new"))
	}
	if !tracker.BusyUnder("older") {
		t.Fatal("prefix rename of old incorrectly changed neighboring older subtree")
	}
	owner := openOwnerFor("new/child", moved)
	pin, ok := tracker.releasePin(owner)
	if !ok || pin.path != "new/child" || pin.ino != 10 {
		t.Fatalf("stable release-pin owner was not re-keyed: %+v, present=%v", pin, ok)
	}
	registry.mu.Lock()
	entryPath := registry.entries[10].path
	registry.mu.Unlock()
	if entryPath != "new/child" {
		t.Fatalf("live registry path = %q, want new/child", entryPath)
	}
}

func TestWriteThroughRenameStaleCloseKeepsNewRegistryPath(t *testing.T) {
	ctx := context.Background()
	v := dialCore(t, serveCore(t), Options{Owner: "stale-close"})
	n, ino := createOpened(t, v, "old")

	if st := v.Rename(ctx, "old", "new", n, nil); st != fsproto.OK {
		t.Fatalf("write-through rename: %d", st)
	}
	// Model a frontend handle that retained its open-time path. CloseHandle
	// must use the tracker's rename-current name for retention bookkeeping.
	v.CloseHandle("old", n)

	v.openReg.mu.Lock()
	entry := v.openReg.entries[ino]
	entryPath := ""
	entryRefs := -1
	retained := false
	if entry != nil {
		entryPath = entry.path
		entryRefs = entry.refs
		retained = entry.lru != nil
	}
	v.openReg.mu.Unlock()
	if entryPath != "new" || entryRefs != 0 || !retained {
		t.Fatalf("registry after stale-path close: path=%q refs=%d retained=%v, want new/0/true", entryPath, entryRefs, retained)
	}
}

func TestConcurrentFinalCloseAndRenamePublishOneRegistryPath(t *testing.T) {
	ctx := context.Background()
	v := dialCore(t, serveCore(t), Options{Owner: "concurrent-close-rename"})
	for i := 0; i < 20; i++ {
		oldPath := fmt.Sprintf("old-%d", i)
		newPath := fmt.Sprintf("new-%d", i)
		n, ino := createOpened(t, v, oldPath)
		renameOut := make(chan Status, 1)
		closeOut := make(chan Status, 1)
		start := make(chan struct{})
		go func() {
			<-start
			renameOut <- v.Rename(ctx, oldPath, newPath, n, nil)
		}()
		go func() {
			<-start
			closeOut <- v.CloseHandle(oldPath, n)
		}()
		close(start)
		if st := <-renameOut; st != fsproto.OK {
			t.Fatalf("iteration %d rename: %d", i, st)
		}
		if st := <-closeOut; st != fsproto.OK {
			t.Fatalf("iteration %d close: %d", i, st)
		}
		v.openReg.mu.Lock()
		entry := v.openReg.entries[ino]
		entryPath := ""
		entryRefs := -1
		if entry != nil {
			entryPath = entry.path
			entryRefs = entry.refs
		}
		v.openReg.mu.Unlock()
		if entryPath != newPath || entryRefs != 0 {
			t.Fatalf("iteration %d registry path=%q refs=%d, want %q/0", i, entryPath, entryRefs, newPath)
		}
	}
}

func TestMultipleHandlesBalanceRegistryRefs(t *testing.T) {
	registry := newOpenRegistry(
		failingOpenRegistrar{status: fsproto.OK, gen: 1},
		func() uint64 { return 1 },
		NewInodeSet(),
		1,
		nil,
	)
	v := &Volume{
		opens:       NewOpenTracker(),
		openReg:     registry,
		openOrphans: NewInodeSet(),
	}
	n := NewNodeState(42, true)
	if st := v.Open(context.Background(), "two", n, false); st != fsproto.OK {
		t.Fatalf("first open: %d", st)
	}
	if st := v.Open(context.Background(), "two", n, false); st != fsproto.OK {
		t.Fatalf("second open: %d", st)
	}
	v.CloseHandle("two", n)

	registry.mu.Lock()
	refsAfterOneClose := registry.entries[42].refs
	registry.mu.Unlock()
	if refsAfterOneClose != 1 || !v.opens.BusyUnder("two") {
		t.Fatalf("after one close: registry refs=%d busy=%v, want 1/true", refsAfterOneClose, v.opens.BusyUnder("two"))
	}

	v.CloseHandle("two", n)
	registry.mu.Lock()
	entry := registry.entries[42]
	refsAfterLastClose := entry.refs
	retained := entry.lru != nil
	registry.mu.Unlock()
	if refsAfterLastClose != 0 || !retained || v.opens.BusyUnder("two") {
		t.Fatalf("after last close: refs=%d retained=%v busy=%v, want 0/true/false", refsAfterLastClose, retained, v.opens.BusyUnder("two"))
	}
}
