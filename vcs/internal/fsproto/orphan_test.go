package fsproto

import (
	"context"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/coherence"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// waitForOrphanInvalidation drains sub until it sees an Orphaned invalidation for path and returns
// its OrphanIno, or fails the test on timeout. It tolerates interleaved plain invalidations.
func waitForOrphanInvalidation(t *testing.T, sub <-chan []coherence.Invalidation, path string) uint64 {
	t.Helper()
	var seen []coherence.Invalidation
	timeout := time.After(2 * time.Second)
	for {
		select {
		case batch, ok := <-sub:
			if !ok {
				t.Fatalf("subscribe stream closed waiting for orphan invalidation for %q; saw %+v", path, seen)
			}
			for _, inv := range batch {
				if inv.Path != path {
					continue
				}
				seen = append(seen, inv)
				if inv.Orphaned {
					if inv.OrphanIno == 0 {
						t.Fatalf("orphan invalidation for %q carried ino 0", path)
					}
					return inv.OrphanIno
				}
			}
		case <-timeout:
			t.Fatalf("no orphan invalidation for %q; saw %+v", path, seen)
		}
	}
}

// drainSubscribeHeartbeat consumes the first (possibly empty) heartbeat batch so the subscription is
// known-live before the test triggers the event it wants to observe.
func drainSubscribeHeartbeat(t *testing.T, sub <-chan []coherence.Invalidation) {
	t.Helper()
	select {
	case _, ok := <-sub:
		if !ok {
			t.Fatal("subscribe stream closed before heartbeat")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no subscribe heartbeat")
	}
}

// TestCrossMountOrphanInvalidationRedirectsPeerOpen is the authority/wire half of B3: when mount A
// unlinks-while-open (Orphan) a file mount B is holding open, B receives an Orphaned invalidation
// carrying the parked ino, the linked name now reads ENOENT, but B can still reach the bytes (and
// renew the lease) by ino — the redirect that lets B's open fd survive A's cross-mount unlink.
func TestCrossMountOrphanInvalidationRedirectsPeerOpen(t *testing.T) {
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cliA, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliA.Close()
	cliA.SetOwner("mountA")

	cliB, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliB.Close()
	cliB.SetOwner("mountB")

	if _, st, err := cliA.Create("shared.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Write("shared.txt", 0, []byte("shared-data"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}
	if data, st, err := cliB.Read("shared.txt", 0, 64); err != nil || st != OK || string(data) != "shared-data" {
		t.Fatalf("peer pre-open read = %q st=%d err=%v", data, st, err)
	}

	sub, err := cliB.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	drainSubscribeHeartbeat(t, sub)

	ino, st, err := cliA.Orphan("shared.txt")
	if err != nil || st != OK {
		t.Fatalf("orphan: ino=%d st=%d err=%v", ino, st, err)
	}

	redirectIno := waitForOrphanInvalidation(t, sub, "shared.txt")
	if redirectIno != ino {
		t.Fatalf("redirect ino = %d, want orphan ino %d", redirectIno, ino)
	}
	if _, st, err := cliB.Read("shared.txt", 0, 64); err != nil || st != ENOENT {
		t.Fatalf("path read after orphan st=%d err=%v, want ENOENT", st, err)
	}
	if data, st, err := cliB.ReadOrphan(redirectIno, 0, 64); err != nil || st != OK || string(data) != "shared-data" {
		t.Fatalf("redirected orphan read = %q st=%d err=%v", data, st, err)
	}
	if st, err := cliB.RenewOrphanLeases([]uint64{redirectIno}); err != nil || st != OK {
		t.Fatalf("peer renew redirected orphan: st=%d err=%v", st, err)
	}
}

// TestCrossMountRenameOverInvalidationRedirectsPeerTarget is the rename-over half of B3: A renames
// src over a dst that B holds open. B's open dst node redirects to the parked old-dst inode (so its
// fd still sees the old bytes), while the dst NAME now resolves to src's replacement content.
func TestCrossMountRenameOverInvalidationRedirectsPeerTarget(t *testing.T) {
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cliA, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliA.Close()
	cliA.SetOwner("mountA")

	cliB, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliB.Close()
	cliB.SetOwner("mountB")

	if _, st, err := cliA.Create("src.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create src: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Write("src.txt", 0, []byte("replacement"), 0o644); err != nil || st != OK {
		t.Fatalf("write src: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Create("dst.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create dst: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Write("dst.txt", 0, []byte("old-dst"), 0o644); err != nil || st != OK {
		t.Fatalf("write dst: st=%d err=%v", st, err)
	}
	if data, st, err := cliB.Read("dst.txt", 0, 64); err != nil || st != OK || string(data) != "old-dst" {
		t.Fatalf("peer pre-open target read = %q st=%d err=%v", data, st, err)
	}

	sub, err := cliB.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	drainSubscribeHeartbeat(t, sub)

	st, parked, err := cliA.RenameWithOrphanTarget("src.txt", "dst.txt", true)
	if err != nil || st != OK || parked == 0 {
		t.Fatalf("rename-over: parked=%d st=%d err=%v", parked, st, err)
	}

	redirectIno := waitForOrphanInvalidation(t, sub, "dst.txt")
	if redirectIno != parked {
		t.Fatalf("redirect ino = %d, want parked ino %d", redirectIno, parked)
	}
	if data, st, err := cliB.Read("dst.txt", 0, 64); err != nil || st != OK || string(data) != "replacement" {
		t.Fatalf("new dst name read = %q st=%d err=%v", data, st, err)
	}
	if data, st, err := cliB.ReadOrphan(redirectIno, 0, 64); err != nil || st != OK || string(data) != "old-dst" {
		t.Fatalf("redirected old-dst read = %q st=%d err=%v", data, st, err)
	}
}

// Open-after-unlink over the protocol: a client creates + writes a file, orphans it (name detached,
// inode parked by ino), keeps reading and writing it by the returned ino, then reaps it on last close.
func TestOrphanRoundTrip(t *testing.T) {
	cli := serve(t)
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("f", 0, []byte("hello"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}

	ino, st, err := cli.Orphan("f")
	if err != nil || st != OK {
		t.Fatalf("orphan: st=%d err=%v", st, err)
	}
	if ino == 0 {
		t.Fatal("orphan returned ino 0")
	}
	// The name is gone from the tree.
	if _, st, _ := cli.Getattr("f"); st != ENOENT {
		t.Fatalf("orphaned name should stat ENOENT, got st=%d", st)
	}
	// But the bytes are still addressable by ino.
	data, st, err := cli.ReadOrphan(ino, 0, 5)
	if err != nil || st != OK || string(data) != "hello" {
		t.Fatalf("readorphan = %q st=%d err=%v, want hello", data, st, err)
	}
	// Write-after-unlink (the temp-file pattern), read it back.
	if _, st, err := cli.WriteOrphan(ino, 0, []byte("WORLD!")); err != nil || st != OK {
		t.Fatalf("writeorphan: st=%d err=%v", st, err)
	}
	data, _, _ = cli.ReadOrphan(ino, 0, 6)
	if string(data) != "WORLD!" {
		t.Fatalf("read after writeorphan = %q, want WORLD!", data)
	}
	// Truncate-after-unlink.
	if st, err := cli.TruncateOrphan(ino, 3); err != nil || st != OK {
		t.Fatalf("truncateorphan: st=%d err=%v", st, err)
	}
	data, _, _ = cli.ReadOrphan(ino, 0, 6)
	if string(data) != "WOR" {
		t.Fatalf("read after truncateorphan = %q, want WOR", data)
	}
	// Last close reaps it; the ino stops resolving.
	if st, err := cli.Reap(ino); err != nil || st != OK {
		t.Fatalf("reap: st=%d err=%v", st, err)
	}
	if _, st, _ := cli.ReadOrphan(ino, 0, 1); st != ENOENT {
		t.Fatalf("read after reap should be ENOENT, got st=%d", st)
	}
}

// The canonical POSIX semantic over the wire: orphan a file, then recreate the same name. The orphan
// keeps its old bytes under its ino while the new name is a DISTINCT inode with its own bytes.
func TestOrphanThenRecreateNameDistinct(t *testing.T) {
	cli := serve(t)
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("f", 0, []byte("AAAAA"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}
	ino, st, err := cli.Orphan("f")
	if err != nil || st != OK {
		t.Fatalf("orphan: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("recreate: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("f", 0, []byte("BBBBB"), 0o644); err != nil || st != OK {
		t.Fatalf("write new: st=%d err=%v", st, err)
	}
	if data, _, _ := cli.ReadOrphan(ino, 0, 5); string(data) != "AAAAA" {
		t.Fatalf("orphan content = %q, want AAAAA (unchanged by the recreate)", data)
	}
	if nb, _, _ := cli.Read("f", 0, 5); string(nb) != "BBBBB" {
		t.Fatalf("recreated name content = %q, want BBBBB", nb)
	}
}

func TestHandleWriteAfterUnlinkRecreateTargetsOldOrphan(t *testing.T) {
	cli := serve(t)
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create old: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("f", 0, []byte("old-one"), 0o644); err != nil || st != OK {
		t.Fatalf("write old: st=%d err=%v", st, err)
	}
	a, st, err := cli.Getattr("f")
	if err != nil || st != OK || a == nil || a.Ino == 0 {
		t.Fatalf("getattr old: attr=%+v st=%d err=%v", a, st, err)
	}
	i1 := a.Ino
	orphIno, st, err := cli.Orphan("f")
	if err != nil || st != OK {
		t.Fatalf("orphan: ino=%d st=%d err=%v", orphIno, st, err)
	}
	if orphIno != i1 {
		t.Fatalf("orphan ino = %d, want original ino %d", orphIno, i1)
	}

	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create new: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("f", 0, []byte("new-two"), 0o644); err != nil || st != OK {
		t.Fatalf("write new: st=%d err=%v", st, err)
	}
	a2, st, err := cli.Getattr("f")
	if err != nil || st != OK || a2 == nil {
		t.Fatalf("getattr new: attr=%+v st=%d err=%v", a2, st, err)
	}
	if a2.Ino == i1 {
		t.Fatalf("recreated name reused old ino %d", i1)
	}

	if n, _, _, st, err := cli.WriteVHandle("f", i1, 0, []byte("old-fd!"), 0o644); err != nil || st != OK || n != len("old-fd!") {
		t.Fatalf("handle write: n=%d st=%d err=%v", n, st, err)
	}
	if got, st, err := cli.ReadOrphan(i1, 0, 64); err != nil || st != OK || string(got) != "old-fd!" {
		t.Fatalf("old inode read = %q st=%d err=%v, want old-fd!", got, st, err)
	}
	if got, st, err := cli.Read("f", 0, 64); err != nil || st != OK || string(got) != "new-two" {
		t.Fatalf("new name read = %q st=%d err=%v, want new-two", got, st, err)
	}
}

func withProtocolOrphanLeaseTiming(t *testing.T, ttl, sweep time.Duration) {
	t.Helper()
	oldTTL, oldSweep := workfs.OrphanLeaseTTL, workfs.OrphanSweepInterval
	workfs.OrphanLeaseTTL, workfs.OrphanSweepInterval = ttl, sweep
	t.Cleanup(func() {
		workfs.OrphanLeaseTTL, workfs.OrphanSweepInterval = oldTTL, oldSweep
	})
}

func startOrphanSweeper(t *testing.T, fs *workfs.FS) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fs.StartOrphanSweeper(ctx)
}

func TestOrphanReconnectBlipKeptByRenewal(t *testing.T) {
	withProtocolOrphanLeaseTiming(t, 400*time.Millisecond, 10*time.Millisecond)
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	if _, st, _ := cli.Create("f", 0o644); st != OK {
		t.Fatalf("create st=%d", st)
	}
	if _, st, _ := cli.Write("f", 0, []byte("keep"), 0o644); st != OK {
		t.Fatalf("write st=%d", st)
	}
	ino, st, err := cli.Orphan("f")
	if err != nil || st != OK {
		t.Fatalf("orphan st=%d err=%v", st, err)
	}

	time.Sleep(120 * time.Millisecond)
	if st, err := cli.RenewOrphanLeases([]uint64{ino}); err != nil || st != OK {
		t.Fatalf("renew st=%d err=%v", st, err)
	}
	time.Sleep(320 * time.Millisecond)

	data, st, err := cli.ReadOrphan(ino, 0, 4)
	if err != nil || st != OK || string(data) != "keep" {
		t.Fatalf("orphan after blip = %q st=%d err=%v, want keep", data, st, err)
	}
}

func TestSameOwnerRestartOldOrphanReaped(t *testing.T) {
	withProtocolOrphanLeaseTiming(t, 80*time.Millisecond, 5*time.Millisecond)
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cli1, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	cli1.SetOwner("stable-owner")
	if _, st, _ := cli1.Create("old", 0o644); st != OK {
		t.Fatalf("create st=%d", st)
	}
	ino, st, err := cli1.Orphan("old")
	if err != nil || st != OK {
		t.Fatalf("orphan st=%d err=%v", st, err)
	}
	_ = cli1.Close()

	cli2, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli2.Close()
	cli2.SetOwner("stable-owner")
	sub, err := cli2.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub:
	case <-time.After(time.Second):
		t.Fatal("no subscribe heartbeat")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, st, _ := cli2.ReadOrphan(ino, 0, 1); st == ENOENT {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("same-owner restarted mount kept an old unknown orphan alive")
}

// TestRemoveOfPeerOpenFileParksInsteadOfRemoving is the core of Stage 2 (authority open-state): mount
// A removes a file ONLY mount B holds open. Because B registered the inode as open (MarkOpen), the
// authority PARKS it as an orphan instead of removing — B keeps reading it by ino until it closes.
func TestRemoveOfPeerOpenFileParksInsteadOfRemoving(t *testing.T) {
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cliA, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliA.Close()
	cliA.SetOwner("A")

	cliB, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliB.Close()
	cliB.SetOwner("B")

	if _, st, err := cliA.Create("shared", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Write("shared", 0, []byte("peer-data"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}
	// B "opens" it: learns the ino and registers open-state. A itself does NOT hold it open.
	a, st, err := cliB.Getattr("shared")
	if err != nil || st != OK || a.Ino == 0 {
		t.Fatalf("getattr: ino=%d st=%d err=%v", a.Ino, st, err)
	}
	ino := a.Ino
	if st, err := cliB.MarkOpen(ino); err != nil || st != OK {
		t.Fatalf("markopen: st=%d err=%v", st, err)
	}

	// A removes the name. Because B holds the inode open, the authority parks it as an orphan.
	if st, err := cliA.Remove("shared"); err != nil || st != OK {
		t.Fatalf("remove: st=%d err=%v", st, err)
	}
	if _, st, _ := cliA.Getattr("shared"); st != ENOENT {
		t.Fatalf("name should be gone after the cross-mount remove, st=%d", st)
	}
	// B still reaches the bytes by ino — the cross-mount unlink became delete-on-last-close.
	got, st, err := cliB.ReadOrphan(ino, 0, 64)
	if err != nil || st != OK || string(got) != "peer-data" {
		t.Fatalf("peer read-by-ino after cross-mount remove = %q st=%d err=%v, want peer-data", got, st, err)
	}
	if st, err := cliB.UnmarkOpen(ino); err != nil || st != OK {
		t.Fatalf("unmarkopen: st=%d err=%v", st, err)
	}
}

// TestCrossMountRenameOverPeerOpenDestParks is the Stage-2 rename-over case: mount A renames src over
// dst that ONLY mount B holds open. A passes OrphanTarget=false (it has no local open dst node), but
// because B registered dst's inode open, the authority parks the replaced dst by ino anyway — B keeps
// reading the OLD dst bytes while the name resolves to src's content.
func TestCrossMountRenameOverPeerOpenDestParks(t *testing.T) {
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cliA, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliA.Close()
	cliA.SetOwner("A")

	cliB, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliB.Close()
	cliB.SetOwner("B")

	if _, st, err := cliA.Create("src", 0o644); err != nil || st != OK {
		t.Fatalf("create src: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Write("src", 0, []byte("replacement"), 0o644); err != nil || st != OK {
		t.Fatalf("write src: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Create("dst", 0o644); err != nil || st != OK {
		t.Fatalf("create dst: st=%d err=%v", st, err)
	}
	if _, st, err := cliA.Write("dst", 0, []byte("old-dst"), 0o644); err != nil || st != OK {
		t.Fatalf("write dst: st=%d err=%v", st, err)
	}
	// B opens dst (A does NOT hold dst open).
	a, st, err := cliB.Getattr("dst")
	if err != nil || st != OK || a.Ino == 0 {
		t.Fatalf("getattr dst: ino=%d st=%d err=%v", a.Ino, st, err)
	}
	dstIno := a.Ino
	if st, err := cliB.MarkOpen(dstIno); err != nil || st != OK {
		t.Fatalf("markopen: st=%d err=%v", st, err)
	}

	// A renames src over dst with OrphanTarget=FALSE (no local open dst node). Stage 2 parks the
	// replaced dst because B holds it open. (A is the remover; it does not need the parked ino — the
	// HOLDER B redirects via the Orphaned invalidation / ino re-derivation, so A's reply ino is moot.)
	if st, _, err := cliA.RenameWithOrphanTarget("src", "dst", false); err != nil || st != OK {
		t.Fatalf("rename-over: st=%d err=%v", st, err)
	}
	// The name now resolves to src's replacement content...
	if data, st, err := cliA.Read("dst", 0, 64); err != nil || st != OK || string(data) != "replacement" {
		t.Fatalf("dst name read = %q st=%d err=%v, want replacement", data, st, err)
	}
	// ...while B still reads the OLD dst by ino — proving the peer-open dest was parked, not dropped.
	if data, st, err := cliB.ReadOrphan(dstIno, 0, 64); err != nil || st != OK || string(data) != "old-dst" {
		t.Fatalf("peer read old dst by ino = %q st=%d err=%v, want old-dst", data, st, err)
	}
}

// TestSweeperKeepsOrphanHeldOpenViaOpenState: a holder that renews its OPEN-state (openInodes) but
// not the ORPHAN lease (it missed the Orphaned invalidation, so its node was never marked) must NOT
// have the orphan reaped out from under it — the sweeper re-arms an orphan any mount still holds open.
func TestSweeperKeepsOrphanHeldOpenViaOpenState(t *testing.T) {
	withProtocolOrphanLeaseTiming(t, 200*time.Millisecond, 10*time.Millisecond)
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)

	cliA, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliA.Close()
	cliA.SetOwner("A")
	cliB, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliB.Close()
	cliB.SetOwner("B")

	if _, st, _ := cliA.Create("f", 0o644); st != OK {
		t.Fatal("create")
	}
	if _, st, _ := cliA.Write("f", 0, []byte("held"), 0o644); st != OK {
		t.Fatal("write")
	}
	a, st, err := cliB.Getattr("f")
	if err != nil || st != OK || a.Ino == 0 {
		t.Fatalf("getattr: ino=%d st=%d err=%v", a.Ino, st, err)
	}
	ino := a.Ino
	if st, err := cliB.MarkOpen(ino); err != nil || st != OK {
		t.Fatalf("markopen: st=%d err=%v", st, err)
	}
	if st, err := cliA.Remove("f"); err != nil || st != OK {
		t.Fatalf("remove: st=%d err=%v", st, err) // parked because B holds it open
	}

	// B renews ONLY its open-state (NOT the orphan lease) well past the orphan TTL.
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		if st, err := cliB.RenewOpenInodes([]uint64{ino}); err != nil || st != OK {
			t.Fatalf("renew open: st=%d err=%v", st, err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	// The orphan must still exist — re-armed by the sweeper because B holds it open per open-state.
	got, st, err := cliB.ReadOrphan(ino, 0, 64)
	if err != nil || st != OK || string(got) != "held" {
		t.Fatalf("orphan held-open via open-state was reaped: read=%q st=%d err=%v", got, st, err)
	}
}

// TestRemoveOfUnopenedFileStillRemoves: with no open holder, remove removes (no spurious parking).
func TestRemoveOfUnopenedFileStillRemoves(t *testing.T) {
	fs, addr := serveFS(t)
	startOrphanSweeper(t, fs)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.SetOwner("A")
	if _, st, _ := cli.Create("f", 0o644); st != OK {
		t.Fatal("create")
	}
	if st, err := cli.Remove("f"); err != nil || st != OK {
		t.Fatalf("remove: st=%d err=%v", st, err)
	}
	if _, st, _ := cli.Getattr("f"); st != ENOENT {
		t.Fatalf("f should be gone, st=%d", st)
	}
}
