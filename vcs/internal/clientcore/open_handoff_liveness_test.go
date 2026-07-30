package clientcore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

type gatedUnmarkRegistrar struct {
	OpenRegistrar

	entered     chan struct{}
	gate        chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newGatedUnmarkRegistrar(reg OpenRegistrar) *gatedUnmarkRegistrar {
	return &gatedUnmarkRegistrar{
		OpenRegistrar: reg,
		entered:       make(chan struct{}),
		gate:          make(chan struct{}),
	}
}

func (r *gatedUnmarkRegistrar) wait() {
	r.enteredOnce.Do(func() { close(r.entered) })
	<-r.gate
}

func (r *gatedUnmarkRegistrar) release() {
	r.releaseOnce.Do(func() { close(r.gate) })
}

func (r *gatedUnmarkRegistrar) UnmarkOpen(ino uint64) (int32, error) {
	r.wait()
	return r.OpenRegistrar.UnmarkOpen(ino)
}

func (r *gatedUnmarkRegistrar) UnmarkOpenBatch(inos []uint64) (int32, error) {
	r.wait()
	return r.OpenRegistrar.UnmarkOpenBatch(inos)
}

func assertClosedPreparedInodeRetired(t *testing.T, v *Volume, ino uint64) {
	t.Helper()
	if ino == 0 {
		t.Fatal("closed prepare snapshot did not retain its proven authority identity")
	}
	if v.openFiles.Contains(ino) {
		t.Fatalf("closed prepared inode %d remains in the renewal set", ino)
	}
	if v.openOrphans.Contains(ino) {
		t.Fatalf("closed prepared inode %d remains in the orphan renewal set", ino)
	}
	v.openReg.mu.Lock()
	_, registered := v.openReg.entries[ino]
	v.openReg.mu.Unlock()
	if registered {
		t.Fatalf("closed prepared inode %d remains in the open registry", ino)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, st, err := v.client.GetattrOrphan(ino)
		if err != nil {
			t.Fatalf("getattr retired prepared inode %d: %v", ino, err)
		}
		if st == fsproto.ENOENT {
			break
		}
		if st != fsproto.OK || time.Now().After(deadline) {
			t.Fatalf("closed prepared inode %d survived reap: status=%d", ino, st)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Renewal registers absent holds, so exercise the real renewal path and
	// prove the retired inode cannot be recreated from stale local state.
	v.renewOpenInodes(nil)
	if v.openFiles.Contains(ino) {
		t.Fatalf("renewal recreated closed prepared inode %d", ino)
	}
	v.openReg.mu.Lock()
	_, registered = v.openReg.entries[ino]
	v.openReg.mu.Unlock()
	if registered {
		t.Fatalf("renewal recreated open-registry entry for inode %d", ino)
	}
	if _, st, err := v.client.GetattrOrphan(ino); err != nil || st != fsproto.ENOENT {
		t.Fatalf("renewal recreated parked inode %d: status=%d err=%v", ino, st, err)
	}
}

func TestRemoveCloseDuringPrepareOrdersPinRetirementBeforeDestroy(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCore(t, addr, Options{
		Owner: "remove-close-during-prepare", VolumeID: "remove-close-during-prepare",
		Branch: "main", WALDir: t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if a.Ino != 0 || !v.wb.Covers("d/held") {
		t.Fatalf("precondition: create was not locally born under a delegation: ino=%d", a.Ino)
	}
	held := NewNodeState(InoOf("d/held"), false)
	if st := v.Open(ctx, "d/held", held, true); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	if _, st := v.Write(ctx, "d/held", held, 0, []byte("remove")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	unmark := newGatedUnmarkRegistrar(v.client)
	v.openReg.reg = unmark
	t.Cleanup(unmark.release)
	checkinApplied := make(chan struct{})
	checkinGate := make(chan struct{})
	var checkinOnce sync.Once
	server.SetDropReply(func(req *fsproto.Request, _ *fsproto.Response) bool {
		if req.Op == fsproto.OpCheckin {
			checkinOnce.Do(func() {
				close(checkinApplied)
				<-checkinGate
			})
		}
		return false
	})

	removeOut := make(chan Status, 1)
	go func() { removeOut <- v.Remove(ctx, "d/held", held) }()
	select {
	case <-checkinApplied:
	case <-time.After(2 * time.Second):
		t.Fatal("remove did not finish delegation prepare")
	}
	if st := v.CloseHandle("d/held", held); st != fsproto.OK {
		t.Fatalf("close during prepared handoff: %d", st)
	}
	close(checkinGate)
	select {
	case <-unmark.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final remove decision did not retire the closed prepared pin")
	}
	select {
	case st := <-removeOut:
		t.Fatalf("remove crossed its blocked prepared-pin retirement: %d", st)
	case <-time.After(50 * time.Millisecond):
	}

	unmark.release()
	select {
	case st := <-removeOut:
		if st != fsproto.OK {
			t.Fatalf("remove: %d", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remove did not resume after prepared-pin retirement")
	}
	assertClosedPreparedInodeRetired(t, v, held.AuthorityIno())
}

func TestRenameOverCloseDuringPrepareOrdersPinRetirementBeforeDestroy(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCore(t, addr, Options{
		Owner: "rename-close-during-prepare", VolumeID: "rename-close-during-prepare",
		Branch: "main", WALDir: t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	srcAttr, st := v.Create(ctx, "d/src", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create src: %d", st)
	}
	dstAttr, st := v.Create(ctx, "d/dst", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create dst: %d", st)
	}
	if srcAttr.Ino != 0 || dstAttr.Ino != 0 || !v.wb.Covers("d/src") || !v.wb.Covers("d/dst") {
		t.Fatalf(
			"precondition: rename files were not locally born under one delegation: src=%d dst=%d",
			srcAttr.Ino,
			dstAttr.Ino,
		)
	}
	src := NewNodeState(InoOf("d/src"), false)
	dst := NewNodeState(InoOf("d/dst"), false)
	if st := v.Open(ctx, "d/dst", dst, true); st != fsproto.OK {
		t.Fatalf("open dst: %d", st)
	}
	if _, st := v.Write(ctx, "d/src", src, 0, []byte("source")); st != fsproto.OK {
		t.Fatalf("write src: %d", st)
	}
	if _, st := v.Write(ctx, "d/dst", dst, 0, []byte("destination")); st != fsproto.OK {
		t.Fatalf("write dst: %d", st)
	}

	unmark := newGatedUnmarkRegistrar(v.client)
	v.openReg.reg = unmark
	t.Cleanup(unmark.release)
	checkinApplied := make(chan struct{})
	checkinGate := make(chan struct{})
	var checkinOnce sync.Once
	server.SetDropReply(func(req *fsproto.Request, _ *fsproto.Response) bool {
		if req.Op == fsproto.OpCheckin {
			checkinOnce.Do(func() {
				close(checkinApplied)
				<-checkinGate
			})
		}
		return false
	})

	renameOut := make(chan Status, 1)
	go func() { renameOut <- v.Rename(ctx, "d/src", "d/dst", src, dst) }()
	select {
	case <-checkinApplied:
	case <-time.After(2 * time.Second):
		t.Fatal("rename-over did not finish delegation prepare")
	}
	if st := v.CloseHandle("d/dst", dst); st != fsproto.OK {
		t.Fatalf("close destination during prepared handoff: %d", st)
	}
	close(checkinGate)
	select {
	case <-unmark.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final rename-over decision did not retire the closed prepared pin")
	}
	select {
	case st := <-renameOut:
		t.Fatalf("rename-over crossed its blocked prepared-pin retirement: %d", st)
	case <-time.After(50 * time.Millisecond):
	}

	unmark.release()
	select {
	case st := <-renameOut:
		if st != fsproto.OK {
			t.Fatalf("rename-over: %d", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rename-over did not resume after prepared-pin retirement")
	}
	assertClosedPreparedInodeRetired(t, v, dst.AuthorityIno())
	if _, st := v.Lookup(ctx, "d/src"); st != fsproto.ENOENT {
		t.Fatalf("rename source still exists: %d", st)
	}
	if _, st := v.Lookup(ctx, "d/dst"); st != fsproto.OK {
		t.Fatalf("rename destination missing: %d", st)
	}
}

func TestOpenHandoffResolvesMultipleLostPrepareReplies(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCore(t, addr, Options{
		Owner: "handoff-lost-prepare", VolumeID: "handoff-lost-prepare",
		Branch: "main", WALDir: t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create held: %d", st)
	}
	if !v.wb.Covers("d/held") {
		t.Fatal("precondition: create did not acquire a delegation")
	}
	held := NewNodeState(InoOf("d/held"), a.Ino != 0)
	if st := v.Open(ctx, "d/held", held, true); st != fsproto.OK {
		t.Fatalf("open held: %d", st)
	}
	if _, st := v.Write(ctx, "d/held", held, 0, []byte("durable")); st != fsproto.OK {
		t.Fatalf("write held: %d", st)
	}

	const lostReplies = 3
	var dropMu sync.Mutex
	dropped := 0
	server.SetDropReply(func(req *fsproto.Request, _ *fsproto.Response) bool {
		dropMu.Lock()
		defer dropMu.Unlock()
		if req.Op == fsproto.OpDelegationPrepareRelease && dropped < lostReplies {
			dropped++
			return true
		}
		return false
	})

	releaseOut := make(chan error, 1)
	go func() { releaseOut <- v.wb.ReleaseFor(ctx, "d/held") }()
	select {
	case err := <-releaseOut:
		if err != nil {
			t.Fatalf("release did not resolve committed prepare: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("release did not resolve consecutive lost prepare replies")
	}
	dropMu.Lock()
	gotDropped := dropped
	dropMu.Unlock()
	if gotDropped != lostReplies {
		t.Fatalf("dropped prepare replies = %d, want %d", gotDropped, lostReplies)
	}
	ino := held.AuthorityIno()
	if ino == 0 {
		t.Fatal("resolved prepare did not publish the committed inode identity")
	}

	// The adopted pin must enter the ordinary registry lifecycle. Last close
	// retains one known hold; this mount's following name mutation synchronously
	// retires it, so the unlink destroys rather than parks the inode. If any
	// lost-reply prepare remained unknown or accumulated, the orphan would
	// still exist after this remove.
	if st := v.CloseHandle("d/held", held); st != fsproto.OK {
		t.Fatalf("close held: %d", st)
	}
	if st := v.Remove(ctx, "d/held", held); st != fsproto.OK {
		t.Fatalf("remove after resolved prepare: %d", st)
	}
	if _, st, err := v.client.GetattrOrphan(ino); err != nil || st != fsproto.ENOENT {
		t.Fatalf("retired prepare pin left inode parked: status=%d err=%v", st, err)
	}
}

func TestOpenHandoffKeepsCloseAndUnrelatedOpenResponsive(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCore(t, addr, Options{
		Owner: "handoff-liveness", VolumeID: "handoff-liveness",
		Branch: "main", WALDir: t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	heldAttr, st := v.Create(ctx, "d/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create held: %d", st)
	}
	queuedAttr, st := v.Create(ctx, "d/queued", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create queued: %d", st)
	}
	outsideAttr, st := v.Create(ctx, "outside", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create outside: %d", st)
	}
	held := NewNodeState(InoOf("d/held"), heldAttr.Ino != 0)
	queued := NewNodeState(InoOf("d/queued"), queuedAttr.Ino != 0)
	outside := NewNodeState(outsideAttr.Ino, outsideAttr.Ino != 0)
	if st := v.Open(ctx, "d/held", held, true); st != fsproto.OK {
		t.Fatalf("open held: %d", st)
	}
	if _, st := v.Write(ctx, "d/held", held, 0, []byte("held")); st != fsproto.OK {
		t.Fatalf("write held: %d", st)
	}

	prepareEntered := make(chan struct{})
	prepareGate := make(chan struct{})
	server.SetBeforeDelegationPrepare(func() {
		select {
		case <-prepareEntered:
		default:
			close(prepareEntered)
		}
		<-prepareGate
	})
	releaseOut := make(chan error, 1)
	go func() { releaseOut <- v.wb.ReleaseFor(ctx, "d/held") }()
	select {
	case <-prepareEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("release did not reach the authority pin")
	}

	queuedOut := make(chan Status, 1)
	go func() { queuedOut <- v.Open(ctx, "d/queued", queued, false) }()
	select {
	case st := <-queuedOut:
		t.Fatalf("same-scope open crossed the handoff barrier: %d", st)
	case <-time.After(50 * time.Millisecond):
	}

	closeOut := make(chan Status, 1)
	go func() { closeOut <- v.CloseHandle("d/held", held) }()
	select {
	case st := <-closeOut:
		if st != fsproto.OK {
			t.Fatalf("close during pin: %d", st)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked behind authority pin I/O")
	}

	outsideOut := make(chan Status, 1)
	go func() { outsideOut <- v.Open(ctx, "outside", outside, false) }()
	select {
	case st := <-outsideOut:
		if st != fsproto.OK {
			t.Fatalf("unrelated open: %d", st)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated open blocked behind subtree handoff")
	}
	v.CloseHandle("outside", outside)

	close(prepareGate)
	select {
	case err := <-releaseOut:
		if err != nil {
			t.Fatalf("release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("release did not finish after pin unblocked")
	}
	// The close won before the prepare reply was adopted. The frozen
	// snapshot still has to publish its proven authority identity so its
	// prepared pin can be found and retired synchronously by any immediately
	// following name mutation.
	closedIno := held.AuthorityIno()
	if closedIno == 0 {
		t.Fatal("close-before-prepare-reply lost the proven authority identity")
	}
	v.openReg.ReleaseNameChange("d/held", closedIno)
	if v.openFiles.Contains(closedIno) {
		t.Fatalf("closed prepared inode %d remains in renewal set", closedIno)
	}
	v.openReg.mu.Lock()
	_, closedRegistered := v.openReg.entries[closedIno]
	v.openReg.mu.Unlock()
	if closedRegistered {
		t.Fatalf("closed prepared inode %d remains in registry", closedIno)
	}
	v.renewOpenInodes(nil)
	if v.openFiles.Contains(closedIno) {
		t.Fatalf("renewal recreated closed prepared inode %d", closedIno)
	}
	select {
	case st := <-queuedOut:
		if st != fsproto.OK {
			t.Fatalf("queued open after release: %d", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("same-scope open did not resume after release")
	}
	if queued.AuthorityIno() == 0 {
		t.Fatal("barrier-woken open returned without a shared-mode authority pin")
	}
	v.CloseHandle("d/queued", queued)

	if got := v.opens.releasePinCount(); got != 0 {
		t.Fatalf("close-during-pin leaked %d tracker release pins", got)
	}
}

func TestOpenHandoffWaitsForPreBarrierOpenReservation(t *testing.T) {
	tracker := NewOpenTracker()
	node := NewNodeState(1, true)
	if _, err := tracker.Inc(context.Background(), "d/opening", node); err != nil {
		t.Fatalf("reserve open: %v", err)
	}

	guardOut := make(chan *OpenReleaseGuard, 1)
	errOut := make(chan error, 1)
	go func() {
		guard, err := tracker.BeginRelease(context.Background(), "d")
		guardOut <- guard
		errOut <- err
	}()
	select {
	case <-guardOut:
		t.Fatal("handoff snapshotted an open before its registration completed")
	case <-time.After(50 * time.Millisecond):
	}

	tracker.FinishInc("d/opening", node, true, true)
	var guard *OpenReleaseGuard
	select {
	case guard = <-guardOut:
	case <-time.After(time.Second):
		t.Fatal("handoff did not resume after open registration completed")
	}
	if err := <-errOut; err != nil {
		t.Fatalf("begin release: %v", err)
	}
	if got := len(guard.Snapshots()); got != 1 {
		t.Fatalf("handoff snapshots = %d, want 1 completed open", got)
	}
	guard.End(false)
}

func TestPreparedPinAdoptsRefsWhenAuthorityIdentityAppearsAfterSnapshot(t *testing.T) {
	tracker := NewOpenTracker()
	node := NewNodeState(1, false)
	if _, err := tracker.Inc(context.Background(), "d/file", node); err != nil {
		t.Fatalf("reserve open: %v", err)
	}
	tracker.FinishInc("d/file", node, true, false)
	guard, err := tracker.BeginRelease(context.Background(), "d")
	if err != nil {
		t.Fatalf("begin release: %v", err)
	}
	defer guard.End(false)
	if !node.RecordAuthorityIno(42) {
		t.Fatal("publish authority identity")
	}
	adoptedRefs := 0
	active, err := guard.AdoptPreparedPin(
		guard.Snapshots()[0], 42, 7,
		func(_ string, ino uint64, refs int, gen uint64) error {
			if ino != 42 || gen != 7 {
				t.Fatalf("adopt mapping ino=%d gen=%d", ino, gen)
			}
			adoptedRefs += refs
			return nil
		},
	)
	if err != nil || !active || adoptedRefs != 1 {
		t.Fatalf("adopt active=%v refs=%d err=%v", active, adoptedRefs, err)
	}
}

func TestPreparedPinBackfillsOnlyUnregisteredLiveHandles(t *testing.T) {
	tracker := NewOpenTracker()
	node := NewNodeState(1, false)
	if _, err := tracker.Inc(context.Background(), "d/file", node); err != nil {
		t.Fatalf("reserve locally-born open: %v", err)
	}
	tracker.FinishInc("d/file", node, true, false)
	if !node.RecordAuthorityIno(42) {
		t.Fatal("publish authority identity")
	}
	if _, err := tracker.Inc(context.Background(), "d/file", node); err != nil {
		t.Fatalf("reserve shared-mode open: %v", err)
	}
	tracker.FinishInc("d/file", node, true, true)

	guard, err := tracker.BeginRelease(context.Background(), "d")
	if err != nil {
		t.Fatalf("begin release: %v", err)
	}
	defer guard.End(false)
	snapshot := guard.Snapshots()[0]
	if !guard.NeedsPreparedPin(snapshot) {
		t.Fatal("one unregistered live handle was incorrectly treated as pinned")
	}
	adoptedRefs := 0
	active, err := guard.AdoptPreparedPin(
		snapshot, 42, 7,
		func(_ string, _ uint64, refs int, _ uint64) error {
			adoptedRefs += refs
			return nil
		},
	)
	if err != nil || !active || adoptedRefs != 1 {
		t.Fatalf("backfill active=%v refs=%d err=%v, want one missing ref", active, adoptedRefs, err)
	}
	if guard.NeedsPreparedPin(snapshot) {
		t.Fatal("prepared backfill did not cover every live handle")
	}
}

func TestCloseKeepsPartialOwnerRegistrationUntilFinalHandle(t *testing.T) {
	tracker := NewOpenTracker()
	node := NewNodeState(1, false)
	if _, err := tracker.Inc(context.Background(), "d/file", node); err != nil {
		t.Fatalf("reserve locally-born open: %v", err)
	}
	tracker.FinishInc("d/file", node, true, false)
	if _, err := tracker.Inc(context.Background(), "d/file", node); err != nil {
		t.Fatalf("reserve registered open: %v", err)
	}
	tracker.FinishInc("d/file", node, true, true)

	remaining, _, found, closeRegistered, _, _ := tracker.Dec("d/file", node)
	if !found || remaining != 1 {
		t.Fatalf("first close: found=%v remaining=%d, want one live handle", found, remaining)
	}
	if closeRegistered {
		t.Fatal("first close retired the owner's only authority ref while a handle remained")
	}
	remaining, _, found, closeRegistered, _, _ = tracker.Dec("d/file", node)
	if !found || remaining != 0 {
		t.Fatalf("final close: found=%v remaining=%d", found, remaining)
	}
	if !closeRegistered {
		t.Fatal("final close did not retire the owner's authority ref")
	}
}

func TestAnonymousOpenQueuedBehindReleaseReusesPreparedPin(t *testing.T) {
	tracker := NewOpenTracker()
	if _, err := tracker.Inc(context.Background(), "d/file", nil); err != nil {
		t.Fatalf("reserve first open: %v", err)
	}
	tracker.FinishInc("d/file", nil, true, false)
	guard, err := tracker.BeginRelease(context.Background(), "d")
	if err != nil {
		t.Fatalf("begin release: %v", err)
	}
	adoptCalls := 0
	if active, err := guard.AdoptPreparedPin(
		guard.Snapshots()[0], 42, 7,
		func(_ string, _ uint64, refs int, _ uint64) error {
			adoptCalls += refs
			return nil
		},
	); err != nil || !active {
		t.Fatalf("adopt first anonymous pin: active=%v err=%v", active, err)
	}
	queued := make(chan error, 1)
	go func() {
		_, err := tracker.Inc(context.Background(), "d/file", nil)
		queued <- err
	}()
	select {
	case <-queued:
		t.Fatal("second anonymous open crossed release barrier")
	case <-time.After(50 * time.Millisecond):
	}
	guard.End(true)
	if err := <-queued; err != nil {
		t.Fatalf("queued anonymous open: %v", err)
	}
	if ino, ok := tracker.AnonymousPin("d/file"); !ok || ino != 42 {
		t.Fatalf("queued open lost shared tracker pin: ino=%d present=%v", ino, ok)
	}
	if adoptCalls != 1 {
		t.Fatalf("anonymous tracker pin adopted %d refs, want one shared ref", adoptCalls)
	}
	tracker.FinishInc("d/file", nil, true, false)
}

func TestConcurrentAnonymousPinJoinOwnsExactlyOneRegistryRef(t *testing.T) {
	const opens = 32
	tracker := NewOpenTracker()
	for i := 0; i < opens; i++ {
		if _, err := tracker.Inc(context.Background(), "d/file", nil); err != nil {
			t.Fatalf("reserve anonymous open %d: %v", i, err)
		}
		tracker.FinishInc("d/file", nil, true, false)
	}

	start := make(chan struct{})
	results := make(chan [2]bool, opens)
	for i := 0; i < opens; i++ {
		go func() {
			<-start
			installed, ok := tracker.InstallOrJoinAnonymousPin("d/file", 42)
			results <- [2]bool{installed, ok}
		}()
	}
	close(start)

	installed := 0
	for i := 0; i < opens; i++ {
		result := <-results
		if !result[1] {
			t.Fatalf("anonymous join %d rejected the common inode", i)
		}
		if result[0] {
			installed++
		}
	}
	if installed != 1 {
		t.Fatalf("tracker accepted %d registry refs, want exactly one", installed)
	}
	if ino, ok := tracker.AnonymousPin("d/file"); !ok || ino != 42 {
		t.Fatalf("shared anonymous pin: ino=%d present=%v", ino, ok)
	}
}

func TestRecallDoesNotDeadlockWriteHoldingNodeState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Volume, context.Context, *NodeState) Status
	}{
		{
			name: "write",
			mutate: func(v *Volume, ctx context.Context, n *NodeState) Status {
				_, st := v.Write(ctx, "d/held", n, 0, []byte("write"))
				return st
			},
		},
		{
			name: "append",
			mutate: func(v *Volume, ctx context.Context, n *NodeState) Status {
				_, st := v.WriteAppend(ctx, "d/held", n, 0, []byte("append"))
				return st
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			addr, server := serveCoreServer(t)
			v := dialCore(t, addr, Options{
				Owner:    "recall-node-lock-" + tc.name,
				VolumeID: "recall-node-lock-" + tc.name,
				Branch:   "main", WALDir: t.TempDir(),
			})
			if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
				t.Fatalf("mkdir: %d", st)
			}
			a, st := v.Create(ctx, "d/held", 0o644)
			if st != fsproto.OK {
				t.Fatalf("create: %d", st)
			}
			n := NewNodeState(InoOf("d/held"), a.Ino != 0)
			if st := v.Open(ctx, "d/held", n, true); st != fsproto.OK {
				t.Fatalf("open: %d", st)
			}
			t.Cleanup(func() { v.CloseHandle("d/held", n) })

			prepareEntered := make(chan struct{})
			prepareGate := make(chan struct{})
			server.SetBeforeDelegationPrepare(func() {
				select {
				case <-prepareEntered:
				default:
					close(prepareEntered)
				}
				<-prepareGate
			})
			releaseOut := make(chan error, 1)
			go func() { releaseOut <- v.wb.ReleaseFor(ctx, "d/held") }()
			select {
			case <-prepareEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("release did not reach open-pin preparation")
			}

			mutationOut := make(chan Status, 1)
			go func() { mutationOut <- tc.mutate(v, ctx, n) }()
			select {
			case st := <-mutationOut:
				t.Fatalf("mutation crossed draining delegation: %d", st)
			case <-time.After(50 * time.Millisecond):
			}

			close(prepareGate)
			select {
			case err := <-releaseOut:
				if err != nil {
					t.Fatalf("release: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("release deadlocked on NodeState held by waiting mutation")
			}
			select {
			case st := <-mutationOut:
				if st != fsproto.OK {
					t.Fatalf("mutation after release: %d", st)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("mutation did not resume after release")
			}
		})
	}
}

func TestDelegatedMultiOpenRemainsPinnedUntilLastClose(t *testing.T) {
	ctx := context.Background()
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner: "multi-open-handoff", VolumeID: "multi-open-handoff",
		Branch: "main", WALDir: t.TempDir(),
	})
	watchInvalidationsForTest(t, v)
	peer := dialCore(t, addr, Options{Owner: "multi-open-peer"})

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(InoOf("d/held"), a.Ino != 0)
	if st := v.Open(ctx, "d/held", n, true); st != fsproto.OK {
		t.Fatalf("first open: %d", st)
	}
	if st := v.Open(ctx, "d/held", n, true); st != fsproto.OK {
		t.Fatalf("second open: %d", st)
	}
	if _, st := v.Write(ctx, "d/held", n, 0, []byte("survives-one-close")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if st := peer.Remove(ctx, "d/held", nil); st != fsproto.OK {
		t.Fatalf("peer remove: %d", st)
	}
	ino := n.AuthorityIno()
	if ino == 0 || !n.MarkOrphan(ino, v.OpenOrphans()) {
		t.Fatalf("handoff did not bind parked authority inode: %d", ino)
	}

	if st := v.CloseHandle("d/held", n); st != fsproto.OK {
		t.Fatalf("first close: %d", st)
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		data, st := v.Read(ctx, "d/held", n, 0, 64)
		if st != fsproto.OK || string(data) != "survives-one-close" {
			t.Fatalf("remaining handle lost after first close: data=%q status=%d", data, st)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if st := v.CloseHandle("d/held", n); st != fsproto.OK {
		t.Fatalf("last close: %d", st)
	}
	awaitOrphanGone(t, v.client, ino, "multi-open inode was not reaped after final close")
}
