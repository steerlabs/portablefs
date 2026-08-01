package portablefsd

import (
	"context"
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// newMutationSeqAttach is a real daemon attach over a real volume with one
// delegated, open, writable file — the shape a refresh pass and an application
// write contend over. It deliberately does NOT saturate the credit lane: this
// suite is about the ORDER of two events, not about admission.
func newMutationSeqAttach(t *testing.T) (*attach, *clientcore.Volume, uint64, uint64) {
	t.Helper()
	authority, _ := serveAuthorityServer(t)
	ctx := context.Background()
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 4, Owner: "mutation-seq-holder",
		WALDir: privateTestDir(t), VolumeID: "mutation-seq-volume",
	})
	if err != nil {
		t.Fatalf("dial volume: %v", err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	if _, st := vol.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	if _, st := vol.Create(ctx, "d/f", 0o644); st != fsproto.OK {
		t.Fatalf("create d/f: %d", st)
	}
	attr, st := vol.Getattr(ctx, "d/f", nil)
	if st != fsproto.OK {
		t.Fatalf("getattr d/f: %d", st)
	}
	if !vol.Writeback().Covers("d/f") {
		t.Fatal("d/f is not delegated; the committed-but-unpublished window is not under test")
	}
	a := &attach{
		vol:                    vol,
		items:                  map[uint64]*itemRecord{},
		paths:                  map[string]*itemRecord{},
		itemAliases:            map[uint64]map[string]struct{}{},
		authorityItems:         map[uint64]frontendItemIdentity{},
		awaitingAuthorityItems: map[uint64]struct{}{},
		handles:                map[uint64]*handleRecord{},
		retiredCloseErrnos:     map[uint64]int32{},
		subscribers:            map[*eventSubscriber]struct{}{},
		localVersions:          map[string]uint64{},
	}
	const itemID, handleID = uint64(101), uint64(11)
	state := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
	if st := vol.Open(ctx, "d/f", state, true); st != fsproto.OK {
		t.Fatalf("open d/f: %d", st)
	}
	rec := a.bindTestRecord(&itemRecord{
		item:  pfslocal.Item{ItemID: itemID, ItemGeneration: 1},
		path:  "d/f",
		state: state,
		attr:  attr,
	})
	a.handles[handleID] = &handleRecord{
		id: handleID, itemID: rec.item.ItemID, path: "d/f", openPath: "d/f",
		state: state, write: true,
	}
	return a, vol, itemID, handleID
}

// TestRefreshCannotTruncateOverACommittedButUnpublishedWrite is finding 1, and
// it is the exact interleaving rather than an approximation of it.
//
// A refresh pass takes its authority sample — the real one, through the same
// helper the real pass uses — while the file is still S bytes. An application
// write then COMMITS an extension to N in the engine: the bytes are in the WAL,
// the count is decided, and the application is about to be told so. Only after
// that does the pass reach applyKernelRefresh, and it reaches it BEFORE
// writeReplyWithAttr has published N into the registry.
//
// Every proof the fence used to have says "nothing has happened": the composed
// size in itemRecord.attr is still S because nothing has written it yet, and the
// version floor has not moved because the extension is delegated and not
// authority-versioned. So the pass armed an Internal window and issued
// ftruncate(S) through the mount, shortening the kernel's vnode back over bytes
// the application had been told were durable.
//
// The mutation sequence is the witness the registry cannot be, and the pass must
// refuse.
func TestRefreshCannotTruncateOverACommittedButUnpublishedWrite(t *testing.T) {
	a, vol, itemID, handleID := newMutationSeqAttach(t)
	ctx := context.Background()

	// PHASE 1 of a refresh pass, taken before the write exists: sample the
	// authority and snapshot the composed size the registry currently holds.
	// These are precisely the values refreshKernelItemStateComposedModeContext
	// would carry into applyKernelRefresh.
	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{
		item: live.item, path: live.path, state: live.state,
		attr: live.attr, graft: live.graft,
	}
	a.mu.RUnlock()
	sampledSize, version, generation, outcome := refreshLocalSampleAuthorityContext(
		ctx, vol, "d/f", snapshot.state.AuthorityIno(),
	)
	if outcome != refreshSampleReady {
		t.Fatalf("pre-write authority sample outcome = %v", outcome)
	}
	if sampledSize != 0 {
		t.Fatalf("pre-write sample size = %d, want 0", sampledSize)
	}
	fence := refreshApplyFence{
		observedSize: snapshot.attr.Size,
		version:      version,
		generation:   generation,
	}

	var (
		truncatedTo  int64 = -1
		applied            = false
		refreshError error
	)
	a.testRefreshKernelFile = func(
		_ string, p string, _ uint64, size int64, arm func() (func(), error),
	) (kernelRefreshOutcome, error) {
		disarm, err := arm()
		if err != nil {
			return kernelRefreshRetry, err
		}
		defer disarm()
		truncatedTo = size
		return kernelRefreshApplied, nil
	}

	// PHASE 2 and 3, interleaved with the write exactly as the finding
	// describes: the pass resumes the instant the engine has committed and
	// before the reply's attributes are published.
	payload := []byte("an acknowledged delegated extension")
	a.testAfterWriteCommit = func() {
		outcome, err := a.applyKernelRefresh("/unused-test-mount", "d/f", snapshot, sampledSize, fence)
		applied = outcome == kernelRefreshApplied
		refreshError = err
	}

	reply, eno := admittedWrite(ctx, a, &pfslocal.WriteRequest{
		Handle: handleID, Offset: 0, Data: payload,
	})
	if eno != 0 {
		t.Fatalf("write: errno=%d", eno)
	}
	if int(reply.Written) != len(payload) {
		t.Fatalf("write reported %d of %d bytes", reply.Written, len(payload))
	}

	if applied {
		t.Fatalf(
			"a refresh pass carrying a pre-write sample applied a kernel truncate to %d "+
				"while a write of %d acknowledged bytes was committed and awaiting "+
				"publication: the kernel's vnode was shortened over durable data",
			truncatedTo, len(payload),
		)
	}
	var superseded *errRefreshSampleSuperseded
	if !errors.As(refreshError, &superseded) {
		t.Fatalf("refresh refused with %v, want a supersession retry", refreshError)
	}
	if truncatedTo != -1 {
		t.Fatalf("refresh issued ftruncate(%d) despite refusing", truncatedTo)
	}

	// And the refusal is transient, not a wedge: once the write has published,
	// the very next pass is admitted and converges on the committed size.
	if seq, open := a.itemMutations[itemID]; open {
		t.Fatalf("the write's mutation sequence stayed open after its reply: %+v", seq)
	}
	sampledSize, version, generation, outcome = refreshLocalSampleAuthorityContext(
		ctx, vol, "d/f", snapshot.state.AuthorityIno(),
	)
	if outcome != refreshSampleReady {
		t.Fatalf("post-write authority sample outcome = %v", outcome)
	}
	a.mu.RLock()
	live = a.items[itemID]
	after := &itemRecord{
		item: live.item, path: live.path, state: live.state,
		attr: live.attr, graft: live.graft,
	}
	a.mu.RUnlock()
	outcome2, err := a.applyKernelRefresh("/unused-test-mount", "d/f", after, sampledSize, refreshApplyFence{
		observedSize: after.attr.Size, version: version, generation: generation,
	})
	if outcome2 != kernelRefreshApplied {
		t.Fatalf("the post-publication refresh was refused too (%v, %v): the fence is a wedge, not a fence", outcome2, err)
	}
	if truncatedTo != int64(len(payload)) {
		t.Fatalf("the post-publication refresh applied size %d, want %d", truncatedTo, len(payload))
	}
}

// TestMutationSequenceBracketsEveryConcurrentWriterOnOneItem is why the
// sequence is a PAIR and not a flag. Two descriptors on one inode overlap; a
// witness that the first writer to publish could clear on its own would declare
// the item stable while the second is still between its commit and its
// publication, which is the whole state being excluded.
func TestMutationSequenceBracketsEveryConcurrentWriterOnOneItem(t *testing.T) {
	a := &attach{}
	const item = uint64(7)

	if a.itemMutationInFlightLocked(item) {
		t.Fatal("an untouched item reported a mutation in flight")
	}
	settleFirst := a.beginItemMutation(item)
	settleSecond := a.beginItemMutation(item)
	if !a.itemMutationInFlightLocked(item) {
		t.Fatal("two open mutations reported nothing in flight")
	}
	settleFirst(true)
	if !a.itemMutationInFlightLocked(item) {
		t.Fatal("one writer's publication cleared the other writer's open commit")
	}
	settleFirst(true) // idempotent: a double settle must not close the survivor
	if !a.itemMutationInFlightLocked(item) {
		t.Fatal("a repeated settle closed a sequence it did not own")
	}
	settleSecond(true)
	if a.itemMutationInFlightLocked(item) {
		t.Fatal("the item stayed unstable after every writer published")
	}
	if len(a.itemMutations) != 0 {
		t.Fatalf("the unstable-item set retained a settled entry: %+v", a.itemMutations)
	}
	if got := a.beginItemMutation(0); got == nil {
		t.Fatal("an unnamed item must still return a settle")
	}
}

// TestSettlingWithoutPublishingRetainsADefiniteUnstableVerdict is the half of
// the bracket that a bare defer could never express.
//
// A handler reaching its settle proves it got to the publication STEP, not that
// it published: the post-op attribute refresh is optional and its failure is
// answered with the committed count on purpose. Closing the sequence there
// declares stable an item whose registry is provably behind its own commit, and
// the next refresh arms on that stale sample. So an unpublished settle retains
// the verdict, and only a real publication clears it.
func TestSettlingWithoutPublishingRetainsADefiniteUnstableVerdict(t *testing.T) {
	a := &attach{}
	const item = uint64(21)

	settle := a.beginItemMutation(item)
	settle(false)
	if !a.itemMutationInFlightLocked(item) {
		t.Fatal("a commit that never published its post-op state closed the item's " +
			"mutation sequence: the registry still holds the pre-write size and the " +
			"next refresh will arm on it and truncate over committed bytes")
	}

	// Another settle is not a publication and must not clear it either.
	second := a.beginItemMutation(item)
	second(true)
	if !a.itemMutationInFlightLocked(item) {
		t.Fatal("a later writer's publication cleared an unpublished commit's verdict")
	}

	// The ordered repair: the next publisher that states this item's attributes.
	a.mu.Lock()
	a.notePublicationLocked(item)
	a.mu.Unlock()
	if a.itemMutationInFlightLocked(item) {
		t.Fatal("the item stayed unstable after its attributes were published")
	}
	if len(a.itemMutations) != 0 {
		t.Fatalf("the unstable-item set retained a repaired entry: %+v", a.itemMutations)
	}
}

// TestRefreshRefusesToArmWhileASizeMutationIsUnpublished pins the fence arm
// itself, independently of any handler: the window that would issue the
// ftruncate must not open at all.
func TestRefreshRefusesToArmWhileASizeMutationIsUnpublished(t *testing.T) {
	a := &attach{
		items:       map[uint64]*itemRecord{},
		paths:       map[string]*itemRecord{},
		itemAliases: map[uint64]map[string]struct{}{},
	}
	rec := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 9, ItemGeneration: 1},
		path: "d/f",
		attr: fsproto.Attr{Kind: "file", Size: 4},
	})
	fence := refreshApplyFence{observedSize: 4}
	snapshot := &itemRecord{item: rec.item, path: rec.path, attr: rec.attr}

	if _, _, err := a.armRefreshWindowLocked("d/f", snapshot, 4, fence); err != nil {
		t.Fatalf("a stable item refused to arm: %v", err)
	}
	a.mu.Lock()
	a.beginItemMutationLocked(9)
	a.mu.Unlock()
	disarm, _, err := a.armRefreshWindowLocked("d/f", snapshot, 4, fence)
	if err == nil {
		disarm()
		t.Fatal("a refresh armed a truncate window over an unpublished size mutation")
	}
	var superseded *errRefreshSampleSuperseded
	if !errors.As(err, &superseded) {
		t.Fatalf("arm refused with %v, want a supersession retry", err)
	}
	a.mu.Lock()
	a.settleItemMutationLocked(9, true)
	a.mu.Unlock()
	if _, _, err := a.armRefreshWindowLocked("d/f", snapshot, 4, fence); err != nil {
		t.Fatalf("the item stayed fenced after its mutation published: %v", err)
	}
}
