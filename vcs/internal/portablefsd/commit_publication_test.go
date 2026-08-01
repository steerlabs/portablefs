package portablefsd

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 1 (ROUND 11): A SEQUENCE MUST NOT SETTLE WITHOUT PUBLISHING ──────
//
// Round 10 bracketed every size mutation with a per-item sequence so a refresh
// pass could see the gap between a commit and its publication. The bracket was
// a bare defer, and a bare defer records that the handler REACHED its
// publication step — never that it published.
//
// Both mutation paths deliberately treat the post-op attribute refresh as
// OPTIONAL, and they are right to: the committed count is the application's
// only chance to learn its bytes are durable, so a transient failure after the
// commit must not be reported as "this write did nothing" (attach.writeReply).
// The consequence was that on exactly that path the registry kept the PRE-write
// size, the deferred settle closed the sequence anyway, and the very next
// refresh — whose whole fence is "itemRecord.attr.Size has not moved since I
// sampled" — armed on the stale sample and issued ftruncate(S) over bytes the
// application had already been told were durable.
//
// The commit itself knows what to publish. clientcore.WriteOutcome carries the
// post-op size the committing lane decided, vol.Setattr's reply IS the post-op
// stat, and a positional write proves the floor off+n on its own. So the
// publication happens before the settle, and the settle carries its verdict.

// TestWriteWithAFailedAttrRefreshStillPublishesItsCommittedSize is the write
// path's exact interleaving.
//
// A refresh pass takes its sample while the file is empty. A write of N bytes
// commits in the engine. Its OPTIONAL post-op attribute refresh then fails —
// here because a concurrent close(2) retired the descriptor's node state, which
// makes GetattrOpenHandle answer ENOENT, and which is an entirely ordinary race
// between a write reply and a close on another descriptor. The reply still
// reports the committed count, as it must. What must ALSO happen is that the
// registry stops holding zero.
func TestWriteWithAFailedAttrRefreshStillPublishesItsCommittedSize(t *testing.T) {
	a, vol, itemID, handleID := newMutationSeqAttach(t)
	ctx := context.Background()

	// Phase 1 of a refresh pass, taken before the write exists.
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

	// Break the OPTIONAL attribute refresh at the one instant the registry is
	// provably behind the engine.
	state := a.handles[handleID].state
	a.testAfterWriteCommit = func() {
		a.testAfterWriteCommit = nil
		if st := vol.CloseHandle("d/f", state); st != fsproto.OK {
			t.Errorf("retire the descriptor mid-reply: %d", st)
		}
	}

	payload := []byte("an acknowledged delegated extension")
	reply, eno := admittedWrite(ctx, a, &pfslocal.WriteRequest{
		Handle: handleID, Offset: 0, Data: payload,
	})
	if eno != 0 {
		t.Fatalf("write: errno=%d", eno)
	}
	// The round-2 contract is unchanged: committed bytes are always reported.
	if int(reply.Written) != len(payload) {
		t.Fatalf("write reported %d of %d bytes: a failed attribute refresh must "+
			"never retract a committed count", reply.Written, len(payload))
	}

	a.mu.RLock()
	published := a.items[itemID].attr.Size
	a.mu.RUnlock()
	if published != int64(len(payload)) {
		t.Fatalf("the registry holds size %d after a write of %d committed bytes: "+
			"the commit's own post-op size was never published, so the refresh fence "+
			"reads a size that has not moved and concludes nothing happened",
			published, len(payload))
	}

	// THE PROPERTY, stated as the fence states it: a pass carrying the pre-write
	// sample must be refused rather than allowed to truncate the kernel's vnode
	// back over the committed bytes.
	truncatedTo := int64(-1)
	a.testRefreshKernelFile = func(
		_ string, _ string, _ uint64, size int64, arm func() (func(), error),
	) (kernelRefreshOutcome, error) {
		disarm, err := arm()
		if err != nil {
			return kernelRefreshRetry, err
		}
		defer disarm()
		truncatedTo = size
		return kernelRefreshApplied, nil
	}
	applied, err := a.applyKernelRefresh("/unused-test-mount", "d/f", snapshot, sampledSize, fence)
	if applied == kernelRefreshApplied {
		t.Fatalf("a refresh carrying the pre-write sample truncated the kernel's vnode "+
			"to %d over %d committed bytes: the handler settled the item's mutation "+
			"sequence without ever publishing what it committed",
			truncatedTo, len(payload))
	}
	var superseded *errRefreshSampleSuperseded
	if !errors.As(err, &superseded) {
		t.Fatalf("refresh refused with %v, want a supersession retry", err)
	}
}

// TestWriteThatCannotPublishAtAllStaysDefinitelyUnstable is the residue: the
// handle's item is not in the registry at all, so there is nothing to publish
// into and the commit's post-op size has nowhere to go.
//
// The answer is not to pretend the item settled. It is to RETAIN the unstable
// verdict — refreshes for that item are refused, which is an ordinary retry
// outcome — until a publication repairs it.
func TestWriteThatCannotPublishAtAllStaysDefinitelyUnstable(t *testing.T) {
	a, vol, itemID, handleID := newMutationSeqAttach(t)
	ctx := context.Background()

	state := a.handles[handleID].state
	a.testAfterWriteCommit = func() {
		a.testAfterWriteCommit = nil
		if st := vol.CloseHandle("d/f", state); st != fsproto.OK {
			t.Errorf("retire the descriptor mid-reply: %d", st)
		}
		// And the item itself leaves the registry: a reclaim landing in the same
		// gap. There is now no record for the commit to publish into.
		a.mu.Lock()
		delete(a.items, itemID)
		delete(a.paths, "d/f")
		a.mu.Unlock()
	}

	payload := []byte("committed with nowhere to publish")
	reply, eno := admittedWrite(ctx, a, &pfslocal.WriteRequest{
		Handle: handleID, Offset: 0, Data: payload,
	})
	if eno != 0 {
		t.Fatalf("write: errno=%d", eno)
	}
	if int(reply.Written) != len(payload) {
		t.Fatalf("write reported %d of %d bytes", reply.Written, len(payload))
	}
	a.mu.RLock()
	unstable := a.itemMutationInFlightLocked(itemID)
	a.mu.RUnlock()
	if !unstable {
		t.Fatal("a commit that could not publish anywhere declared its item stable: " +
			"the fence's own witness now says a mutation it cannot see never happened")
	}
}

// TestControlWriteWithAFailedAttrRefreshPublishesTheCommittedSize is the same
// defect on the control plane, which the finding names separately because its
// shape is different: the SUCCESSFUL Setattr's reply — which carries the post-op
// attributes at the mutation's own ordered apply position — was discarded
// outright, and the pre-write lookup attributes were retained and registered
// whenever the optional trailing getattr failed.
func TestControlWriteWithAFailedAttrRefreshPublishesTheCommittedSize(t *testing.T) {
	a, vol, _, _ := newMutationSeqAttach(t)
	a.mountPath = t.TempDir()
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }
	a.testControlWriteRefreshFails = func() bool { return true }

	// The name exists and is registered, so the control write brackets it.
	if _, st := vol.Create(context.Background(), "d/control", 0o644); st != fsproto.OK {
		t.Fatalf("create d/control: %d", st)
	}
	attr, st := vol.Getattr(context.Background(), "d/control", nil)
	if st != fsproto.OK {
		t.Fatalf("getattr d/control: %d", st)
	}
	rec, _ := a.registerOwned("d/control", attr)
	if rec == nil {
		t.Fatal("register d/control")
	}
	itemID := rec.item.ItemID

	body := strings.NewReader(`{"path":"d/control","dataBase64":"YWJjZGVmZ2hpag=="}`)
	req := httptest.NewRequest("POST", "/fs/write", body)
	w := httptest.NewRecorder()
	(&Server{}).controlFSWrite(w, req, a)
	if w.Code != 204 {
		t.Fatalf("control write status = %d (%s)", w.Code, w.Body.String())
	}

	a.mu.RLock()
	size := a.items[itemID].attr.Size
	unstable := a.itemMutationInFlightLocked(itemID)
	a.mu.RUnlock()
	if size != 10 {
		t.Fatalf("the registry holds size %d after a control write of 10 committed "+
			"bytes: the committing Setattr's own post-op reply was discarded, so the "+
			"only publication left was an optional getattr and the item settled over "+
			"the PRE-write attributes", size)
	}
	if unstable {
		t.Fatal("the control write left its item permanently unstable despite publishing")
	}
}

// TestWriteOutcomeCarriesTheCommittedSize pins the clientcore half: the count
// alone was never enough for a caller that keeps its own attribute store, and
// an append's offset is deliberately never computed by a frontend.
func TestWriteOutcomeCarriesTheCommittedSize(t *testing.T) {
	authority, _ := serveAuthorityServer(t)
	ctx := context.Background()
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 4, Owner: "write-outcome",
		WALDir: privateTestDir(t), VolumeID: "write-outcome-volume",
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
	state := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
	if st := vol.Open(ctx, "d/f", state, true); st != fsproto.OK {
		t.Fatalf("open d/f: %d", st)
	}

	out, st := vol.WriteOpenHandleCommitted(ctx, "d/f", state, 0, []byte("hello"))
	if st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if out.Count != 5 || !out.SizeKnown || out.Size != 5 {
		t.Fatalf("positional write outcome = %+v, want count 5 and a stated size of 5", out)
	}

	out, st = vol.WriteAppendOpenHandleCommitted(ctx, "d/f", state, []byte(" world"))
	if st != fsproto.OK {
		t.Fatalf("append: %d", st)
	}
	if out.Count != 6 || !out.SizeKnown || out.Size != 11 {
		t.Fatalf("append outcome = %+v, want count 6 and a stated size of 11: the "+
			"frontend cannot compute an append's offset, so the lane that resolved it "+
			"is the only thing that can state the resulting size", out)
	}
}
