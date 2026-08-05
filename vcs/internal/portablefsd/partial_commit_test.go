package portablefsd

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDINGS 2 AND 3 (ROUND 12): A COMPOUND OPERATION'S PARTIAL COMMIT ───────
//
// Round 11 taught every handler to publish the size its commit decided even
// when the steps AFTER the commit failed. Both of the operations here are
// COMPOUND — two or three ordered mutations under one call — and for them the
// failure is not after the commit, it is BETWEEN the commits. The call returns
// one error for the whole thing, the earlier mutation has already landed at the
// authority, and reading the commit off the status records nothing at all.
//
//	setattr:       size first, metadata second (clientcore.Volume.Setattr).
//	control write: bytes first, truncate second (attach.controlWriteLocked).
//
// So each carries its committed outcome out separately from its status, and the
// carrier is recorded before the status is inspected.

// partialCommitFixture is a daemon attach over one delegated and one
// write-through file — the two lanes a setattr splits across — with no credit
// occupied: this suite is about what a failure records, not about admission.
type partialCommitFixture struct {
	a   *attach
	vol *clientcore.Volume
}

const (
	partialDelegatedPath    = "d/f"
	partialWriteThroughPath = "wt/g"
	partialDelegatedItem    = uint64(201)
	partialWriteThroughItem = uint64(202)
	partialDelegatedHandle  = uint64(21)
	partialWriteThruHandle  = uint64(22)
)

func newPartialCommitFixture(t *testing.T) *partialCommitFixture {
	t.Helper()
	authority, _ := serveAuthorityServer(t)
	ctx := context.Background()

	// A peer mount creates the write-through target and leaves, so nothing here
	// delegates it and its setattr resolves the authority lane.
	peer, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 2, Owner: "partial-commit-peer",
		WALDir: privateTestDir(t) + "/peer-wal", VolumeID: "partial-commit-volume",
	})
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	if _, st := peer.Mkdir(ctx, "wt", 0o755); st != fsproto.OK {
		t.Fatalf("peer mkdir wt: %d", st)
	}
	if _, st := peer.Create(ctx, partialWriteThroughPath, 0o644); st != fsproto.OK {
		t.Fatalf("peer create %s: %d", partialWriteThroughPath, st)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}

	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 4, Owner: "partial-commit-holder",
		WALDir: privateTestDir(t) + "/wal", VolumeID: "partial-commit-volume",
	})
	if err != nil {
		t.Fatalf("dial volume: %v", err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	if _, st := vol.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	if _, st := vol.Create(ctx, partialDelegatedPath, 0o644); st != fsproto.OK {
		t.Fatalf("create %s: %d", partialDelegatedPath, st)
	}
	if !vol.Writeback().Covers(partialDelegatedPath) {
		t.Fatalf("%s is not delegated; the delegated arm is not under test", partialDelegatedPath)
	}
	if vol.Writeback().Covers(partialWriteThroughPath) {
		t.Fatalf("%s is delegated; the authority arm is not under test", partialWriteThroughPath)
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
	bind := func(path string, id, handle uint64) {
		attr, st := vol.Getattr(ctx, path, nil)
		if st != fsproto.OK {
			t.Fatalf("getattr %s: %d", path, st)
		}
		state := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
		if st := vol.Open(ctx, path, state, true); st != fsproto.OK {
			t.Fatalf("open %s: %d", path, st)
		}
		rec := a.bindTestRecord(&itemRecord{
			item:  pfslocal.Item{ItemID: id, ItemGeneration: 1},
			path:  path,
			state: state,
			attr:  attr,
		})
		a.handles[handle] = &handleRecord{
			id: handle, itemID: rec.item.ItemID, path: path, openPath: path,
			state: state, write: true,
		}
	}
	bind(partialDelegatedPath, partialDelegatedItem, partialDelegatedHandle)
	bind(partialWriteThroughPath, partialWriteThroughItem, partialWriteThruHandle)
	return &partialCommitFixture{a: a, vol: vol}
}

// admittedSetattr runs one setattr the way the DISPATCHER runs it: the complete
// pre-lock admission first — which is where the provenance verdict is frozen and
// where a size mutation takes its item token — then the locked handler.
func admittedSetattr(
	ctx context.Context,
	a *attach,
	req *pfslocal.SetAttrRequest,
) (*pfslocal.SetAttrReply, int32) {
	ctx, cancel := clientcore.WithOperationDeadline(ctx)
	defer cancel()
	for forceAuthority := false; ; forceAuthority = true {
		opCtx, settle, eno, classified := a.admitRequest(ctx, req, forceAuthority)
		if eno != 0 {
			settle()
			return nil, eno
		}
		reply, eno := a.setattr(opCtx, req)
		settle()
		if eno != errnoLaneChanged || !classified {
			return reply, eno
		}
	}
}

// TestSetattrPublishesATruncateItCommittedBeforeAFailedMetadataGroup is finding
// 2 on the DELEGATED arm.
//
// A multi-field setattr applies the size first and the metadata second. The
// truncate commits in the engine; the metadata group then fails; Volume.Setattr
// returns only the error. The handler used to read its commit off that status —
// so it recorded nothing, the deferred settlement reported published=true, and
// the registry kept the PRE-truncate size while the engine held the new one. The
// next refresh armed on that sample.
func TestSetattrPublishesATruncateItCommittedBeforeAFailedMetadataGroup(t *testing.T) {
	f := newPartialCommitFixture(t)
	f.vol.SetSetattrFaultForTest(clientcore.SetattrFaultMetadata, fsproto.EIO)

	size := uint64(4096)
	mode := uint32(0o600)
	reply, eno := admittedSetattr(context.Background(), f.a, &pfslocal.SetAttrRequest{
		Item: pfslocal.Item{ItemID: partialDelegatedItem, ItemGeneration: 1},
		Size: &size, Mode: &mode,
	})
	if eno == 0 {
		t.Fatalf("the setattr reported success (%+v) despite a failed metadata group", reply)
	}

	f.a.mu.RLock()
	published := f.a.items[partialDelegatedItem].attr.Size
	unstable := f.a.itemMutationInFlightLocked(partialDelegatedItem)
	f.a.mu.RUnlock()
	if published != int64(size) {
		t.Fatalf("the registry holds size %d after a truncate to %d that COMMITTED: "+
			"the setattr returned only its error, so the committed size was never "+
			"recorded and the item settled over the pre-truncate view", published, size)
	}
	if unstable {
		t.Fatal("the item stayed unstable after its committed size was published")
	}
}

// TestSetattrPublishesATruncateItCommittedOnTheAuthorityArm is the same finding
// on the write-through lane, where the two groups are two independently
// exact-once authority records rather than two engine operations.
func TestSetattrPublishesATruncateItCommittedOnTheAuthorityArm(t *testing.T) {
	f := newPartialCommitFixture(t)
	f.vol.SetSetattrFaultForTest(clientcore.SetattrFaultMetadata, fsproto.EIO)

	size := uint64(1234)
	mode := uint32(0o640)
	if _, eno := admittedSetattr(context.Background(), f.a, &pfslocal.SetAttrRequest{
		Item: pfslocal.Item{ItemID: partialWriteThroughItem, ItemGeneration: 1},
		Size: &size, Mode: &mode,
	}); eno == 0 {
		t.Fatal("the setattr reported success despite a failed metadata group")
	}

	f.a.mu.RLock()
	published := f.a.items[partialWriteThroughItem].attr.Size
	unstable := f.a.itemMutationInFlightLocked(partialWriteThroughItem)
	f.a.mu.RUnlock()
	if published != int64(size) {
		t.Fatalf("the registry holds size %d after an authority truncate to %d that "+
			"COMMITTED", published, size)
	}
	if unstable {
		t.Fatal("the item stayed unstable after its committed size was published")
	}
}

// TestSetattrOutcomeCarriesTheCommittedSizeOnEveryArm pins the clientcore half
// directly, including the exact-handle arm the frontend reaches for a detached
// descriptor and the orphan arm it reaches for a parked last link.
func TestSetattrOutcomeCarriesTheCommittedSizeOnEveryArm(t *testing.T) {
	f := newPartialCommitFixture(t)
	ctx := context.Background()
	f.vol.SetSetattrFaultForTest(clientcore.SetattrFaultMetadata, fsproto.EIO)

	req := clientcore.SetattrRequest{
		Size: 777, SetSize: true, Mode: 0o600, SetMode: true,
	}
	for _, arm := range []struct {
		name string
		run  func(n *clientcore.NodeState) (clientcore.SetattrOutcome, clientcore.Status)
	}{
		{"delegated", func(n *clientcore.NodeState) (clientcore.SetattrOutcome, clientcore.Status) {
			_, out, st := f.vol.SetattrCommitted(ctx, partialDelegatedPath, n, req)
			return out, st
		}},
		{"authority", func(n *clientcore.NodeState) (clientcore.SetattrOutcome, clientcore.Status) {
			_, out, st := f.vol.SetattrCommitted(ctx, partialWriteThroughPath, n, req)
			return out, st
		}},
		{"exact-handle", func(n *clientcore.NodeState) (clientcore.SetattrOutcome, clientcore.Status) {
			_, out, st := f.vol.SetattrExactHandleCommitted(ctx, n, req)
			return out, st
		}},
	} {
		item := partialDelegatedItem
		if arm.name == "authority" {
			item = partialWriteThroughItem
		}
		f.a.mu.RLock()
		n := f.a.items[item].state
		f.a.mu.RUnlock()
		out, st := arm.run(n)
		if st == fsproto.OK {
			t.Fatalf("%s: the setattr succeeded despite a failed metadata group", arm.name)
		}
		if !out.SizeCommitted || out.Size != req.Size {
			t.Fatalf("%s: outcome = %+v after a truncate to %d that committed: a caller "+
				"holding only the status has no way to learn the size changed",
				arm.name, out, req.Size)
		}
	}
}

// TestControlWriteThatFailsItsTruncatePublishesTheCommittedBytes is finding 3.
//
// A control replacement is TWO mutations: vol.Write commits at offset 0, and the
// following size-set cuts whatever the old contents left behind. When the second
// fails, the first has already happened — and the handler used to call the
// compatibility Volume.Write wrapper, discard its WriteOutcome, and record a
// commit only after the SECOND op succeeded. commit.published stayed its initial
// true, the sequence closed over the pre-write registry size, and the HTTP error
// skipped the kernel refresh that would otherwise have converged it.
func TestControlWriteThatFailsItsTruncatePublishesTheCommittedBytes(t *testing.T) {
	a, vol, _, _ := newMutationSeqAttach(t)
	a.mountPath = t.TempDir()
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }

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

	// The truncate half fails; the bytes are already in the WAL by then.
	vol.SetSetattrFaultForTest(clientcore.SetattrFaultSize, fsproto.EIO)

	payload := []byte("bytes committed by a control write whose truncate failed")
	body := strings.NewReader(`{"path":"d/control","dataBase64":"` +
		base64.StdEncoding.EncodeToString(payload) + `"}`)
	req := httptest.NewRequest("POST", "/fs/write", body)
	w := httptest.NewRecorder()
	(&Server{}).controlFSWrite(w, req, a)
	if w.Code < 400 {
		t.Fatalf("control write status = %d, want a failure (%s)", w.Code, w.Body.String())
	}

	a.mu.RLock()
	published := a.items[itemID].attr.Size
	unstable := a.itemMutationInFlightLocked(itemID)
	a.mu.RUnlock()
	if published < int64(len(payload)) {
		t.Fatalf("the registry holds size %d after a control write that COMMITTED %d "+
			"bytes and then failed its truncate: the first mutation's progress was "+
			"discarded with the compatibility wrapper's outcome, so the item settled "+
			"over the pre-write size", published, len(payload))
	}
	if unstable {
		t.Fatal("the control write left its item permanently unstable despite publishing " +
			"the size floor its committed bytes prove")
	}
}

// TestGraftControlWriteThatFailsItsStatPublishesTheCommittedSize is finding 3's
// graft arm.
//
// The old shape was one os.WriteFile — which opens O_TRUNC, so any failure after
// the open left the host inode at ZERO with nothing recorded — followed by a
// stat that can fail on its own terms and returned an errno for a size change
// that had really happened. Neither had a bracket, and neither published
// anything, so the registry kept the pre-write size for an inode the host had
// already replaced.
func TestGraftControlWriteThatFailsItsStatPublishesTheCommittedSize(t *testing.T) {
	a := newAttach("att-graft-partial", "key", ensureAttachRequest{
		VolumeID:  "vol-graft-partial",
		Branch:    "main",
		MountPath: "/Volumes/GraftPartial",
		Options:   AttachOptions{LocalDirs: []string{"cache"}},
	}, graftTestDir(t))
	if _, err := a.addLocalDirs([]string{"cache"}); err != nil {
		t.Fatal(err)
	}
	itemID, eno := a.writeLocalFile("cache/f", "cache", []byte("original contents"))
	if eno != 0 {
		t.Fatalf("seed graft file: errno=%d", eno)
	}
	a.mu.RLock()
	seeded := a.items[itemID].attr.Size
	a.mu.RUnlock()
	if seeded != int64(len("original contents")) {
		t.Fatalf("seeded registry size = %d", seeded)
	}

	// The stat that follows the host commit fails: the name is gone by the time
	// it runs. That is an ordinary race with a concurrent remove, and it is the
	// exact instant at which the registry is behind the host inode.
	replacement := []byte("a replacement whose stat never lands")
	a.testAfterLocalFileWrite = func(p string) {
		a.testAfterLocalFileWrite = nil
		if err := os.Remove(a.localRoot + "/" + p); err != nil {
			t.Errorf("remove the graft backing mid-write: %v", err)
		}
	}
	if _, eno := a.writeLocalFile("cache/f", "cache", replacement); eno == 0 {
		t.Fatal("the graft write reported success despite a failed stat")
	}

	a.mu.RLock()
	published := a.items[itemID].attr.Size
	unstable := a.itemMutationInFlightLocked(itemID)
	a.mu.RUnlock()
	if published != int64(len(replacement)) {
		t.Fatalf("the registry holds size %d after a graft replacement that COMMITTED "+
			"%d bytes to the host inode: the write's own committed size was never "+
			"recorded, so the next refresh arms on a sample the host has moved past",
			published, len(replacement))
	}
	if unstable {
		t.Fatal("the graft write left its item permanently unstable despite publishing")
	}
}

// TestGraftControlWriteNeverTruncatesBeforeItWrites is the ordering half of the
// same fix: a replacement that fails must not have destroyed the old contents on
// its way to failing. os.WriteFile's O_TRUNC did exactly that.
func TestGraftControlWriteNeverTruncatesBeforeItWrites(t *testing.T) {
	a := newAttach("att-graft-order", "key", ensureAttachRequest{
		VolumeID:  "vol-graft-order",
		Branch:    "main",
		MountPath: "/Volumes/GraftOrder",
		Options:   AttachOptions{LocalDirs: []string{"cache"}},
	}, graftTestDir(t))
	if _, err := a.addLocalDirs([]string{"cache"}); err != nil {
		t.Fatal(err)
	}
	original := []byte("the contents a failed replacement must not destroy")
	if _, eno := a.writeLocalFile("cache/f", "cache", original); eno != 0 {
		t.Fatalf("seed graft file: errno=%d", eno)
	}
	commit := &setattrCommit{published: true}
	// A zero-length payload is the worst case for the old order: O_TRUNC alone
	// was the whole mutation, so a failure between the open and the write left
	// nothing at all.
	if eno := a.replaceLocalFileContents("cache/f", []byte("short"), commit); eno != 0 {
		t.Fatalf("replace: errno=%d", eno)
	}
	if !commit.sizeKnown || commit.floor || commit.size != 5 {
		t.Fatalf("a completed replacement recorded %+v, want the exact size 5", commit)
	}
	data, err := os.ReadFile(a.localRoot + "/cache/f")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "short" {
		t.Fatalf("host contents = %q, want the replacement exactly (the trailing bytes "+
			"of the longer original must be cut by the truncate)", data)
	}
}

// TestSetattrOutcomeSurvivesTheExactRetryHandoff pins the one place the outcome
// could be dropped in transit: SetattrOpenHandle re-runs the whole request
// against the exact handle when the pathname arm answers statusExactRetry, and
// a truncate that already landed on the first arm is committed regardless.
func TestSetattrOutcomeSurvivesTheExactRetryHandoff(t *testing.T) {
	f := newPartialCommitFixture(t)
	ctx := context.Background()
	f.a.mu.RLock()
	n := f.a.items[partialDelegatedItem].state
	f.a.mu.RUnlock()

	_, out, st := f.vol.SetattrOpenHandleCommitted(ctx, partialDelegatedPath, n,
		clientcore.SetattrRequest{Size: 88, SetSize: true})
	if st != fsproto.OK {
		t.Fatalf("setattr: %d", st)
	}
	if !out.SizeCommitted || out.Size != 88 {
		t.Fatalf("outcome = %+v, want a committed size of 88", out)
	}

	// And an empty path routes straight to the exact-handle arm, which reports
	// its own commit through the same carrier.
	_, out, st = f.vol.SetattrOpenHandleCommitted(ctx, "", n,
		clientcore.SetattrRequest{Size: 99, SetSize: true})
	if st != fsproto.OK {
		t.Fatalf("exact setattr: %d", st)
	}
	if !out.SizeCommitted || out.Size != 99 {
		t.Fatalf("exact-handle outcome = %+v, want a committed size of 99", out)
	}
}
