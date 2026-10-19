package portablefsd

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// cachedV3Fixture is a data plane on a controlled clock whose authority is
// the versioned fake namespace, with a live cache horizon.
type cachedV3Fixture struct {
	t      *testing.T
	client *fakeV3DataClient
	ns     *v3TestNamespace
	clock  *fakeV3Clock
	d      *v3DataPlane
	root   pfslocal.Item
}

func newCachedV3Fixture(t *testing.T, objects map[byte]*v3TestObject) *cachedV3Fixture {
	t.Helper()
	client := newFakeV3DataClient()
	ns := newV3TestNamespace(client, objects)
	clock := newFakeV3Clock()
	d := testV3DataPlaneWithClock(t, client, clock)
	if v3Horizon(d) == 0 {
		t.Fatal("fixture has no cache horizon")
	}
	return &cachedV3Fixture{t: t, client: client, ns: ns, clock: clock, d: d, root: d.resolveReply().Root}
}

// authorityCalls counts the filesystem requests that reached the fake
// authority. Release traffic (Reclaim, CloseBatch) is asynchronous ownership
// cleanup, not an answer to a read, so it is not counted.
func (f *cachedV3Fixture) authorityCalls() int {
	f.client.mu.Lock()
	defer f.client.mu.Unlock()
	calls := f.client.readCalls
	for _, request := range f.client.mutations {
		if request.GetReclaim() == nil && request.GetCloseBatch() == nil {
			calls++
		}
	}
	return calls
}

func (f *cachedV3Fixture) dispatch(body any) (any, int32) {
	f.t.Helper()
	return dispatchV3Test(f.d, context.Background(), 0, body)
}

func (f *cachedV3Fixture) lookup(dir pfslocal.Item, name string) pfslocal.Attr {
	f.t.Helper()
	return lookupTestAttr(f.t, f.d, dir, name)
}

func (f *cachedV3Fixture) getattr(item pfslocal.Item) pfslocal.Attr {
	f.t.Helper()
	return getattrTestAttr(f.t, f.d, item, 0)
}

func (f *cachedV3Fixture) record(item pfslocal.Item) *v3ItemRecord {
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	return f.d.itemsByID[item.ItemID]
}

// requireServedLocally runs body and requires that it never reached the
// authority.
func (f *cachedV3Fixture) requireServedLocally(what string, body func()) {
	f.t.Helper()
	before := f.authorityCalls()
	body()
	if after := f.authorityCalls(); after != before {
		f.t.Fatalf("%s reached the authority %d time(s), want a local hit", what, after-before)
	}
}

func (f *cachedV3Fixture) requireAuthority(what string, body func()) {
	f.t.Helper()
	before := f.authorityCalls()
	body()
	if after := f.authorityCalls(); after == before {
		f.t.Fatalf("%s was served locally, want the authority path", what)
	}
}

func v3FileObjects() map[byte]*v3TestObject {
	return map[byte]*v3TestObject{
		0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
		0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 1, size: 3},
	}
}

// GetAttr and positive and negative Lookup are answered locally once their
// coherent samples are cached under a live horizon; a positive hit mints no
// authority capability and hands out exactly one provisional item.
func TestV3CacheServesAttrAndNamesLocally(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root) // first coherent fill of the root
	file := f.lookup(f.root, "file")
	f.requireServedLocally("GetAttr", func() {
		if attr := f.getattr(file.Item); attr.Size != 3 || attr.ParentFileID != v3RootFileID {
			t.Fatalf("cached attr = %+v", attr)
		}
	})
	live := f.client.liveTokens()
	f.requireServedLocally("positive Lookup", func() {
		collector := &v3ReplyResourceCollector{d: f.d}
		reply, errno := f.d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0,
			&pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")})
		if errno != 0 || reply.(*pfslocal.LookupReply).Attr.Item != file.Item {
			t.Fatalf("cached lookup = (%#v,%d)", reply, errno)
		}
		if len(collector.items) != 1 || collector.items[0].provisional != 1 || collector.cached == nil {
			t.Fatalf("cached lookup collected %d items, want one provisional item", len(collector.items))
		}
		resources, err := f.d.prepareReplyResources(collector)
		if err != nil {
			t.Fatal(err)
		}
		if cleanup, err := f.d.applyReplyResourceDisposition(resources, false, 1); err != nil || cleanup.required() {
			t.Fatalf("accept = (%+v,%v)", cleanup, err)
		}
	})
	if f.client.liveTokens() != live {
		t.Fatal("a cached lookup minted an authority capability")
	}
	if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("absent")}); errno != darwinENOENT {
		t.Fatalf("negative lookup errno=%d", errno)
	}
	f.requireServedLocally("negative Lookup", func() {
		if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("absent")}); errno != darwinENOENT {
			t.Fatalf("cached negative lookup errno=%d", errno)
		}
	})
}

// The activation root seeds nothing: its first GetAttr goes to the
// authority, and only that coherent fill makes the root cacheable.
func TestV3CacheRootIsFilledByItsFirstCoherentGetAttr(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.requireAuthority("first root GetAttr", func() { f.getattr(f.root) })
	f.requireServedLocally("second root GetAttr", func() { f.getattr(f.root) })
}

// No hit without a usable horizon: after the continuous clock passes H (a
// sleep longer than the promise), reads take the authority path; a fresh
// renewal restores eligibility for the same live session.
func TestV3CacheHorizonExpiryAndSleepForceTheAuthorityPath(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	f.requireServedLocally("GetAttr inside H", func() { f.getattr(file.Item) })
	f.clock.advance(10 * time.Minute) // host slept past the proof
	f.requireAuthority("GetAttr after H", func() { f.getattr(file.Item) })
	if f.d.terminalError() != nil {
		t.Fatal("horizon expiry alone ended the session")
	}
	if err := f.d.renewHorizon(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.requireServedLocally("GetAttr after renewal", func() { f.getattr(file.Item) })
}

// Immediate client poison closes hit admission before any public terminal
// signal, and the signed deadline is an additional local denial.
func TestV3CacheHitsStopAtImmediatePoisonAndTheAuthorizationDeadline(t *testing.T) {
	t.Run("poison", func(t *testing.T) {
		f := newCachedV3Fixture(t, v3FileObjects())
		f.ns.bind(0x20, "file", 0x70)
		file := f.lookup(f.root, "file")
		f.client.poisoned.Store(true)
		// No hit is served; the authority path is refused by the poisoned
		// session itself and the data plane ends.
		if _, errno := f.dispatch(&pfslocal.GetAttrRequest{Item: file.Item}); errno == 0 || f.d.terminalError() == nil {
			t.Fatalf("GetAttr on a poisoned session = %d terminal=%v, want a terminal refusal", errno, f.d.terminalError())
		}
	})
	t.Run("authorization-deadline", func(t *testing.T) {
		f := newCachedV3Fixture(t, v3FileObjects())
		f.ns.bind(0x20, "file", 0x70)
		file := f.lookup(f.root, "file")
		f.d.mu.Lock()
		f.d.authorizationDeadline = time.Now().Add(-time.Second)
		f.d.mu.Unlock()
		f.requireAuthority("GetAttr past the signed deadline", func() { f.getattr(file.Item) })
	})
	t.Run("terminal", func(t *testing.T) {
		f := newCachedV3Fixture(t, v3FileObjects())
		f.ns.bind(0x20, "file", 0x70)
		file := f.lookup(f.root, "file")
		record := f.record(file.Item)
		_ = f.d.stopServing(errors.New("frontend lost"))
		d := f.d
		d.bridge.sourcePublication.cacheRead(func(conflict v3CacheConflict) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if _, reason := d.attrHitLocked(conflict, record, nil); reason == v3CacheHit {
				t.Fatal("a terminal data plane admitted a hit")
			}
		})
	})
}

// A hit is atomic with source acquisition: a held coordinate or any
// unresolved post-binding claim, including one owned by the same callback,
// sends the read to the authority.
func TestV3CacheHitsYieldToSourceHoldsAndUnresolvedClaims(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	file := f.lookup(f.root, "file")
	coordinator := f.d.bridge.sourcePublication

	hold := func(operationID uint64, gate *v3SourceGate) func() {
		coordinator.reserve(testCallback(operationID))
		if _, err := coordinator.acquireSource(context.Background(), testCallback(operationID), gate); err != nil {
			t.Fatal(err)
		}
		return func() {
			if _, err := coordinator.acknowledge(testCallback(operationID), pfslocal.PublicationSemanticCommitPublished); err != nil {
				t.Fatal(err)
			}
			coordinator.retire(testCallback(operationID))
		}
	}
	itemGate, err := v3ItemSourceGate(file.Item, true)
	if err != nil {
		t.Fatal(err)
	}
	release := hold(9101, itemGate)
	f.requireAuthority("GetAttr under a write hold", func() { f.getattr(file.Item) })
	release()
	f.requireServedLocally("GetAttr after release", func() { f.getattr(file.Item) })

	// An unrelated create's unresolved claim could bind any identity.
	createGate, err := v3NamespaceSourceGate(f.root, []byte("other"), false)
	if err != nil {
		t.Fatal(err)
	}
	release = hold(9102, createGate)
	f.requireAuthority("GetAttr under an unresolved claim", func() { f.getattr(file.Item) })
	f.requireAuthority("Lookup under an unresolved claim", func() { f.lookup(f.root, "file") })
	release()
	f.requireServedLocally("Lookup after release", func() { f.lookup(f.root, "file") })

	// A claim owned by the very callback asking is still a conflict: its own
	// in-flight request may already have committed.
	const sameCallback = uint64(9103)
	release = hold(sameCallback, itemGate)
	f.requireAuthority("GetAttr under the same callback's hold", func() {
		if _, errno := dispatchV3Owned(f.d, context.Background(), sameCallback, &pfslocal.GetAttrRequest{Item: file.Item}); errno != 0 {
			t.Fatalf("getattr errno=%d", errno)
		}
	})
	release()
}

// The r2 counterexample: a Lookup of an unheld X samples s=5; an unlink of X
// commits and its REMOVED PostState is processed while X is unheld; then the
// old Lookup reply arrives. Capability adoption succeeds, but neither the
// stale attrs (nlink=1) nor the stale name may become servable.
func TestV3CacheColdFloorRejectsAnOldLookupOfAnUnheldIdentity(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.getattr(f.root)
	d := f.d
	rootRecord := f.record(f.root)
	d.mu.Lock()
	rootRecord.watermark = 4
	d.mu.Unlock()
	removal := &v3MutationEffect{snapshot: 7,
		objects: []v3Observation{
			{identity: [16]byte(testV3ID(0x20)), attr: testV3DirAttr(1, 2), version: 7},
			{identity: [16]byte(testV3ID(0x70)), attr: testV3FileAttr(7, 3, 0), version: 7},
		},
		names: []v3NameEffect{{parent: rootRecord, name: "x"}},
	}
	if err := d.applyMutation(removal); err != nil {
		t.Fatal(err)
	}
	// The old Lookup reply (sampled at 5, before the unlink) arrives now.
	stale := testV3StampedItem(f.client.issueItem(7, authoritypb.Attr_REGULAR, 0x70).GetToken(), 0x70, testV3FileAttr(7, 3, 1), 3, 5)
	collector := &v3ReplyResourceCollector{d: d}
	record, errno := d.intern(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), stale)
	if errno != 0 {
		t.Fatalf("adopting the returned capability failed: %d", errno)
	}
	d.mu.Lock()
	if err := d.observeLocked(record, stale.GetAttr(), stale.GetObjectVersion(), stale.GetSnapshotSequence()); err != nil {
		t.Fatal(err)
	}
	d.fillLookupLocked(rootRecord, "x", record, stale.GetSnapshotSequence())
	valid, snapshot := record.valid, record.snapshot
	positive := rootRecord.children["x"]
	_, negative := rootRecord.negatives["x"]
	d.mu.Unlock()
	if valid || snapshot != 7 {
		t.Fatalf("stale attrs became servable: valid=%t floor=%d", valid, snapshot)
	}
	if positive != nil || !negative {
		t.Fatalf("stale name filled: positive=%v negative=%t, want the newer absence kept", positive, negative)
	}
}

// Reclaim never lowers the cold floor: a relookup's fresh record cannot adopt
// a sample older than a mutation already processed.
func TestV3CacheColdFloorSurvivesReclaimAndRelookup(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	if _, errno := f.dispatch(&pfslocal.ReclaimRequest{Item: file.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	// A mutation elsewhere advances the floor.
	if err := f.d.applyMutation(&v3MutationEffect{snapshot: 9, objects: []v3Observation{
		{identity: [16]byte(testV3ID(0x50)), attr: testV3DirAttr(5, 2), version: 9},
	}}); err != nil {
		t.Fatal(err)
	}
	relookup := f.lookup(f.root, "file") // the fake authority still answers at snapshot 1
	record := f.record(relookup.Item)
	f.d.mu.Lock()
	valid, floor := record.valid, record.snapshot
	f.d.mu.Unlock()
	if relookup.Item.ItemID == file.Item.ItemID || valid || floor != 9 {
		t.Fatalf("relookup record id=%d valid=%t floor=%d, want a fresh invalid record at the floor", relookup.Item.ItemID, valid, floor)
	}
}

// Attribute ordering for reads and mutations alike, delivered in every
// order: the newest object version wins, an older one is discarded without a
// fence, and an equal version must agree logically.
func TestV3CacheAttributeOrderingAcrossDeliveryOrders(t *testing.T) {
	sample := func(size int64, nlink uint32, blocks uint64) *authoritypb.Attr {
		attr := testV3FileAttr(7, size, nlink)
		attr.Blocks = blocks
		return attr
	}
	type delivery struct {
		attr              *authoritypb.Attr
		version, snapshot uint64
	}
	for _, test := range []struct {
		name       string
		deliveries []delivery
		wantSize   int64
		wantNlink  uint32
		wantBlocks uint64
		terminal   bool
	}{
		// unlink(P,a->X) commits v7 (nlink 0, size 0); write(X) commits v8.
		{name: "unlink-then-write", deliveries: []delivery{{sample(0, 0, 0), 7, 7}, {sample(4096, 0, 8), 8, 8}}, wantSize: 4096, wantBlocks: 8},
		{name: "write-then-delayed-unlink", deliveries: []delivery{{sample(4096, 0, 8), 8, 8}, {sample(0, 0, 0), 7, 7}}, wantSize: 4096, wantBlocks: 8},
		// Same-callback writes committed in one order, applied in the other.
		{name: "same-operation-writes-reversed", deliveries: []delivery{{sample(200, 1, 1), 12, 12}, {sample(100, 1, 1), 11, 11}}, wantSize: 200, wantNlink: 1, wantBlocks: 1},
		// A delayed read sampled before the mutation, arriving after it.
		{name: "read-before-mutation-delivered-late", deliveries: []delivery{{sample(9, 1, 2), 6, 6}, {sample(3, 1, 1), 5, 5}}, wantSize: 9, wantNlink: 1, wantBlocks: 2},
		// A later read of the same version refreshes observational blocks only.
		{name: "equal-version-newer-snapshot-refreshes-blocks", deliveries: []delivery{{sample(9, 1, 2), 6, 6}, {sample(9, 1, 5), 6, 9}}, wantSize: 9, wantNlink: 1, wantBlocks: 5},
		{name: "equal-version-older-snapshot-keeps-held", deliveries: []delivery{{sample(9, 1, 5), 6, 9}, {sample(9, 1, 2), 6, 6}}, wantSize: 9, wantNlink: 1, wantBlocks: 5},
		{name: "equal-version-tie-keeps-held", deliveries: []delivery{{sample(9, 1, 5), 6, 9}, {sample(9, 1, 7), 6, 9}}, wantSize: 9, wantNlink: 1, wantBlocks: 5},
		{name: "equal-version-logical-disagreement-is-terminal", deliveries: []delivery{{sample(9, 1, 2), 6, 6}, {sample(10, 1, 2), 6, 7}}, terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			record := f.record(f.lookup(f.root, "file").Item)
			var err error
			for _, delivery := range test.deliveries {
				err = errors.Join(err, f.d.applyMutation(&v3MutationEffect{snapshot: delivery.snapshot, objects: []v3Observation{
					{identity: record.item.StableIdentity, attr: delivery.attr, version: delivery.version},
				}}))
			}
			if test.terminal {
				if err == nil {
					t.Fatal("equal-version logical disagreement was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("legal out-of-order delivery fenced: %v", err)
			}
			f.d.mu.Lock()
			attr := record.attr
			f.d.mu.Unlock()
			if attr.GetSize() != test.wantSize || attr.GetNlink() != test.wantNlink || attr.GetBlocks() != test.wantBlocks {
				t.Fatalf("cached attr size=%d nlink=%d blocks=%d, want %d/%d/%d",
					attr.GetSize(), attr.GetNlink(), attr.GetBlocks(), test.wantSize, test.wantNlink, test.wantBlocks)
			}
		})
	}
}

// Rename-over and a concurrent setattr on the victim, in both delivery
// orders, leave the victim's newest attrs and the moved binding.
func TestV3CacheRenameOverAndVictimSetattrInBothOrders(t *testing.T) {
	for _, renameFirst := range []bool{true, false} {
		f := newCachedV3Fixture(t, map[byte]*v3TestObject{
			0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 1},
			0x71: {inode: 8, kind: authoritypb.Attr_REGULAR, nlink: 1},
		})
		f.ns.bind(0x20, "x", 0x70)
		f.ns.bind(0x20, "y", 0x71)
		f.getattr(f.root)
		f.lookup(f.root, "x")
		victim := f.record(f.lookup(f.root, "y").Item)
		root := f.record(f.root)
		rename := &v3MutationEffect{snapshot: 10,
			objects: []v3Observation{
				{identity: [16]byte(testV3ID(0x20)), attr: testV3DirAttr(1, 2), version: 10},
				{identity: [16]byte(testV3ID(0x70)), attr: testV3FileAttr(7, 0, 1), version: 10},
				{identity: [16]byte(testV3ID(0x71)), attr: testV3FileAttr(8, 0, 0), version: 10},
			},
			names: []v3NameEffect{{parent: root, name: "x"}, {parent: root, name: "y", bound: true, identity: [16]byte(testV3ID(0x70))}},
		}
		chmod := testV3FileAttr(8, 0, 0)
		chmod.Mode = 0o600
		setattr := &v3MutationEffect{snapshot: 11, objects: []v3Observation{{identity: [16]byte(testV3ID(0x71)), attr: chmod, version: 11}}}
		order := []*v3MutationEffect{rename, setattr}
		if !renameFirst {
			order = []*v3MutationEffect{setattr, rename}
		}
		for _, effect := range order {
			if err := f.d.applyMutation(effect); err != nil {
				t.Fatalf("renameFirst=%t: %v", renameFirst, err)
			}
		}
		f.d.mu.Lock()
		mode, bound := victim.attr.GetMode(), root.children["y"]
		victimBinding := victim.bindings
		f.d.mu.Unlock()
		if mode != 0o600 || bound == nil || bound.item.StableIdentity != [16]byte(testV3ID(0x70)) || len(victimBinding) != 0 {
			t.Fatalf("renameFirst=%t: victim mode=%o y=%v victim binding=%v", renameFirst, mode, bound, victimBinding)
		}
	}
}

// Names are ordered by the directory watermark, never by the parent's object
// version: an older mutation result drops its touched coordinates, an older
// Lookup fills neither side, and a newer observation installs.
func TestV3CacheNameWatermarkOrdering(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.getattr(f.root)
	d := f.d
	root := f.record(f.root)
	d.mu.Lock()
	root.watermark = 10
	d.mu.Unlock()
	child := acceptedTestItem(t, d, authorityTestItem(9, authoritypb.Attr_REGULAR, 0x39, 0x79))
	// An old create result (s=8 < W=10) drops the touched coordinate.
	if err := d.applyMutation(&v3MutationEffect{snapshot: 8, names: []v3NameEffect{{parent: root, name: "n", bound: true, identity: child.item.StableIdentity}}}); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	installed := root.children["n"] != nil
	d.recordAbsenceLocked(root, "m")
	d.fillLookupLocked(root, "m", child, 9) // old positive lookup
	_, negative := root.negatives["m"]
	clobbered := !negative || root.children["m"] != nil
	d.mu.Unlock()
	if installed || clobbered {
		t.Fatalf("stale name effects installed=%t clobbered=%t", installed, clobbered)
	}
	if err := d.applyMutation(&v3MutationEffect{snapshot: 12, names: []v3NameEffect{{parent: root, name: "n", bound: true, identity: child.item.StableIdentity}}}); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if root.children["n"] != child || root.watermark != 12 {
		t.Fatalf("newer name effect children[n]=%v W=%d", root.children["n"], root.watermark)
	}
}

// A lookup-relevant permission change on a directory, first discovered by a
// read or a mutation, forgets every name beneath it and raises W to its
// version, so an older cached name cannot bypass a new search-permission
// failure.
func TestV3CachePermissionChangeForgetsNamesAndRaisesTheWatermark(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "dir", 0x50)
	f.ns.bind(0x50, "file", 0x70)
	f.getattr(f.root)
	dir := f.lookup(f.root, "dir")
	f.getattr(dir.Item)
	file := f.lookup(dir.Item, "file")
	_, _ = f.dispatch(&pfslocal.LookupRequest{Dir: dir.Item, Name: []byte("missing")})
	dirRecord := f.record(dir.Item)
	locked := testV3DirAttr(5, 2)
	locked.Mode = 0o700
	f.d.mu.Lock()
	err := f.d.observeLocked(dirRecord, locked, 20, 21) // discovered through a read
	children, negatives, watermark := len(dirRecord.children), len(dirRecord.negatives), dirRecord.watermark
	fileBinding := f.d.itemsByID[file.Item.ItemID].bindings
	f.d.fillLookupLocked(dirRecord, "file", f.d.itemsByID[file.Item.ItemID], 19)
	refilled := dirRecord.children["file"] != nil
	f.d.mu.Unlock()
	if err != nil || children != 0 || negatives != 0 || watermark != 20 || len(fileBinding) != 0 || refilled {
		t.Fatalf("permission change: err=%v children=%d negatives=%d W=%d binding=%v refilled=%t",
			err, children, negatives, watermark, fileBinding, refilled)
	}
}

// A real directory retirement removes its names, its negatives, and the
// parent references of the children it named; nothing renders a stale parent.
func TestV3CacheDirectoryRetirementDropsNamesAndChildParents(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "dir", 0x50)
	f.ns.bind(0x50, "file", 0x70)
	dir := f.lookup(f.root, "dir")
	file := f.lookup(dir.Item, "file")
	_, _ = f.dispatch(&pfslocal.LookupRequest{Dir: dir.Item, Name: []byte("missing")})
	if _, errno := f.dispatch(&pfslocal.ReclaimRequest{Item: dir.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	f.d.mu.Lock()
	binding, negatives := f.d.itemsByID[file.Item.ItemID].bindings, f.d.negativeNames
	f.d.mu.Unlock()
	if len(binding) != 0 || negatives != 0 {
		t.Fatalf("retired directory left binding=%v negatives=%d", binding, negatives)
	}
	if attr := f.getattr(file.Item); attr.Parent != nil || attr.ParentFileID != 0 {
		t.Fatalf("child of a retired directory rendered parent %+v", attr.Parent)
	}
}

// Same-inode no-op rename and an open nlink-zero inode keep exact state.
func TestV3CacheNoOpRenameAndUnlinkedOpenInode(t *testing.T) {
	f := newCachedV3Fixture(t, map[byte]*v3TestObject{0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 2}})
	f.ns.bind(0x20, "a", 0x70)
	f.ns.bind(0x20, "b", 0x70)
	f.getattr(f.root)
	a := f.lookup(f.root, "a")
	if _, errno := f.dispatch(&pfslocal.RenameRequest{FromDir: f.root, FromName: []byte("a"), ToDir: f.root, ToName: []byte("b")}); errno != 0 {
		t.Fatalf("no-op rename errno=%d", errno)
	}
	if attr := f.getattr(a.Item); attr.Nlink != 2 {
		t.Fatalf("no-op rename changed nlink to %d", attr.Nlink)
	}
	opened, errno := f.dispatch(&pfslocal.OpenRequest{Item: a.Item, Mode: pfslocal.OpenModeRead})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	for _, name := range []string{"a", "b"} {
		if _, errno := f.dispatch(&pfslocal.RemoveRequest{Dir: f.root, Name: []byte(name)}); errno != 0 {
			t.Fatalf("remove %s errno=%d", name, errno)
		}
	}
	f.requireServedLocally("GetAttr of the unlinked open inode", func() {
		attr := getattrTestAttr(t, f.d, a.Item, opened.(*pfslocal.OpenReply).Handle)
		if attr.Nlink != 0 || attr.Parent != nil {
			t.Fatalf("unlinked open inode attr = %+v", attr)
		}
	})
	f.requireServedLocally("Lookup of a removed name", func() {
		if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("a")}); errno != darwinENOENT {
			t.Fatalf("removed name errno=%d", errno)
		}
	})
}

// Hard-link aliases retain both names, one capability and one shared sample.
func TestV3CacheHardLinkAliasesShareOneSample(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "dir", 0x50)
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	dir := f.lookup(f.root, "dir")
	f.getattr(dir.Item)
	file := f.lookup(f.root, "file")
	reply, errno := f.dispatch(&pfslocal.HardLinkRequest{Item: file.Item, Dir: dir.Item, Name: []byte("alias")})
	if errno != 0 || reply.(*pfslocal.HardLinkReply).Attr.Nlink != 2 {
		t.Fatalf("link = (%#v,%d)", reply, errno)
	}
	f.requireServedLocally("alias Lookup and shared GetAttr", func() {
		alias := f.lookup(dir.Item, "alias")
		if alias.Item != file.Item || alias.Nlink != 2 || alias.ParentFileID != dir.FileID {
			t.Fatalf("alias = %+v", alias)
		}
		if attr := f.getattr(file.Item); attr.Nlink != 2 || (attr.ParentFileID != dir.FileID && attr.ParentFileID != v3RootFileID) {
			t.Fatalf("shared attr = %+v", attr)
		}
	})
	f.requireServedLocally("original Lookup after LINK", func() { f.lookup(f.root, "file") })
	root := f.record(f.root)
	f.d.mu.Lock()
	retained := root.children["file"] == f.d.itemsByID[file.Item.ItemID]
	f.d.mu.Unlock()
	if !retained {
		t.Fatal("LINK forgot the original binding")
	}
}

// Create, write, and unlink results apply whole: the parent's attrs, the
// created binding, and the removal's absence are all served locally after.
func TestV3CacheAppliesWholeMutationResults(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.getattr(f.root)
	created, errno := f.dispatch(&pfslocal.CreateRequest{Dir: f.root, Name: []byte("new"), Mode: 0o644, Exclusive: true})
	if errno != 0 {
		t.Fatalf("create errno=%d", errno)
	}
	item, handle := created.(*pfslocal.CreateReply).Attr.Item, created.(*pfslocal.CreateReply).Handle
	if _, errno := f.dispatch(&pfslocal.WriteRequest{Handle: handle, Data: []byte("hello")}); errno != 0 {
		t.Fatalf("write errno=%d", errno)
	}
	f.requireServedLocally("reads after create and write", func() {
		if attr := f.lookup(f.root, "new"); attr.Item != item || attr.Size != 5 {
			t.Fatalf("cached created binding = %+v", attr)
		}
		f.getattr(f.root)
	})
	rootVersion := f.record(f.root).version
	if _, errno := f.dispatch(&pfslocal.RemoveRequest{Dir: f.root, Name: []byte("new")}); errno != 0 {
		t.Fatalf("remove errno=%d", errno)
	}
	if f.record(f.root).version <= rootVersion {
		t.Fatal("unlink did not apply its PARENT post-state")
	}
	f.requireServedLocally("lookup after unlink", func() {
		if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("new")}); errno != darwinENOENT {
			t.Fatalf("lookup after unlink errno=%d", errno)
		}
	})
}

// Negative entries are bounded by count and bytes, cleared wholesale.
func TestV3CacheNegativeEntriesAreBounded(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	root := f.record(f.root)
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	for index := range v3MaxNegativeNames {
		f.d.recordAbsenceLocked(root, string(rune(0x4e00+index)))
	}
	if f.d.negativeNames != v3MaxNegativeNames {
		t.Fatalf("negatives=%d", f.d.negativeNames)
	}
	f.d.recordAbsenceLocked(root, "overflow")
	if f.d.negativeNames != 1 || len(root.negatives) != 1 {
		t.Fatalf("capacity exhaustion kept %d negatives, want a wholesale clear", f.d.negativeNames)
	}
}

// Definite namespace refusals evict affected cache coordinates without
// deriving a causal contradiction from an older cached observation.
func TestV3CacheNamespaceErrnoEvictsTheCoordinate(t *testing.T) {
	for _, absent := range []bool{true, false} {
		t.Run(map[bool]string{true: "EEXIST", false: "ENOENT"}[absent], func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.getattr(f.root)
			var body any
			want := darwinEEXIST
			if absent {
				_, _ = f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("n")})
				f.ns.bind(0x20, "n", 0x70)
				body = &pfslocal.MkdirRequest{Dir: f.root, Name: []byte("n"), Mode: 0o755}
			} else {
				f.ns.bind(0x20, "n", 0x70)
				f.lookup(f.root, "n")
				delete(f.ns.names, "20/n")
				body = &pfslocal.RemoveRequest{Dir: f.root, Name: []byte("n")}
				want = darwinENOENT
			}
			if _, errno := f.dispatch(body); errno != want || f.d.terminalError() != nil {
				t.Fatalf("errno=%d terminal=%v", errno, f.d.terminalError())
			}
			root := f.record(f.root)
			f.d.mu.Lock()
			_, negative := root.negatives["n"]
			positive := root.children["n"] != nil
			f.d.mu.Unlock()
			if negative || positive {
				t.Fatal("definite refusal retained a cached name")
			}
		})
	}
}

// Paused replies retain their snapshot across overlapping local effects.
// Proof or authorization expiry admits one authority miss; poison and clock errors revoke
// publication, and provisional ownership settles exactly once.
func TestV3CachedReplyIsRevalidatedAtThePhysicalWriteBoundary(t *testing.T) {
	for _, test := range []struct {
		name    string
		between func(*cachedV3Fixture, pfslocal.Item)
	}{
		{name: "intervening-mutation", between: func(f *cachedV3Fixture, file pfslocal.Item) {
			// A truncate commits at the authority and its result is applied.
			f.ns.mu.Lock()
			f.ns.objects[0x70].size = 42
			f.ns.mu.Unlock()
			if err := f.d.applyMutation(&v3MutationEffect{snapshot: 30, objects: []v3Observation{
				{identity: file.StableIdentity, attr: testV3FileAttr(7, 42, 1), version: 30},
			}}); err != nil {
				f.t.Fatal(err)
			}
		}},
		{name: "horizon-expiry", between: func(f *cachedV3Fixture, _ pfslocal.Item) { f.clock.advance(10 * time.Minute) }},
		// The second acquisition order: a mutation acquires its source claim
		// after the hit's snapshot but before the frame is written.
		{name: "claim-acquired-after-snapshot", between: func(f *cachedV3Fixture, _ pfslocal.Item) {
			gate, err := v3NamespaceSourceGate(f.root, []byte("racing"), false)
			if err != nil {
				f.t.Fatal(err)
			}
			coordinator := f.d.bridge.sourcePublication
			coordinator.reserve(testCallback(9501))
			if _, err := coordinator.acquireSource(context.Background(), testCallback(9501), gate); err != nil {
				f.t.Fatal(err)
			}
		}},
		{name: "terminal-service", between: func(f *cachedV3Fixture, _ pfslocal.Item) { _ = f.d.stopServing(errors.New("terminal service")) }},
		{name: "expired-authorization", between: func(f *cachedV3Fixture, _ pfslocal.Item) {
			f.d.mu.Lock()
			f.d.authorizationDeadline = time.Now().Add(-time.Second)
			f.d.mu.Unlock()
		}},
		{name: "immediate-poison", between: func(f *cachedV3Fixture, _ pfslocal.Item) { f.client.poisoned.Store(true) }},
		{name: "clock-read-error", between: func(f *cachedV3Fixture, _ pfslocal.Item) { v3ClockFaults[0].fault(f.clock) }},
	} {
		for _, kind := range []string{"getattr", "lookup", "negative-lookup"} {
			lookup := kind != "getattr"
			negative := kind == "negative-lookup"
			name := test.name + "/" + kind
			t.Run(name, func(t *testing.T) {
				f := newCachedV3Fixture(t, v3FileObjects())
				f.ns.bind(0x20, "file", 0x70)
				f.getattr(f.root)
				file := f.lookup(f.root, "file").Item
				if negative {
					if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("missing")}); errno != darwinENOENT {
						t.Fatal(errno)
					}
				}
				a := &attach{ref: "write-boundary", v3Data: f.d, v3Coherence: f.d.bridge}
				server, peer := net.Pipe()
				defer peer.Close()
				c := &frontendConn{origin: 1, conn: server, attach: a}
				const operationID = uint64(9401)
				var once sync.Once
				c.testBeforeReplyWrite = func(uint64) { once.Do(func() { test.between(f, file) }) }
				initialize, ok := c.reserveLogicalOperation(operationID, true)
				if !ok || !initialize {
					t.Fatal("operation was not reserved")
				}
				f.d.bridge.reserveFrontendPublication(testCallback(operationID))
				before := f.authorityCalls()
				beforeMetrics := f.d.cacheMetrics()
				var body any = &pfslocal.GetAttrRequest{Item: file}
				if lookup {
					lookupName := "file"
					if negative {
						lookupName = "missing"
					}
					body = &pfslocal.LookupRequest{Dir: f.root, Name: []byte(lookupName)}
				}
				done := make(chan struct{})
				go func() {
					c.handleV3Attached(context.Background(), a, 1, operationID, initialize, body)
					close(done)
				}()
				envelope, err := pfslocal.ReadFrame(peer)
				<-done
				afterMetrics := f.d.cacheMetrics()
				countsBefore, countsAfter := beforeMetrics.GetAttr, afterMetrics.GetAttr
				if lookup {
					countsBefore, countsAfter = beforeMetrics.Lookup, afterMetrics.Lookup
					polarity := "positive"
					if negative {
						polarity = "negative"
					}
					if err != nil || f.d.terminalError() != nil {
						polarity = "error"
					}
					for _, result := range []string{"positive", "negative", "error"} {
						want := uint64(0)
						if result == polarity {
							want = 1
						}
						if got := afterMetrics.LookupPolarity[result] - beforeMetrics.LookupPolarity[result]; got != want {
							t.Errorf("lookup polarity %s delta=%d, want %d", result, got, want)
						}
					}
				}
				reason := "hit"
				switch test.name {
				case "horizon-expiry":
					reason = "horizon"
				case "expired-authorization":
					reason = "authorization"
				case "immediate-poison", "terminal-service":
					reason = "terminal"
				case "clock-read-error":
					reason = "clock"
				}
				for result := range countsAfter {
					want := uint64(0)
					if result == reason {
						want = 1
					}
					if got := countsAfter[result] - countsBefore[result]; got != want {
						t.Errorf("cache result %s delta=%d, want %d", result, got, want)
					}
				}
				if test.name == "immediate-poison" || test.name == "terminal-service" {
					if f.authorityCalls() != before {
						t.Fatal("ineligible reply issued an authority substitute")
					}
					// The poisoned session refuses the coherent retry itself.
					if err == nil || f.d.terminalError() == nil {
						t.Fatalf("poisoned write boundary wrote %#v terminal=%v, want no frame and a terminal data plane", envelope, f.d.terminalError())
					}
					return
				}
				if strings.HasPrefix(test.name, "clock-") {
					// The fault ends serving before the coherent retry runs, so
					// neither the cached answer nor an authority answer is
					// written.
					if f.authorityCalls() != before {
						t.Fatal("a clock fault at the write boundary fell back to the authority")
					}
					if err == nil {
						switch envelope.Body.(type) {
						case *pfslocal.GetAttrReply, *pfslocal.LookupReply:
							t.Fatalf("a clock fault at the write boundary wrote %#v", envelope.Body)
						}
					}
					requireV3ClockTerminal(t, f.d, f.client)
					return
				}
				wantCalls := before
				if test.name == "horizon-expiry" || test.name == "expired-authorization" {
					wantCalls++
				}
				if f.authorityCalls() != wantCalls {
					t.Fatalf("authority calls=%d, want %d", f.authorityCalls(), wantCalls)
				}
				if err != nil {
					t.Fatal(err)
				}
				var attr pfslocal.Attr
				switch reply := envelope.Body.(type) {
				case *pfslocal.GetAttrReply:
					attr = reply.Attr
				case *pfslocal.LookupReply:
					attr = reply.Attr
				case *pfslocal.ErrorReply:
					if !negative || reply.Errno != darwinENOENT {
						t.Fatalf("unexpected error reply: %+v", reply)
					}
				default:
					t.Fatalf("reply = %#v", envelope.Body)
				}
				if test.name == "intervening-mutation" && !negative && attr.Size != 3 {
					t.Fatalf("overlapping read lost its admitted snapshot: size=%d", attr.Size)
				}
				if f.d.terminalError() != nil {
					t.Fatalf("ordinary cache miss terminated the session: %v", f.d.terminalError())
				}
				if lookup && !negative {
					resources := c.provisional[1]
					if resources == nil || len(resources.items) != 1 || resources.items[0].provisional != 1 {
						t.Fatalf("lookup provisional ownership after refusal = %+v", resources)
					}
				}
			})
		}
	}
}

// Concurrent cached lookups, reclaims, and accepted or abandoned dispositions
// settle every provisional reference exactly once.
func TestV3CachedLookupsSettleProvisionalOwnershipExactlyOnce(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.client.limit = 8
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	f.lookup(f.root, "file")
	var wg sync.WaitGroup
	var failures atomic.Int32
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := range 20 {
				collector := &v3ReplyResourceCollector{d: f.d}
				reply, errno := f.d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0,
					&pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")})
				if errno != 0 {
					failures.Add(1)
					return
				}
				resources, err := f.d.prepareReplyResources(collector)
				if err != nil {
					failures.Add(1)
					return
				}
				accept := uint32(0)
				if (worker+iteration)%2 == 0 {
					accept = 1
				}
				cleanup, err := f.d.applyReplyResourceDisposition(resources, false, accept)
				if err != nil {
					failures.Add(1)
					return
				}
				if cleanup.required() {
					_ = cleanup.finish()
				}
				if accept == 1 {
					item := reply.(*pfslocal.LookupReply).Attr.Item
					if _, errno := f.d.reclaim(context.Background(), &pfslocal.ReclaimRequest{Item: item}); errno != 0 {
						failures.Add(1)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	waitV3ReleasesIdle(t, f.d)
	if failures.Load() != 0 || f.d.terminalError() != nil {
		t.Fatalf("failures=%d terminal=%v", failures.Load(), f.d.terminalError())
	}
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	for _, record := range f.d.itemsByID {
		if record.provisional != 0 {
			t.Fatalf("record %d kept %d provisional references", record.item.ItemID, record.provisional)
		}
	}
}

// Every PostState object must be representable before anything is applied,
// held or not: an unheld REMOVED object with a negative size, an allocation
// that overflows in bytes, or an inode outside the file-ID range is a
// malformed outcome and terminal.
func TestV3CacheRejectsUnrepresentableUnheldPostState(t *testing.T) {
	for _, malformed := range []string{"negative-size", "allocation-overflow", "inode-out-of-range"} {
		t.Run(malformed, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			f.getattr(f.root)
			f.ns.hold = func(request *authoritypb.Request, response *authoritypb.Response) {
				if request.GetUnlink() == nil {
					return
				}
				for _, object := range response.GetPostState().GetObjects() {
					if object.GetRoles() != v3PostStateRoleRemoved {
						continue
					}
					switch malformed {
					case "negative-size":
						object.Attr.Size = -1
					case "allocation-overflow":
						object.Attr.Blocks = math.MaxUint64
					case "inode-out-of-range":
						object.Attr.Inode = math.MaxUint64
					}
				}
			}
			f.d.mu.Lock()
			floor := f.d.coldFloor
			f.d.mu.Unlock()
			if _, errno := f.dispatch(&pfslocal.RemoveRequest{Dir: f.root, Name: []byte("file")}); errno == 0 || f.d.terminalError() == nil {
				t.Fatalf("unrepresentable unheld REMOVED accepted: errno=%d terminal=%v", errno, f.d.terminalError())
			}
			root := f.record(f.root)
			f.d.mu.Lock()
			defer f.d.mu.Unlock()
			if f.d.coldFloor != floor || len(root.negatives) != 0 {
				t.Fatal("a refused reply was partially applied")
			}
		})
	}
}

// A mutation reply must have exactly its operation's shape: a SetAttr success
// carrying an unexpected body (here a contradictory GetAttr) is malformed.
func TestV3CacheRejectsAMutationReplyWithAnUnexpectedBody(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	f.ns.hold = func(request *authoritypb.Request, response *authoritypb.Response) {
		if request.GetSetAttr() != nil {
			response.Body = &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: testV3FileAttr(7, 999, 1), ObjectVersion: 1, SnapshotSequence: 1}}
		}
	}
	size := uint64(42)
	if _, errno := f.dispatch(&pfslocal.SetAttrRequest{Item: file.Item, Size: &size}); errno == 0 || f.d.terminalError() == nil {
		t.Fatalf("setattr with a foreign body = %d terminal=%v, want terminal", errno, f.d.terminalError())
	}
}

// A success that carries a failure class is contradictory and terminal on
// both read and mutation paths.
func TestV3CacheRejectsASuccessCarryingAFailureClass(t *testing.T) {
	t.Run("lookup", func(t *testing.T) {
		f := newCachedV3Fixture(t, v3FileObjects())
		f.ns.bind(0x20, "file", 0x70)
		f.ns.hold = func(request *authoritypb.Request, response *authoritypb.Response) {
			if request.GetLookup() != nil {
				response.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL
			}
		}
		if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")}); errno == 0 || f.d.terminalError() == nil {
			t.Fatalf("lookup success with a failure class = %d terminal=%v", errno, f.d.terminalError())
		}
	})
	t.Run("setattr", func(t *testing.T) {
		f := newCachedV3Fixture(t, v3FileObjects())
		f.ns.bind(0x20, "file", 0x70)
		file := f.lookup(f.root, "file")
		f.ns.hold = func(request *authoritypb.Request, response *authoritypb.Response) {
			if request.GetSetAttr() != nil {
				response.Failure = authoritypb.FailureClass_FAILURE_CLASS_RESTORE
			}
		}
		size := uint64(1)
		if _, errno := f.dispatch(&pfslocal.SetAttrRequest{Item: file.Item, Size: &size}); errno == 0 || f.d.terminalError() == nil {
			t.Fatalf("setattr success with a failure class = %d terminal=%v", errno, f.d.terminalError())
		}
	})
}

// Valid replacement permission preserves an admitted cache candidate and
// the original coherence proof. A shortened deadline still denies exposure.
func TestV3CachedReplySurvivesReauthorizationWithValidPermission(t *testing.T) {
	client := newFakeV3DataClient()
	ns := newV3TestNamespace(client, v3FileObjects())
	ns.bind(0x20, "file", 0x70)
	wrapper := &reauthorizingV3Client{fakeV3DataClient: client, deadline: time.Now().Add(time.Hour)}
	d := testV3DataPlaneOnClient(t, wrapper, client, newFakeV3Clock())
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	collector := &v3ReplyResourceCollector{d: d}
	if _, errno := d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0, &pfslocal.GetAttrRequest{Item: file.Item}); errno != 0 || collector.cached == nil {
		t.Fatalf("getattr was not a cache hit: errno=%d", errno)
	}
	defer consumeV3ResponseConsumptions(collector.responseConsumptions)
	if !collector.cached.revalidate() {
		t.Fatal("an unchanged candidate was refused")
	}
	if _, err := d.reauthorize(context.Background(), []byte("token"), 1); err != nil {
		t.Fatal(err)
	}
	if v3Horizon(d) == 0 {
		t.Fatal("reauthorization discarded retained proof")
	}
	if !collector.cached.revalidate() {
		t.Fatal("valid permission rejected an admitted candidate after reauthorization")
	}
	d.mu.Lock()
	d.authorizationDeadline = time.Now().Add(-time.Second)
	d.mu.Unlock()
	if collector.cached.revalidate() || !collector.cached.expired {
		t.Fatal("expired replacement permission did not require one authority read")
	}
}

// A rename of X whose reply is delayed past another callback's committed
// setattr(X), which still holds X's attribute coordinate awaiting its
// PublicationAck, is legal concurrency: the rename's binding joins the
// holders instead of fencing the mount, the older rename sample is discarded,
// and cache reads become eligible after both handlers settle.
func TestV3RenameDelayedPastAHeldSetattrOfTheMovedObjectIsLegal(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	file := f.lookup(f.root, "file")
	renameCommitted, releaseRename := make(chan struct{}), make(chan struct{})
	f.ns.hold = func(request *authoritypb.Request, _ *authoritypb.Response) {
		if request.GetRename() != nil {
			close(renameCommitted)
			<-releaseRename
		}
	}
	const renameOp, setattrOp = uint64(97001), uint64(97002)
	f.d.bridge.reserveFrontendPublication(testCallback(renameOp))
	f.d.bridge.reserveFrontendPublication(testCallback(setattrOp))
	renamed := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Owned(f.d, context.Background(), renameOp, &pfslocal.RenameRequest{
			FromDir: f.root, FromName: []byte("file"), ToDir: f.root, ToName: []byte("renamed"),
		})
		renamed <- errno
	}()
	select {
	case <-renameCommitted:
	case <-time.After(2 * time.Second):
		t.Fatal("rename did not commit")
	}
	size := uint64(42)
	if _, errno := dispatchV3Owned(f.d, context.Background(), setattrOp, &pfslocal.SetAttrRequest{Item: file.Item, Size: &size}); errno != 0 {
		t.Fatalf("setattr errno=%d", errno)
	}
	close(releaseRename)
	if errno := <-renamed; errno != 0 || f.d.terminalError() != nil {
		t.Fatalf("legal rename/setattr overlap fenced: errno=%d terminal=%v", errno, f.d.terminalError())
	}
	attribute := v3AttributeCoordinate(f.record(file.Item))
	coordinator := f.d.bridge.sourcePublication
	coordinator.mu.Lock()
	holders := len(coordinator.sourceHolds[attribute])
	coordinator.mu.Unlock()
	if holders != 2 {
		t.Fatalf("moved object's attribute coordinate has %d holders, want both callbacks", holders)
	}
	record := f.record(file.Item)
	f.d.mu.Lock()
	cachedSize, bindings := record.attr.GetSize(), record.bindings
	_, hasRenamed := bindings[v3Binding{parent: f.d.itemsByID[f.root.ItemID], name: "renamed"}]
	f.d.mu.Unlock()
	if cachedSize != 42 || !hasRenamed {
		t.Fatalf("after the overlap size=%d binding=%+v, want the setattr's size and the rename's name", cachedSize, bindings)
	}
	f.requireServedLocally("GetAttr after both handlers settle before either ack", func() { f.getattr(file.Item) })
	for _, operationID := range []uint64{setattrOp, renameOp} {
		if _, err := f.d.bridge.acknowledgePublication(testCallback(operationID), pfslocal.PublicationSemanticCommitPublished); err != nil {
			t.Fatal(err)
		}
		f.d.bridge.releaseFrontendPublication(testCallback(operationID))
		_ = f.d.bridge.finishFrontendPublication(testCallback(operationID))
	}
	f.requireServedLocally("GetAttr after both publish", func() { f.getattr(file.Item) })
}

// r2 §5.1 through admission, reply validation, and publication: two writes of
// one callback commit in one order and their replies are applied in the
// other; the older result is discarded without a fence.
func TestV3CacheSameCallbackWritesWithReversedReplies(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	opened, errno := f.dispatch(&pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	handle := opened.(*pfslocal.OpenReply).Handle
	firstCommitted, releaseFirst := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.ns.hold = func(request *authoritypb.Request, _ *authoritypb.Response) {
		if request.GetWrite() != nil && request.GetWrite().GetPosition() == 0 {
			once.Do(func() {
				close(firstCommitted)
				<-releaseFirst
			})
		}
	}
	const operationID = uint64(97101)
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	first := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Owned(f.d, context.Background(), operationID, &pfslocal.WriteRequest{Handle: handle, Data: []byte("abcde")})
		first <- errno
	}()
	<-firstCommitted
	if _, errno := dispatchV3Owned(f.d, context.Background(), operationID, &pfslocal.WriteRequest{Handle: handle, Offset: 10, Data: []byte("fghij")}); errno != 0 {
		t.Fatalf("second write errno=%d", errno)
	}
	f.requireAuthority("read with an overlapping source request still active", func() { f.getattr(file.Item) })
	close(releaseFirst)
	if errno := <-first; errno != 0 || f.d.terminalError() != nil {
		t.Fatalf("older reply after newer = %d terminal=%v, want no fence", errno, f.d.terminalError())
	}
	record := f.record(file.Item)
	f.d.mu.Lock()
	size := record.attr.GetSize()
	f.d.mu.Unlock()
	if size != 15 {
		t.Fatalf("cached size=%d, want the newer write's 15", size)
	}
	f.requireServedLocally("read after all same-callback writes settle before ack", func() { f.getattr(file.Item) })
}

// Same-name namespace requests of one callback: create(n) commits first, an
// unlink(n) of the same callback commits second and is applied first; the
// delayed create result is older than the directory watermark and drops the
// coordinate instead of reinstalling the name.
func TestV3CacheSameCallbackSameNameNamespaceRequests(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.getattr(f.root)
	createCommitted, releaseCreate := make(chan struct{}), make(chan struct{})
	f.ns.hold = func(request *authoritypb.Request, _ *authoritypb.Response) {
		if request.GetMkdir() != nil {
			close(createCommitted)
			<-releaseCreate
		}
	}
	const operationID = uint64(97201)
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	created := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Owned(f.d, context.Background(), operationID, &pfslocal.MkdirRequest{Dir: f.root, Name: []byte("n"), Mode: 0o755})
		created <- errno
	}()
	<-createCommitted
	if _, errno := dispatchV3Owned(f.d, context.Background(), operationID, &pfslocal.RemoveRequest{Dir: f.root, Name: []byte("n"), Directory: true}); errno != 0 {
		t.Fatalf("unlink errno=%d", errno)
	}
	close(releaseCreate)
	if errno := <-created; errno != 0 || f.d.terminalError() != nil {
		t.Fatalf("delayed create = %d terminal=%v, want no fence", errno, f.d.terminalError())
	}
	root := f.record(f.root)
	f.d.mu.Lock()
	positive := root.children["n"]
	_, negative := root.negatives["n"]
	f.d.mu.Unlock()
	if positive != nil || negative {
		t.Fatalf("after reversed same-name results positive=%v negative=%t, want the coordinate dropped", positive, negative)
	}
	if _, err := f.d.bridge.acknowledgePublication(testCallback(operationID), pfslocal.PublicationSemanticCommitPublished); err != nil {
		t.Fatal(err)
	}
	f.d.bridge.releaseFrontendPublication(testCallback(operationID))
	_ = f.d.bridge.finishFrontendPublication(testCallback(operationID))
	f.requireAuthority("lookup of the dropped coordinate", func() {
		if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("n")}); errno != darwinENOENT {
			t.Fatalf("lookup errno=%d", errno)
		}
	})
}

// An unresolved namespace claim owned by the very callback asking gates its
// hits too: the identity it will bind is not known yet.
func TestV3CacheSameCallbackUnresolvedNamespaceClaimGatesAHit(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	file := f.lookup(f.root, "file")
	const operationID = uint64(97301)
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	gate, err := v3NamespaceSourceGate(f.root, []byte("other"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.bridge.sourcePublication.acquireSource(context.Background(), testCallback(operationID), gate); err != nil {
		t.Fatal(err)
	}
	f.requireAuthority("GetAttr under the same callback's unresolved claim", func() {
		if _, errno := dispatchV3Owned(f.d, context.Background(), operationID, &pfslocal.GetAttrRequest{Item: file.Item}); errno != 0 {
			t.Fatalf("getattr errno=%d", errno)
		}
	})
}

// An overlapping create does not invalidate a previously admitted absence
// snapshot, just as it cannot invalidate an authority read already sampled.
func TestV3CachedNegativeKeepsItsSnapshotAcrossAnOverlappingCreate(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.getattr(f.root)
	if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("n")}); errno != darwinENOENT {
		t.Fatalf("negative lookup errno=%d", errno)
	}
	a := &attach{ref: "negative-boundary", v3Data: f.d, v3Coherence: f.d.bridge}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{origin: 1, conn: server, attach: a}
	var once sync.Once
	c.testBeforeReplyWrite = func(uint64) {
		once.Do(func() {
			if _, errno := f.dispatch(&pfslocal.CreateRequest{Dir: f.root, Name: []byte("n"), Mode: 0o644, Exclusive: true}); errno != 0 {
				t.Errorf("create errno=%d", errno)
			}
		})
	}
	const operationID = uint64(97401)
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("operation was not reserved")
	}
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 1, operationID, initialize, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("n")})
		close(done)
	}()
	envelope, err := pfslocal.ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if reply, negative := envelope.Body.(*pfslocal.ErrorReply); !negative || reply.Errno != darwinENOENT {
		t.Fatalf("overlapping lookup lost its admitted absence snapshot: %#v", envelope.Body)
	}
}

// A cached positive Lookup whose callback already acknowledged NOT_PUBLISHED
// (FSKit cancellation) is discarded without a frame and its provisional
// reference settles once; the item stays owned by its earlier acceptance.
func TestV3CachedPositiveAfterNotPublishedAckSettlesOnce(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	file := f.lookup(f.root, "file")
	a := &attach{ref: "late-cached-lookup", v3Data: f.d, v3Coherence: f.d.bridge}
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	c := &frontendConn{origin: 1, conn: server, attach: a}
	const operationID = uint64(97501)
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("operation was not reserved")
	}
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	if known, err := f.d.bridge.acknowledgePublication(testCallback(operationID), pfslocal.PublicationSemanticCommitNotPublished); !known || err != nil {
		t.Fatalf("bridge NOT_PUBLISHED = (%t,%v)", known, err)
	}
	if !c.acknowledgePublication(operationID) {
		t.Fatal("frontend NOT_PUBLISHED refused")
	}
	f.requireServedLocally("cached lookup of a canceled callback", func() {
		c.handleV3Attached(context.Background(), a, 1, operationID, initialize, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")})
	})
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if envelope, err := pfslocal.ReadFrame(peer); err == nil {
		t.Fatalf("a canceled callback received a frame: %+v", envelope)
	}
	record := f.record(file.Item)
	f.d.mu.Lock()
	provisional, accepted := record.provisional, record.accepted
	f.d.mu.Unlock()
	if provisional != 0 || !accepted || f.d.terminalError() != nil || len(c.provisional) != 0 {
		t.Fatalf("after cancellation provisional=%d accepted=%t terminal=%v table=%d", provisional, accepted, f.d.terminalError(), len(c.provisional))
	}
}

// An exposed cached positive Lookup whose item FSKit reclaims before the
// disposition, followed by socket loss, settles the provisional reference
// once, retires the record, and leaves its capability to session cleanup of
// the now-terminal (unprovable-publication) data plane.
func TestV3CachedPositiveReclaimThenSocketLossSettlesOnce(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	file := f.lookup(f.root, "file")
	a := &attach{ref: "cached-reclaim-loss", v3Data: f.d, v3Coherence: f.d.bridge}
	server, peer := net.Pipe()
	c := &frontendConn{origin: 1, conn: server, attach: a}
	const operationID = uint64(97601)
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("operation was not reserved")
	}
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	go c.handleV3Attached(context.Background(), a, 1, operationID, initialize, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")})
	envelope, err := pfslocal.ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, positive := envelope.Body.(*pfslocal.LookupReply); !positive {
		t.Fatalf("reply = %#v", envelope.Body)
	}
	if _, errno := f.d.reclaim(context.Background(), &pfslocal.ReclaimRequest{Item: file.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	record := f.record(file.Item)
	_ = peer.Close()
	c.close()
	f.d.mu.Lock()
	provisional, live := record.provisional, f.d.itemsByID[file.Item.ItemID] == record
	f.d.mu.Unlock()
	if provisional != 0 || live || f.d.terminalError() == nil {
		t.Fatalf("after reclaim and socket loss provisional=%d live=%t terminal=%v", provisional, live, f.d.terminalError())
	}
}

func TestV3SettledEffectsHitCacheBeforePublicationAck(t *testing.T) {
	for _, name := range []string{"create-getattr", "link-lookup", "write-getattr", "unlink-negative"} {
		t.Run(name, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			f.getattr(f.root)
			file := f.lookup(f.root, "file")
			var handle uint64
			if name == "write-getattr" {
				reply, errno := f.dispatch(&pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeReadWrite})
				if errno != 0 {
					t.Fatal(errno)
				}
				handle = reply.(*pfslocal.OpenReply).Handle
			}
			const operationID = uint64(97501)
			f.d.bridge.reserveFrontendPublication(testCallback(operationID))
			var body any
			switch name {
			case "create-getattr":
				body = &pfslocal.CreateRequest{Dir: f.root, Name: []byte("new"), Exclusive: true, Mode: 0o644}
			case "link-lookup":
				body = &pfslocal.HardLinkRequest{Item: file.Item, Dir: f.root, Name: []byte("alias")}
			case "write-getattr":
				body = &pfslocal.WriteRequest{Handle: handle, Data: []byte("hello")}
			case "unlink-negative":
				body = &pfslocal.RemoveRequest{Dir: f.root, Name: []byte("file")}
			}
			reply, errno := dispatchV3Owned(f.d, context.Background(), operationID, body)
			if errno != 0 {
				t.Fatalf("mutation errno=%d", errno)
			}
			if name == "create-getattr" {
				file = reply.(*pfslocal.CreateReply).Attr
			}
			lease := f.d.bridge.sourcePublication.operationLease(testCallback(operationID))
			lease.gate.mu.Lock()
			active, claims, holds := lease.active, len(lease.names), len(lease.coordinates)
			lease.gate.mu.Unlock()
			if active != 0 || claims != 0 || holds == 0 {
				t.Fatalf("settlement active=%d claims=%d holds=%d", active, claims, holds)
			}
			f.requireServedLocally("successor before ack", func() {
				switch name {
				case "create-getattr", "write-getattr":
					f.getattr(file.Item)
				case "link-lookup":
					f.lookup(f.root, "alias")
				case "unlink-negative":
					if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")}); errno != darwinENOENT {
						t.Fatal(errno)
					}
				}
			})
			// A callback can issue another request before its final ack. Its
			// acquisition must make the same retained holds active again.
			gate, _ := v3ItemSourceGate(file.Item, false)
			if _, err := lease.gate.acquireSource(context.Background(), testCallback(operationID), gate); err != nil {
				t.Fatal(err)
			}
			lease.gate.cacheRead(func(conflict v3CacheConflict) {
				if conflict(v3AttributeCoordinate(f.record(file.Item))) != v3CacheHeld {
					t.Fatal("new request failed to reactivate retained holds")
				}
			})
			lease.finishRequest()
			if _, err := f.d.bridge.acknowledgePublication(testCallback(operationID), pfslocal.PublicationSemanticCommitNotPublished); !errors.Is(err, errV3SourcePublicationNotPublished) {
				t.Fatalf("committed NOT_PUBLISHED=%v", err)
			}
		})
	}
}

type closeObservingV3Client struct {
	*fakeV3DataClient
	onClose func()
}

func (c *closeObservingV3Client) Close() error {
	c.onClose()
	return c.fakeV3DataClient.Close()
}

func TestV3ActiveHandlerCoversPostStateValidation(t *testing.T) {
	client := newFakeV3DataClient()
	ns := newV3TestNamespace(client, v3FileObjects())
	ns.bind(0x20, "file", 0x70)
	const operationID = uint64(97502)
	var d *v3DataPlane
	var checked sync.Once
	var observed atomic.Bool
	wrapper := &closeObservingV3Client{fakeV3DataClient: client, onClose: func() {
		checked.Do(func() {
			observed.Store(true)
			lease := d.bridge.sourcePublication.operationLease(testCallback(operationID))
			if lease == nil {
				t.Error("malformed handler had no source lease")
				return
			}
			lease.gate.mu.Lock()
			defer lease.gate.mu.Unlock()
			if lease.active != 1 || lease.gate.terminal == nil {
				t.Errorf("malformed handler closed its transport with active=%d terminal=%v, want terminal before settlement", lease.active, lease.gate.terminal)
			}
		})
	}}
	d = testV3DataPlaneOnClient(t, wrapper, client, newFakeV3Clock())
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	d.bridge.reserveFrontendPublication(testCallback(operationID))
	mutate := client.mutation
	client.mutation = func(ctx context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response, err := mutate(ctx, identity, request)
		response.PostState = nil
		return response, err
	}
	mode := uint32(0o600)
	if _, errno := d.dispatchFrontend(context.WithValue(context.Background(), v3CallbackContextKey{}, uint64(1)), operationID, &pfslocal.SetAttrRequest{Item: file.Item, Mode: &mode}); errno != darwinEIO || d.terminalError() == nil {
		t.Fatalf("malformed SetAttr = %d terminal=%v", errno, d.terminalError())
	}
	if !observed.Load() {
		t.Fatal("malformed handler never closed its transport")
	}
	lease := d.bridge.sourcePublication.operationLease(testCallback(operationID))
	lease.gate.mu.Lock()
	defer lease.gate.mu.Unlock()
	if lease.active != 0 || lease.gate.terminal == nil {
		t.Fatalf("malformed handler left active=%d terminal=%v", lease.active, lease.gate.terminal)
	}
}

func TestV3CacheMetricsExposeBoundedMissReasonsAndLookupPolarity(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)                // cold
	file := f.lookup(f.root, "file") // unknown name
	f.getattr(file.Item)             // hit
	if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("missing")}); errno != darwinENOENT {
		t.Fatal(errno)
	}
	if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("missing")}); errno != darwinENOENT {
		t.Fatal(errno)
	}
	const operationID = uint64(97503)
	f.d.bridge.reserveFrontendPublication(testCallback(operationID))
	gate, _ := v3ItemSourceGate(file.Item, false)
	lease, err := f.d.bridge.sourcePublication.acquireSource(context.Background(), testCallback(operationID), gate)
	if err != nil {
		t.Fatal(err)
	}
	f.getattr(file.Item) // held
	lease.finishRequest()
	f.clock.advance(10 * time.Minute)
	f.getattr(file.Item) // horizon
	f.d.mu.Lock()
	f.d.authorizationDeadline = time.Now().Add(-time.Second)
	f.d.mu.Unlock()
	f.getattr(file.Item) // authorization
	a := &attach{v3Data: f.d}
	metrics := a.status().MetadataCache
	if len(metrics.GetAttr) != int(v3CacheResultCount) || len(metrics.LookupPolarity) != 3 {
		t.Fatalf("unbounded/absent metrics: %+v", metrics)
	}
	for _, reason := range []string{"cold", "hit", "held", "horizon", "authorization"} {
		if metrics.GetAttr[reason] == 0 {
			t.Errorf("missing getattr reason %s: %v", reason, metrics.GetAttr)
		}
	}
	if metrics.Lookup["unknown_name"] != 2 || metrics.Lookup["hit"] != 1 || metrics.LookupPolarity["positive"] != 1 || metrics.LookupPolarity["negative"] != 2 {
		t.Fatalf("lookup metrics: %+v", metrics)
	}
}

func TestV3CacheMetricsDistinguishTerminalCoordinatorFromSourceHolds(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	record := f.record(file.Item)
	coordinator := f.d.bridge.sourcePublication
	// Withdraw between the initial admission check and the atomic
	// snapshot, without a source holder to obscure the reason.
	f.client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		coordinator.mu.Lock()
		coordinator.terminal = errors.New("coordinator withdrawn")
		coordinator.mu.Unlock()
		return &fakeV3ResponseConsumption{consume: func() {}}
	}
	collector := &v3ReplyResourceCollector{d: f.d}
	ctx := context.WithValue(context.WithValue(context.Background(), v3CallbackContextKey{}, uint64(1)), v3ReplyResourceContextKey{}, collector)
	if _, hit, errno := f.d.serveCachedAttr(ctx, 0, record, nil); hit || errno != 0 {
		t.Fatalf("withdrawn coordinator: hit=%t errno=%d", hit, errno)
	}
	metrics := f.d.cacheMetrics()
	if metrics.GetAttr["terminal"] != 1 || metrics.GetAttr["held"] != 0 || metrics.GetAttr["hit"] != 0 {
		t.Fatalf("withdrawn coordinator metrics = %v", metrics.GetAttr)
	}
}

func TestV3WrittenCachedReplyRemainsInTerminalPublicationLifetime(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	var consumed atomic.Int32
	var revoke func(error)
	f.client.newConsumption = func(force func(error)) authorityrpc.ResponseConsumption {
		revoke = force
		return &fakeV3ResponseConsumption{consume: func() { consumed.Add(1) }}
	}
	a := &attach{ref: "cached-terminal-drain", v3Data: f.d, v3Coherence: f.d.bridge}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{origin: 1, conn: server, attach: a}
	const operationID = uint64(98003)
	publicationTestOperation(t, c, a, operationID)
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 1, operationID, false, &pfslocal.GetAttrRequest{Item: file.Item})
		close(done)
	}()
	if _, err := pfslocal.ReadFrame(peer); err != nil {
		t.Fatal(err)
	}
	<-done
	if consumed.Load() != 0 || revoke == nil {
		t.Fatal("written cache reply escaped publication accounting before ack")
	}
	f.client.poisoned.Store(true)
	revoke(errors.New("terminal publication deadline"))
	if f.d.terminalError() == nil {
		t.Fatal("terminal drain did not revoke the cached publication")
	}
	c.close()
	c.close()
	if consumed.Load() != 1 {
		t.Fatalf("revoked receipt consumed %d times", consumed.Load())
	}
}

func TestV3AuthorityAndCachedReadsKeepTheSameOverlappingSnapshot(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "authority", true: "cache"}[cached], func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			file := f.lookup(f.root, "file")
			admitted, resume := make(chan struct{}), make(chan struct{})
			if !cached {
				read := f.client.read
				f.client.read = func(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
					response, err := read(ctx, req)
					close(admitted)
					<-resume
					return response, err
				}
			}
			a := &attach{ref: "overlap", v3Data: f.d, v3Coherence: f.d.bridge}
			server, peer := net.Pipe()
			defer peer.Close()
			c := &frontendConn{origin: 1, conn: server, attach: a}
			if cached {
				c.testBeforeReplyWrite = func(uint64) { close(admitted); <-resume }
			}
			const operationID = uint64(98004)
			publicationTestOperation(t, c, a, operationID)
			done := make(chan struct{})
			go func() {
				ctx, cancel := withOperationDeadline(context.Background())
				defer cancel()
				c.serveV3Attempt(ctx, a, f.d, 1, operationID, true, &pfslocal.GetAttrRequest{Item: file.Item}, !cached)
				close(done)
			}()
			<-admitted
			size := uint64(42)
			if _, errno := f.dispatch(&pfslocal.SetAttrRequest{Item: file.Item, Size: &size}); errno != 0 {
				t.Fatal(errno)
			}
			close(resume)
			envelope, err := pfslocal.ReadFrame(peer)
			if err != nil {
				t.Fatal(err)
			}
			<-done
			if attr := envelope.Body.(*pfslocal.GetAttrReply).Attr; attr.Size != 3 {
				t.Fatalf("overlapping snapshot size=%d, want 3", attr.Size)
			}
		})
	}
}
