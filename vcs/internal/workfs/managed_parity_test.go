package workfs

// Three-way parity goldens for the ONE canonical managed-entry reducer: the
// SAME durable journal rows are (a) applied live, (b) cold-replayed, and
// (c) materialized through the HistoryCut engine — and the resulting PFC2
// control states (projection digests: sessions, exact outcomes, checkout
// epochs, database-time floors), allocator watermarks, parked-orphan sets,
// and namespace trees must agree byte-for-byte. The scenario deliberately
// mixes successes, deterministic failures (stored outcomes), unused
// reservation identities, env-less benign phantoms, grouped rows, controls,
// and checkout epoch movement. Materialization is additionally proven
// deterministic across a crash/retry rerun (identical object refs).

import (
	"context"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/historycut"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// parityJournal is the in-memory journal source over the fake entry log's
// exact durable payloads, with the recorded hashes the DB would serve.
type parityJournal struct {
	records []historycut.PageRecord
}

func (j *parityJournal) ReadPage(_ context.Context, fromSeq uint64, maxRecords int, _ int64) ([]historycut.PageRecord, error) {
	var out []historycut.PageRecord
	for _, r := range j.records {
		if r.Seq >= fromSeq && len(out) < maxRecords {
			out = append(out, r)
		}
	}
	return out, nil
}

func parityPages(t *testing.T, log *fakeEntryLog) ([]historycut.PageRecord, string) {
	t.Helper()
	log.mu.Lock()
	rows := append([][]byte(nil), log.rows[:log.durable]...)
	log.mu.Unlock()
	var chain [32]byte
	var out []historycut.PageRecord
	for i, payload := range rows {
		rec := historycut.RecordHash(payload)
		chain = historycut.ChainStep(chain, payload)
		out = append(out, historycut.PageRecord{
			Seq:         uint64(i),
			Payload:     payload,
			RecordHash:  hex.EncodeToString(rec[:]),
			ChainDigest: hex.EncodeToString(chain[:]),
		})
	}
	return out, hex.EncodeToString(chain[:])
}

// Each interesting exact record gets its OWN slot so its stored outcome
// remains the slot's retained latest (older sequences retire by design).
func parityEnv(slot uint32, slotSeq uint64, hb byte) *wal.Envelope {
	hash := make([]byte, pfc2.RequestHashBytes)
	hash[0] = hb
	hash[31] = ^hb
	return &wal.Envelope{SessionID: "m1", Generation: 1, Slot: slot, SlotSeq: slotSeq, ReqHash: hash}
}

func parityKey(slot uint32, slotSeq uint64, hb byte) pfc2.ExactKey {
	env := parityEnv(slot, slotSeq, hb)
	key := pfc2.ExactKey{
		Session: pfc2.SessionRef{SessionID: env.SessionID, Generation: env.Generation},
		Slot:    env.Slot, SlotSeq: env.SlotSeq,
	}
	copy(key.RequestHash[:], env.ReqHash)
	return key
}

// buildParityAuthority drives the live scenario and returns the FS and its
// durable log.
func buildParityAuthority(t *testing.T) (*FS, *fakeEntryLog) {
	t.Helper()
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	openManagedSession(t, fs, "m1", 1)

	// Exact create success (slot 0), then the SAME path again with a fresh
	// identity: deterministic EEXIST whose preassigned ino is burned but
	// never used (slot 1 — its own slot keeps the outcome retained).
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "a.txt", Mode: 0o644, Excl: true, Env: parityEnv(0, 1, 0x11)}, nil, "own"); err != nil {
		t.Fatalf("exact create: %v", err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "a.txt", Mode: 0o644, Excl: true, Env: parityEnv(1, 1, 0x22)}, nil, "own"); err != nil {
		t.Fatalf("exact duplicate create: %v", err)
	}
	// Exact write then exact append (stored offsets 0 and 5).
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpWrite, Path: "a.txt", Data: []byte("hello"), Env: parityEnv(2, 1, 0x33)}, nil, "own"); err != nil {
		t.Fatalf("exact write: %v", err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpWrite, Path: "a.txt", Append: true, Data: []byte("tail"), Env: parityEnv(3, 1, 0x44)}, nil, "own"); err != nil {
		t.Fatalf("exact append: %v", err)
	}

	// mkdirAll whose first reservation member is unused (g1 exists).
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpMkdir, Path: "g1", Mode: 0o755, Excl: true}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpMkdir, Path: "g1/g2", Mode: 0o755}, nil, ""); err != nil {
		t.Fatal(err)
	}
	// Env-less benign phantom: remove of a missing path is journaled and
	// tolerated identically everywhere.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "never-existed"}, nil, ""); err != nil {
		t.Fatal(err)
	}

	// Checkout epoch movement: grant then release. The reduced checkout map
	// returns to empty but the next epoch must stay advanced everywhere.
	control, err := fs.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	grant := &pfc2.CheckoutChange{
		Key: parityKey(4, 1, 0x55), Op: pfc2.CheckoutGrant,
		Path: "proj/a", Epoch: control.NextCheckoutEpoch(),
	}
	grant.Key.RequestHash = grant.RequestHash()
	if _, err := fs.CommitEntry(nil, []pfc2.Record{{Kind: pfc2.KindCheckoutChange, CheckoutChange: grant}}, ""); err != nil {
		t.Fatalf("checkout grant: %v", err)
	}
	release := &pfc2.CheckoutChange{
		Key: parityKey(5, 1, 0x66), Op: pfc2.CheckoutRelease,
		Path: "proj/a", Epoch: grant.Epoch,
	}
	release.Key.RequestHash = release.RequestHash()
	if _, err := fs.CommitEntry(nil, []pfc2.Record{{Kind: pfc2.KindCheckoutChange, CheckoutChange: release}}, ""); err != nil {
		t.Fatalf("checkout release: %v", err)
	}

	// Pin a.txt durably, then unlink it: the parked orphan is pin-held, so
	// the asynchronous reap sweep never journals for it — the scenario is
	// deterministic AND the anchor carries a live pin + parked orphan.
	aIno := lazyLstatIno(t, fs, "a.txt")
	pin := &pfc2.OpenPinChange{Session: pfc2.SessionRef{SessionID: "m1", Generation: 1}, Ino: aIno}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{{Kind: pfc2.KindOpenPinChange, OpenPinChange: pin}}, ""); err != nil {
		t.Fatalf("open pin: %v", err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "a.txt"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.commitEntriesGroup([]entrySpec{
		{tree: &wal.Record{Op: wal.OpCreate, Path: "grp1", Mode: 0o600}},
		{tree: &wal.Record{Op: wal.OpCreate, Path: "grp2", Mode: 0o640}},
	}, ""); err != nil {
		t.Fatalf("group: %v", err)
	}
	return fs, log
}

func parityDigest(t *testing.T, st *pfc2.State) [32]byte {
	t.Helper()
	d, err := st.Project().Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func parityOrphans(fs *FS) []uint64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := make([]uint64, 0, len(fs.orphans))
	for ino := range fs.orphans {
		out = append(out, ino)
	}
	return out
}

func assertExactParity(t *testing.T, label string, st *pfc2.State) {
	t.Helper()
	dup := st.CheckExact(parityKey(1, 1, 0x22))
	if dup.Disposition != pfc2.ExactReplay || dup.Outcome.Status != errnos.EEXIST || dup.Outcome.Ino != 0 {
		t.Fatalf("%s: duplicate-create stored outcome = %+v", label, dup)
	}
	app := st.CheckExact(parityKey(3, 1, 0x44))
	if app.Disposition != pfc2.ExactReplay || app.Outcome.Status != errnos.OK ||
		app.Outcome.Offset != 5 || app.Outcome.Count != 4 {
		t.Fatalf("%s: append stored outcome = %+v", label, app)
	}
}

func TestManagedParityLiveReplayMaterialize(t *testing.T) {
	fs, log := buildParityAuthority(t)
	ctx := context.Background()

	liveControl, err := fs.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	liveDigest := parityDigest(t, liveControl)
	assertExactParity(t, "live", liveControl)
	if liveControl.DbTimeFloorMs() == 0 {
		t.Fatal("scenario advanced no database-time floor; the parity would be vacuous")
	}
	if liveControl.NextCheckoutEpoch() == pfc2.FirstEpoch {
		t.Fatal("scenario advanced no checkout epoch; the parity would be vacuous")
	}

	// ── cold replay ────────────────────────────────────────────────────────
	replayed, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("cold replay: %v", err)
	}
	replayedControl, err := replayed.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	if got := parityDigest(t, replayedControl); got != liveDigest {
		t.Fatal("cold replay control projection digest diverges from live")
	}
	assertExactParity(t, "replay", replayedControl)
	if fs.alloc != replayed.alloc {
		t.Fatalf("allocator diverges after cold replay: live %+v, replayed %+v (burned identities must be observed on failure too)",
			fs.alloc, replayed.alloc)
	}
	liveFacts, liveOrphans := workfsFacts(t, fs)
	replayFacts, replayOrphans := workfsFacts(t, replayed)
	if !equalStrings(sortedKeys(liveFacts), sortedKeys(replayFacts)) {
		t.Fatalf("replay path set diverges:\nlive: %v\nreplay: %v", sortedKeys(liveFacts), sortedKeys(replayFacts))
	}
	for p, l := range liveFacts {
		if r := replayFacts[p]; l != r {
			t.Fatalf("replay %q diverges:\nlive:   %+v\nreplay: %+v", p, l, r)
		}
	}
	if len(liveOrphans) != 1 || len(replayOrphans) != 1 {
		t.Fatalf("orphan sets: live %v, replay %v (want the parked a.txt)", liveOrphans, replayOrphans)
	}
	for ino, content := range liveOrphans {
		if replayOrphans[ino] != content {
			t.Fatalf("orphan %d content diverges", ino)
		}
	}

	// ── HistoryCut materialization ─────────────────────────────────────────
	pages, cutDigest := parityPages(t, log)
	facts := historycut.CutFacts{
		CutID: "hcut_parity", Kind: "user", SourceKind: "managed_journal",
		GenerationID: "gen_parity", RecordCodec: "pfj3", ControlCodec: "pfc2",
		SourceBaseSeq: "0", SourceBaseDig: hex.EncodeToString(make([]byte, 32)),
		CutSeqExclusive: strconv.Itoa(len(pages)), CutDigest: cutDigest,
		InodeNamespace: "9",
	}
	spool := historycut.NewSpool()
	m := &historycut.Materializer{Facts: facts, Journal: &parityJournal{records: pages}, Spool: spool}
	res, err := m.Run(ctx)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}

	// Crash/retry determinism: a rerun from scratch produces byte-identical
	// objects (same content-addressed refs for every arm).
	spool2 := historycut.NewSpool()
	m2 := &historycut.Materializer{Facts: facts, Journal: &parityJournal{records: pages}, Spool: spool2}
	res2, err := m2.Run(ctx)
	if err != nil {
		t.Fatalf("re-materialize: %v", err)
	}
	if res2.Root != res.Root || res2.RecoveryRoot != res.RecoveryRoot ||
		(res.ControlRoot == nil) != (res2.ControlRoot == nil) ||
		(res.ControlRoot != nil && *res2.ControlRoot != *res.ControlRoot) {
		t.Fatal("re-materialization produced different object refs; the reduction is not deterministic")
	}

	// The anchor ALWAYS carries a ControlRoot, and adopting it through the
	// production decode path (loadPft2Recovery) rebuilds the EXACT live
	// control state: same projection digest, same epochs, same floors, same
	// stored exact outcomes. With live sessions anchored, this Rebuild is
	// exactly the step that fails when the floor is dropped.
	if res.ControlRoot == nil {
		t.Fatal("materialized anchor carries no control root")
	}
	anchor, err := loadPft2Recovery(ctx, spool, res.RecoveryRoot)
	if err != nil {
		t.Fatalf("adopt materialized anchor: %v", err)
	}
	if anchor.state == nil {
		t.Fatal("materialized anchor rebuilt no control state")
	}
	if got := parityDigest(t, anchor.state); got != liveDigest {
		t.Fatal("materialized control projection digest diverges from live")
	}
	assertExactParity(t, "materialized", anchor.state)
	if anchor.state.DbTimeFloorMs() != liveControl.DbTimeFloorMs() {
		t.Fatalf("materialized database-time floor %d, live %d",
			anchor.state.DbTimeFloorMs(), liveControl.DbTimeFloorMs())
	}
	if anchor.state.NextCheckoutEpoch() != liveControl.NextCheckoutEpoch() {
		t.Fatalf("materialized next checkout epoch %s, live %s",
			anchor.state.NextCheckoutEpoch(), liveControl.NextCheckoutEpoch())
	}

	// Allocator parity: the anchor's high-water covers every logged identity
	// — the EEXIST-burned ino and the unused mkdir member included.
	fs.mu.RLock()
	liveMax := fs.alloc.maxInoSeen
	fs.mu.RUnlock()
	if res.MaxInoSeen != liveMax {
		t.Fatalf("materialized MaxInoSeen %d, live allocator high-water %d (burned identities lost)",
			res.MaxInoSeen, liveMax)
	}

	// Parked-orphan parity, including content.
	liveOrphanInos := parityOrphans(fs)
	if len(anchor.orphans) != len(liveOrphanInos) {
		t.Fatalf("materialized orphan count %d, live %d", len(anchor.orphans), len(liveOrphanInos))
	}
	for _, view := range anchor.orphans {
		if view.Inode.Ino != liveOrphanInos[0] {
			t.Fatalf("materialized orphan ino %d, live %d", view.Inode.Ino, liveOrphanInos[0])
		}
		if got, want := view.Inode.Size, uint64(len("hellotail")); got != want {
			t.Fatalf("materialized orphan size %d, want %d", got, want)
		}
	}

	// Namespace parity for the folded tree: the materialized root serves the
	// same names/identities the live tree does.
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: spool}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"g1", "grp1", "grp2"} {
		entry, err := reader.Lookup(ctx, rootView.Ref, name)
		if err != nil {
			t.Fatalf("materialized lookup %q: %v", name, err)
		}
		if l := liveFacts[name]; l.Ino != entry.Ino {
			t.Fatalf("materialized %q ino %d, live %d", name, entry.Ino, l.Ino)
		}
	}
	if _, err := reader.Lookup(ctx, rootView.Ref, "a.txt"); err == nil {
		t.Fatal("materialized root still names the parked a.txt")
	}
}
