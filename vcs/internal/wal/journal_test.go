package wal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// fakeJournal is an in-memory wal.DurableJournal with the exact semantics the
// remote service implements: epoch-fenced reads, duplicate-tolerant contiguous
// appends, chain digests over canonical payloads. Mutators let tests model
// remote corruption and identity changes.
type fakeJournal struct {
	mu      sync.Mutex
	state   DurableJournalState
	records []Record // records[i].Seq == state.BaseSeq + i

	tamperPayloadAt int64 // record seq whose payload hash/content is corrupted on read (-1 = off)
	misSeqAt        int64 // record seq reported with a shifted LSN on read (-1 = off)
	failAppends     bool
}

func newFakeJournal(t *testing.T, baseCommitID string) *fakeJournal {
	t.Helper()
	epoch, err := randomEpoch()
	if err != nil {
		t.Fatalf("randomEpoch: %v", err)
	}
	return &fakeJournal{
		state: DurableJournalState{
			GenerationID:        "jgen_fake",
			RuntimeGeneration:   1,
			AuthorityGeneration: 1,
			Status:              "active",
			BaseCommitID:        baseCommitID,
			Epoch:               epoch,
		},
		tamperPayloadAt: -1,
		misSeqAt:        -1,
	}
}

func (f *fakeJournal) seed(t *testing.T, records []Record) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	chain := f.state.TipDigest
	for i := range records {
		records[i].Seq = f.state.NextSeq + uint64(i)
		next, err := recordDigest(chain, records[i])
		if err != nil {
			t.Fatalf("recordDigest: %v", err)
		}
		chain = next
	}
	f.records = append(f.records, records...)
	f.state.NextSeq += uint64(len(records))
	f.state.TipDigest = chain
}

func (f *fakeJournal) JournalState() (DurableJournalState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

func (f *fakeJournal) StateExact() (ReplicaState, error) {
	s, _ := f.JournalState()
	return ReplicaState{
		Epoch: s.Epoch, BaseSeq: s.BaseSeq, NextSeq: s.NextSeq,
		BaseDigest: s.BaseDigest, TipDigest: s.TipDigest, HA: true,
	}, nil
}

func (f *fakeJournal) DigestAtExact(epoch, seq uint64) ([32]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if epoch != f.state.Epoch {
		return [32]byte{}, ErrEpochMismatch
	}
	if seq < f.state.BaseSeq || seq > f.state.NextSeq {
		return [32]byte{}, fmt.Errorf("fake: digest %d outside [%d,%d]", seq, f.state.BaseSeq, f.state.NextSeq)
	}
	chain := f.state.BaseDigest
	for _, r := range f.records {
		if r.Seq >= seq {
			break
		}
		var err error
		chain, err = recordDigest(chain, r)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return chain, nil
}

func (f *fakeJournal) RecordsExact(epoch, from, to uint64) ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if epoch != f.state.Epoch {
		return nil, ErrEpochMismatch
	}
	if from < f.state.BaseSeq || to > f.state.NextSeq || to < from {
		return nil, fmt.Errorf("fake: range [%d,%d) outside retained", from, to)
	}
	out := make([]Record, 0, to-from)
	for _, r := range f.records {
		if r.Seq >= from && r.Seq < to {
			if int64(r.Seq) == f.tamperPayloadAt {
				r.Data = append(append([]byte(nil), r.Data...), 0xFF)
			}
			if int64(r.Seq) == f.misSeqAt {
				r.Seq++
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeJournal) AppendBatchExact(epoch uint64, records []Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAppends {
		return errors.New("fake: journal outage")
	}
	if epoch != f.state.Epoch {
		return ErrEpochMismatch
	}
	for _, r := range records {
		switch {
		case r.Seq < f.state.NextSeq:
			stored := f.records[r.Seq-f.state.BaseSeq]
			want, _ := recordDigest([32]byte{}, stored)
			got, _ := recordDigest([32]byte{}, r)
			if want != got {
				return ErrReplicationConflict
			}
		case r.Seq == f.state.NextSeq:
			next, err := recordDigest(f.state.TipDigest, r)
			if err != nil {
				return err
			}
			f.records = append(f.records, r)
			f.state.NextSeq++
			f.state.TipDigest = next
		default:
			return ErrReplicationGap
		}
	}
	return nil
}

func (f *fakeJournal) Append(r Record) error         { return f.AppendBatchExact(f.state.Epoch, []Record{r}) }
func (f *fakeJournal) AppendBatch(rs []Record) error { return f.AppendBatchExact(f.state.Epoch, rs) }
func (f *fakeJournal) Reset() error                  { return errors.New("fake: never reset") }
func (f *fakeJournal) Compact(uint64) error          { return errors.New("fake: exact only") }
func (f *fakeJournal) AdoptExact(uint64, uint64, [32]byte) error {
	return errors.New("fake: never adopt local state")
}

func (f *fakeJournal) CompactExact(epoch, throughSeq uint64, digest [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if epoch != f.state.Epoch {
		return ErrEpochMismatch
	}
	chain := f.state.BaseDigest
	kept := make([]Record, 0, len(f.records))
	for _, r := range f.records {
		if r.Seq < throughSeq {
			var err error
			chain, err = recordDigest(chain, r)
			if err != nil {
				return err
			}
			continue
		}
		kept = append(kept, r)
	}
	if chain != digest {
		return ErrReplicationConflict
	}
	f.records = kept
	f.state.BaseSeq = throughSeq
	f.state.BaseDigest = chain
	return nil
}

func (f *fakeJournal) SetCheckpointCutExact(cut CheckpointCut) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state.HasCheckpoint, f.state.Checkpoint = true, cut
	return nil
}

func (f *fakeJournal) SetMaintenanceCutExact(cut MaintenanceCut) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state.HasMaintenance, f.state.Maintenance = true, cut
	return nil
}

func (f *fakeJournal) CompactMaintenanceExact(cut MaintenanceCut) error {
	digest, err := f.DigestAtExact(cut.Epoch, cut.Watermark)
	if err != nil {
		return err
	}
	return f.CompactExact(cut.Epoch, cut.Watermark, digest)
}

func journalTestRecords(texts ...string) []Record {
	out := make([]Record, len(texts))
	for i, text := range texts {
		out[i] = Record{Op: OpWrite, Path: "/f", Data: []byte(text)}
	}
	return out
}

func TestJournalDigestGoldenVector(t *testing.T) {
	// Pinned in packages/metadata-db/src/journal.test.ts: the shared
	// cross-language chain formula sha256(prev[32] || be64(len) || payload).
	first := []byte("portablefs golden payload")
	second := []byte("second record")
	h1 := ChainDigestBytes([32]byte{}, first)
	if hex.EncodeToString(h1[:]) != "fe09d60c3e04d2da7ca7df524d4fff1de0c0d05621757e5883ddc595bbb05cf3" {
		t.Fatalf("record hash diverged from the TS golden vector: %x", h1)
	}
	h2 := ChainDigestBytes(h1, second)
	if hex.EncodeToString(h2[:]) != "d94275bb13beb719863c6c7daf252cf17487d5a8a8b531ff4610946b39698baa" {
		t.Fatalf("chain digest diverged from the TS golden vector: %x", h2)
	}
}

func TestCanonicalPayloadMatchesRecordDigest(t *testing.T) {
	records := journalTestRecords("alpha", "beta")
	records[0].Seq, records[1].Seq = 7, 8
	prev := [32]byte{1, 2, 3}
	for _, r := range records {
		payload, err := CanonicalPayload(r)
		if err != nil {
			t.Fatalf("CanonicalPayload: %v", err)
		}
		direct, err := recordDigest(prev, r)
		if err != nil {
			t.Fatalf("recordDigest: %v", err)
		}
		if ChainDigestBytes(prev, payload) != direct {
			t.Fatalf("payload chain digest does not match recordDigest for %+v", r)
		}
		prev = direct
	}
}

func TestVerifyCanonicalRecordFailsClosed(t *testing.T) {
	r := Record{Seq: 3, Op: OpWrite, Path: "/f", Data: []byte("payload")}
	payload, err := CanonicalPayload(r)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	hash, err := RecordHash(r)
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	if _, err := VerifyCanonicalRecord(3, payload, hash); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := VerifyCanonicalRecord(3, tampered, hash); !errors.Is(err, ErrJournalDiverged) {
		t.Fatalf("tampered payload accepted: %v", err)
	}
	if _, err := VerifyCanonicalRecord(4, payload, hash); !errors.Is(err, ErrJournalDiverged) {
		t.Fatalf("wrong-seq record accepted: %v", err)
	}
}

func openJournalWAL(t *testing.T, dir string) *WAL {
	t.Helper()
	return openTestWAL(t, filepath.Join(dir, "wal.log"))
}

func TestAttachDurableJournalAdoptsRemoteIdentity(t *testing.T) {
	dir := t.TempDir()
	w := openJournalWAL(t, dir)

	journal := newFakeJournal(t, "cmt_base_1")
	journal.seed(t, journalTestRecords("remote-0", "remote-1", "remote-2"))

	state, err := w.AttachDurableJournal(journal)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if state.BaseCommitID != "cmt_base_1" {
		t.Fatalf("unexpected base commit: %q", state.BaseCommitID)
	}
	local := w.State()
	if local.Epoch != journal.state.Epoch || local.NextSeq != 3 || local.TipDigest != journal.state.TipDigest {
		t.Fatalf("local cache did not adopt remote identity: %+v", local)
	}
	if w.BaseCommitID() != "cmt_base_1" {
		t.Fatalf("BaseCommitID not adopted: %q", w.BaseCommitID())
	}
	replayed, err := w.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(replayed) != 3 || string(replayed[2].Data) != "remote-2" {
		t.Fatalf("replayed cache does not carry the remote suffix: %+v", replayed)
	}

	// Appends flow through the journal (replicate-before-ack).
	if err := w.Append(Record{Op: OpWrite, Path: "/f", Data: []byte("local-3")}); err != nil {
		t.Fatalf("append after attach: %v", err)
	}
	if journal.state.NextSeq != 4 {
		t.Fatalf("journal did not receive the append: %d", journal.state.NextSeq)
	}
	if w.State().TipDigest != journal.state.TipDigest {
		t.Fatalf("tips diverged after append")
	}

	// BaseCommitID survives close/reopen: recovery knows the exact manifest.
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened := openJournalWAL(t, dir)
	if reopened.BaseCommitID() != "cmt_base_1" {
		t.Fatalf("BaseCommitID lost across restart: %q", reopened.BaseCommitID())
	}
	if !reopened.RequiresReplica() {
		t.Fatalf("journal cache must fence writes until re-attached")
	}
}

func TestAttachDurableJournalPullsRemoteAheadSuffix(t *testing.T) {
	dir := t.TempDir()
	w := openJournalWAL(t, dir)
	journal := newFakeJournal(t, "cmt_base_1")
	journal.seed(t, journalTestRecords("shared-0", "shared-1"))
	if _, err := w.AttachDurableJournal(journal); err != nil {
		t.Fatalf("first attach: %v", err)
	}

	// The journal advances while this authority is detached (a takeover wrote
	// more records); on re-attach the missing suffix is pulled, not rebuilt.
	journal.seed(t, journalTestRecords("ahead-2", "ahead-3"))
	if _, err := w.AttachDurableJournal(journal); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	local := w.State()
	if local.NextSeq != 4 || local.TipDigest != journal.state.TipDigest {
		t.Fatalf("remote-ahead suffix not pulled: %+v", local)
	}
	records, err := w.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(records) != 4 || string(records[3].Data) != "ahead-3" {
		t.Fatalf("pulled records wrong: %+v", records)
	}
}

func TestAttachDurableJournalDiscardsLocalAheadState(t *testing.T) {
	dir := t.TempDir()
	w := openJournalWAL(t, dir)
	journal := newFakeJournal(t, "cmt_base_1")
	journal.seed(t, journalTestRecords("shared-0"))
	if _, err := w.AttachDurableJournal(journal); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Simulate local-ahead state: a record fsync'd locally whose remote append
	// never happened (the classic resurrection hazard). Detach the replica so
	// the append stays local-only.
	w.SetReplica(nil)
	w.mu.Lock()
	w.haRequired = false
	w.mu.Unlock()
	if err := w.Append(Record{Op: OpWrite, Path: "/f", Data: []byte("never-acked")}); err != nil {
		t.Fatalf("local-only append: %v", err)
	}
	if w.State().NextSeq != 2 {
		t.Fatalf("expected local-ahead state")
	}

	// Remote wins: the unacknowledged local suffix is rebuilt away, never pushed.
	if _, err := w.AttachDurableJournal(journal); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	local := w.State()
	if local.NextSeq != 1 || local.TipDigest != journal.state.TipDigest {
		t.Fatalf("local-ahead state survived attach: %+v", local)
	}
	if journal.state.NextSeq != 1 {
		t.Fatalf("local state was pushed into the journal")
	}
	records, err := w.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(records) != 1 || string(records[0].Data) != "shared-0" {
		t.Fatalf("rebuilt cache wrong: %+v", records)
	}
}

func TestAttachDurableJournalRebuildsOnEpochBaseOrDigestMismatch(t *testing.T) {
	cases := []struct {
		name string
		warp func(t *testing.T, w *WAL, journal *fakeJournal)
	}{
		{
			name: "epoch mismatch",
			warp: func(t *testing.T, w *WAL, journal *fakeJournal) {
				journal.mu.Lock()
				journal.state.Epoch++
				journal.mu.Unlock()
			},
		},
		{
			name: "base mismatch",
			warp: func(t *testing.T, w *WAL, journal *fakeJournal) {
				// Remote compacts its first record; local base stays behind.
				digest, err := journal.DigestAtExact(journal.state.Epoch, 1)
				if err != nil {
					t.Fatalf("digest: %v", err)
				}
				if err := journal.CompactExact(journal.state.Epoch, 1, digest); err != nil {
					t.Fatalf("compact: %v", err)
				}
			},
		},
		{
			name: "digest conflict",
			warp: func(t *testing.T, w *WAL, journal *fakeJournal) {
				// Rewrite remote history at the same LSNs (different content).
				journal.mu.Lock()
				journal.records = nil
				journal.state.NextSeq = journal.state.BaseSeq
				journal.state.TipDigest = journal.state.BaseDigest
				journal.mu.Unlock()
				journal.seed(t, journalTestRecords("DIFFERENT-0", "DIFFERENT-1", "DIFFERENT-2"))
			},
		},
		{
			name: "base commit mismatch",
			warp: func(t *testing.T, w *WAL, journal *fakeJournal) {
				journal.mu.Lock()
				journal.state.BaseCommitID = "cmt_other"
				journal.mu.Unlock()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			w := openJournalWAL(t, dir)
			journal := newFakeJournal(t, "cmt_base_1")
			journal.seed(t, journalTestRecords("r0", "r1"))
			if _, err := w.AttachDurableJournal(journal); err != nil {
				t.Fatalf("attach: %v", err)
			}
			tc.warp(t, w, journal)
			if _, err := w.AttachDurableJournal(journal); err != nil {
				t.Fatalf("re-attach after %s: %v", tc.name, err)
			}
			local := w.State()
			journal.mu.Lock()
			remote := journal.state
			journal.mu.Unlock()
			if local.Epoch != remote.Epoch || local.BaseSeq != remote.BaseSeq ||
				local.NextSeq != remote.NextSeq || local.TipDigest != remote.TipDigest ||
				local.BaseDigest != remote.BaseDigest {
				t.Fatalf("local cache did not adopt remote identity after %s: %+v vs %+v", tc.name, local, remote)
			}
			if w.BaseCommitID() != remote.BaseCommitID {
				t.Fatalf("BaseCommitID not adopted after %s", tc.name)
			}
		})
	}
}

func TestAttachDurableJournalFailsClosedOnRemoteCorruption(t *testing.T) {
	cases := []struct {
		name string
		warp func(journal *fakeJournal)
	}{
		{"tampered payload", func(j *fakeJournal) { j.tamperPayloadAt = 1 }},
		{"shifted LSN", func(j *fakeJournal) { j.misSeqAt = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			w := openJournalWAL(t, dir)
			// Local has its own prior identity so a rebuild is required.
			if err := w.Append(Record{Op: OpWrite, Path: "/f", Data: []byte("local")}); err != nil {
				t.Fatalf("append: %v", err)
			}
			before := w.State()

			journal := newFakeJournal(t, "cmt_base_1")
			journal.seed(t, journalTestRecords("r0", "r1", "r2"))
			tc.warp(journal)

			if _, err := w.AttachDurableJournal(journal); err == nil {
				t.Fatalf("corrupted journal was accepted")
			}
			after := w.State()
			if after != before {
				t.Fatalf("failed attach mutated the local cache: %+v -> %+v", before, after)
			}
			if w.IsPoisoned() {
				t.Fatalf("failed attach must not poison the local WAL")
			}
			// The corrupt journal was never published as a replica.
			if err := w.Append(Record{Op: OpWrite, Path: "/f", Data: []byte("still-local")}); err != nil {
				t.Fatalf("local append after failed attach: %v", err)
			}
			if journal.state.NextSeq != 3 {
				t.Fatalf("journal unexpectedly received records")
			}
		})
	}
}

func TestAttachDurableJournalRefusesTerminalGenerations(t *testing.T) {
	dir := t.TempDir()
	w := openJournalWAL(t, dir)
	journal := newFakeJournal(t, "cmt_base_1")
	journal.state.Status = "retired"
	if _, err := w.AttachDurableJournal(journal); err == nil {
		t.Fatalf("attached to a retired generation")
	}
	journal.state.Status = "abandoned"
	if _, err := w.AttachDurableJournal(journal); err == nil {
		t.Fatalf("attached to an abandoned generation")
	}
}

func TestJournalOutageFencesWritesBeforeVisibility(t *testing.T) {
	dir := t.TempDir()
	w := openJournalWAL(t, dir)
	journal := newFakeJournal(t, "cmt_base_1")
	if _, err := w.AttachDurableJournal(journal); err != nil {
		t.Fatalf("attach: %v", err)
	}
	journal.mu.Lock()
	journal.failAppends = true
	journal.mu.Unlock()
	if err := w.Append(Record{Op: OpWrite, Path: "/f", Data: []byte("doomed")}); err == nil {
		t.Fatalf("append succeeded during journal outage")
	}
	if !w.IsPoisoned() {
		t.Fatalf("journal outage must poison (fence) the WAL before visibility")
	}
	select {
	case <-w.PoisonedCh():
	default:
		t.Fatalf("poison channel not closed")
	}
}

func TestBaseCommitIDSurvivesCompactionAndClearsOnReset(t *testing.T) {
	dir := t.TempDir()
	w := openJournalWAL(t, dir)
	journal := newFakeJournal(t, "cmt_base_1")
	journal.seed(t, journalTestRecords("r0", "r1"))
	if _, err := w.AttachDurableJournal(journal); err != nil {
		t.Fatalf("attach: %v", err)
	}
	// Detach into standalone mode so compaction/reset run without HA guards.
	w.SetReplica(nil)
	w.mu.Lock()
	w.haRequired = false
	w.mu.Unlock()
	if err := w.CompactThrough(1); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if w.BaseCommitID() != "cmt_base_1" {
		t.Fatalf("compaction dropped BaseCommitID")
	}
	if err := w.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if w.BaseCommitID() != "" {
		t.Fatalf("reset kept a stale BaseCommitID")
	}
}
