package wal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/ctlrec"
)

func openTestWAL(t *testing.T, path string) *WAL {
	t.Helper()
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func controlPayload(t *testing.T, p ctlrec.Payload) []byte {
	t.Helper()
	b, err := ctlrec.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func appendControlRotationFixture(t *testing.T, w *WAL) (uint64, uint64) {
	t.Helper()
	if err := w.Append(Record{Op: OpControl, Data: controlPayload(t, ctlrec.Payload{
		Kind: ctlrec.KindSession, Session: &ctlrec.Session{SessionID: "s", Generation: 1, Slots: 1},
	})}); err != nil {
		t.Fatal(err)
	}
	cut := w.Watermark()
	if err := w.Append(Record{Op: OpControl, Data: controlPayload(t, ctlrec.Payload{
		Kind: ctlrec.KindSnapshot, Snapshot: &ctlrec.Snapshot{AsOfLSN: cut},
	})}); err != nil {
		t.Fatal(err)
	}
	return cut, cut
}

func TestReplicatedAppendRejectsGapAndConflictingDuplicate(t *testing.T) {
	w := openTestWAL(t, filepath.Join(t.TempDir(), "standby.wal"))
	original := Record{Seq: 0, Op: OpCreate, Path: "a", Mode: 0o644}
	if err := w.AppendReplicated(original); err != nil {
		t.Fatal(err)
	}
	if err := w.AppendReplicated(original); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	if err := w.AppendReplicated(Record{Seq: 0, Op: OpCreate, Path: "different", Mode: 0o644}); !errors.Is(err, ErrReplicationConflict) {
		t.Fatalf("conflicting duplicate error = %v, want ErrReplicationConflict", err)
	}
	if err := w.AppendReplicated(Record{Seq: 2, Op: OpCreate, Path: "gap", Mode: 0o644}); !errors.Is(err, ErrReplicationGap) {
		t.Fatalf("gap error = %v, want ErrReplicationGap", err)
	}
	got, err := w.Replay()
	if err != nil || len(got) != 1 || got[0].Path != "a" {
		t.Fatalf("rejected writes changed prefix: records=%+v err=%v", got, err)
	}
}

func TestEmptyCompactionPersistsEpochBaseAndDigestAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "primary.wal")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		if err := w.Append(Record{Op: OpCreate, Path: name, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	before := w.State()
	if before.Epoch == 0 || before.TipDigest == ([32]byte{}) {
		t.Fatalf("uninitialised state: %+v", before)
	}
	if err := w.CompactThrough(before.NextSeq); err != nil {
		t.Fatal(err)
	}
	compacted := w.State()
	if compacted.BaseSeq != before.NextSeq || compacted.NextSeq != before.NextSeq || compacted.BaseDigest != before.TipDigest || compacted.TipDigest != before.TipDigest {
		t.Fatalf("bad empty compacted state: before=%+v after=%+v", before, compacted)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	after := w2.State()
	if after.Epoch != before.Epoch || after.BaseSeq != compacted.BaseSeq || after.NextSeq != compacted.NextSeq || after.BaseDigest != compacted.BaseDigest || after.TipDigest != compacted.TipDigest {
		t.Fatalf("metadata lost across restart: compacted=%+v reopened=%+v", compacted, after)
	}
	if records, err := w2.Replay(); err != nil || len(records) != 0 {
		t.Fatalf("empty replay=%+v err=%v", records, err)
	}
	seq, err := w2.AppendBuffered(Record{Op: OpCreate, Path: "d", Mode: 0o644})
	if err != nil || seq != compacted.NextSeq {
		t.Fatalf("post-compaction append seq=%d err=%v, want %d", seq, err, compacted.NextSeq)
	}
}

func TestMissingMetadataForExistingEmptyWALFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "covered"}); err != nil {
		t.Fatal(err)
	}
	if err := w.CompactThrough(w.Watermark()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".meta"); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if !w2.State().Legacy {
		t.Fatal("existing empty WAL without metadata was treated as pristine")
	}
	if _, err := w2.AppendBuffered(Record{Op: OpCreate, Path: "unsafe"}); !errors.Is(err, ErrLegacyReplica) {
		t.Fatalf("metadata-loss append error=%v, want ErrLegacyReplica", err)
	}
}

func TestAttachRepairsAckLossSuffixInEitherDirection(t *testing.T) {
	dir := t.TempDir()
	primary := openTestWAL(t, filepath.Join(dir, "primary.wal"))
	standby := openTestWAL(t, filepath.Join(dir, "standby.wal"))
	for _, name := range []string{"a", "b"} {
		if err := primary.Append(Record{Op: OpCreate, Path: name, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := primary.AttachReplica(standby); err != nil {
		t.Fatal(err)
	}
	primary.SetReplica(nil)

	// Simulate response loss after the standby durably stored LSN 2 while the
	// restarting primary retained only the common prefix.
	epoch := primary.State().Epoch
	lostAck := Record{Seq: primary.State().NextSeq, Op: OpCreate, Path: "ack-lost", Mode: 0o644}
	if err := standby.AppendReplicatedExact(epoch, []Record{lostAck}); err != nil {
		t.Fatal(err)
	}
	if err := primary.AttachReplica(standby); err != nil {
		t.Fatalf("reconcile remote suffix: %v", err)
	}
	got, err := primary.Replay()
	if err != nil || len(got) != 3 || got[2].Path != "ack-lost" {
		t.Fatalf("primary did not pull exact suffix: %+v err=%v", got, err)
	}
	if primary.State().TipDigest != standby.State().TipDigest {
		t.Fatal("replicas did not converge")
	}
}

func TestAttachRejectsDivergentSuffixWithoutReset(t *testing.T) {
	dir := t.TempDir()
	primary := openTestWAL(t, filepath.Join(dir, "primary.wal"))
	standby := openTestWAL(t, filepath.Join(dir, "standby.wal"))
	if err := primary.Append(Record{Op: OpCreate, Path: "common", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := primary.AttachReplica(standby); err != nil {
		t.Fatal(err)
	}
	primary.SetReplica(nil)
	epoch, seq := primary.State().Epoch, primary.State().NextSeq
	if err := primary.AppendReplicatedExact(epoch, []Record{{Seq: seq, Op: OpCreate, Path: "primary"}}); err != nil {
		t.Fatal(err)
	}
	if err := standby.AppendReplicatedExact(epoch, []Record{{Seq: seq, Op: OpCreate, Path: "standby"}}); err != nil {
		t.Fatal(err)
	}
	before := standby.State()
	if err := primary.AttachReplica(standby); !errors.Is(err, ErrReplicationConflict) {
		t.Fatalf("divergent attach error=%v, want ErrReplicationConflict", err)
	}
	if after := standby.State(); after != before {
		t.Fatalf("failed attach changed standby: before=%+v after=%+v", before, after)
	}
}

func TestPromotedHAMemberRefusesSingleCopyWritesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	primary := openTestWAL(t, filepath.Join(dir, "primary.wal"))
	standbyPath := filepath.Join(dir, "standby.wal")
	standby, err := Open(standbyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.AttachReplica(standby); err != nil {
		t.Fatal(err)
	}
	if err := primary.Append(Record{Op: OpCreate, Path: "durable", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := standby.Close(); err != nil {
		t.Fatal(err)
	}
	promoted, err := Open(standbyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer promoted.Close()
	if !promoted.RequiresReplica() {
		t.Fatal("HA membership did not survive restart")
	}
	if _, err := promoted.AppendBuffered(Record{Op: OpCreate, Path: "single-copy"}); !errors.Is(err, ErrReplicaRequired) {
		t.Fatalf("single-copy promoted write error=%v, want ErrReplicaRequired", err)
	}
	replacement := openTestWAL(t, filepath.Join(dir, "replacement.wal"))
	if err := promoted.AttachReplica(replacement); err != nil {
		t.Fatalf("attach replacement: %v", err)
	}
	if err := promoted.Append(Record{Op: OpCreate, Path: "two-copy", Mode: 0o644}); err != nil {
		t.Fatalf("write after replacement: %v", err)
	}
}

type legacyOnlyReplica struct{ w *WAL }

func (l legacyOnlyReplica) Append(r Record) error         { return l.w.AppendReplicated(r) }
func (l legacyOnlyReplica) AppendBatch(rs []Record) error { return l.w.AppendReplicatedBatch(rs) }
func (l legacyOnlyReplica) Reset() error                  { return l.w.Reset() }
func (l legacyOnlyReplica) Compact(seq uint64) error      { return l.w.CompactThrough(seq) }

func TestAttachLegacyReplicaFailsClosed(t *testing.T) {
	primary := openTestWAL(t, filepath.Join(t.TempDir(), "primary.wal"))
	standby := openTestWAL(t, filepath.Join(t.TempDir(), "standby.wal"))
	if err := primary.AttachReplica(legacyOnlyReplica{w: standby}); !errors.Is(err, ErrLegacyReplica) {
		t.Fatalf("legacy attach error=%v, want ErrLegacyReplica", err)
	}
}

func TestRestartReconcilesInterruptedCompactionMetadataTransition(t *testing.T) {
	t.Run("intent before rewrite keeps old prefix", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal")
		w, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"a", "b"} {
			if err := w.Append(Record{Op: OpCreate, Path: p}); err != nil {
				t.Fatal(err)
			}
		}
		old := w.State()
		w.mu.Lock()
		target := metadata{Version: metadataVersion, Epoch: old.Epoch, BaseSeq: old.NextSeq, BaseDigest: old.TipDigest}
		if err := w.beginTransitionLocked(target, old.NextSeq, old.TipDigest); err != nil {
			w.mu.Unlock()
			t.Fatal(err)
		}
		w.mu.Unlock()
		_ = w.Close() // crash before WAL rename

		w2, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer w2.Close()
		if got := w2.State(); got.BaseSeq != old.BaseSeq || got.NextSeq != old.NextSeq || got.TipDigest != old.TipDigest {
			t.Fatalf("pre-rewrite intent changed prefix: old=%+v got=%+v", old, got)
		}
	})

	t.Run("rewrite before metadata installs target", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal")
		w, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"a", "b"} {
			if err := w.Append(Record{Op: OpCreate, Path: p}); err != nil {
				t.Fatal(err)
			}
		}
		old := w.State()
		w.commitMu.Lock()
		w.mu.Lock()
		target := metadata{Version: metadataVersion, Epoch: old.Epoch, BaseSeq: old.NextSeq, BaseDigest: old.TipDigest}
		if err := w.beginTransitionLocked(target, old.NextSeq, old.TipDigest); err != nil {
			w.mu.Unlock()
			w.commitMu.Unlock()
			t.Fatal(err)
		}
		if err := w.rewriteLocked(nil); err != nil {
			w.mu.Unlock()
			w.commitMu.Unlock()
			t.Fatal(err)
		}
		w.mu.Unlock()
		w.commitMu.Unlock()
		_ = w.Close() // crash after WAL rename, before metadata rename

		w2, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer w2.Close()
		got := w2.State()
		if got.BaseSeq != old.NextSeq || got.NextSeq != old.NextSeq || got.BaseDigest != old.TipDigest || got.TipDigest != old.TipDigest {
			t.Fatalf("post-rewrite transition not recovered: old=%+v got=%+v", old, got)
		}
	})
}

type faultExactReplica struct {
	*WAL
	failSetBefore, failSetAfter                                                 bool
	failCompactAfter, failMaintenanceCompactAfter, failMaintenanceFinalizeAfter bool
}

func (r *faultExactReplica) SetCheckpointCutExact(cut CheckpointCut) error {
	if r.failSetBefore {
		return errors.New("injected checkpoint replication failure")
	}
	err := r.WAL.SetCheckpointCutExact(cut)
	if err == nil && r.failSetAfter {
		return errors.New("injected checkpoint ACK loss")
	}
	return err
}

func (r *faultExactReplica) CompactExact(epoch, seq uint64, digest [32]byte) error {
	err := r.WAL.CompactExact(epoch, seq, digest)
	if err == nil && r.failCompactAfter {
		return errors.New("injected compact ACK loss")
	}
	return err
}

func (r *faultExactReplica) SetMaintenanceCutExact(cut MaintenanceCut) error {
	err := r.WAL.SetMaintenanceCutExact(cut)
	if err == nil && cut.Status == MaintenanceFinalized && r.failMaintenanceFinalizeAfter {
		return errors.New("injected maintenance finalize ACK loss")
	}
	return err
}

func (r *faultExactReplica) CompactMaintenanceExact(cut MaintenanceCut) error {
	err := r.WAL.CompactMaintenanceExact(cut)
	if err == nil && r.failMaintenanceCompactAfter {
		return errors.New("injected maintenance compact ACK loss")
	}
	return err
}

func checkpointFixture(t *testing.T) (*WAL, *WAL, *faultExactReplica, CheckpointCut) {
	t.Helper()
	dir := t.TempDir()
	primary := openTestWAL(t, filepath.Join(dir, "primary"))
	standby := openTestWAL(t, filepath.Join(dir, "standby"))
	replica := &faultExactReplica{WAL: standby}
	if err := primary.AttachReplica(replica); err != nil {
		t.Fatal(err)
	}
	if err := primary.Append(Record{Op: OpCreate, Path: "covered", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	cut := CheckpointCut{
		OperationID: "pfck_test", Watermark: primary.Watermark(), ExpectedHeadCommitID: "cmt_old",
		TreeHash: "sha256:tree", CanonicalRequestHash: "sha256:request", AuxiliaryBlobDigestsHash: "sha256:aux",
	}
	return primary, standby, replica, cut
}

func TestCheckpointPrepareFailurePreventsDispatchAndLeavesStandbyUnchanged(t *testing.T) {
	primary, standby, replica, cut := checkpointFixture(t)
	replica.failSetBefore = true
	if _, err := primary.PrepareCheckpointCut(cut); err == nil {
		t.Fatal("prepare unexpectedly succeeded")
	}
	if _, ok := primary.CheckpointCutState(); !ok {
		t.Fatal("local retry intent was not retained")
	}
	if _, ok := standby.CheckpointCutState(); ok {
		t.Fatal("failed pre-dispatch replication changed standby")
	}
}

func TestCheckpointCutBindsAuxiliaryDigestSet(t *testing.T) {
	primary, _, _, cut := checkpointFixture(t)
	if _, err := primary.PrepareCheckpointCut(cut); err != nil {
		t.Fatal(err)
	}
	changed := cut
	changed.AuxiliaryBlobDigestsHash = "sha256:different"
	if _, err := primary.PrepareCheckpointCut(changed); err == nil {
		t.Fatal("same checkpoint operation accepted a changed auxiliary digest set")
	}
}

func TestLandedCheckpointRejectsPartialBaseAdoption(t *testing.T) {
	primary, _, _, cut := checkpointFixture(t)
	if cut.Watermark == 0 {
		t.Fatal("fixture must contain a non-empty checkpoint cut")
	}
	if _, err := primary.PrepareCheckpointCut(cut); err != nil {
		t.Fatal(err)
	}
	if err := primary.ResolveCheckpointCut(cut.OperationID, "cmt_exact_cut", true); err != nil {
		t.Fatal(err)
	}
	before := primary.State()
	if err := primary.CompactThrough(cut.Watermark - 1); err == nil {
		t.Fatal("partial compaction adopted a later checkpoint base")
	}
	after := primary.State()
	if after.BaseSeq != before.BaseSeq || after.BaseDigest != before.BaseDigest {
		t.Fatalf("rejected partial compaction changed the base: before=%+v after=%+v", before, after)
	}
}

func TestCheckpointResolveAckLossLeavesPromotableStandbyLanded(t *testing.T) {
	primary, standby, replica, cut := checkpointFixture(t)
	if _, err := primary.PrepareCheckpointCut(cut); err != nil {
		t.Fatal(err)
	}
	replica.failSetAfter = true
	if err := primary.ResolveCheckpointCut(cut.OperationID, "cmt_new", true); err == nil {
		t.Fatal("resolve ACK loss not surfaced")
	}
	local, _ := primary.CheckpointCutState()
	remote, _ := standby.CheckpointCutState()
	if local.Status != CheckpointPrepared {
		t.Fatalf("local status=%s, want prepared", local.Status)
	}
	if remote.Status != CheckpointLanded || remote.CommitID != "cmt_new" {
		t.Fatalf("standby lacks landed proof after ACK loss: %+v", remote)
	}
}

func TestCompactionAckLossIsStandbyFirstAndAttachRepairsLocalBase(t *testing.T) {
	primary, standby, replica, cut := checkpointFixture(t)
	if _, err := primary.PrepareCheckpointCut(cut); err != nil {
		t.Fatal(err)
	}
	if err := primary.ResolveCheckpointCut(cut.OperationID, "cmt_new", true); err != nil {
		t.Fatal(err)
	}
	replica.failCompactAfter = true
	if err := primary.CompactThrough(cut.Watermark); err == nil {
		t.Fatal("compact ACK loss not surfaced")
	}
	if got := primary.CompactedThrough(); got >= cut.Watermark {
		t.Fatalf("local compacted before standby ACK: %d", got)
	}
	if got := standby.CompactedThrough(); got != cut.Watermark {
		t.Fatalf("standby did not compact first: %d", got)
	}

	primary.SetReplica(nil)
	if err := primary.AttachReplica(standby); err != nil {
		t.Fatalf("reconcile compacted standby: %v", err)
	}
	if primary.CompactedThrough() != cut.Watermark || primary.State().BaseDigest != standby.State().BaseDigest {
		t.Fatalf("attach did not reconcile compacted base: primary=%+v standby=%+v", primary.State(), standby.State())
	}
	if err := primary.FinalizeCheckpointCut(cut.OperationID); err != nil {
		t.Fatal(err)
	}
	remote, _ := standby.CheckpointCutState()
	if remote.Status != CheckpointFinalized {
		t.Fatalf("standby final status=%s", remote.Status)
	}
}

func TestControlOnlyRotationRejectsUserPrefixAndAcceptsControlBatch(t *testing.T) {
	t.Run("reject user", func(t *testing.T) {
		w := openTestWAL(t, filepath.Join(t.TempDir(), "wal"))
		if err := w.Append(Record{Op: OpCreate, Path: "user"}); err != nil {
			t.Fatal(err)
		}
		cut := w.Watermark()
		data := controlPayload(t, ctlrec.Payload{Kind: ctlrec.KindSnapshot, Snapshot: &ctlrec.Snapshot{AsOfLSN: cut}})
		if err := w.Append(Record{Op: OpControl, Data: data}); err != nil {
			t.Fatal(err)
		}
		if err := w.RotateControlOnlyThrough(cut, cut); err == nil {
			t.Fatal("rotation compacted a user mutation")
		}
		if w.CompactedThrough() != 0 {
			t.Fatal("rejected rotation changed base")
		}
	})

	t.Run("control batch", func(t *testing.T) {
		w := openTestWAL(t, filepath.Join(t.TempDir(), "wal"))
		data := controlPayload(t, ctlrec.Payload{Kind: ctlrec.KindSession, Session: &ctlrec.Session{SessionID: "s", Generation: 1, Slots: 1}})
		leaf := Record{Op: OpControl, Data: data}
		if err := w.Append(Record{Op: OpBatch, Mutations: []Record{leaf, leaf}}); err != nil {
			t.Fatal(err)
		}
		cut := w.Watermark()
		sidecar := controlPayload(t, ctlrec.Payload{Kind: ctlrec.KindSnapshot, Snapshot: &ctlrec.Snapshot{AsOfLSN: cut}})
		if err := w.Append(Record{Op: OpControl, Data: sidecar}); err != nil {
			t.Fatal(err)
		}
		if err := w.RotateControlOnlyThrough(cut, cut); err != nil {
			t.Fatal(err)
		}
		if w.CompactedThrough() != cut || w.Count() != 1 {
			t.Fatalf("rotation base=%d count=%d", w.CompactedThrough(), w.Count())
		}
	})
}

func TestHAControlRotationResolvesCompactAndFinalizeAckLoss(t *testing.T) {
	dir := t.TempDir()
	primary := openTestWAL(t, filepath.Join(dir, "primary"))
	standby := openTestWAL(t, filepath.Join(dir, "standby"))
	replica := &faultExactReplica{WAL: standby, failMaintenanceCompactAfter: true, failMaintenanceFinalizeAfter: true}
	if err := primary.AttachReplica(replica); err != nil {
		t.Fatal(err)
	}
	cut, sidecar := appendControlRotationFixture(t, primary)
	if err := primary.RotateControlOnlyThrough(cut, sidecar); err != nil {
		t.Fatalf("ACK-loss reconciliation: %v", err)
	}
	local, remote := primary.State(), standby.State()
	if local.BaseSeq != cut || remote.BaseSeq != cut || !local.HasMaintenance || !remote.HasMaintenance || local.Maintenance.Status != MaintenanceFinalized || remote.Maintenance.Status != MaintenanceFinalized {
		t.Fatalf("rotation did not converge: local=%+v remote=%+v", local, remote)
	}
}

func TestPreparedControlRotationRecoversOnPromotionAndAttach(t *testing.T) {
	t.Run("promoted single member", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal")
		w, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		cut, sidecar := appendControlRotationFixture(t, w)
		hash := w.recordHashes[sidecar]
		prepared := MaintenanceCut{OperationID: maintenanceID(w.Epoch(), cut, sidecar, hash), Epoch: w.Epoch(), Watermark: cut, SidecarSeq: sidecar, SidecarHash: hash, Status: MaintenancePrepared}
		if err := w.SetMaintenanceCutExact(prepared); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		promoted, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer promoted.Close()
		if err := promoted.RecoverControlRotation(); err != nil {
			t.Fatal(err)
		}
		state := promoted.State()
		if state.BaseSeq != cut || state.Maintenance.Status != MaintenanceFinalized {
			t.Fatalf("promotion did not recover: %+v", state)
		}
	})

	t.Run("standby compacted before primary crash", func(t *testing.T) {
		dir := t.TempDir()
		primary := openTestWAL(t, filepath.Join(dir, "primary"))
		standby := openTestWAL(t, filepath.Join(dir, "standby"))
		if err := primary.AttachReplica(standby); err != nil {
			t.Fatal(err)
		}
		cut, sidecar := appendControlRotationFixture(t, primary)
		hash := primary.recordHashes[sidecar]
		prepared := MaintenanceCut{OperationID: maintenanceID(primary.Epoch(), cut, sidecar, hash), Epoch: primary.Epoch(), Watermark: cut, SidecarSeq: sidecar, SidecarHash: hash, Status: MaintenancePrepared}
		if err := primary.SetMaintenanceCutExact(prepared); err != nil {
			t.Fatal(err)
		}
		if err := standby.SetMaintenanceCutExact(prepared); err != nil {
			t.Fatal(err)
		}
		if err := standby.CompactMaintenanceExact(prepared); err != nil {
			t.Fatal(err)
		}
		primary.SetReplica(nil)
		if err := primary.AttachReplica(standby); err != nil {
			t.Fatal(err)
		}
		if primary.State().Maintenance.Status != MaintenanceFinalized || standby.State().Maintenance.Status != MaintenanceFinalized {
			t.Fatal("attach did not finalize prepared rotation")
		}
	})
}

func TestReopenedHAMemberRecoveryNeverUsesOrdinaryReplicaFlush(t *testing.T) {
	t.Run("no maintenance", func(t *testing.T) {
		dir := t.TempDir()
		primary := openTestWAL(t, filepath.Join(dir, "primary"))
		standbyPath := filepath.Join(dir, "standby")
		standby, err := Open(standbyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := primary.AttachReplica(standby); err != nil {
			t.Fatal(err)
		}
		if err := primary.Append(Record{Op: OpCreate, Path: "durable"}); err != nil {
			t.Fatal(err)
		}
		_ = standby.Close()
		promoted, err := Open(standbyPath)
		if err != nil {
			t.Fatal(err)
		}
		defer promoted.Close()
		if err := promoted.RecoverControlRotation(); err != nil {
			t.Fatal(err)
		}
		if promoted.IsPoisoned() {
			t.Fatal("no-op recovery poisoned reopened HA WAL")
		}
		if _, err := promoted.AppendBuffered(Record{Op: OpCreate, Path: "single"}); !errors.Is(err, ErrReplicaRequired) {
			t.Fatalf("write fence error=%v", err)
		}
	})

	t.Run("prepared maintenance", func(t *testing.T) {
		dir := t.TempDir()
		primary := openTestWAL(t, filepath.Join(dir, "primary"))
		standbyPath := filepath.Join(dir, "standby")
		standby, err := Open(standbyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := primary.AttachReplica(standby); err != nil {
			t.Fatal(err)
		}
		cut, sidecar := appendControlRotationFixture(t, primary)
		hash := primary.recordHashes[sidecar]
		prepared := MaintenanceCut{OperationID: maintenanceID(primary.Epoch(), cut, sidecar, hash), Epoch: primary.Epoch(), Watermark: cut, SidecarSeq: sidecar, SidecarHash: hash, Status: MaintenancePrepared}
		if err := primary.SetMaintenanceCutExact(prepared); err != nil {
			t.Fatal(err)
		}
		if err := standby.SetMaintenanceCutExact(prepared); err != nil {
			t.Fatal(err)
		}
		_ = standby.Close()
		promoted, err := Open(standbyPath)
		if err != nil {
			t.Fatal(err)
		}
		defer promoted.Close()
		if err := promoted.RecoverControlRotation(); err != nil {
			t.Fatal(err)
		}
		if promoted.IsPoisoned() || promoted.CompactedThrough() != cut || promoted.State().Maintenance.Status != MaintenanceFinalized {
			t.Fatalf("bad recovered maintenance: %+v", promoted.State())
		}
		if _, err := promoted.AppendBuffered(Record{Op: OpCreate, Path: "single"}); !errors.Is(err, ErrReplicaRequired) {
			t.Fatalf("write fence error=%v", err)
		}
	})

	t.Run("landed checkpoint", func(t *testing.T) {
		dir := t.TempDir()
		primary := openTestWAL(t, filepath.Join(dir, "primary"))
		standbyPath := filepath.Join(dir, "standby")
		standby, err := Open(standbyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := primary.AttachReplica(standby); err != nil {
			t.Fatal(err)
		}
		if err := primary.Append(Record{Op: OpWrite, Path: "log", Append: true, Data: []byte("A")}); err != nil {
			t.Fatal(err)
		}
		cut := CheckpointCut{OperationID: "pfck_landed", Watermark: primary.Watermark(), TreeHash: "sha256:t", CanonicalRequestHash: "sha256:r"}
		if _, err := primary.PrepareCheckpointCut(cut); err != nil {
			t.Fatal(err)
		}
		if err := primary.ResolveCheckpointCut(cut.OperationID, "cmt_landed", true); err != nil {
			t.Fatal(err)
		}
		_ = standby.Close()
		promoted, err := Open(standbyPath)
		if err != nil {
			t.Fatal(err)
		}
		defer promoted.Close()
		if err := promoted.CompactRecoveredCheckpoint(cut.OperationID); err != nil {
			t.Fatal(err)
		}
		if err := promoted.FinalizeCheckpointCut(cut.OperationID); err != nil {
			t.Fatal(err)
		}
		if promoted.IsPoisoned() || promoted.CompactedThrough() != cut.Watermark {
			t.Fatalf("bad recovered checkpoint: %+v", promoted.State())
		}
		if _, err := promoted.AppendBuffered(Record{Op: OpCreate, Path: "single"}); !errors.Is(err, ErrReplicaRequired) {
			t.Fatalf("write fence error=%v", err)
		}
	})
}

func TestRecoveredCompactionRejectsMissingOrCorruptProof(t *testing.T) {
	w := openTestWAL(t, filepath.Join(t.TempDir(), "wal"))
	if err := w.Append(Record{Op: OpCreate, Path: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := w.CompactRecoveredCheckpoint("missing"); err == nil {
		t.Fatal("missing proof compacted")
	}
	w.mu.Lock()
	w.hasCheckpoint = true
	w.checkpoint = CheckpointCut{OperationID: "bad", Epoch: w.epoch, Watermark: w.nextSeq + 1, Status: CheckpointLanded, CommitID: "cmt"}
	w.mu.Unlock()
	if err := w.CompactRecoveredCheckpoint("bad"); err == nil {
		t.Fatal("corrupt watermark proof compacted")
	}
	if w.CompactedThrough() != 0 {
		t.Fatal("invalid recovery proof changed base")
	}
}

func TestCheckpointCannotCrossPreparedMaintenanceCut(t *testing.T) {
	w := openTestWAL(t, filepath.Join(t.TempDir(), "wal"))
	cut, sidecar := appendControlRotationFixture(t, w)
	hash := w.recordHashes[sidecar]
	maintenance := MaintenanceCut{OperationID: maintenanceID(w.Epoch(), cut, sidecar, hash), Epoch: w.Epoch(), Watermark: cut, SidecarSeq: sidecar, SidecarHash: hash, Status: MaintenancePrepared}
	if err := w.SetMaintenanceCutExact(maintenance); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "later-user"}); err != nil {
		t.Fatal(err)
	}
	checkpoint := CheckpointCut{OperationID: "pfck_later", Watermark: w.Watermark(), TreeHash: "sha256:t", CanonicalRequestHash: "sha256:r"}
	if _, err := w.PrepareCheckpointCut(checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := w.ResolveCheckpointCut(checkpoint.OperationID, "cmt_later", true); err != nil {
		t.Fatal(err)
	}
	if err := w.CompactThrough(checkpoint.Watermark); err == nil {
		t.Fatal("checkpoint crossed active maintenance cut")
	}
	if w.CompactedThrough() != 0 {
		t.Fatal("rejected checkpoint changed base")
	}
	if err := w.RecoverControlRotation(); err != nil {
		t.Fatal(err)
	}
	if err := w.CompactThrough(checkpoint.Watermark); err != nil {
		t.Fatalf("checkpoint after maintenance recovery: %v", err)
	}
}
