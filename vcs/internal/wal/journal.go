package wal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
)

// LEGACY / TEST-ONLY. This file is the PROTOTYPE journal-as-replica attach:
// a remote journal published as the file WAL's synchronous replica, with the
// local WAL file kept as a disposable cache. It is NOT the journal-native
// architecture and is NOT wired anywhere in cmd/vcs. The journal-native path
// uses internal/remotejournal (a direct wal.DurableLog against PostgreSQL)
// with no local WAL file or authority cache at all.
// The attach machinery below is retained only because its asymmetric
// remote-wins reconciliation is exercised by fault-injection tests of the
// file WAL (journal_test.go supplies an in-memory DurableJournal fake).
//
// Two things in this file are NOT legacy and are shared with production:
// ErrJournalDiverged and ChainDigestBytes/RecordHash — the digest-chain
// primitives the remote journal, the SQL layer, and the file WAL all agree on.
//
// The symmetric two-member AttachReplica contract is deliberately NOT reused:
// it repairs missing suffixes in BOTH directions, so a local-ahead suffix that
// was fsync'd locally but never acknowledged remotely would be pushed into the
// journal and resurrected as acknowledged history. AttachDurableJournal is
// asymmetric: remote state always wins, remote-ahead records are pulled, and
// any local-ahead/epoch/base/digest divergence atomically rebuilds the local
// cache from the remote base plus retained suffix. Local records are NEVER
// pushed to a journal here.

// ErrJournalDiverged reports a remote journal whose own state or record chain
// failed verification (corruption or a concurrent identity change). The attach
// fails closed without publishing anything.
var ErrJournalDiverged = errors.New("wal: durable journal state failed verification")

// DurableJournalState is the remote journal's identity: the exact replica
// prefix identity PLUS the immutable base manifest anchor (BaseCommitID), the
// durable runtime-generation facts, and the current fencing generation. It is
// distinct from ReplicaState because recovery must know the exact manifest the
// retained suffix extends and whether this generation may accept appends.
type DurableJournalState struct {
	GenerationID        string
	RuntimeGeneration   uint64
	AuthorityGeneration uint64
	Status              string // active | suspended | retiring | retired | abandoned
	BaseCommitID        string
	Epoch               uint64
	BaseSeq             uint64
	NextSeq             uint64
	BaseDigest          [32]byte
	TipDigest           [32]byte
	BacklogBytes        int64
	HasCheckpoint       bool
	Checkpoint          CheckpointCut
	HasMaintenance      bool
	Maintenance         MaintenanceCut
}

// DurableJournal is the client contract for a claimed remote journal
// generation. The write path reuses the ExactReplica methods (epoch-fenced
// batch append, digest reads, exact compaction, cut replication), so group
// commit and checkpoint/maintenance semantics are identical to two-member HA;
// JournalState adds the BaseCommitID/runtime-generation facts that make the
// asymmetric attach possible. Implementations must translate lost/ambiguous
// transport outcomes into errors (never fabricate success), because the WAL
// poisons itself on replication failure and fences writes before visibility.
type DurableJournal interface {
	ExactReplica
	JournalState() (DurableJournalState, error)
}

// CanonicalPayload is the LEGACY gob encoding of one WAL record — the bytes
// recordDigest hashes in the file WAL. Gob is DECODE-ONLY for migration: no
// new journal epoch may be written with it (production epochs are PFR1, see
// pfr1.go), and no epoch mixes codecs. It remains exported only for the
// legacy attach machinery in this file and its fault-injection tests.
func CanonicalPayload(r Record) ([]byte, error) {
	var payload bytesBuffer
	if err := gob.NewEncoder(&payload).Encode(&r); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

// DecodeCanonicalPayload decodes one canonical record payload. Callers must
// verify the decoded Seq and the payload hash against the wire facts
// (VerifyCanonicalRecord) before trusting the record.
func DecodeCanonicalPayload(data []byte) (Record, error) {
	var r Record
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&r); err != nil {
		return Record{}, err
	}
	return r, nil
}

// ChainDigestBytes advances the WAL digest chain over one canonical payload:
// sha256(prev[32] || be64(len(payload)) || payload). It is recordDigest
// expressed over the opaque payload bytes, so a reader that only has the
// stored bytes (the journal service, or this client on pull) reproduces the
// identical chain.
func ChainDigestBytes(prev [32]byte, payload []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(prev[:])
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(payload)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RecordHash is the zero-anchored canonical hash of one record (the identity
// used for exact-duplicate detection across the journal and both WAL members).
func RecordHash(r Record) ([32]byte, error) {
	return recordDigest([32]byte{}, r)
}

// VerifyCanonicalRecord decodes payload and proves it is exactly the record the
// wire facts claim: the payload hashes to recordHash, the decoded record
// carries seq, and re-encoding the decoded record reproduces the same hash (so
// this WAL's own digest math will extend the journal chain identically).
func VerifyCanonicalRecord(seq uint64, payload []byte, recordHash [32]byte) (Record, error) {
	if ChainDigestBytes([32]byte{}, payload) != recordHash {
		return Record{}, fmt.Errorf("%w: record %d payload does not match its hash", ErrJournalDiverged, seq)
	}
	r, err := DecodeCanonicalPayload(payload)
	if err != nil {
		return Record{}, fmt.Errorf("%w: record %d payload does not decode: %v", ErrJournalDiverged, seq, err)
	}
	if r.Seq != seq {
		return Record{}, fmt.Errorf("%w: record payload carries LSN %d, wire says %d", ErrJournalDiverged, r.Seq, seq)
	}
	reencoded, err := RecordHash(r)
	if err != nil {
		return Record{}, err
	}
	if reencoded != recordHash {
		return Record{}, fmt.Errorf("%w: record %d does not re-encode canonically", ErrJournalDiverged, seq)
	}
	return r, nil
}

// BaseCommitID is the immutable backend manifest the compacted prefix (and so
// the retained suffix) extends. Empty when this WAL never attached to a durable
// journal (pre-journal WALs anchor recovery on checkpoint receipts instead).
func (w *WAL) BaseCommitID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.baseCommitID
}

// journalAttachable reports whether the generation may serve a live authority.
func journalAttachable(status string) bool {
	return status == "active" || status == "retiring"
}

// AttachDurableJournal adopts the remote journal as the authoritative log and
// publishes it as this WAL's synchronous replica. Remote state always wins:
//
//   - If the local cache is a proven exact prefix of the remote journal (same
//     epoch, base, base digest, base commit anchor, and the remote digest at the
//     local tip equals the local tip digest), the remote-ahead suffix is pulled
//     and appended locally.
//   - Otherwise — local ahead, pristine, legacy, epoch/base/BaseCommitID
//     mismatch, or digest conflict — the local cache is atomically rebuilt from
//     the remote base plus retained suffix (temp file + rename via the metadata
//     transition, so a crash leaves the old or the new cache, never a mix).
//
// Every pulled record is decoded and verified (seq, payload hash, canonical
// re-encode) and the full chain is verified against the remote tip digest
// BEFORE the rebuilt cache is published; any verification failure fails closed
// with the WAL unchanged and no replica installed. Local records are never
// pushed to the journal.
func (w *WAL) AttachDurableJournal(j DurableJournal) (DurableJournalState, error) {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()

	w.mu.Lock()
	if w.poisoned {
		w.mu.Unlock()
		return DurableJournalState{}, ErrPoisoned
	}
	if err := w.f.Sync(); err != nil {
		w.poisonLocked()
		w.mu.Unlock()
		return DurableJournalState{}, err
	}
	local := w.stateLocked()
	localBaseCommit := w.baseCommitID
	w.mu.Unlock()

	remote, err := j.JournalState()
	if err != nil {
		return DurableJournalState{}, err
	}
	if remote.Epoch == 0 {
		return DurableJournalState{}, fmt.Errorf("%w: journal carries no epoch", ErrJournalDiverged)
	}
	if !journalAttachable(remote.Status) {
		return DurableJournalState{}, fmt.Errorf("wal: journal generation is %s; a live authority cannot attach", remote.Status)
	}

	keepLocal := !local.Legacy && !local.Pristine && !local.Poisoned &&
		local.Epoch == remote.Epoch &&
		local.BaseSeq == remote.BaseSeq &&
		local.BaseDigest == remote.BaseDigest &&
		local.NextSeq <= remote.NextSeq &&
		(localBaseCommit == "" || localBaseCommit == remote.BaseCommitID)
	if keepLocal {
		remoteAtLocalTip, derr := j.DigestAtExact(remote.Epoch, local.NextSeq)
		if derr != nil {
			return DurableJournalState{}, derr
		}
		// A digest conflict is not an error here: the remote is authoritative,
		// so the conflicting local suffix is simply rebuilt away.
		keepLocal = remoteAtLocalTip == local.TipDigest
	}

	if keepLocal {
		if err := w.pullJournalSuffixLocked(j, remote, local.NextSeq); err != nil {
			return DurableJournalState{}, err
		}
	} else {
		if err := w.rebuildFromJournalLocked(j, remote); err != nil {
			return DurableJournalState{}, err
		}
	}

	// Adopt the journal's cut facts verbatim (remote wins; the local cache may
	// hold an older phase after a crash) and its base manifest anchor, then
	// verify the final identity before publishing anything to the write path.
	w.mu.Lock()
	w.hasCheckpoint, w.checkpoint = remote.HasCheckpoint, remote.Checkpoint
	w.hasMaintenance, w.maintenance = remote.HasMaintenance, remote.Maintenance
	w.baseCommitID = remote.BaseCommitID
	w.legacy = false
	now := w.stateLocked()
	w.mu.Unlock()
	if now.Epoch != remote.Epoch || now.BaseSeq != remote.BaseSeq || now.NextSeq != remote.NextSeq ||
		now.BaseDigest != remote.BaseDigest || now.TipDigest != remote.TipDigest {
		return DurableJournalState{}, fmt.Errorf("%w: local cache does not match the journal after reconciliation", ErrJournalDiverged)
	}
	fresh, err := j.JournalState()
	if err != nil {
		return DurableJournalState{}, err
	}
	if fresh.Epoch != remote.Epoch || fresh.BaseSeq != remote.BaseSeq || fresh.NextSeq != remote.NextSeq ||
		fresh.BaseDigest != remote.BaseDigest || fresh.TipDigest != remote.TipDigest ||
		fresh.GenerationID != remote.GenerationID || fresh.AuthorityGeneration != remote.AuthorityGeneration {
		return DurableJournalState{}, fmt.Errorf("%w: journal state changed during attach", ErrJournalDiverged)
	}

	w.mu.Lock()
	w.replica = j
	w.replicaExact = true
	w.haRequired = true
	w.unflushed = nil
	err = w.persistMetadataLocked()
	if err != nil {
		w.poisonLocked()
	}
	w.mu.Unlock()
	if err != nil {
		return DurableJournalState{}, err
	}
	w.durableSeq = remote.NextSeq // commitMu held; everything local is in the journal
	return remote, nil
}

const journalPullChunk = uint64(512)

// pullJournalSuffixLocked appends the remote-ahead records [from, remote.NextSeq)
// to a local cache already proven to be an exact prefix. Caller holds commitMu.
func (w *WAL) pullJournalSuffixLocked(j DurableJournal, remote DurableJournalState, from uint64) error {
	for from < remote.NextSeq {
		to := min64(from+journalPullChunk, remote.NextSeq)
		records, err := j.RecordsExact(remote.Epoch, from, to)
		if err != nil {
			return err
		}
		if uint64(len(records)) != to-from {
			return fmt.Errorf("%w: journal returned %d records for [%d,%d)", ErrJournalDiverged, len(records), from, to)
		}
		w.mu.Lock()
		err = w.appendReplicatedBatchLocked(records)
		w.mu.Unlock()
		if err != nil {
			return err
		}
		from = to
	}
	w.mu.Lock()
	tip := w.tipDigest
	w.mu.Unlock()
	if tip != remote.TipDigest {
		return fmt.Errorf("%w: pulled suffix does not chain to the journal tip", ErrJournalDiverged)
	}
	return nil
}

// rebuildFromJournalLocked atomically replaces the local cache with the remote
// base identity plus retained suffix. The whole suffix is pulled and chain
// verified against the remote tip digest BEFORE any local byte changes; the
// swap itself is the crash-safe metadata transition + temp-file rename used by
// compaction. Caller holds commitMu.
func (w *WAL) rebuildFromJournalLocked(j DurableJournal, remote DurableJournalState) error {
	records := make([]Record, 0, remote.NextSeq-remote.BaseSeq)
	chain := remote.BaseDigest
	next := remote.BaseSeq
	for from := remote.BaseSeq; from < remote.NextSeq; {
		to := min64(from+journalPullChunk, remote.NextSeq)
		batch, err := j.RecordsExact(remote.Epoch, from, to)
		if err != nil {
			return err
		}
		if uint64(len(batch)) != to-from {
			return fmt.Errorf("%w: journal returned %d records for [%d,%d)", ErrJournalDiverged, len(batch), from, to)
		}
		for _, r := range batch {
			if r.Seq != next {
				return fmt.Errorf("%w: journal records are not contiguous at LSN %d", ErrJournalDiverged, next)
			}
			chain, err = recordDigest(chain, r)
			if err != nil {
				return err
			}
			next++
		}
		records = append(records, batch...)
		from = to
	}
	if chain != remote.TipDigest {
		return fmt.Errorf("%w: journal record chain does not match its tip digest", ErrJournalDiverged)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	target := metadata{
		Version: metadataVersion, Epoch: remote.Epoch,
		BaseSeq: remote.BaseSeq, BaseDigest: remote.BaseDigest,
		BaseCommitID: remote.BaseCommitID, HA: true,
		HasCheckpoint: remote.HasCheckpoint, Checkpoint: remote.Checkpoint,
		HasMaintenance: remote.HasMaintenance, Maintenance: remote.Maintenance,
	}
	if err := w.beginTransitionLocked(target, remote.NextSeq, remote.TipDigest); err != nil {
		return err
	}
	if err := w.rewriteLocked(records); err != nil {
		_ = removeDurable(w.transitionPath())
		return err
	}
	if err := w.finishTransitionLocked(target); err != nil {
		w.poisonLocked()
		return err
	}
	w.count = len(records)
	w.nextSeq = remote.NextSeq
	w.compactedThrough = remote.BaseSeq
	w.epoch = remote.Epoch
	w.baseDigest = remote.BaseDigest
	w.tipDigest = remote.TipDigest
	w.baseCommitID = remote.BaseCommitID
	w.recordHashes = make(map[uint64][32]byte, len(records))
	for _, r := range records {
		h, herr := recordDigest([32]byte{}, r)
		if herr != nil {
			w.poisonLocked() // file already swapped; in-memory identity incomplete
			return herr
		}
		w.recordHashes[r.Seq] = h
	}
	w.legacy = false
	w.initErr = nil
	w.unflushed = nil
	return nil
}
