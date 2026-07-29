package wal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const metadataVersion = 1

// metadata is the small, crash-durable identity of a WAL generation. The live
// suffix remains in the WAL itself; BaseDigest commits to every record compacted
// before BaseSeq, allowing an empty post-checkpoint WAL to retain an exact prefix
// identity across restart.
type metadata struct {
	Version    uint32   `json:"version"`
	Epoch      uint64   `json:"epoch"`
	BaseSeq    uint64   `json:"baseSeq"`
	BaseDigest [32]byte `json:"baseDigest"`
	// BaseCommitID anchors BaseSeq/BaseDigest to the exact immutable backend
	// manifest the retained suffix extends. Set when this WAL is a durable
	// journal cache; empty (and omitted, so 007-era files round-trip
	// unchanged) for standalone/two-member WALs, which anchor recovery on
	// checkpoint receipts instead.
	BaseCommitID  string        `json:"baseCommitId,omitempty"`
	HasCheckpoint bool          `json:"hasCheckpoint,omitempty"`
	Checkpoint    CheckpointCut `json:"checkpoint,omitempty"`
}

type metadataTransition struct {
	Version uint32   `json:"version"`
	Target  metadata `json:"target"`
	NextSeq uint64   `json:"nextSeq"`
	Tip     [32]byte `json:"tip"`
}

func (w *WAL) metaPath() string       { return w.path + ".meta" }
func (w *WAL) transitionPath() string { return w.path + ".meta.transition" }

func randomEpoch() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("wal: generate epoch: %w", err)
	}
	e := binary.BigEndian.Uint64(b[:])
	if e == 0 { // zero is reserved for an uninitialised/legacy WAL.
		e = 1
	}
	return e, nil
}

// BaseCommitID is the immutable backend manifest the compacted prefix (and so
// the retained suffix) extends. Always empty for a locally-born file WAL; the
// remote journal's implementation reports the claimed generation's anchor.
// ensureEpochLocked mints and persists the log's LSN-namespace epoch on first
// write. A legacy pre-metadata file cannot prove its epoch and fails closed.
func (w *WAL) ensureEpochLocked() error {
	if w.legacy {
		return ErrLegacyLog
	}
	if w.epoch != 0 {
		return nil
	}
	e, err := randomEpoch()
	if err != nil {
		return err
	}
	w.epoch = e
	if err := w.persistMetadataLocked(); err != nil {
		w.epoch = 0
		return err
	}
	return nil
}

func (w *WAL) BaseCommitID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.baseCommitID
}

func recordDigest(prev [32]byte, r Record) ([32]byte, error) {
	var payload bytesBuffer
	if err := gob.NewEncoder(&payload).Encode(&r); err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write(prev[:])
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(payload.Len()))
	_, _ = h.Write(n[:])
	_, _ = h.Write(payload.Bytes())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// bytesBuffer is the tiny subset gob.Encoder needs. Keeping it here avoids
// exposing digest construction outside this file.
type bytesBuffer struct{ b []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) { b.b = append(b.b, p...); return len(p), nil }
func (b *bytesBuffer) Bytes() []byte               { return b.b }
func (b *bytesBuffer) Len() int                    { return len(b.b) }

func digestRecords(base [32]byte, records []Record) ([32]byte, error) {
	d := base
	var err error
	for _, r := range records {
		d, err = recordDigest(d, r)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return d, nil
}

func loadJSON(path string, dst any) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return false, fmt.Errorf("wal: decode %s: %w", filepath.Base(path), err)
	}
	return true, nil
}

func persistJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	clean := func() { _ = f.Close(); _ = os.Remove(tmp) }
	if _, err := f.Write(b); err != nil {
		clean()
		return err
	}
	if err := f.Sync(); err != nil {
		clean()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func removeDurable(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func (w *WAL) persistMetadataLocked() error {
	return persistJSON(w.metaPath(), metadata{
		Version: metadataVersion, Epoch: w.epoch, BaseSeq: w.compactedThrough,
		BaseDigest: w.baseDigest, BaseCommitID: w.baseCommitID,
		HasCheckpoint: w.hasCheckpoint, Checkpoint: w.checkpoint,
	})
}

// recordsLocked reads the full retained record suffix. Caller holds w.mu.
func (w *WAL) recordsLocked() ([]Record, error) {
	records, _, err := readRecords(w.path, w.enc)
	return records, err
}

// digestAtLocked answers the chain digest at seq within the retained range.
func (w *WAL) digestAtLocked(seq uint64) ([32]byte, error) {
	if seq < w.compactedThrough || seq > w.nextSeq {
		return [32]byte{}, fmt.Errorf("wal: digest boundary %d outside retained range [%d,%d]", seq, w.compactedThrough, w.nextSeq)
	}
	if seq == w.compactedThrough {
		return w.baseDigest, nil
	}
	records, err := w.recordsLocked()
	if err != nil {
		return [32]byte{}, err
	}
	d := w.baseDigest
	for _, r := range records {
		if r.Seq >= seq {
			break
		}
		d, err = recordDigest(d, r)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return d, nil
}

func (w *WAL) beginTransitionLocked(target metadata, next uint64, tip [32]byte) error {
	return persistJSON(w.transitionPath(), metadataTransition{
		Version: metadataVersion, Target: target, NextSeq: next, Tip: tip,
	})
}

func (w *WAL) finishTransitionLocked(target metadata) error {
	if err := persistJSON(w.metaPath(), target); err != nil {
		return err
	}
	return removeDurable(w.transitionPath())
}

func validateSequence(base uint64, records []Record) (uint64, error) {
	next := base
	for i, r := range records {
		if r.Seq != next {
			return 0, fmt.Errorf("wal: non-contiguous LSN at record %d: got %d, want %d", i, r.Seq, next)
		}
		next++
	}
	return next, nil
}

// recoverTransition completes an interrupted atomic rewrite. The transition is
// written before the WAL rename; after a crash, matching target bytes prove the
// rename landed and make it safe to install the target metadata. Otherwise the
// old WAL/metadata pair won and the unused intent is discarded.
func (w *WAL) recoverTransition(records []Record) error {
	var tr metadataTransition
	ok, err := loadJSON(w.transitionPath(), &tr)
	if err != nil || !ok {
		return err
	}
	if tr.Version != metadataVersion || tr.Target.Version != metadataVersion {
		return fmt.Errorf("wal: unsupported metadata transition version %d", tr.Version)
	}
	next, seqErr := validateSequence(tr.Target.BaseSeq, records)
	tip, digErr := digestRecords(tr.Target.BaseDigest, records)
	if seqErr == nil && digErr == nil && next == tr.NextSeq && tip == tr.Tip {
		if err := persistJSON(w.metaPath(), tr.Target); err != nil {
			return fmt.Errorf("wal: finish metadata transition: %w", err)
		}
	}
	return removeDurable(w.transitionPath())
}

// initialize restores persistent generation metadata and derives the exact live
// suffix identity. Corruption discovered by the record scanner is deferred to
// Replay so callers retain the historical salvage contract (Replay returns the
// intact prefix alongside the error).
func (w *WAL) initialize(newFile bool) error {
	records, validEnd, scanErr := readRecords(w.path, w.enc)
	if scanErr == nil {
		if err := w.recoverTransition(records); err != nil {
			return err
		}
	}
	var meta metadata
	hasMeta, err := loadJSON(w.metaPath(), &meta)
	if err != nil {
		return err
	}
	if hasMeta && meta.Version != metadataVersion {
		return fmt.Errorf("wal: unsupported metadata version %d", meta.Version)
	}
	if !hasMeta {
		meta.Version = metadataVersion
		if len(records) > 0 || !newFile {
			// Pre-metadata files remain locally recoverable, but cannot prove the
			// compacted prefix/epoch needed for production HA reconciliation.
			if len(records) > 0 {
				meta.BaseSeq = records[0].Seq
			}
			w.legacy = true
		}
	}
	w.epoch = meta.Epoch
	w.compactedThrough = meta.BaseSeq
	w.baseDigest = meta.BaseDigest
	w.baseCommitID = meta.BaseCommitID
	w.hasCheckpoint = meta.HasCheckpoint
	w.checkpoint = meta.Checkpoint
	next, seqErr := validateSequence(meta.BaseSeq, records)
	if seqErr != nil && scanErr == nil {
		scanErr = seqErr
	}
	tip, digErr := digestRecords(meta.BaseDigest, records)
	if digErr != nil && scanErr == nil {
		scanErr = digErr
	}
	w.nextSeq = next
	w.tipDigest = tip
	w.count = len(records)
	w.recordHashes = make(map[uint64][32]byte, len(records))
	for _, r := range records {
		h, err := recordDigest([32]byte{}, r)
		if err != nil && scanErr == nil {
			scanErr = err
		}
		w.recordHashes[r.Seq] = h
	}
	w.unflushed = append([]Record(nil), records...)
	w.durableSeq = meta.BaseSeq
	w.offset = validEnd
	w.initErr = scanErr
	// Remove a torn tail now, before any caller can append after it. Mid-log
	// corruption remains untouched for salvage/forensics.
	if scanErr == nil {
		if info, err := w.f.Stat(); err != nil {
			return err
		} else if info.Size() > validEnd {
			if err := w.f.Truncate(validEnd); err != nil {
				return err
			}
			if err := w.f.Sync(); err != nil {
				return err
			}
		}
	}
	return nil
}
