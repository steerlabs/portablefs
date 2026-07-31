// Package wal is a crash-safe write-ahead log for the working tree. Every
// filesystem mutation is framed first, then ordinary write acknowledgement waits
// for CommitThrough: local fsync plus synchronous exact standby durability. On
// restart the log is replayed to reconstruct state newer than the backend
// manifest. Buffered append is an internal group-commit stage and is never itself
// a client durability acknowledgement. After a checkpoint commit is proven by a
// replicated landed cut, the covered prefix is compacted standby-first.
//
// Framing per record: [uint32 len][uint32 crc32(data)][data], data = gob(Record).
// A torn tail (a partial final record from a crash) fails the length/crc check
// and is discarded on replay, leaving the longest intact prefix. A corrupt record
// with valid data after it (mid-log corruption, not a tail tear) is reported as an
// error rather than silently truncating the still-good records that follow it.
//
// Every record carries a monotonic sequence number (LSN). Replication and
// compaction are expressed in terms of LSNs, not positions: a standby is a faithful
// mirror keyed by LSN, and "compact everything the checkpoint committed" is
// "compact every record below watermark LSN" — position-independent, so the primary
// and standby never diverge even across restarts and reconnects.
package wal

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

// maxRecordBytes bounds a single record's framed size on read, so a corrupt or
// hostile length field cannot drive an unbounded allocation.
const maxRecordBytes = 256 << 20 // 256 MiB

// headerBytes is the per-record framing header: [uint32 len][uint32 lenCrc][uint32
// payloadCrc]. lenCrc protects the length field itself, so a corrupted length is
// detected BEFORE its (bogus) body is read — otherwise an over-long length silently
// consumes the valid records that follow it and they are lost as a "torn tail".
const headerBytes = 12

// errPoisoned is returned once the WAL can no longer guarantee its durability
// invariant (a rollback or post-rename reopen failed). The log refuses all further
// appends so the node stops acknowledging writes it cannot make durable/consistent,
// forcing failover to a healthy node instead of silently diverging or losing data.
var errPoisoned = errors.New("wal: log poisoned by an unrecoverable durability failure")

// ErrPoisoned lets callers classify a poisoned-log rejection (errors.Is).
var ErrPoisoned = errPoisoned

// ErrEpochMismatch classifies a checkpoint cut minted under a different LSN
// namespace than this log's current epoch.
var ErrEpochMismatch = errors.New("wal: epoch mismatch")

// ErrLegacyLog reports a non-empty pre-metadata file: it cannot prove an
// epoch, so it replays read-only and refuses writes.
var ErrLegacyLog = errors.New("wal: legacy pre-metadata log cannot prove an epoch")

// Op identifies a mutation kind.
type Op uint8

const (
	OpCreate Op = iota + 1
	OpWrite
	OpTruncate
	OpMkdir
	OpRemove
	OpRename
	OpSymlink
	OpChmod
	OpChtimes
	OpChown
	// OpOrphan and OpReap implement delete-on-last-close (open-after-unlink). OpOrphan detaches the
	// inode at Path from its parent and PARKS it in the orphan table (keyed by its stable ino) so an
	// open handle keeps reading/writing it after its name is gone; OpReap drops the parked inode on
	// last close. APPENDED after OpChown so every pre-existing op value (1..10) is unchanged — old WAL
	// records and manifests replay identically.
	OpOrphan
	OpReap
	// OpControl carries replicated CONTROL metadata (protocol session
	// establishment/expiry, write-back flush watermarks, and the compact
	// versioned control snapshot appended before compaction) through the same
	// durability/replication/apply pipeline as user mutations WITHOUT touching
	// the user namespace: control records are never part of manifests, tree
	// hashes, path walks, snapshots, or blob GC. The payload is a versioned,
	// tagged union (see internal/ctlrec) in Data. Appended after OpReap so every
	// pre-existing op value is unchanged.
	OpControl
	// OpBatch is one atomically-framed logical filesystem intent containing an
	// ordered Mutations slice. Its Seq is the authority LSN; inner Seq fields
	// remain mount-local flush sequence numbers.
	OpBatch
	// OpLink adds a hard link: a second directory entry (NewPath) that
	// references the SAME inode as an existing non-directory name (Path).
	// Apply resolves the source inode (by Ino when carried — deterministic on
	// replay — else by Path), requires NewPath's parent present and NewPath
	// absent (EEXIST), and increments the inode's link count. Directories are
	// never hard-linked (EPERM). Appended after OpBatch so every pre-existing
	// op value is unchanged; legacy logs and manifests replay identically.
	OpLink
	// OpSetxattr sets (create-or-overwrite, last writer wins) one extended
	// attribute on the inode resolved by Ino-else-Path: name in XattrName,
	// raw value bytes in Data. Bounds are frozen apply-level semantics
	// (MaxXattrNameBytes / MaxXattrValueBytes / MaxXattrTotalBytes); an
	// over-total set is a deterministic ENOSPC outcome at the record's
	// ordered position. Reads (get/list) are never journaled. Appended after
	// OpLink so every pre-existing op value is unchanged; old decoders
	// reject the unknown op (the sanctioned fencing).
	OpSetxattr
	// OpRemovexattr removes the extended attribute XattrName from the inode
	// resolved by Ino-else-Path. A missing name is a deterministic ENODATA
	// outcome (Linux removexattr semantics), never a silent no-op. Appended
	// after OpSetxattr.
	OpRemovexattr
	// OpJournalEntry frames one canonical PFJ3 journal entry (tree arm plus
	// ordered PFC2 controls) in Data. It exists ONLY for the file-backed
	// PFJ3 entry log (pfj3.FileEntryLog — the bench/torture/test authority
	// backend); the production journal is PostgreSQL and never touches this
	// op. A WAL carrying it is an entry log, never replayed record-shaped.
	// Appended after OpRemovexattr.
	OpJournalEntry
	// OpChflags sets the BSD file flags (Darwin st_flags / chflags(2)) of the
	// inode resolved by Ino-else-Path to the ABSOLUTE value in Record.Flags.
	// Like OpChmod it carries the whole new value rather than an intent
	// delta, so replay is deterministic without re-reading the tree, and like
	// OpChmod it leaves every timestamp alone. The authority stores the full
	// uint32 it was given: which bits a mount may set is a client-side policy
	// decision, and re-masking here would make the durable record disagree
	// with what the client asked for. Appended after OpJournalEntry so every
	// pre-existing op value is unchanged; an older decoder rejects the unknown
	// op (the sanctioned fencing for appended ops).
	OpChflags
)

// Frozen apply-level xattr bounds, shared by every generation (admission,
// apply, PFR1, and the PFT2 anchor all enforce one finite shape):
//   - a name is 1..MaxXattrNameBytes bytes of NUL-free UTF-8 (ERANGE beyond,
//     matching Linux XATTR_NAME_MAX);
//   - a value is raw bytes up to MaxXattrValueBytes (E2BIG beyond, matching
//     Linux XATTR_SIZE_MAX);
//   - one inode's total xattr bytes (sum of every name+value) never exceed
//     MaxXattrTotalBytes (ENOSPC beyond, decided deterministically at the
//     record's ordered apply position).
const (
	MaxXattrNameBytes  = 255
	MaxXattrValueBytes = 64 << 10
	MaxXattrTotalBytes = 128 << 10
)

// Atomic setxattr preconditions carried in Record.XattrFlags. Zero is the
// ordinary create-or-replace operation. The bits are mutually exclusive and
// are evaluated by the authority reducer at the record's ordered apply
// position, never by a client-side read.
const (
	XattrCreate uint8 = 1 << iota
	XattrReplace
	XattrFlagMask = XattrCreate | XattrReplace
)

// IsControl reports whether op is replicated control metadata rather than a
// user-namespace mutation.
func (op Op) IsControl() bool { return op == OpControl }

// IsBatch reports whether op is an atomically framed multi-mutation intent.
func (op Op) IsBatch() bool { return op == OpBatch }

// Envelope is the exact-once mutation identity stamped on protocol-v2 mutation
// records: the authenticated mount session, its generation (incarnation),
// a bounded slot id, the per-slot monotonic sequence, and the server-computed
// SHA-256 canonical request fingerprint. WAL replay rebuilds the latest
// retryable outcome per slot from these envelopes, so a retried request after
// restart/failover returns its original essential response instead of
// re-executing.
type Envelope struct {
	SessionID  string
	Generation uint64
	Slot       uint32
	SlotSeq    uint64
	ReqHash    []byte // SHA-256 of the canonical request
}

// Valid reports whether the envelope carries an identity (v2 mutation).
func (e *Envelope) Valid() bool { return e != nil && e.SessionID != "" }

// Record is a single logged mutation. Seq is its log sequence number (LSN),
// assigned by the primary on append and preserved across replication and replay.
type Record struct {
	Seq              uint64 // log sequence number (monotonic, assigned on append)
	Op               Op
	Path             string
	NewPath          string   // OpRename target
	Offset           int64    // OpWrite
	Size             int64    // OpTruncate
	Mode             uint32   // OpCreate, OpMkdir, OpChmod
	Target           string   // OpSymlink
	Data             []byte   // OpWrite payload; control payload for OpControl* records
	MtimeMs          int64    // OpChtimes
	AtimeMs          int64    // OpChtimes (exact atime; see ChtimesSetAtime)
	ChtimesSetAtime  bool     // distinguishes an intentional Unix-epoch atime from legacy omission
	ChtimesKeepMtime bool     // atime-only update; false preserves legacy "always set mtime"
	UID              uint32   // OpChown
	GID              uint32   // OpChown
	Ino              uint64   // OpReap and handle-addressed OpWrite/OpTruncate/OpChmod/OpChtimes/OpChown: target stable ino. Zero for path-addressed ops — gob omits it, so existing logs are byte-compatible.
	Inos             []uint64 // OpMkdir: one reserved stable inode per normalized path component (legacy nil records allocate during replay)
	OrphanTarget     bool     // compatibility-only: deterministic apply always parks a replaced NewPath; old true records replay identically

	// TsMs is the server-selected mutation timestamp (ms), stamped at append so
	// replay and the standby reproduce identical mtimes/ctimes instead of each
	// re-deriving wall-clock time. Zero on legacy records ⇒ apply falls back to
	// its own clock (old behaviour).
	TsMs int64
	// ChownSetUID/ChownSetGID carry OpChown INTENT: only the flagged field
	// changes; the other is resolved against the tree at the record's LSN
	// position (deterministic on replay). A legacy record with neither flag
	// carries absolute values for both fields (old behaviour).
	ChownSetUID bool
	ChownSetGID bool
	// Append marks an authority-side O_APPEND write: apply resolves the offset
	// atomically as EOF in sequencer order (deterministic on replay because the
	// apply order is the LSN order) and returns the chosen offset to the client.
	// Offset is ignored on append records.
	Append bool
	// ReapIfLeaseExpiresByMs records the deterministic lease cutoff used by an
	// OpReap decision. Replay applies the already-selected decision rather than
	// consulting a new wall clock.
	ReapIfLeaseExpiresByMs int64
	// Env is the exact-once identity for protocol-v2 mutations (nil for v1 and
	// internal records). Gob omits nil, so existing logs are byte-compatible.
	Env *Envelope
	// Mutations is populated only for OpBatch. Nested batches are rejected
	// before append. One frame per logical batch prevents crash-valid prefixes.
	Mutations []Record
	// Excl marks a conditional requireAbsent create/mkdir/symlink (O_EXCL and
	// POSIX single-component mkdir): apply fails EEXIST when the final
	// component exists at the record's ordered position, deterministically on
	// replay and the standby. An exclusive OpMkdir creates EXACTLY one
	// component under an existing parent (its leaf identity rides Ino, never
	// Inos). Legacy false records keep idempotent-create/mkdir-p semantics.
	Excl bool
	// RenameNoReplace marks a RENAME_NOREPLACE rename: apply fails EEXIST
	// when NewPath exists at the record's ordered apply position, atomically
	// against any concurrent destination create (LSN order is the decision).
	RenameNoReplace bool
	// XattrName is the extended-attribute name of an OpSetxattr/OpRemovexattr
	// record (raw case-sensitive bytes, 1..MaxXattrNameBytes, NUL-free UTF-8).
	// The set value rides Data. Empty on every other op — gob omits it, so
	// existing logs are byte-compatible.
	XattrName string
	// XattrFlags carries XattrCreate or XattrReplace for OpSetxattr. The
	// authority evaluates the precondition atomically with the mutation.
	// Zero preserves the released create-or-overwrite behavior.
	XattrFlags uint8
	// Flags is the ABSOLUTE new BSD file-flag word (Darwin st_flags) of an
	// OpChflags record — the full uint32 the client sent, unmasked. Zero on
	// every other op, and a legal value on OpChflags itself (clearing every
	// flag); gob omits the zero, so existing logs are byte-compatible.
	Flags uint32
}

// WAL is an append-only log whose append path writes complete framed records to
// the fd before returning; fsync/replication can be batched separately. It tracks
// a monotonic next-LSN so a checkpoint can compact away just the prefix it
// committed, preserving writes that arrived during the checkpoint.
type WAL struct {
	mu         sync.Mutex
	f          *os.File
	path       string
	enc        *secure.AtRest // nil = plaintext (records framed verbatim)
	nextSeq    uint64         // LSN to assign to the next appended record
	offset     int64          // current size of the log file (append position)
	count      int            // live record count (for observability/tests)
	poisoned   bool           // set when a durability invariant can no longer be upheld
	poisonOnce sync.Once      // closes poisonedCh exactly once
	poisonedCh chan struct{}  // closed on poison, so the node can fence the data plane
	unflushed  []Record       // records written to the fd but not yet fsync'd+replicated
	initErr    error          // deferred disk validation error surfaced by Replay/mutations

	// Group commit: a write becomes durable (fsync'd + replicated) via CommitThrough.
	// commitMu serializes flushes so only one fsync+replication runs at a time and the
	// standby receives ordered batches; durableSeq (the exclusive upper bound of LSNs
	// known durable) is read/written only under commitMu. Many concurrent writers share
	// one flush, so throughput is bounded by batch latency, not per-write RTT.
	commitMu   sync.Mutex
	durableSeq uint64

	// compactedThrough is the exclusive lower LSN bound of records still in the log:
	// every record with Seq < compactedThrough has been compacted away by a checkpoint.
	// Together with a caller-tracked applied watermark it yields the exact count of
	// applied-but-uncompacted records (LSNs are contiguous). Guarded by mu.
	compactedThrough uint64
	baseDigest       [32]byte            // digest of every record with Seq < compactedThrough
	baseCommitID     string              // immutable backend manifest the compacted prefix extends (durable journal caches only)
	tipDigest        [32]byte            // digest at nextSeq (baseDigest chained through live records)
	recordHashes     map[uint64][32]byte // retained LSN -> canonical record hash (duplicate validation)
	legacy           bool                // non-empty pre-metadata log; cannot prove an epoch
	hasCheckpoint    bool
	checkpoint       CheckpointCut

	// epoch numbers this log's LSN NAMESPACE: it advances whenever Reset or
	// Renumber restarts numbering, so previously-issued LSNs become ambiguous
	// and any revision naming them (LiveRevision = branch + incarnation +
	// walEpoch + appliedLsnExclusive) can never alias across the restart.
	// Compaction never reissues LSNs and does NOT advance it. Guarded by mu.
	epoch uint64

	// capacityBytes bounds the on-disk backlog (0 = unbounded). Above it,
	// OverCapacity reports true and the authority fails NEW writes at this
	// documented threshold instead of redefining write persistence during a
	// checkpoint/object-store outage. Guarded by mu.
	capacityBytes int64
}

// Epoch returns the LSN-namespace epoch (bumped by Reset/Renumber).
func (w *WAL) Epoch() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.epoch
}

// SetCapacity bounds the on-disk backlog in bytes; 0 disables the bound.
func (w *WAL) SetCapacity(bytes int64) {
	w.mu.Lock()
	w.capacityBytes = bytes
	w.mu.Unlock()
}

// OverCapacity reports whether the log currently exceeds its capacity bound.
func (w *WAL) OverCapacity() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.capacityBytes > 0 && w.offset > w.capacityBytes
}

// QuotaBytes reports the configured backlog capacity bound (0 = unbounded).
func (w *WAL) QuotaBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.capacityBytes
}

// BacklogBytes is the current on-disk size of the log (observability).
func (w *WAL) BacklogBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.offset
}

// IsPoisoned reports whether the log refuses further appends.
func (w *WAL) IsPoisoned() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.poisoned
}

// RecordsBelow returns every live record with Seq < seq, in LSN order — the
// exact prefix a pinned capture cut covers. Used to rebuild a capture snapshot
// after a crash (base manifest + this prefix reproduces the identical tree).
func (w *WAL) RecordsBelow(seq uint64) ([]Record, error) {
	w.commitMu.Lock() // exclude compaction/flush rewrites while reading the file
	defer w.commitMu.Unlock()
	w.mu.Lock()
	path, enc := w.path, w.enc
	w.mu.Unlock()
	records, _, err := readRecords(path, enc)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if r.Seq < seq {
			out = append(out, r)
		}
	}
	return out, nil
}

// Open creates or opens an unencrypted log at path.
func Open(path string) (*WAL, error) {
	return OpenEncrypted(path, nil)
}

// OpenEncrypted creates or opens the log at path for appending and fsyncs the
// parent directory, so the file's existence is itself crash-durable (without the
// directory fsync a freshly created log can vanish on power loss even after a
// record's own fsync returned). When enc is non-nil every record's payload is
// sealed with AES-256-GCM at rest; a nil enc frames records verbatim (byte-for-byte
// the same on-disk format as before, so encryption is fully opt-in).
func OpenEncrypted(path string, enc *secure.AtRest) (*WAL, error) {
	_, statErr := os.Stat(path)
	newFile := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !newFile {
		return nil, statErr
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		_ = f.Close()
		return nil, err
	}
	w := &WAL{f: f, path: path, enc: enc, poisonedCh: make(chan struct{})}
	if err := w.initialize(newFile); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// poisonLocked marks the WAL unrecoverable (a durability invariant failed) and signals
// PoisonedCh so the node can fence its data plane. Caller holds w.mu.
func (w *WAL) poisonLocked() {
	w.poisoned = true
	w.poisonOnce.Do(func() { close(w.poisonedCh) })
}

// Poison marks the log unusable for further appends (AppendBuffered returns errPoisoned) and
// fences the data plane via PoisonedCh. Recovery calls this when it detects corruption it could
// NOT rewrite away, so a later append can't land past the corrupt region and vanish on reopen.
func (w *WAL) Poison() {
	w.mu.Lock()
	w.poisonLocked()
	w.mu.Unlock()
}

// PoisonedCh is closed when the WAL can no longer uphold durability. The serving node
// selects on it to fence the data plane (stop reads/writes/checkpoints and fail over),
// so a poisoned primary never keeps serving applied-but-unacked state that a promoted
// standby would lack.
func (w *WAL) PoisonedCh() <-chan struct{} { return w.poisonedCh }

// frame encodes a record into its on-disk framing: [len][crc32][payload], where
// payload is gob(record) sealed by enc (verbatim gob when enc is nil). The crc is
// over the on-disk payload, so a torn write is detected before any decryption.
func frame(r Record, enc *secure.AtRest) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&r); err != nil {
		return nil, err
	}
	payload, err := enc.Seal(buf.Bytes())
	if err != nil {
		return nil, err
	}
	// Refuse to write a frame the reader would reject (the sealed size includes the
	// GCM nonce+tag, which can push a near-limit record over maxRecordBytes — that
	// would otherwise be written successfully but lost on every later read).
	if len(payload) > maxRecordBytes {
		return nil, fmt.Errorf("wal: framed record size %d exceeds the %d-byte limit", len(payload), maxRecordBytes)
	}
	out := make([]byte, headerBytes+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(out[4:8], crc32.ChecksumIEEE(out[0:4])) // length integrity
	binary.BigEndian.PutUint32(out[8:12], crc32.ChecksumIEEE(payload)) // payload integrity
	copy(out[headerBytes:], payload)
	return out, nil
}

// Append writes a record AND makes it durable before returning (buffer + commit). It
// is the simple per-write path used by tests and non-batched callers; the hot path
// uses AppendBuffered + CommitThrough so concurrent writers share one fsync+replicate.
func (w *WAL) Append(r Record) error {
	seq, err := w.AppendBuffered(r)
	if err != nil {
		return err
	}
	return w.CommitThrough(seq)
}

// AppendBuffered assigns the next LSN and writes the record's complete framed
// bytes to the log fd WITHOUT fsyncing or replicating. Once this returns nil, the
// frame is in the kernel's file state and is replayable after process death; a
// machine crash can still lose it until CommitThrough/fsync or backend flush.
// Buffering many records before a single fsync + single replication round-trip is
// what lets concurrent writers share one commit (group commit), so write
// throughput is bounded by batch latency, not per-write RTT.
func (w *WAL) AppendBuffered(r Record) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return 0, errPoisoned
	}
	if w.initErr != nil {
		return 0, w.initErr
	}
	if err := w.ensureEpochLocked(); err != nil {
		return 0, err
	}
	r.Seq = w.nextSeq
	framed, err := frame(r, w.enc)
	if err != nil {
		return 0, err
	}
	nextDigest, err := recordDigest(w.tipDigest, r)
	if err != nil {
		return 0, err
	}
	prevOffset := w.offset
	if err := writeFull(w.f, framed); err != nil {
		return 0, w.rollbackToLocked(prevOffset, err)
	}
	w.offset += int64(len(framed))
	seq := w.nextSeq
	w.nextSeq++
	w.count++
	w.tipDigest = nextDigest
	if w.recordHashes == nil {
		w.recordHashes = make(map[uint64][32]byte)
	}
	w.recordHashes[r.Seq], _ = recordDigest([32]byte{}, r)
	w.unflushed = append(w.unflushed, r)
	return seq, nil
}

// AppendBatchBuffered reserves ONE contiguous LSN range for records and writes
// their frames to the log fd under a single w.mu hold, without fsyncing or
// replicating. It is all-or-nothing: every frame is encoded BEFORE the first
// byte is written, and a write failure rolls the file back to its pre-batch
// offset — no LSN is consumed and no partial batch can ever be replayed. The
// records' Seq fields are assigned in place (records[i].Seq = first+i). Returns
// the exclusive end of the reserved range (first, first+len).
func (w *WAL) AppendBatchBuffered(records []Record) (firstSeq, endSeq uint64, err error) {
	if len(records) == 0 {
		return 0, 0, fmt.Errorf("wal: empty batch")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return 0, 0, errPoisoned
	}
	if w.initErr != nil {
		return 0, 0, w.initErr
	}
	if err := w.ensureEpochLocked(); err != nil {
		return 0, 0, err
	}
	first := w.nextSeq
	// Encode every frame before writing any byte, so an encode failure (e.g. an
	// over-size record) rejects the whole batch with the log untouched.
	framed := make([][]byte, len(records))
	var total int64
	tip := w.tipDigest
	for i := range records {
		records[i].Seq = first + uint64(i)
		f, ferr := frame(records[i], w.enc)
		if ferr != nil {
			return 0, 0, ferr
		}
		framed[i] = f
		total += int64(len(f))
		tip, ferr = recordDigest(tip, records[i])
		if ferr != nil {
			return 0, 0, ferr
		}
	}
	prevOffset := w.offset
	for _, f := range framed {
		if werr := writeFull(w.f, f); werr != nil {
			return 0, 0, w.rollbackToLocked(prevOffset, werr)
		}
	}
	w.offset = prevOffset + total
	w.nextSeq = first + uint64(len(records))
	w.count += len(records)
	w.tipDigest = tip
	if w.recordHashes == nil {
		w.recordHashes = make(map[uint64][32]byte)
	}
	for _, r := range records {
		w.recordHashes[r.Seq], _ = recordDigest([32]byte{}, r)
	}
	w.unflushed = append(w.unflushed, records...)
	return first, w.nextSeq, nil
}

func writeFull(f *os.File, p []byte) error {
	for len(p) > 0 {
		n, err := f.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// CommitThrough makes every record up to (and including) seq durable: fsync'd locally
// and replicated to the standby. Concurrent callers are batched — the first to arrive
// flushes the whole pending buffer in one fsync + one replication round-trip; callers
// whose LSN a prior flush already covered return immediately. Callers that require
// local-media/replica durability should ack that stronger guarantee only once this
// returns nil. On any durability failure the log is poisoned and the authority
// fences before apply/visibility; restart reconciliation determines the exact
// common durable prefix instead of guessing whether a timed-out replica applied.
func (w *WAL) CommitThrough(seq uint64) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	if w.durableSeq > seq { // durableSeq is exclusive: seq < durableSeq => already durable
		return nil
	}
	return w.flushLocked()
}

// flushLocked fsyncs the file and replicates every buffered record, advancing
// durableSeq. The caller holds commitMu (so flushes never overlap and the standby
// gets ordered batches). On failure it poisons the log and returns the error.
func (w *WAL) flushLocked() error {
	w.mu.Lock()
	if w.poisoned {
		w.mu.Unlock()
		return errPoisoned
	}
	w.unflushed = nil
	target := w.nextSeq // exclusive upper bound of what this flush makes durable
	f := w.f
	w.mu.Unlock()

	err := f.Sync()
	if err != nil {
		w.mu.Lock()
		w.poisonLocked()
		w.mu.Unlock()
		return err
	}
	if target > w.durableSeq {
		w.durableSeq = target
	}
	return nil
}

// rollbackToLocked truncates the log back to off, undoing a partially/locally
// written record after a write/sync/replicate failure (caller holds w.mu), and
// returns cause so the caller can propagate the original error. nextSeq/count are
// not advanced until an append fully succeeds, so there is nothing to roll back
// there. If the truncate/sync THEMSELVES fail, the log now holds a durable record
// the caller is being told failed (and which O_APPEND would strand before the next
// record, reusing its LSN) — an unrecoverable divergence, so the log is poisoned to
// refuse further appends rather than ack writes it cannot keep consistent.
func (w *WAL) rollbackToLocked(off int64, cause error) error {
	if terr := w.f.Truncate(off); terr != nil {
		w.poisonLocked()
		return fmt.Errorf("wal: append failed (%v) and rollback truncate failed: %w", cause, terr)
	}
	if serr := w.f.Sync(); serr != nil {
		w.poisonLocked()
		return fmt.Errorf("wal: append failed (%v) and rollback sync failed: %w", cause, serr)
	}
	w.offset = off
	return cause
}

// Watermark is the exclusive upper bound of LSNs appended so far: every current
// record has Seq < Watermark. A checkpoint captures it at snapshot time and later
// passes it to CompactThrough to drop exactly the committed prefix.
func (w *WAL) Watermark() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nextSeq
}

// DurableWatermark is the exclusive upper bound of LSNs known durable (fsync'd
// locally and replicated when a replica is attached): every record with
// Seq < DurableWatermark survived its durability barrier. It is always <=
// Watermark; the gap [DurableWatermark, Watermark) is buffered-but-not-durable.
func (w *WAL) DurableWatermark() uint64 {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	return w.durableSeq
}

// CompactedThrough is the exclusive lower bound of LSNs still in the log: every
// record with Seq < CompactedThrough has been compacted away by a checkpoint.
func (w *WAL) CompactedThrough() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.compactedThrough
}

// Count is the number of records currently in the log.
func (w *WAL) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// hasMore reports whether any unread byte remains in rf. It distinguishes a torn
// tail (a bad final record at EOF — a normal crash artifact, discarded) from
// mid-log corruption (a bad record with valid data after it — a real fault that
// must not silently swallow the good records that follow).
func hasMore(rf *os.File) bool {
	var b [1]byte
	_, err := rf.Read(b[:])
	return err == nil
}

// readRecords reads every intact record from path, in order. A torn or partial
// tail stops the scan and the longest intact prefix is returned without error. A
// corrupt record that is NOT at the tail (data follows it) returns an error, so
// valid records after a mid-log fault are never silently dropped.
// readRecords reads every intact record from path, in order, and returns the byte
// offset just past the last intact record (validEnd) so the caller can truncate any
// torn trailing bytes. A torn or partial tail stops the scan (the longest intact
// prefix is returned without error). A corrupt record that is NOT at the tail (data
// follows it) returns an error, so valid records after a mid-log fault are never
// silently dropped.
func readRecords(path string, enc *secure.AtRest) ([]Record, int64, error) {
	rf, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	defer rf.Close()

	var records []Record
	var validEnd int64 // bytes consumed by intact records so far
	var hdr [headerBytes]byte
	for {
		if _, err := io.ReadFull(rf, hdr[:]); err != nil {
			break // EOF at a record boundary, or a torn (partial) header at the tail
		}
		n := binary.BigEndian.Uint32(hdr[0:4])
		lenCrc := binary.BigEndian.Uint32(hdr[4:8])
		payloadCrc := binary.BigEndian.Uint32(hdr[8:12])
		if crc32.ChecksumIEEE(hdr[0:4]) != lenCrc {
			// The length field itself is corrupt. We read the full header, so this is
			// not a torn tail (which truncates the header) but bit-rot in a length we
			// must not trust: a too-large length would consume the records that follow
			// it and lose them. Fail loudly instead of silently truncating.
			return records, validEnd, fmt.Errorf("wal: corrupt length header after %d intact records", len(records))
		}
		if n > maxRecordBytes {
			// The length is integrity-checked, so this is a genuine oversize record
			// (our writer never emits one) — refuse it rather than allocate blindly.
			return records, validEnd, fmt.Errorf("wal: record length %d exceeds the %d-byte limit after %d intact records", n, maxRecordBytes, len(records))
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(rf, payload); err != nil {
			break // torn body at the tail (partial final record) -> discard
		}
		if crc32.ChecksumIEEE(payload) != payloadCrc {
			if hasMore(rf) {
				return records, validEnd, fmt.Errorf("wal: corrupt record (crc) after %d intact records with data following", len(records))
			}
			break // a bad final record == torn tail -> discard
		}
		data, oerr := enc.Open(payload)
		if oerr != nil {
			// The crc already passed over the full payload, so this is NOT a torn
			// write (a torn write fails the crc or the read). A complete, crc-valid
			// frame that won't authenticate means a wrong key or tampering — fail
			// loudly rather than silently discarding acknowledged records.
			return records, validEnd, fmt.Errorf("wal: record %d failed to decrypt/authenticate (wrong key or tampering): %w", len(records), oerr)
		}
		var r Record
		if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&r); err != nil {
			if hasMore(rf) {
				return records, validEnd, fmt.Errorf("wal: undecodable record after %d intact records with data following: %w", len(records), err)
			}
			break
		}
		records = append(records, r)
		validEnd += int64(headerBytes + n) // this frame is fully accounted for
	}
	return records, validEnd, nil
}

// Replay returns every intact record from the start of the log and restores the
// in-memory state (next LSN past the highest stored, live count, append offset).
func (w *WAL) Replay() ([]Record, error) {
	records, validEnd, err := readRecords(w.path, w.enc)
	if err != nil {
		// readRecords already returns the valid PREFIX it decoded before hitting an
		// unreadable record (mid-log corruption/tamper). Return that prefix alongside the
		// error so a recovery caller can salvage and re-flush what survived rather than
		// abandon the whole tail. The WAL is left untouched here (no truncation): callers
		// that salvage (session.New) atomically Renumber it to the prefix (removing the corrupt
		// region), and callers that must not proceed on corruption (the authority replay) still
		// see err and bail, leaving the file intact for forensics. We do NOT poison here: that
		// would make the salvaging Renumber refuse (it checks w.poisoned) and the poison-channel
		// close is irreversible. The salvage caller poisons via Poison() iff it cannot rewrite
		// the log clean (see session.New) — closing the "append lands past the corrupt region and
		// vanishes on the next replay" gap without defeating recovery.
		return records, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, seqErr := validateSequence(w.compactedThrough, records); seqErr != nil {
		w.initErr = seqErr
		return records, seqErr
	}
	w.count = len(records)
	w.nextSeq = w.compactedThrough + uint64(len(records))
	tip, derr := digestRecords(w.baseDigest, records)
	if derr != nil {
		w.initErr = derr
		return records, derr
	}
	w.tipDigest = tip
	w.recordHashes = make(map[uint64][32]byte, len(records))
	for _, r := range records {
		h, herr := recordDigest([32]byte{}, r)
		if herr != nil {
			w.initErr = herr
			return records, herr
		}
		w.recordHashes[r.Seq] = h
	}
	w.initErr = nil
	// Truncate any torn trailing bytes so new appends land immediately after the
	// last intact record. Otherwise (O_APPEND) they would land after the stale torn
	// bytes, and a later replay would read [valid][torn][new] and reject the whole
	// log as mid-log corruption — losing the new acknowledged records.
	if info, serr := w.f.Stat(); serr == nil && info.Size() > validEnd {
		if terr := w.f.Truncate(validEnd); terr != nil {
			// The torn tail could not be removed. If we left the log writable, the next
			// O_APPEND would land AFTER the torn bytes, and a later replay would read
			// [valid][torn][new] and reject the whole log as mid-log corruption — losing
			// the acknowledged new records. Poison so further appends are refused (fail
			// loud) instead; the records read so far are still returned for re-flush.
			w.poisonLocked()
			return records, terr
		}
		if serr := w.f.Sync(); serr != nil {
			w.poisonLocked() // truncate not durable: same torn-tail interleave risk on a crash
			return records, serr
		}
	}
	w.offset = validEnd
	return records, nil
}

// Renumber atomically rewrites the log so its records start at Seq 0 and run contiguously,
// for crash recovery: a prior generation's acked prefix was compacted away, so the surviving
// tail starts mid-stream — but a fresh generation's first flush must begin at Seq 0 (the
// authority's per-generation gap check). Unlike a Reset followed by a per-record AppendBuffered
// loop, the rewrite is a single temp+rename, so a mid-write failure can never leave a TRUNCATED
// tail (silent data loss). Record DATA is unchanged; only Seq is reassigned. Returns the
// re-numbered records for the caller to flush.
func (w *WAL) Renumber(records []Record) ([]Record, error) {
	w.commitMu.Lock() // exclude the group-commit flush from the rewrite (w.f swap)
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return nil, errPoisoned
	}
	if w.hasCheckpoint && !checkpointTerminal(w.checkpoint.Status) {
		return nil, errors.New("wal: renumber refused with an unresolved checkpoint cut")
	}
	out := make([]Record, len(records))
	for i, r := range records {
		r.Seq = uint64(i)
		out[i] = r
	}
	epoch, err := randomEpoch()
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	tip, err := digestRecords(zero, out)
	if err != nil {
		return nil, err
	}
	target := metadata{Version: metadataVersion, Epoch: epoch, BaseSeq: 0, BaseDigest: zero}
	if err := w.beginTransitionLocked(target, uint64(len(out)), tip); err != nil {
		return nil, err
	}
	if err := w.rewriteLocked(out); err != nil {
		_ = removeDurable(w.transitionPath())
		return nil, err
	}
	if err := w.finishTransitionLocked(target); err != nil {
		w.poisonLocked()
		return nil, err
	}
	w.count = len(out)
	w.nextSeq = uint64(len(out))
	w.compactedThrough = 0
	w.epoch = epoch
	w.baseDigest = zero
	w.baseCommitID = "" // fresh identity: any prior journal base anchor is void
	w.tipDigest = tip
	w.recordHashes = make(map[uint64][32]byte, len(out))
	for _, r := range out {
		h, _ := recordDigest([32]byte{}, r)
		w.recordHashes[r.Seq] = h
	}
	w.legacy = false
	w.initErr = nil
	w.unflushed = nil
	w.durableSeq = uint64(len(out)) // rewriteLocked synced the new file: every record is durable
	return out, nil
}

// Reset is a destructive standalone/test operation that creates a fresh epoch.
func (w *WAL) Reset() error {
	w.commitMu.Lock() // exclude the group-commit flush from the rewrite (w.f swap)
	defer w.commitMu.Unlock()
	w.mu.Lock()
	if w.hasCheckpoint && !checkpointTerminal(w.checkpoint.Status) {
		w.mu.Unlock()
		return errors.New("wal: reset refused with an unresolved checkpoint cut")
	}
	epoch, err := randomEpoch()
	if err != nil {
		w.mu.Unlock()
		return err
	}
	var zero [32]byte
	target := metadata{Version: metadataVersion, Epoch: epoch, BaseSeq: 0, BaseDigest: zero}
	if err := w.beginTransitionLocked(target, 0, zero); err != nil {
		w.mu.Unlock()
		return err
	}
	if err := w.rewriteLocked(nil); err != nil {
		_ = removeDurable(w.transitionPath())
		w.mu.Unlock()
		return err
	}
	if err := w.finishTransitionLocked(target); err != nil {
		w.poisonLocked()
		w.mu.Unlock()
		return err
	}
	w.count = 0
	w.nextSeq = 0
	w.compactedThrough = 0
	w.epoch = epoch
	w.baseDigest = zero
	w.baseCommitID = ""
	w.tipDigest = zero
	w.recordHashes = make(map[uint64][32]byte)
	w.legacy = false
	w.initErr = nil
	w.unflushed = nil
	w.mu.Unlock()
	w.durableSeq = 0 // commitMu-protected
	return nil
}

// CompactThrough drops every record with Seq < throughSeq — the prefix a
// checkpoint has just committed — and keeps the rest, so writes that arrived
// during the checkpoint survive. It replicates the same LSN watermark so a standby
// drops exactly the same prefix, regardless of its own record positions.
func (w *WAL) CompactThrough(throughSeq uint64) error {
	w.commitMu.Lock() // exclude the group-commit flush from the rewrite (w.f swap)
	defer w.commitMu.Unlock()
	// Make the pending batch durable first, so compaction operates on a
	// stable file (no unflushed tail).
	if err := w.flushLocked(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	effective := throughSeq
	if effective > w.nextSeq {
		effective = w.nextSeq
	}
	if effective < w.compactedThrough {
		effective = w.compactedThrough
	}
	if err := w.validateCheckpointCompactionLocked(effective); err != nil {
		return err
	}
	boundaryDigest, err := w.digestAtLocked(effective)
	if err != nil {
		return err
	}
	return w.compactLocalLocked(effective, boundaryDigest)
}

// compactLocalLocked installs one already-validated local compacted prefix.
// Caller holds w.mu and has made the live suffix durable.
func (w *WAL) compactLocalLocked(effective uint64, boundaryDigest [32]byte) error {
	records, _, err := readRecords(w.path, w.enc)
	if err != nil {
		return err
	}
	kept := make([]Record, 0, len(records))
	for _, r := range records {
		if r.Seq >= effective {
			kept = append(kept, r)
		}
	}
	target := metadata{
		Version: metadataVersion, Epoch: w.epoch, BaseSeq: effective, BaseDigest: boundaryDigest,
		BaseCommitID:  w.baseCommitID,
		HasCheckpoint: w.hasCheckpoint, Checkpoint: w.checkpoint,
	}
	if err := w.beginTransitionLocked(target, w.nextSeq, w.tipDigest); err != nil {
		return err
	}
	if err := w.rewriteLocked(kept); err != nil {
		_ = removeDurable(w.transitionPath())
		return err
	}
	if err := w.finishTransitionLocked(target); err != nil {
		w.poisonLocked()
		return err
	}
	w.count = len(kept)
	w.compactedThrough = effective
	w.baseDigest = boundaryDigest
	for seq := range w.recordHashes {
		if seq < effective {
			delete(w.recordHashes, seq)
		}
	}
	return nil
}

// rewriteLocked atomically replaces the log's contents with records: it writes a
// fresh temp file, fsyncs it, renames it over the live log, and fsyncs the parent
// directory (caller holds w.mu). A crash leaves either the whole old log or the
// whole new log — never a half-rewritten one (the old in-place truncate+rewrite
// could lose the kept tail mid-compaction).
func (w *WAL) rewriteLocked(records []Record) error {
	tmp := w.path + ".compact"
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	var off int64
	for _, r := range records {
		framed, ferr := frame(r, w.enc)
		if ferr != nil {
			_ = tf.Close()
			_ = os.Remove(tmp)
			return ferr
		}
		if werr := writeFull(tf, framed); werr != nil {
			_ = tf.Close()
			_ = os.Remove(tmp)
			return werr
		}
		off += int64(len(framed))
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Rename over the live log WITHOUT first closing w.f: the existing fd keeps
	// referring to the old inode (which the rename unlinks), and we only swap fds
	// after the replacement opens. So a rename or reopen failure never leaves w.f
	// closed (which would panic the next write) or the temp file stranded.
	if err := os.Rename(tmp, w.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := fsyncDir(filepath.Dir(w.path)); err != nil {
		return err
	}
	newF, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// The rename already swapped the new (compacted) file into place, but we could
		// not reopen it. w.f still refers to the OLD, now-unlinked inode; appending to
		// it would fsync "durable" records into a file no restart ever reads — silent
		// loss of acknowledged writes. Poison so further appends are refused.
		w.poisonLocked()
		return fmt.Errorf("wal: reopen after compaction rename failed (log poisoned): %w", err)
	}
	_ = w.f.Close()
	w.f = newF
	w.offset = off
	return nil
}

// fsyncDir fsyncs a directory so a create/rename within it is crash-durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Some filesystems don't SUPPORT directory fsync — treat only that as
		// non-fatal. A genuine I/O error must propagate, or we'd fake durability for a
		// create/rename that may not survive power loss.
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
			return nil
		}
		return err
	}
	return nil
}

// Close closes the underlying file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// RemoveFiles deletes a (closed) log at path together with its durable sidecar
// metadata. Removing only the log file would leave the sidecar's BaseSeq
// behind, and a later Open at the same path would resurrect it: a brand-new
// log whose sequence numbering silently starts mid-stream. The first error is
// returned; later removals are still attempted.
func RemoveFiles(path string) error {
	var firstErr error
	for _, p := range []string{path, path + ".meta", path + ".meta.transition"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
