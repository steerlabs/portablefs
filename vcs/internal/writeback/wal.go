package writeback

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Segment layout: a 4096-byte header followed by frames. Every integer is
// big-endian. Frames are 8-byte aligned.
const (
	segmentHeaderSize = 4096
	frameHeaderSize   = 40
	frameAlign        = 8

	// maxMutationPayload bounds one MUTATION frame's PFR1 payload; larger
	// writes split into contiguous records before admission.
	maxMutationPayload = (1 << 20) + (64 << 10)

	// groupSyncBytes is the local group-sync byte threshold.
	groupSyncBytes = 4 << 20
)

// ─── the legacy-stream recovery contract ─────────────────────────────────────
//
// ANY WAL VALID UNDER THE FROZEN PFW5 FRAME DECODER MUST REACH A DEFINITE
// RECOVERY OUTCOME WITHIN THE CONFIGURED BOUND.
//
// PFW5 is frozen. Its only on-disk size rule is decodeFrameAt's: every frame's
// payloadLen is bounded by maxMutationPayload, whatever the frame type. A WAL
// written by ANY version of this code that satisfies that rule is a WAL this
// version must be able to finish, because the alternative — a stream that
// replays forever and never releases — wedges the mount and strands authority
// grants for every peer.
//
// Two things follow, and both are load-bearing:
//
//  1. FIELD CAPS ARE ADMISSION-ONLY. maxScopeBytes/maxEpochBytes/maxJobIDBytes/
//     maxReasonBytes/maxDigestBytes were introduced (81e235b) so the control
//     reserve's arithmetic has finite terms over the values the WRITE PATH can
//     still choose. Applying them to a value that is already accepted and
//     already durable in this stream turns a valid WAL into an unfinalizable
//     one. So there are two encoders, not one flag: encodeControlPayload for a
//     NEW value entering the log, encodeDurableControlPayload for re-emitting a
//     value this stream already holds. The bytes they produce are identical;
//     only the admissible input set differs.
//
//  2. CLOSE-OUT IS BUDGETED, NOT ASSUMED. A pre-upgrade stream carries no
//     control reserve — it may sit at the full cap with nothing held back. So
//     recovery's close-out cannot append blind: it computes the certificate's
//     EXACT cost from the actual encoded payloads and, when that does not fit,
//     reclaims the fully-applied segment prefix it is entitled to (recovery only
//     writes the certificate once the whole tail is authority-applied) before
//     appending. If it still does not fit, recovery lands in a TYPED TERMINAL
//     state. See appendRecoveryReleaseCertificate.
//
// Reserve arithmetic is stated in ACTUAL encoded sizes wherever the value is
// known (liveGrant.frameBytes, w.liveDelegationBytes); the maxima above are the
// bound only for values not yet chosen. That is what keeps the reserve correct
// for a live set of any frame size.

// Control frames carry the only variable-length fields the log holds outside a
// mutation payload. The stream's byte cap can only be a bound if the bytes
// those fields can produce are bounded, so each is capped here and checked
// before the frame is encoded: an over-long value is a definite refusal at the
// write path, never a frame the strict decoder would later reject as
// corruption (decodeFrameAt bounds payloadLen by maxMutationPayload for EVERY
// frame type, so an unchecked control frame is writable and unreplayable).
const (
	// maxScopeBytes bounds a delegation scope. A scope is a path, so this
	// mirrors fsproto.MaxPathBytes (not imported here: the WAL owns its own
	// frame bounds and must not inherit them from the wire protocol).
	maxScopeBytes = 4096
	// maxEpochBytes bounds the authority-supplied grant epoch.
	maxEpochBytes = 256
	// maxJobIDBytes bounds a recovery job identifier.
	maxJobIDBytes = 128
	// maxReasonBytes bounds a forced-close diagnostic string.
	maxReasonBytes = 256
	// maxDigestBytes is the hex chain digest an APPLIED certificate carries.
	maxDigestBytes = 2 * 32

	// jsonEscapeFactor is encoding/json's worst-case expansion for one input
	// byte: \uXXXX, emitted for a control byte and for < > &.
	jsonEscapeFactor = 6
	// maxUint64Digits bounds a JSON-encoded uint64.
	maxUint64Digits = 20

	// The worst-case JSON encoding of each control payload shape, from the
	// field caps above plus each struct's fixed punctuation:
	//
	//	{"scope":"S","epoch":"E"}               23 + |S| + |E|
	//	{"through":N,"digest":"D"}              24 + |N| + |D|
	//	{"through":N,"jobId":"J","reason":"R"}  35 + |N| + |J| + |R|
	//
	// These are the terms the control reserve's arithmetic is written in.
	maxDelegationPayload = 23 + jsonEscapeFactor*(maxScopeBytes+maxEpochBytes)
	maxAppliedPayload    = 24 + maxUint64Digits + maxDigestBytes
	maxClosePayload      = 35 + maxUint64Digits + jsonEscapeFactor*(maxJobIDBytes+maxReasonBytes)
)

var (
	segmentMagic = [4]byte{'P', 'F', 'W', '5'}
	frameMagic   = [4]byte{'P', 'F', 'R', '5'}
	crcTable     = crc32.MakeTable(crc32.Castagnoli)

	// groupSyncDelay is the time threshold. A variable lets package tests
	// pin the write-versus-fsync boundary; production never changes it.
	groupSyncDelay = 5 * time.Millisecond
)

// segmentTargetBytes is the rotation threshold (a variable so rotation tests
// stay fast; production never changes it).
var segmentTargetBytes int64 = 64 << 20

// ErrCorrupt marks mid-log damage that recovery must not scan past: the
// stream fails closed into a corrupt recovery job instead of guessing.
var ErrCorrupt = errors.New("writeback: wal corruption")

type frameType uint8

const (
	frameMutation   frameType = 1
	frameDelegation frameType = 2
	// Frame type 3 was a reserved SESSION_BIND that never shipped: the v5
	// session posture never rebinds a live mount in-process (a fenced
	// session means remount), and a parked stream's rebind is durable
	// AUTHORITY state (ManagedWritebackRebind). The value stays a hole in
	// the numbering; the decoder rejects it like any unknown type.
	frameApplied     frameType = 4
	frameClose       frameType = 5
	frameForcedClose frameType = 6
	frameRelease     frameType = 7
)

// validFrameType fails closed on unknown record types, including the
// retired/reserved hole at 3.
func validFrameType(t frameType) bool {
	switch t {
	case frameMutation, frameDelegation, frameApplied, frameClose, frameForcedClose, frameRelease:
		return true
	default:
		return false
	}
}

// delegationFrame records a grant installation (or, as a frameRelease, the
// durable local decision that a fully drained grant no longer authorizes new
// mutations). frameRelease is synced before the authority Checkin: recovery
// can therefore sweep a still-held grant or accept an already-committed
// Checkin without guessing from a lost reply. Control frames are stream-local:
// they never cross a process boundary, so JSON under the frame CRC is
// sufficient.
type delegationFrame struct {
	Scope string `json:"scope"`
	Epoch string `json:"epoch"`
}

type appliedFrame struct {
	Through uint64 `json:"through"`
	Digest  string `json:"digest"` // hex chain digest at Through
}

type closeFrame struct {
	Through uint64 `json:"through"`
	JobID   string `json:"jobId,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (f delegationFrame) validate() error {
	if len(f.Scope) > maxScopeBytes {
		return fmt.Errorf("writeback: delegation scope of %d bytes exceeds the %d-byte control-frame bound", len(f.Scope), maxScopeBytes)
	}
	if len(f.Epoch) > maxEpochBytes {
		return fmt.Errorf("writeback: delegation epoch of %d bytes exceeds the %d-byte control-frame bound", len(f.Epoch), maxEpochBytes)
	}
	return nil
}

func (f appliedFrame) validate() error {
	if len(f.Digest) > maxDigestBytes {
		return fmt.Errorf("writeback: applied digest of %d bytes exceeds the %d-byte control-frame bound", len(f.Digest), maxDigestBytes)
	}
	return nil
}

func (f closeFrame) validate() error {
	if len(f.JobID) > maxJobIDBytes {
		return fmt.Errorf("writeback: close job id of %d bytes exceeds the %d-byte control-frame bound", len(f.JobID), maxJobIDBytes)
	}
	if len(f.Reason) > maxReasonBytes {
		return fmt.Errorf("writeback: close reason of %d bytes exceeds the %d-byte control-frame bound", len(f.Reason), maxReasonBytes)
	}
	return nil
}

// encodeControlPayload is the ADMISSION-SIDE control encoder: the one every
// control frame carrying a NEWLY CHOSEN value goes through, online and offline.
// It bounds the variable-length fields before marshalling, so the reserve's
// arithmetic holds over the payloads the write path can actually produce, and
// then applies the frozen frame bound. The encoded bytes are unchanged: this is
// an admission check over the identical replay format.
//
// It is NOT the encoder for a value this stream already holds durably — see
// encodeDurableControlPayload and the legacy-stream recovery contract above.
func encodeControlPayload(v any) ([]byte, error) {
	switch f := v.(type) {
	case delegationFrame:
		if err := f.validate(); err != nil {
			return nil, err
		}
	case appliedFrame:
		if err := f.validate(); err != nil {
			return nil, err
		}
	case closeFrame:
		if err := f.validate(); err != nil {
			return nil, err
		}
	}
	// Anything else carries no bounded fields to check and is left to the
	// encoded-length bound below: recovery's fail-closed contract for a
	// CRC-valid payload that does not decode is exercised with exactly such a
	// value, and it must reach the log to be exercised at all.
	return encodeDurableControlPayload(v)
}

// encodeDurableControlPayload is the REPLAY / CLOSE-OUT side control encoder:
// it re-emits a value that is ALREADY durable in this stream — a scope and
// epoch scanned back out of its own DELEGATION frames, or a live grant copied
// into a fresh segment by rotation. Such a value was admitted by whatever
// version wrote it, so the only bound that may apply to it is the frozen
// on-disk one the decoder enforces (maxMutationPayload). Re-checking it against
// today's admission caps would make a WAL that replays fine impossible to
// finalize, which is exactly what the contract above forbids.
//
// It produces byte-identical output to encodeControlPayload for every value the
// admission caps accept; the two differ only in which inputs they refuse.
func encodeDurableControlPayload(v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxMutationPayload {
		return nil, fmt.Errorf("writeback: control payload %d exceeds frame bound", len(payload))
	}
	return payload, nil
}

// streamDigest chains the mutation payload digests:
//
//	D(0) = SHA-256("PortableFS/PFW5/empty/v1\0")
//	D(n) = SHA-256("PortableFS/PFW5/stream/v1\0" || D(n-1) || be64(n) || SHA-256(payload))
//
// The authority computes the identical chain from the flushed records.
func digestZero() [32]byte {
	return sha256.Sum256([]byte("PortableFS/PFW5/empty/v1\x00"))
}

func digestNext(prev [32]byte, seq uint64, payload []byte) [32]byte {
	inner := sha256.Sum256(payload)
	h := sha256.New()
	h.Write([]byte("PortableFS/PFW5/stream/v1\x00"))
	h.Write(prev[:])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	h.Write(b[:])
	h.Write(inner[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// segmentHeader identifies one segment within a stream.
type segmentHeader struct {
	MountID    [16]byte
	VolumeID   string
	Branch     string
	WALEpoch   uint64
	Ordinal    uint64
	FirstFrame uint64 // dense physical frame number of the first frame
	FirstSeq   uint64 // first mutation sequence that may appear
	CreatedMs  int64
}

func encodeSegmentHeader(h segmentHeader) ([]byte, error) {
	if len(h.VolumeID) > 1024 || len(h.Branch) > 255 {
		return nil, fmt.Errorf("writeback: segment identity too long")
	}
	buf := make([]byte, segmentHeaderSize)
	copy(buf[0:4], segmentMagic[:])
	binary.BigEndian.PutUint16(buf[4:6], 1) // format version
	copy(buf[8:24], h.MountID[:])
	binary.BigEndian.PutUint64(buf[24:32], h.WALEpoch)
	binary.BigEndian.PutUint64(buf[32:40], h.Ordinal)
	binary.BigEndian.PutUint64(buf[40:48], h.FirstFrame)
	binary.BigEndian.PutUint64(buf[48:56], h.FirstSeq)
	binary.BigEndian.PutUint64(buf[56:64], uint64(h.CreatedMs))
	binary.BigEndian.PutUint16(buf[64:66], uint16(len(h.VolumeID)))
	binary.BigEndian.PutUint16(buf[66:68], uint16(len(h.Branch)))
	off := 68
	off += copy(buf[off:], h.VolumeID)
	copy(buf[off:], h.Branch)
	crc := crc32.Checksum(buf[:segmentHeaderSize-4], crcTable)
	binary.BigEndian.PutUint32(buf[segmentHeaderSize-4:], crc)
	return buf, nil
}

func decodeSegmentHeader(buf []byte) (segmentHeader, error) {
	var h segmentHeader
	if len(buf) < segmentHeaderSize {
		return h, fmt.Errorf("%w: short segment header", ErrCorrupt)
	}
	if [4]byte(buf[0:4]) != segmentMagic {
		return h, fmt.Errorf("%w: bad segment magic", ErrCorrupt)
	}
	if binary.BigEndian.Uint16(buf[4:6]) != 1 {
		return h, fmt.Errorf("%w: unknown segment format version", ErrCorrupt)
	}
	if crc32.Checksum(buf[:segmentHeaderSize-4], crcTable) != binary.BigEndian.Uint32(buf[segmentHeaderSize-4:segmentHeaderSize]) {
		return h, fmt.Errorf("%w: segment header checksum mismatch", ErrCorrupt)
	}
	copy(h.MountID[:], buf[8:24])
	h.WALEpoch = binary.BigEndian.Uint64(buf[24:32])
	h.Ordinal = binary.BigEndian.Uint64(buf[32:40])
	h.FirstFrame = binary.BigEndian.Uint64(buf[40:48])
	h.FirstSeq = binary.BigEndian.Uint64(buf[48:56])
	h.CreatedMs = int64(binary.BigEndian.Uint64(buf[56:64]))
	vl := int(binary.BigEndian.Uint16(buf[64:66]))
	bl := int(binary.BigEndian.Uint16(buf[66:68]))
	if 68+vl+bl > segmentHeaderSize-4 {
		return h, fmt.Errorf("%w: segment identity overflows header", ErrCorrupt)
	}
	h.VolumeID = string(buf[68 : 68+vl])
	h.Branch = string(buf[68+vl : 68+vl+bl])
	return h, nil
}

// frame is one decoded WAL frame.
type frame struct {
	typ     frameType
	frameNo uint64
	seq     uint64 // mutation sequence; zero for control frames
	payload []byte
	// ordinal/payloadOff locate the payload on disk for extent references.
	ordinal    uint64
	payloadOff int64
}

func frameLen(payloadLen int) int64 {
	n := int64(frameHeaderSize + payloadLen)
	if rem := n % frameAlign; rem != 0 {
		n += frameAlign - rem
	}
	return n
}

func encodeFrame(dst []byte, typ frameType, frameNo, seq uint64, payload []byte) []byte {
	start := len(dst)
	total := frameLen(len(payload))
	dst = append(dst, make([]byte, total)...)
	buf := dst[start:]
	copy(buf[0:4], frameMagic[:])
	buf[4] = 1 // frame version
	buf[5] = byte(typ)
	binary.BigEndian.PutUint64(buf[8:16], frameNo)
	binary.BigEndian.PutUint64(buf[16:24], seq)
	binary.BigEndian.PutUint32(buf[24:28], uint32(len(payload)))
	binary.BigEndian.PutUint32(buf[28:32], crc32.Checksum(payload, crcTable))
	binary.BigEndian.PutUint32(buf[32:36], crc32.Checksum(buf[:32], crcTable))
	copy(buf[frameHeaderSize:], payload)
	return dst
}

// liveGrant is one entry of the re-emit projection: the grant's epoch and the
// exact framed size of the DELEGATION record rotation re-emits for it.
type liveGrant struct {
	epoch      string
	frameBytes int64
}

// segmentInfo tracks one live segment.
type segmentInfo struct {
	ordinal uint64
	path    string
	header  segmentHeader
	size    int64
	// lastSeq is the highest mutation sequence in the segment (0 = none).
	lastSeq uint64
	// lastFrame is the highest frame number present.
	lastFrame uint64
}

// streamWAL is one mount stream's segmented on-disk log.
type streamWAL struct {
	dir      string
	mountID  [16]byte
	volumeID string
	branch   string
	epoch    uint64

	mu        sync.Mutex
	segments  []segmentInfo // ordinal ascending; last is active
	active    *os.File
	files     map[uint64]*os.File // open segment fds by ordinal (reads)
	nextFrame uint64
	lastSeq   uint64
	digest    [32]byte // chain digest at lastSeq

	// liveDelegations is the control-frame projection for grants that have
	// been installed but not released. Rotation re-emits this set into the new
	// segment before it can accept mutations, so reclaiming every older
	// segment can never erase the recovery authority for a later tail.
	liveDelegations map[string]liveGrant // scope -> grant
	// liveDelegationBytes is Σ frameBytes over liveDelegations: the exact
	// number of bytes one rotation's re-emit writes. It is the term the control
	// reserve is built on, so it is maintained with the projection rather than
	// recomputed per append.
	liveDelegationBytes int64

	// readRefs pins segments a composed read snapshot references, so
	// checkpoint+reclaim can never delete a segment out from under an
	// in-flight pread (the read snapshots extents under e.mu, then reads
	// without it).
	readRefs map[uint64]int

	// reserved is the byte cost of appends that have been ADMITTED against the
	// budget but have not finished writing yet. Budget admission adds a cost
	// here before it can release w.mu (rotation waits on an in-flight sync
	// without the mutex), so a concurrent admission counts the bytes an
	// in-flight append is already entitled to write and can never double-admit
	// the same headroom. It settles to zero as each append completes and its
	// bytes appear in the segment sizes.
	reserved int64
	// admitMu serializes budgeted admissions end-to-end (taken strictly
	// outside w.mu; see appendMutationsWithin).
	admitMu sync.Mutex

	unsyncedBytes int64
	unsyncedSince time.Time
	syncTimer     *time.Timer
	syncing       bool
	syncDone      chan struct{}
	syncErr       error
	// syncFile is a test seam. Nil uses (*os.File).Sync.
	syncFile  func(*os.File) error
	onFailure func(error)
	closed    bool
}

func segmentPath(dir string, ordinal uint64) string {
	return filepath.Join(dir, fmt.Sprintf("wb-%08d.pfw", ordinal))
}

// createStreamWAL initializes a fresh stream directory with its first
// segment, fsynced before any acknowledgment can happen.
func createStreamWAL(dir string, mountID [16]byte, volumeID, branch string, epoch uint64) (*streamWAL, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &streamWAL{
		dir: dir, mountID: mountID, volumeID: volumeID, branch: branch, epoch: epoch,
		files:           map[uint64]*os.File{},
		readRefs:        map[uint64]int{},
		liveDelegations: map[string]liveGrant{},
		digest:          digestZero(),
	}
	if err := w.openSegmentLocked(1, 1, 1); err != nil {
		return nil, err
	}
	if err := fsyncDir(dir); err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

// openSegmentLocked creates segment `ordinal` and makes it active.
func (w *streamWAL) openSegmentLocked(ordinal, firstFrame, firstSeq uint64) error {
	h := segmentHeader{
		MountID: w.mountID, VolumeID: w.volumeID, Branch: w.branch,
		WALEpoch: w.epoch, Ordinal: ordinal,
		FirstFrame: firstFrame, FirstSeq: firstSeq,
		CreatedMs: time.Now().UnixMilli(),
	}
	buf, err := encodeSegmentHeader(h)
	if err != nil {
		return err
	}
	path := segmentPath(w.dir, ordinal)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	w.segments = append(w.segments, segmentInfo{ordinal: ordinal, path: path, header: h, size: segmentHeaderSize})
	w.active = f
	w.files[ordinal] = f
	if w.nextFrame == 0 {
		// nextFrame tracks the LAST issued dense frame number.
		w.nextFrame = firstFrame - 1
	}
	return nil
}

// appendResult locates an appended mutation payload for extent references.
type appendResult struct {
	seq        uint64
	ordinal    uint64
	payloadOff int64
	payloadLen int
	digest     [32]byte // chain digest AFTER this record
}

// appendMutations appends one syscall's mutation records all-or-nothing:
// a partial append is truncated before any acknowledgment. Sequences are
// assigned densely from lastSeq+1. Returns per-record placements.
func (w *streamWAL) appendMutations(payloads [][]byte) ([]appendResult, error) {
	return w.appendMutationsWithin(payloads, 0)
}

// appendMutationsWithin is appendMutations under a hard on-disk budget.
//
// Admission is a RESERVATION, not an observation: the exact number of bytes
// this append will add to the stream's footprint — every aligned frame, plus a
// segment rollover's header and re-emitted live delegations when the active
// segment is at its rotation threshold — is computed and charged against the
// budget while holding w.mu, before a single byte is written. It therefore
// answers ErrNoSpace strictly BEFORE the mutation (nothing to undo, no
// half-written frame, no failure to latch), and an admitted append can never
// push the footprint past the budget: an append twice the budget's size is
// refused whether usage is at 99% or at zero. budget <= 0 means unbounded, for
// the control-plane and recovery paths that must be able to close out a stream
// which is already at its bound.
//
// The reservation is taken against the budget MINUS the control reserve, so a
// saturated mutation lane always leaves the lifecycle control frames it cannot
// refuse enough room to land inside the same cap (controlReserveLocked).
func (w *streamWAL) appendMutationsWithin(payloads [][]byte, budget int64) ([]appendResult, error) {
	if budget > 0 {
		// Budgeted admissions serialize across the whole append, including the
		// rotation window where rotateIfNeededLocked releases w.mu to wait on
		// a background sync. Without this, two admissions straddling a segment
		// boundary each charge the same rollover cost and the second can be
		// refused headroom that actually exists. Engine mutations are already
		// serialized above this layer, so the lock is contention-free in
		// production; it makes the reservation invariant true of the WAL
		// itself rather than of its current caller.
		w.admitMu.Lock()
		defer w.admitMu.Unlock()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, errors.New("writeback: wal closed")
	}
	if w.syncErr != nil {
		return nil, w.syncErr
	}
	for _, p := range payloads {
		if len(p) > maxMutationPayload {
			return nil, fmt.Errorf("writeback: mutation payload %d exceeds frame bound", len(p))
		}
	}
	if budget > 0 {
		cost, err := w.appendCostLocked(payloads)
		if err != nil {
			return nil, err
		}
		// The control reserve is held back from the mutation lanes: it is the
		// headroom the lifecycle frames a mutation lane cannot refuse (APPLIED,
		// RELEASE, CLOSE, FORCED_CLOSE and the rotations they trip) are
		// guaranteed to find. See controlReserveLocked.
		if w.diskBytesLocked()+w.reserved+cost+w.controlReserveLocked(0, 0) > budget {
			return nil, ErrNoSpace
		}
		w.reserved += cost
		// Settle the reservation on every exit: on success the bytes are in the
		// segment sizes, on failure they were never written.
		defer func() { w.reserved -= cost }()
	}
	if err := w.rotateIfNeededLocked(); err != nil {
		return nil, err
	}
	seg := &w.segments[len(w.segments)-1]
	startSize := seg.size
	var buf []byte
	results := make([]appendResult, 0, len(payloads))
	seq := w.lastSeq
	fno := w.nextFrame
	digest := w.digest
	for _, p := range payloads {
		seq++
		fno++
		digest = digestNext(digest, seq, p)
		results = append(results, appendResult{
			seq: seq, ordinal: seg.ordinal,
			payloadOff: startSize + int64(len(buf)) + frameHeaderSize,
			payloadLen: len(p),
			digest:     digest,
		})
		buf = encodeFrame(buf, frameMutation, fno, seq, p)
	}
	if err := w.writeActiveLocked(buf, startSize); err != nil {
		return nil, err
	}
	seg.size += int64(len(buf))
	seg.lastSeq = seq
	seg.lastFrame = fno
	w.lastSeq = seq
	w.nextFrame = fno
	w.digest = digest
	return results, nil
}

// appendControl appends one LIFECYCLE control frame: a frame the stream can be
// obliged to write and that therefore must never be refused for want of space —
// an unwritable CLOSE, FORCED_CLOSE, APPLIED or RELEASE is a wedged mount. It
// draws from the control reserve, which controlReserveLocked sizes to dominate
// exactly this set. New grants are NOT lifecycle: they use appendControlWithin.
func (w *streamWAL) appendControl(typ frameType, v any) error {
	payload, err := encodeControlPayload(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendControlLocked(typ, payload)
}

// appendControlWithin appends one control frame under the stream's hard cap,
// keeping the control reserve for the live set this frame would produce intact.
// It is how a NEW delegation enters the log: a new grant is the one control
// frame that is not obliged — it raises the re-emit cost of every later
// rotation and adds an eventual release, so it is admitted only while the
// reserve still dominates the close-out of the set it joins. ErrNoSpace here is
// a definite "not delegable now", not a failure: the caller hands the grant
// back and the mutation takes the authority lane.
func (w *streamWAL) appendControlWithin(typ frameType, v any, budget int64) error {
	payload, err := encodeControlPayload(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if budget > 0 {
		frame := frameLen(len(payload))
		cost := w.controlCostLocked(frame)
		if w.diskBytesLocked()+w.reserved+cost+w.controlReserveLocked(frame, 1) > budget {
			return ErrNoSpace
		}
	}
	return w.appendControlLocked(typ, payload)
}

// recordDrainedRelease writes the authority-confirmed applied prefix and the
// locally-final grant release as one WAL transaction: both frames are
// appended while holding the WAL mutex and become durable in the same sync.
// Recovery can therefore use the APPLIED certificate when Checkin committed
// but its reply was lost and the authority has already retired the stream
// ledger. No mutation may be admitted under scope after this operation.
func (w *streamWAL) recordDrainedRelease(scope, epoch string, through uint64, digest [32]byte) error {
	if scope == "" || epoch == "" {
		return errors.New("writeback: invalid drained release")
	}
	appliedPayload, err := encodeControlPayload(appliedFrame{
		Through: through,
		Digest:  fmt.Sprintf("%x", digest),
	})
	if err != nil {
		return err
	}
	releasePayload, err := encodeControlPayload(delegationFrame{Scope: scope, Epoch: epoch})
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("writeback: wal closed")
	}
	if w.syncErr != nil {
		return w.syncErr
	}
	if through > w.lastSeq {
		return fmt.Errorf("writeback: drained release watermark %d is past WAL tail %d", through, w.lastSeq)
	}
	if through == w.lastSeq && digest != w.digest {
		return errors.New("writeback: drained release digest does not match WAL tail")
	}
	// Rotate at most once before constructing the pair. Writing both encoded
	// frames in one WriteAt means a partial write truncates both, and neither
	// frame can independently trigger a rotation or sync.
	if err := w.rotateIfNeededLocked(); err != nil {
		return err
	}
	seg := &w.segments[len(w.segments)-1]
	firstFrame := w.nextFrame + 1
	buf := encodeFrame(nil, frameApplied, firstFrame, 0, appliedPayload)
	buf = encodeFrame(buf, frameRelease, firstFrame+1, 0, releasePayload)
	if err := w.writeActiveLocked(buf, seg.size); err != nil {
		return err
	}
	seg.size += int64(len(buf))
	seg.lastFrame = firstFrame + 1
	w.nextFrame = firstFrame + 1
	w.applyDelegationControlLocked(frameRelease, releasePayload)
	return w.syncLocked()
}

func (w *streamWAL) appendControlLocked(typ frameType, payload []byte) error {
	if w.closed {
		return errors.New("writeback: wal closed")
	}
	if w.syncErr != nil {
		return w.syncErr
	}
	if err := w.rotateIfNeededLocked(); err != nil {
		return err
	}
	if err := w.writeControlLocked(typ, payload); err != nil {
		return err
	}
	w.applyDelegationControlLocked(typ, payload)
	return nil
}

// writeControlLocked writes one control frame without consulting the rotation
// threshold. Rotation uses this lower-level primitive to seed a new segment
// without recursively rotating it.
func (w *streamWAL) writeControlLocked(typ frameType, payload []byte) error {
	seg := &w.segments[len(w.segments)-1]
	fno := w.nextFrame + 1
	buf := encodeFrame(nil, typ, fno, 0, payload)
	if err := w.writeActiveLocked(buf, seg.size); err != nil {
		return err
	}
	seg.size += int64(len(buf))
	seg.lastFrame = fno
	w.nextFrame = fno
	return nil
}

// applyDelegationControlLocked advances the in-memory projection only after
// its corresponding frame is fully written. Malformed controls are left for
// the strict recovery decoder to reject; production only emits typed frames.
func (w *streamWAL) applyDelegationControlLocked(typ frameType, payload []byte) {
	if typ != frameDelegation && typ != frameRelease {
		return
	}
	var df delegationFrame
	if err := json.Unmarshal(payload, &df); err != nil || df.Scope == "" {
		return
	}
	switch typ {
	case frameDelegation:
		if df.Epoch != "" {
			w.dropLiveDelegationLocked(df.Scope)
			w.liveDelegations[df.Scope] = liveGrant{epoch: df.Epoch, frameBytes: frameLen(len(payload))}
			w.liveDelegationBytes += frameLen(len(payload))
		}
	case frameRelease:
		w.dropLiveDelegationLocked(df.Scope)
	}
}

// dropLiveDelegationLocked removes a scope from the re-emit projection together
// with its exact contribution to the re-emit size, so the two never diverge.
func (w *streamWAL) dropLiveDelegationLocked(scope string) {
	grant, ok := w.liveDelegations[scope]
	if !ok {
		return
	}
	delete(w.liveDelegations, scope)
	w.liveDelegationBytes -= grant.frameBytes
}

// reemitLiveDelegationsLocked makes the new active segment independently
// recoverable before any mutation can use it. Scope sorting keeps physical WAL
// bytes deterministic despite map iteration order.
//
// Every value here is already durable in this stream, so it goes through the
// DURABLE encoder: a rotation must never be able to fail on a grant the log
// already holds. The bytes are identical to the ones the admitting DELEGATION
// frame wrote, which is what makes liveGrant.frameBytes — recorded at install
// time — the exact cost of this re-emit for the reserve arithmetic.
func (w *streamWAL) reemitLiveDelegationsLocked() error {
	scopes := make([]string, 0, len(w.liveDelegations))
	for scope := range w.liveDelegations {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		payload, err := encodeDurableControlPayload(delegationFrame{Scope: scope, Epoch: w.liveDelegations[scope].epoch})
		if err != nil {
			return err
		}
		if err := w.writeControlLocked(frameDelegation, payload); err != nil {
			return err
		}
	}
	return nil
}

// writeActiveLocked writes buf at offset off in the active segment and
// truncates back on a partial write so recovery never sees a half frame the
// engine acknowledged.
func (w *streamWAL) writeActiveLocked(buf []byte, off int64) error {
	n, err := w.active.WriteAt(buf, off)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 {
			_ = w.active.Truncate(off)
		}
		return w.failLocked(fmt.Errorf("write active segment: %w", err))
	}
	w.unsyncedBytes += int64(len(buf))
	if w.unsyncedSince.IsZero() {
		w.unsyncedSince = time.Now()
	}
	if w.unsyncedBytes >= groupSyncBytes {
		w.startBackgroundSyncLocked()
		return nil
	}
	w.armSyncTimerLocked()
	return nil
}

func (w *streamWAL) armSyncTimerLocked() {
	if w.syncTimer != nil || w.syncing {
		return
	}
	w.syncTimer = time.AfterFunc(groupSyncDelay, func() {
		w.mu.Lock()
		w.syncTimer = nil
		if !w.closed && w.unsyncedBytes > 0 {
			w.startBackgroundSyncLocked()
		}
		w.mu.Unlock()
	})
}

// startBackgroundSyncLocked snapshots the currently-unsynced prefix and
// syncs it without holding the append mutex. Writes accepted after the
// snapshot accumulate in a fresh unsynced generation and are conservatively
// covered by the next group sync, even if the kernel happened to include
// them in the in-flight fsync. This keeps a slow local fsync from serializing
// every FSKit create/write/xattr callback behind the WAL mutex.
func (w *streamWAL) startBackgroundSyncLocked() {
	if w.syncing || w.unsyncedBytes == 0 || w.active == nil || w.closed {
		return
	}
	f := w.active
	syncFile := w.syncFile
	done := make(chan struct{})
	w.syncing = true
	w.syncDone = done
	w.unsyncedBytes = 0
	w.unsyncedSince = time.Time{}
	go func() {
		var err error
		if syncFile != nil {
			err = syncFile(f)
		} else {
			err = f.Sync()
		}

		w.mu.Lock()
		if err != nil && !w.closed {
			_ = w.failLocked(fmt.Errorf("sync active segment: %w", err))
		}
		w.syncing = false
		w.syncDone = nil
		close(done)
		if err == nil && !w.closed && w.unsyncedBytes > 0 {
			w.armSyncTimerLocked()
		}
		w.mu.Unlock()
	}()
}

func (w *streamWAL) failLocked(err error) error {
	if w.syncErr != nil {
		return w.syncErr
	}
	w.syncErr = err
	if w.onFailure != nil {
		w.onFailure(err)
	}
	return err
}

func (w *streamWAL) syncLocked() error {
	for w.syncing {
		done := w.syncDone
		w.mu.Unlock()
		<-done
		w.mu.Lock()
		if w.syncErr != nil {
			return w.syncErr
		}
	}
	if w.unsyncedBytes == 0 || w.active == nil {
		return w.syncErr
	}
	var err error
	if w.syncFile != nil {
		err = w.syncFile(w.active)
	} else {
		err = w.active.Sync()
	}
	if err != nil {
		return w.failLocked(fmt.Errorf("sync active segment: %w", err))
	}
	w.unsyncedBytes = 0
	w.unsyncedSince = time.Time{}
	return nil
}

// Sync forces an immediate local fdatasync (fsync-class barriers, rotation,
// forced close).
func (w *streamWAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.syncErr != nil {
		return w.syncErr
	}
	return w.syncLocked()
}

func (w *streamWAL) rotateIfNeededLocked() error {
	seg := &w.segments[len(w.segments)-1]
	if seg.size < segmentTargetBytes {
		return nil
	}
	if err := w.syncLocked(); err != nil {
		return err
	}
	// syncLocked may temporarily release w.mu while an already-running
	// background sync completes. Another appender can rotate the active
	// segment during that wait, so decide against the current segment again.
	seg = &w.segments[len(w.segments)-1]
	if seg.size < segmentTargetBytes {
		return nil
	}
	if err := w.openSegmentLocked(seg.ordinal+1, w.nextFrame+1, w.lastSeq+1); err != nil {
		return w.failLocked(fmt.Errorf("rotate segment: %w", err))
	}
	if err := w.reemitLiveDelegationsLocked(); err != nil {
		return w.failLocked(fmt.Errorf("writeback: re-emit live delegations after rotation: %w", err))
	}
	// Rotation is rare and recovery-critical. Make the copied grant set
	// durable before any caller can append/ack a mutation in this segment.
	if err := w.syncLocked(); err != nil {
		return err
	}
	if err := fsyncDir(w.dir); err != nil {
		return w.failLocked(fmt.Errorf("writeback: sync WAL directory after rotation: %w", err))
	}
	return nil
}

// ReadAt serves extent bytes from a segment file.
func (w *streamWAL) ReadAt(ordinal uint64, dst []byte, off int64) error {
	w.mu.Lock()
	f := w.files[ordinal]
	w.mu.Unlock()
	if f == nil {
		return fmt.Errorf("writeback: segment %d is not live", ordinal)
	}
	_, err := f.ReadAt(dst, off)
	return err
}

// ReadPayload re-reads a frame payload for the flusher.
func (w *streamWAL) ReadPayload(ordinal uint64, off int64, length int) ([]byte, error) {
	buf := make([]byte, length)
	if err := w.ReadAt(ordinal, buf, off); err != nil {
		return nil, err
	}
	return buf, nil
}

// pinSegments takes read references on the given segment ordinals so a
// concurrent checkpoint+reclaim cannot delete them mid-pread. Pair with
// unpinSegments.
func (w *streamWAL) pinSegments(ordinals []uint64) {
	if len(ordinals) == 0 {
		return
	}
	w.mu.Lock()
	for _, ord := range ordinals {
		w.readRefs[ord]++
	}
	w.mu.Unlock()
}

func (w *streamWAL) unpinSegments(ordinals []uint64) {
	if len(ordinals) == 0 {
		return
	}
	w.mu.Lock()
	for _, ord := range ordinals {
		if w.readRefs[ord] <= 1 {
			delete(w.readRefs, ord)
		} else {
			w.readRefs[ord]--
		}
	}
	w.mu.Unlock()
}

// reclaimUnlinkSegment and reclaimSyncDir are the indirections every segment
// reclaim goes through — the online one here and the offline one at barrier B
// of the recovery close-out. They exist so a test can record the exact ORDER of
// unlinks and directory barriers a reclaim issues, and from that order derive
// every set of unlinks a crash could have left persisted. Persistence order is
// not syscall order: without a barrier between two unlinks, either, both, or
// neither may survive the crash, and a surviving hole in the ordinal chain is
// an unrecoverable stream. In production these are os.Remove and fsyncDir and
// nothing else.
var (
	reclaimUnlinkSegment = os.Remove
	reclaimSyncDir       = fsyncDir
)

// CheckpointAndReclaim is the ONE reclamation operation: it appends the
// durable APPLIED checkpoint (through + the stream digest at through), syncs
// it to media, and only then deletes whole segments fully covered by the
// watermark that are neither extent-pinned nor read-pinned. Reclamation is
// impossible unless the APPLIED append AND the sync both succeeded — a
// failure returns the error with every segment intact (and latches syncErr,
// so later appends fail loudly instead of acknowledging onto a broken log).
// A call with nothing reclaimable is a no-op (no checkpoint spam).
func (w *streamWAL) CheckpointAndReclaim(through uint64, digest [32]byte, pinned func(ordinal uint64) bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("writeback: wal closed")
	}
	var reclaimable int64
	for i := 0; i < len(w.segments)-1; i++ {
		seg := w.segments[i]
		if seg.lastSeq <= through && !pinned(seg.ordinal) && w.readRefs[seg.ordinal] == 0 {
			reclaimable += seg.size
		}
	}
	payload, err := encodeControlPayload(appliedFrame{Through: through, Digest: fmt.Sprintf("%x", digest)})
	if err != nil {
		return err
	}
	// The certificate is charged to the space its own reclamation frees, so a
	// checkpoint can never leave more frame bytes behind than it retired. That
	// is what lets the control reserve hold a SINGLE checkpoint term instead of
	// one per authority advance. (A rollover this call happens to trip is not
	// charged here: a rollover fires at most once per segment, and a segment is
	// only created after segmentTargetBytes of already-admitted bytes filled the
	// previous one.)
	if reclaimable < frameLen(len(payload)) {
		return nil
	}
	if err := w.appendControlLocked(frameApplied, payload); err != nil {
		return err
	}
	if err := w.syncLocked(); err != nil {
		return err
	}
	// Ascending, EACH UNLINK MADE DURABLE BEFORE THE NEXT IS ISSUED. Persistence
	// order is not syscall order: with a single trailing fsyncDir the whole
	// batch is unordered against a crash, and the crash that persists the unlink
	// of ordinal 2 but not ordinal 1 leaves a HOLE in the retained ordinal
	// chain. scanStreamWithTailRepair rejects that gap as ErrCorrupt, so the
	// stream comes back unreadable rather than merely shorter. One directory
	// barrier per unlink reduces the reachable crash states to prefixes of this
	// loop — a retained contiguous suffix, which is what the reader accepts.
	// Reclaim is rare (it runs behind the applied watermark, at most once per
	// retired segment), so the extra syncs are not on any hot path.
	kept := make([]segmentInfo, 0, len(w.segments))
	for i := range w.segments {
		seg := w.segments[i]
		isActive := i == len(w.segments)-1
		if isActive || seg.lastSeq > through || pinned(seg.ordinal) || w.readRefs[seg.ordinal] != 0 {
			kept = append(kept, seg)
			continue
		}
		if f := w.files[seg.ordinal]; f != nil {
			_ = f.Close()
			delete(w.files, seg.ordinal)
		}
		if err := reclaimUnlinkSegment(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			// The certificate is already durable but the space it was charged
			// against did not come back. Retrying would append another one
			// against the same segments, so the footprint would grow without a
			// bound: fail the stream closed instead.
			kept = append(kept, w.segments[i:]...)
			w.segments = kept
			return w.failLocked(fmt.Errorf("reclaim segment %d: %w", seg.ordinal, err))
		}
		if err := reclaimSyncDir(w.dir); err != nil {
			// The unlink is gone from the in-memory set either way; only the
			// segments after it are still accounted for.
			kept = append(kept, w.segments[i+1:]...)
			w.segments = kept
			return w.failLocked(fmt.Errorf("sync WAL directory after reclaiming segment %d: %w", seg.ordinal, err))
		}
	}
	w.segments = kept
	return nil
}

// DiskBytes reports the stream's on-disk footprint.
func (w *streamWAL) DiskBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.diskBytesLocked()
}

func (w *streamWAL) diskBytesLocked() int64 {
	var n int64
	for _, seg := range w.segments {
		n += seg.size
	}
	return n
}

// appendCostLocked is the EXACT number of bytes appendMutationsWithin will add
// to the stream's footprint for payloads: every frame it writes, aligned as it
// will be written, plus the rollover cost when the active segment has reached
// the rotation threshold (a fresh segment header and the live-delegation set
// re-emitted into it before the new segment may carry a mutation).
//
// It is never an underestimate. A concurrent appender that rotates first only
// makes the real cost SMALLER (this append then pays no rollover), and a
// rollover cannot appear where none was projected: the decision is read from
// the same seg.size under the same held mutex that rotateIfNeededLocked reads.
func (w *streamWAL) appendCostLocked(payloads [][]byte) (int64, error) {
	cost := w.rolloverCostLocked()
	for _, p := range payloads {
		cost += frameLen(len(p))
	}
	return cost, nil
}

// rolloverCostLocked is the segment rollover the NEXT append pays: zero unless
// the active segment has reached its threshold, otherwise a fresh header plus
// the live-delegation set re-emitted into it before it may carry anything else.
func (w *streamWAL) rolloverCostLocked() int64 {
	if seg := &w.segments[len(w.segments)-1]; seg.size >= segmentTargetBytes {
		return segmentHeaderSize + w.liveDelegationBytes
	}
	return 0
}

// controlCostLocked is the EXACT footprint one control operation writing
// frameBytes of frames adds, rollover included.
func (w *streamWAL) controlCostLocked(frameBytes int64) int64 {
	return w.rolloverCostLocked() + frameBytes
}

// controlReserveLocked is the CONTROL RESERVE: the number of bytes held back
// inside the stream's cap so that every control frame the current live set can
// still OBLIGE this stream to write is guaranteed to fit. `pendingBytes` and
// `pendingCount` add a delegation frame that is being admitted right now.
//
// Terms, with n live grants and G = Σ frameLen(delegation frame) over them
// (w.liveDelegationBytes — a RELEASE frame has the same payload shape as the
// DELEGATION it retires, so G is also the total release-frame cost):
//
//	R    = segmentHeaderSize + G                 one segment rollover
//	body = n·frameLen(maxAppliedPayload) + G     n drained releases (APPLIED+RELEASE)
//	     + frameLen(maxAppliedPayload)           one reclamation checkpoint
//	     + 2·frameLen(maxClosePayload)           CLOSE and FORCED_CLOSE
//	C    = R·rolloverCount(n+3, body, R) + body
//
// C dominates the whole close-out because each of those n+3 operations trips at
// most one rollover and rolloverCount bounds how many rollovers they can trip
// between them. It also SHRINKS by at least what it pays out: releasing scope s
// costs R + frameLen(maxAppliedPayload) + f_s, while C falls by
// R + (n+3)·f_s + frameLen(maxAppliedPayload). So the reserve stays dominant
// through an arbitrarily long close-out.
//
// C is bounded because both of its inputs are: n by maxLiveDelegations and each
// frame by the control-field caps, giving a worst case of
// C ≤ R·(n+3) + body with R ≤ segmentHeaderSize + n·frameLen(maxDelegationPayload).
//
// The reserve is a THIRD slice of BudgetBytes, and it composes with the
// two-lane split by being subtracted ONCE, inside admission, from whichever
// lane budget the caller presents (credit.go's metadataReserveFor decides the
// other boundary). The resulting partition of the cap B is:
//
//	[0, B − metadataReserve − C)   bulk data, metadata and control
//	[B − metadataReserve − C, B−C) metadata and control
//	[B − C, B]                     control only — this reserve
func (w *streamWAL) controlReserveLocked(pendingBytes, pendingCount int64) int64 {
	n := int64(len(w.liveDelegations)) + pendingCount
	g := w.liveDelegationBytes + pendingBytes
	rollover := int64(segmentHeaderSize) + g
	body := n*frameLen(maxAppliedPayload) + g +
		frameLen(maxAppliedPayload) + 2*frameLen(maxClosePayload)
	return rollover*rolloverCount(n+3, body, rollover) + body
}

// rolloverCount bounds how many segment rollovers `ops` control operations
// writing `body` bytes between them can trip. The first operation can rotate
// immediately (the active segment may already be at its threshold); every later
// rotation needs the fresh segment — which starts at `rollover` bytes — filled
// back to segmentTargetBytes. No operation rotates more than once.
func rolloverCount(ops, body, rollover int64) int64 {
	room := segmentTargetBytes - rollover
	if room <= 0 {
		// A re-emit set that alone fills a segment: every operation rotates.
		return ops
	}
	n := 1 + (body+room-1)/room
	if n > ops {
		return ops
	}
	return n
}

// maxAppendCost is the cost appendMutationsWithin could charge for payloads at
// ANY occupancy: every frame plus a segment rollover, whether or not the active
// segment has reached its threshold right now. A budget below this refuses the
// append no matter how empty the stream is — which is exactly the condition
// that stays a definite ENOSPC rather than something a drain could relieve.
// Callers use it to tell "this can never fit" from "this does not fit yet".
func (w *streamWAL) maxAppendCost(payloads [][]byte) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// The control reserve is held back from the mutation lanes at every
	// occupancy, so it belongs in the "can this ever fit" answer too.
	cost := int64(segmentHeaderSize) + w.liveDelegationBytes + w.controlReserveLocked(0, 0)
	for _, p := range payloads {
		cost += frameLen(len(p))
	}
	return cost, nil
}

func (w *streamWAL) LastSeq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastSeq
}

func (w *streamWAL) Digest() [32]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.digest
}

func (w *streamWAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	err := w.syncLocked()
	if w.syncTimer != nil {
		w.syncTimer.Stop()
		w.syncTimer = nil
	}
	w.closeFilesLocked()
	w.closed = true
	return err
}

// Abandon closes descriptors without issuing a sync, matching a process
// termination boundary. The kernel may still write dirty pages later, but
// the method never upgrades a plain write into an fsync.
func (w *streamWAL) Abandon() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	// Mark the object closed before waiting so the in-flight worker neither
	// arms another timer nor reports a post-abandon health failure. We still
	// wait for that worker to release the descriptor before closing it.
	w.closed = true
	if w.syncTimer != nil {
		w.syncTimer.Stop()
		w.syncTimer = nil
	}
	done := w.syncDone
	w.mu.Unlock()
	if done != nil {
		<-done
	}
	w.mu.Lock()
	w.closeFilesLocked()
	w.mu.Unlock()
}

func (w *streamWAL) closeFilesLocked() {
	for _, f := range w.files {
		_ = f.Close()
	}
	w.files = map[uint64]*os.File{}
	w.active = nil
}

// RemoveAll closes and deletes the whole stream directory (clean close).
func (w *streamWAL) RemoveAll() error {
	_ = w.Close()
	if err := os.RemoveAll(w.dir); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(w.dir))
}

// ─── scan / recovery ─────────────────────────────────────────────────────────

// streamScan is a recovered stream's decoded content. Reclaimed prefixes
// mean the first retained mutation may start past sequence 1; the digest at
// any retained point is rebuilt from the latest APPLIED checkpoint.
type streamScan struct {
	header   segmentHeader // first retained segment's identity
	frames   []frame       // every valid frame in order (payloads retained)
	firstSeq uint64        // first retained mutation sequence (0 = none retained)
	// lastSeq is the stream's last acknowledged mutation sequence: the last
	// retained mutation, or FirstSeq-1 when the retained segments hold none
	// (fully reclaimed prefix; zero for a fresh stream).
	lastSeq   uint64
	truncated bool // a torn tail was discarded
}

// scanStream reads and validates every segment of a stream directory.
// The ONLY shape that truncates is a physically short header/payload at the
// end of the LAST segment (a torn append). Everything else invalid — bad
// magic, version, frame number, length, header CRC, payload CRC, INCLUDING a
// fully-present final frame — fails closed with ErrCorrupt: an acknowledged
// last mutation must never be silently discarded.
func scanStream(dir string) (*streamScan, error) {
	return scanStreamWithTailRepair(dir, true)
}

// scanStreamReadOnly performs the same strict framing and identity validation
// as recovery without changing a torn final append. Offline force-parking uses
// this form to validate the entire store before it changes any stream.
func scanStreamReadOnly(dir string) (*streamScan, error) {
	return scanStreamWithTailRepair(dir, false)
}

func scanStreamWithTailRepair(dir string, repairTornTail bool) (*streamScan, error) {
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: stream %s has no segments", ErrCorrupt, dir)
	}
	sort.Strings(names)
	scan := &streamScan{}
	var prev *segmentHeader
	var frameNo, lastSeq uint64
	for i, name := range names {
		buf, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		h, err := decodeSegmentHeader(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(name), err)
		}
		if filepath.Clean(name) != segmentPath(dir, h.Ordinal) {
			return nil, fmt.Errorf("%w: segment filename %s does not match header ordinal %d", ErrCorrupt, filepath.Base(name), h.Ordinal)
		}
		if prev == nil {
			// The first retained segment establishes the dense frame and
			// mutation-sequence bases (earlier segments were reclaimed whole).
			scan.header = h
			frameNo = h.FirstFrame - 1
			lastSeq = h.FirstSeq - 1
		} else {
			if h.Ordinal != prev.Ordinal+1 || h.WALEpoch != prev.WALEpoch || h.MountID != prev.MountID {
				return nil, fmt.Errorf("%w: segment chain broken at %s", ErrCorrupt, filepath.Base(name))
			}
			if h.VolumeID != prev.VolumeID || h.Branch != prev.Branch {
				return nil, fmt.Errorf("%w: segment %s identifies %s@%s, breaking stream identity %s@%s", ErrCorrupt, filepath.Base(name), h.VolumeID, h.Branch, prev.VolumeID, prev.Branch)
			}
			if h.FirstFrame != frameNo+1 {
				return nil, fmt.Errorf("%w: segment %s first frame %d does not continue %d", ErrCorrupt, filepath.Base(name), h.FirstFrame, frameNo)
			}
			if h.FirstSeq != lastSeq+1 {
				return nil, fmt.Errorf("%w: segment %s first sequence %d does not continue %d", ErrCorrupt, filepath.Base(name), h.FirstSeq, lastSeq)
			}
		}
		hCopy := h
		prev = &hCopy
		last := i == len(names)-1
		validEnd, err := scanSegmentFrames(scan, buf, h.Ordinal, &frameNo, &lastSeq, last)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(name), err)
		}
		if last && validEnd < int64(len(buf)) {
			if repairTornTail {
				// Torn tail (physically short frame): truncate to the last
				// complete frame and fsync.
				f, err := os.OpenFile(name, os.O_RDWR, 0o600)
				if err != nil {
					return nil, err
				}
				if err := f.Truncate(validEnd); err != nil {
					_ = f.Close()
					return nil, err
				}
				if err := f.Sync(); err != nil {
					_ = f.Close()
					return nil, err
				}
				if err := f.Close(); err != nil {
					return nil, err
				}
			}
			scan.truncated = true
		}
	}
	// lastSeq is FirstSeq-1 when no mutation is retained: with a reclaimed
	// prefix that is the true acknowledged tail (everything below it was
	// applied and checkpointed), and for a fresh stream it is zero.
	scan.lastSeq = lastSeq
	return scan, nil
}

// errTornTail marks a frame that is physically incomplete at the buffer end
// (short header, or a validated header whose payload extends past EOF) — the
// only shape recovery may truncate, and only in the last segment.
var errTornTail = errors.New("torn frame at physical EOF")

// scanSegmentFrames validates frames in one segment. Returns the byte offset
// of the end of the last valid frame. A physically short final frame in the
// LAST segment is a torn tail (valid end returned short); every other
// invalid frame — anywhere, including the final one — is corruption.
func scanSegmentFrames(scan *streamScan, buf []byte, ordinal uint64, frameNo, lastSeq *uint64, lastSegment bool) (int64, error) {
	off := int64(segmentHeaderSize)
	for {
		if off == int64(len(buf)) {
			return off, nil // clean end at a frame boundary
		}
		f, fLen, err := decodeFrameAt(buf, off, *frameNo+1)
		if err != nil {
			if errors.Is(err, errTornTail) && lastSegment {
				return off, nil // torn tail: caller truncates
			}
			return off, fmt.Errorf("%w: invalid frame at offset %d: %v", ErrCorrupt, off, err)
		}
		*frameNo++
		f.ordinal = ordinal
		f.payloadOff = off + frameHeaderSize
		if f.typ == frameMutation {
			if f.seq != *lastSeq+1 {
				return off, fmt.Errorf("%w: mutation sequence %d does not continue %d", ErrCorrupt, f.seq, *lastSeq)
			}
			if scan.firstSeq == 0 {
				scan.firstSeq = f.seq
			}
			*lastSeq = f.seq
		} else if f.seq != 0 {
			return off, fmt.Errorf("%w: control frame %d carries mutation sequence %d", ErrCorrupt, f.frameNo, f.seq)
		}
		scan.frames = append(scan.frames, f)
		off += fLen
	}
}

func decodeFrameAt(buf []byte, off int64, wantFrameNo uint64) (frame, int64, error) {
	var f frame
	if off+frameHeaderSize > int64(len(buf)) {
		return f, 0, fmt.Errorf("%w: short frame header", errTornTail)
	}
	h := buf[off : off+frameHeaderSize]
	if [4]byte(h[0:4]) != frameMagic {
		return f, 0, errors.New("bad frame magic")
	}
	if h[4] != 1 {
		return f, 0, errors.New("unknown frame version")
	}
	if crc32.Checksum(h[:32], crcTable) != binary.BigEndian.Uint32(h[32:36]) {
		return f, 0, errors.New("frame header checksum mismatch")
	}
	f.typ = frameType(h[5])
	if !validFrameType(f.typ) {
		return f, 0, fmt.Errorf("unknown frame type %d", f.typ)
	}
	f.frameNo = binary.BigEndian.Uint64(h[8:16])
	if f.frameNo != wantFrameNo {
		return f, 0, fmt.Errorf("frame number %d, want %d", f.frameNo, wantFrameNo)
	}
	f.seq = binary.BigEndian.Uint64(h[16:24])
	payloadLen := int(binary.BigEndian.Uint32(h[24:28]))
	if payloadLen > maxMutationPayload {
		return f, 0, fmt.Errorf("payload length %d exceeds bound", payloadLen)
	}
	total := frameLen(payloadLen)
	if off+total > int64(len(buf)) {
		// The header itself validated (magic, version, header CRC): the
		// payload is physically missing, the write was torn mid-frame.
		return f, 0, fmt.Errorf("%w: short frame payload", errTornTail)
	}
	payload := buf[off+frameHeaderSize : off+frameHeaderSize+int64(payloadLen)]
	if crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(h[28:32]) {
		return f, 0, errors.New("frame payload checksum mismatch")
	}
	f.payload = append([]byte(nil), payload...)
	return f, total, nil
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// streamEpochFromDir extracts the epoch from a stream directory name
// (stream-%016x); ok=false for foreign names.
func streamEpochFromDir(name string) (uint64, bool) {
	const prefix = "stream-"
	if len(name) != len(prefix)+16 || !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	epoch, err := strconv.ParseUint(name[len(prefix):], 16, 64)
	if err != nil || epoch == 0 || name != streamDirName(epoch) {
		return 0, false
	}
	return epoch, true
}

func streamDirName(epoch uint64) string {
	return fmt.Sprintf("stream-%016x", epoch)
}
