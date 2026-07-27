// Package ctlrec defines the typed, versioned payloads carried by wal.OpControl
// records: replicated CONTROL metadata that rides the same durability,
// replication, and LSN-ordered apply pipeline as user mutations WITHOUT ever
// entering the user namespace. Control payloads are excluded from user
// manifests, tree hashes, and path walks. Checkpoint orphan sidecars are an
// explicit exception for reachability: their externalized auxiliary content
// references are committed and GC-marked until ordered reap.
//
// Payloads are a tagged union encoded with gob and prefixed by a version byte.
// An unknown version or kind FAILS CLOSED at apply/replay: control state drives
// exactly-once semantics, so guessing at an undecodable record could silently
// re-execute an acknowledged mutation.
package ctlrec

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
)

// Version is the current control-payload schema version. Version 2 adds the
// checkpoint orphan sidecar and complete slot outcomes. Readers accept v1 so
// existing incremental/snapshot records survive an upgrade; older readers
// reject v2 rather than silently dropping failover-critical orphan state.
const Version = 2

const legacyVersion = 1

// Snapshot bounds keep one replicated control record well below the WAL frame
// ceiling. A checkpoint that exceeds them fails before backend dispatch and
// leaves ordinary live writes unaffected; it never emits a partial sidecar.
const (
	// MaxEncodedControlBytes bounds gob input before decode. The largest legal
	// inline orphan snapshot is 32 MiB; 64 MiB leaves room for bounded session,
	// source, and framing metadata without accepting attacker-sized payloads.
	MaxEncodedControlBytes = 64 << 20
	MaxSessions            = 16_384
	MaxWatermarks          = 65_536
	MaxSlotStates          = 262_144
	MaxSessionIDBytes      = 128
	MaxOwnerBytes          = 256
	TokenHashBytes         = 32
	RequestHashBytes       = 32

	MaxSnapshotOrphans = 65_536
	// MaxSnapshotDirtyBytes is the hard wire/WAL ceiling for inline unnamed
	// dirty data. It deliberately leaves ample room below the 256 MiB WAL and
	// replication frame limits for sessions, receipts, metadata, and framing.
	// Authorities may configure a lower per-volume limit, never a higher one.
	MaxSnapshotDirtyBytes   int64 = 32 << 20
	MaxSnapshotBlockBytes         = 4 << 20
	MaxSnapshotSourceChunks       = 262_144
)

// Kind tags the union.
type Kind uint8

const (
	// KindSession records mount-session establishment: a session id bound to a
	// generation (incarnation) and an owner identity. A generation supersedes
	// (tombstones) every lower generation of the same session id.
	KindSession Kind = iota + 1
	// KindSessionExpire records lease-expiry (or explicit close) of a session.
	// The fence is durable before process-local locks/delegations/open state are
	// released, so a crash between those steps cannot resurrect authority.
	KindSessionExpire
	// KindFlushWatermark advances a write-back session's exactly-once flush
	// watermark (epoch + next-expected local Seq). Appended in the SAME
	// contiguous WAL range as the flushed user records, so the watermark moves
	// iff the mutations land — replacing the legacy hidden ".portablefs-<id>"
	// user-namespace file.
	KindFlushWatermark
	// KindSnapshot is the compact versioned control-state snapshot the
	// checkpointer appends right before compaction: control records compacted
	// away below the watermark stay reconstructable on replay. Applied by
	// monotonic MERGE (per-key newest wins), so its position relative to
	// surviving incremental records cannot corrupt state.
	KindSnapshot
	// KindOutcome records the essential response of a statically-rejected or
	// otherwise tree-neutral exact-once mutation, so slot sequence progression
	// survives restart/failover even when no user mutation was applied.
	KindOutcome
	// KindSessionRenew durably advances a live session's absolute lease expiry.
	// Renewals are coalesced by workfs, so active sessions remain safe across
	// promotion/restart without producing one WAL record per request.
	KindSessionRenew
)

// Session is KindSession's payload.
type Session struct {
	SessionID  string
	Generation uint64
	Owner      string
	// TokenHash binds the session to its opaque reconnect credential (SHA-256
	// of either a client-supplied exact token or a legacy authority-minted one).
	// Reconnects prove identity against the hash without persisting the secret.
	TokenHash []byte
	Slots     uint32 // bounded slot count granted to this session
	AtMs      int64
	// ExpiresMs is the absolute durable lease expiry selected by the authority.
	// Zero is legacy v1/v2 input and is reconstructed as AtMs + local TTL.
	ExpiresMs int64
}

// SessionExpire is KindSessionExpire's payload.
type SessionExpire struct {
	SessionID  string
	Generation uint64
	AtMs       int64
	// Force distinguishes an explicit run/admin fence from conditional lease
	// expiry. Conditional expiry is reserved only if no renewal won first.
	Force bool
}

// SessionRenew is KindSessionRenew's payload. TokenHash makes the renewal's
// session tuple self-validating at reservation and deterministic replay.
type SessionRenew struct {
	SessionID  string
	Generation uint64
	TokenHash  []byte
	ExpiresMs  int64
}

// FlushWatermark is KindFlushWatermark's payload.
type FlushWatermark struct {
	SessionID string
	Epoch     uint64 // write-back session generation
	Through   uint64 // next-expected local Seq (exclusive upper bound applied)
}

// Outcome is KindOutcome's payload: the essential response of a mutation that
// consumed a slot sequence without applying a user record.
type Outcome struct {
	SessionID  string
	Generation uint64
	Slot       uint32
	SlotSeq    uint64
	ReqHash    []byte
	Status     int32
}

// SlotState is one slot's latest outcome inside a snapshot.
type SlotState struct {
	Slot      uint32
	SlotSeq   uint64
	ReqHash   []byte
	Status    int32
	Count     int32
	Version   uint64
	Offset    int64
	Ino       uint64
	OrphanIno uint64
}

// ChunkState and SourceState are the wire-independent content-source shape for
// an orphan snapshot. The control package deliberately does not import backend
// or workfs packages.
type ChunkState struct {
	Digest string
	Size   int64
	Offset int64
}

type SourceState struct {
	BlobDigest      string
	BlobSize        int64
	BlobCompression string
	BlobPacked      bool
	Chunks          []ChunkState
	Size            int64
}

// DirtyBlock is one immutable 4 MiB-or-smaller block override.
type DirtyBlock struct {
	Index int64
	Data  []byte
}

// OrphanState is a complete unnamed inode image at Snapshot.AsOfLSN. It is a
// restart/promotion sidecar, never a user-manifest entry. Non-empty directories
// cannot be orphaned, so no child tree is required.
type OrphanState struct {
	Ino        uint64
	Name       string
	Kind       string
	Mode       uint32
	MtimeMs    int64
	CtimeMs    int64
	AtimeMs    int64
	UID        uint32
	GID        uint32
	LinkTarget string
	Source     SourceState
	Blocks     []DirtyBlock
	Size       int64
	Born       bool
	Truncated  bool
}

// SessionState is one session's full control state inside a snapshot.
type SessionState struct {
	SessionID  string
	Generation uint64
	Owner      string
	TokenHash  []byte
	Slots      uint32
	ExpiresMs  int64
	SlotStates []SlotState
	Expired    bool
}

// Snapshot is KindSnapshot's payload: the complete control state as of AsOfLSN
// (exclusive). Applied by monotonic merge.
type Snapshot struct {
	AsOfLSN    uint64
	Sessions   []SessionState
	Watermarks []FlushWatermark
	Orphans    []OrphanState
}

// Payload is the tagged union.
type Payload struct {
	Kind           Kind
	Session        *Session
	SessionExpire  *SessionExpire
	FlushWatermark *FlushWatermark
	Outcome        *Outcome
	SessionRenew   *SessionRenew
	Snapshot       *Snapshot
}

// Encode serializes p with the version prefix.
func Encode(p Payload) ([]byte, error) {
	if err := validatePayload(p); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(Version)
	if err := gob.NewEncoder(&buf).Encode(&p); err != nil {
		return nil, fmt.Errorf("ctlrec: encode: %w", err)
	}
	if buf.Len() > MaxEncodedControlBytes {
		return nil, fmt.Errorf("ctlrec: encoded control payload is %d bytes (max %d)", buf.Len(), MaxEncodedControlBytes)
	}
	return buf.Bytes(), nil
}

// Decode parses a control payload, failing closed on unknown versions/kinds.
func Decode(data []byte) (Payload, error) {
	if len(data) == 0 {
		return Payload{}, fmt.Errorf("ctlrec: empty control payload")
	}
	if len(data) > MaxEncodedControlBytes {
		return Payload{}, fmt.Errorf("ctlrec: control payload is %d bytes (max %d)", len(data), MaxEncodedControlBytes)
	}
	if data[0] != Version && data[0] != legacyVersion {
		return Payload{}, fmt.Errorf("ctlrec: unsupported control payload version %d (this build understands %d and legacy %d); refusing to guess", data[0], Version, legacyVersion)
	}
	var p Payload
	decoder := gob.NewDecoder(bytes.NewReader(data[1:]))
	if err := decoder.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("ctlrec: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Payload{}, fmt.Errorf("ctlrec: trailing gob value")
		}
		return Payload{}, fmt.Errorf("ctlrec: trailing payload: %w", err)
	}
	if err := validatePayload(p); err != nil {
		return Payload{}, err
	}
	return p, nil
}

func validatePayload(p Payload) error {
	pointers := 0
	for _, present := range []bool{
		p.Session != nil, p.SessionExpire != nil, p.FlushWatermark != nil,
		p.Outcome != nil, p.SessionRenew != nil, p.Snapshot != nil,
	} {
		if present {
			pointers++
		}
	}
	if pointers != 1 {
		return fmt.Errorf("ctlrec: payload kind %d has %d union values (want exactly one)", p.Kind, pointers)
	}
	switch p.Kind {
	case KindSession:
		if p.Session == nil {
			return fmt.Errorf("ctlrec: session payload is nil")
		}
		s := p.Session
		if err := validateSessionIdentity(s.SessionID, s.Owner, s.Slots, s.TokenHash); err != nil {
			return err
		}
		if s.AtMs < 0 || s.ExpiresMs < 0 || (s.ExpiresMs != 0 && s.ExpiresMs < s.AtMs) {
			return fmt.Errorf("ctlrec: malformed session lease times")
		}
	case KindSessionExpire:
		if p.SessionExpire == nil || !validSessionID(p.SessionExpire.SessionID) || p.SessionExpire.AtMs < 0 {
			return fmt.Errorf("ctlrec: malformed session-expire payload")
		}
	case KindSessionRenew:
		if p.SessionRenew == nil || !validSessionID(p.SessionRenew.SessionID) ||
			len(p.SessionRenew.TokenHash) != TokenHashBytes || p.SessionRenew.ExpiresMs <= 0 {
			return fmt.Errorf("ctlrec: malformed session-renew payload")
		}
	case KindFlushWatermark:
		if p.FlushWatermark == nil || !validSessionID(p.FlushWatermark.SessionID) {
			return fmt.Errorf("ctlrec: malformed flush-watermark payload")
		}
	case KindOutcome:
		if p.Outcome == nil || !validSessionID(p.Outcome.SessionID) || p.Outcome.SlotSeq == 0 || len(p.Outcome.ReqHash) != RequestHashBytes {
			return fmt.Errorf("ctlrec: malformed exact outcome payload")
		}
	case KindSnapshot:
		if p.Snapshot == nil {
			return fmt.Errorf("ctlrec: snapshot payload is nil")
		}
		if err := validateSnapshot(p.Snapshot); err != nil {
			return err
		}
	default:
		return fmt.Errorf("ctlrec: unknown control record kind %d; refusing to guess", p.Kind)
	}
	return nil
}

func validSessionID(id string) bool { return id != "" && len(id) <= MaxSessionIDBytes }

func validateSessionIdentity(id, owner string, slots uint32, tokenHash []byte) error {
	if !validSessionID(id) || len(owner) > MaxOwnerBytes || slots == 0 || slots > 4096 {
		return fmt.Errorf("ctlrec: malformed session identity")
	}
	// Empty hashes remain readable for old diagnostic fixtures and legacy WALs;
	// every new WorkFS establishment requires an exact SHA-256 hash.
	if len(tokenHash) != 0 && len(tokenHash) != TokenHashBytes {
		return fmt.Errorf("ctlrec: session token hash is %d bytes (want 0 legacy or %d)", len(tokenHash), TokenHashBytes)
	}
	return nil
}

func validateSnapshot(snapshot *Snapshot) error {
	if len(snapshot.Sessions) > MaxSessions {
		return fmt.Errorf("ctlrec: snapshot has %d sessions (max %d)", len(snapshot.Sessions), MaxSessions)
	}
	if len(snapshot.Watermarks) > MaxWatermarks {
		return fmt.Errorf("ctlrec: snapshot has %d watermarks (max %d)", len(snapshot.Watermarks), MaxWatermarks)
	}
	seenSessions := make(map[string]struct{}, len(snapshot.Sessions))
	var totalSlots int
	for i := range snapshot.Sessions {
		s := &snapshot.Sessions[i]
		if err := validateSessionIdentity(s.SessionID, s.Owner, s.Slots, s.TokenHash); err != nil {
			return fmt.Errorf("ctlrec: session[%d]: %w", i, err)
		}
		if _, duplicate := seenSessions[s.SessionID]; duplicate {
			return fmt.Errorf("ctlrec: duplicate session id %q", s.SessionID)
		}
		seenSessions[s.SessionID] = struct{}{}
		if s.ExpiresMs < 0 || len(s.SlotStates) > int(s.Slots) {
			return fmt.Errorf("ctlrec: session %q has malformed expiry/slot count", s.SessionID)
		}
		totalSlots += len(s.SlotStates)
		if totalSlots > MaxSlotStates {
			return fmt.Errorf("ctlrec: snapshot slot states exceed %d", MaxSlotStates)
		}
		seenSlots := make(map[uint32]struct{}, len(s.SlotStates))
		for j := range s.SlotStates {
			slot := &s.SlotStates[j]
			if slot.Slot >= s.Slots || slot.SlotSeq == 0 || len(slot.ReqHash) != RequestHashBytes {
				return fmt.Errorf("ctlrec: session %q has malformed slot[%d]", s.SessionID, j)
			}
			if _, duplicate := seenSlots[slot.Slot]; duplicate {
				return fmt.Errorf("ctlrec: session %q has duplicate slot %d", s.SessionID, slot.Slot)
			}
			seenSlots[slot.Slot] = struct{}{}
		}
	}
	seenWatermarks := make(map[string]struct{}, len(snapshot.Watermarks))
	for i := range snapshot.Watermarks {
		id := snapshot.Watermarks[i].SessionID
		if !validSessionID(id) {
			return fmt.Errorf("ctlrec: watermark[%d] has malformed session id", i)
		}
		if _, duplicate := seenWatermarks[id]; duplicate {
			return fmt.Errorf("ctlrec: duplicate watermark session %q", id)
		}
		seenWatermarks[id] = struct{}{}
	}
	if len(snapshot.Orphans) > MaxSnapshotOrphans {
		return fmt.Errorf("ctlrec: snapshot has %d orphans (max %d)", len(snapshot.Orphans), MaxSnapshotOrphans)
	}
	seen := make(map[uint64]struct{}, len(snapshot.Orphans))
	var dirtyBytes int64
	var sourceChunks int
	for i := range snapshot.Orphans {
		orphan := &snapshot.Orphans[i]
		if orphan.Ino == 0 {
			return fmt.Errorf("ctlrec: orphan[%d] has zero inode", i)
		}
		if _, duplicate := seen[orphan.Ino]; duplicate {
			return fmt.Errorf("ctlrec: duplicate orphan inode %d", orphan.Ino)
		}
		seen[orphan.Ino] = struct{}{}
		if orphan.Kind != "file" && orphan.Kind != "directory" && orphan.Kind != "symlink" {
			return fmt.Errorf("ctlrec: orphan inode %d has invalid kind %q", orphan.Ino, orphan.Kind)
		}
		if orphan.Size < 0 || orphan.Source.Size < 0 || orphan.Source.BlobSize < 0 {
			return fmt.Errorf("ctlrec: orphan inode %d has negative size", orphan.Ino)
		}
		if orphan.Kind != "file" && (len(orphan.Blocks) != 0 || orphan.Source.BlobDigest != "" || len(orphan.Source.Chunks) != 0 || orphan.Born || orphan.Truncated) {
			return fmt.Errorf("ctlrec: non-file orphan inode %d carries file content state", orphan.Ino)
		}
		lastBlock := int64(-1)
		for _, block := range orphan.Blocks {
			if block.Index < 0 || block.Index <= lastBlock {
				return fmt.Errorf("ctlrec: orphan inode %d has unsorted/duplicate block index %d", orphan.Ino, block.Index)
			}
			if len(block.Data) > MaxSnapshotBlockBytes {
				return fmt.Errorf("ctlrec: orphan inode %d block %d is %d bytes (max %d)", orphan.Ino, block.Index, len(block.Data), MaxSnapshotBlockBytes)
			}
			lastBlock = block.Index
			dirtyBytes += int64(len(block.Data))
			if dirtyBytes > MaxSnapshotDirtyBytes {
				return fmt.Errorf("ctlrec: snapshot dirty orphan state exceeds %d bytes", MaxSnapshotDirtyBytes)
			}
		}
		lastOffset := int64(-1)
		for _, chunk := range orphan.Source.Chunks {
			sourceChunks++
			if sourceChunks > MaxSnapshotSourceChunks {
				return fmt.Errorf("ctlrec: snapshot source chunks exceed %d", MaxSnapshotSourceChunks)
			}
			if chunk.Digest == "" || chunk.Size < 0 || chunk.Offset < 0 || chunk.Offset <= lastOffset {
				return fmt.Errorf("ctlrec: orphan inode %d has malformed source chunk %+v", orphan.Ino, chunk)
			}
			lastOffset = chunk.Offset
		}
	}
	return nil
}
