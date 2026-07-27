package workfs

// Control-record payload codec. A wal.OpControl record's Data is one gob-encoded
// ctlPayload: a tagged union of the replicated control transitions (session
// establish / renew / expire, a static exact-once slot outcome, or a full
// control snapshot). Control records ride the same WAL append / fsync /
// replication / replay pipeline as user mutations but never touch the user
// namespace: nothing here is part of a manifest, tree hash, or path walk.
//
// WAL compatibility: OpControl is an APPENDED op value, so a WAL written by a
// pre-session release (no control records) replays unchanged. Decoding fails
// closed on an unknown payload kind — replay refuses to start rather than
// guess at exactly-once state.

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type ctlKind uint8

const (
	// ctlKindSession establishes (or idempotently re-establishes) a session
	// generation: identity, owner, token hash, slot budget, lease expiry.
	ctlKindSession ctlKind = iota + 1
	// ctlKindRenew durably extends a session lease (reconnect resume or the
	// periodic renewal). Monotonic: an older expiry never regresses a newer.
	ctlKindRenew
	// ctlKindExpire fences a session generation (voluntary close, lease
	// sweep, or a proven client-state-corruption fence). Force distinguishes
	// unconditional fences from the sweeper's lease-conditional expiry.
	ctlKindExpire
	// ctlKindOutcome records a definite pre-admission rejection (static
	// reject) against an exact-once identity, so slot-sequence progression
	// survives restart/failover even though no user mutation was appended.
	ctlKindOutcome
	// ctlKindSnapshot is a compact image of the whole control state, appended
	// before WAL compaction (and after a WAL reset) so the compacted-away
	// control tail stays reconstructable on replay.
	ctlKindSnapshot
	// ctlKindWatermark advances a write-back session's flush watermark. It is
	// appended INSIDE the same atomic flush batch as the user mutations it
	// covers, so the watermark moves iff the mutations land — replacing the
	// legacy hidden .portablefs-<id> file with replicated control state.
	ctlKindWatermark
)

type ctlSessionRec struct {
	SessionID  string
	Generation uint64
	Owner      string
	TokenHash  []byte
	Slots      uint32
	ExpiresMs  int64
}

type ctlRenewRec struct {
	SessionID  string
	Generation uint64
	TokenHash  []byte
	ExpiresMs  int64
}

type ctlExpireRec struct {
	SessionID  string
	Generation uint64
	AtMs       int64
	Force      bool
}

type ctlOutcomeRec struct {
	SessionID  string
	Generation uint64
	Slot       uint32
	SlotSeq    uint64
	ReqHash    []byte
	Status     int32
}

// ctlSlotState is one slot's latest recorded outcome inside a snapshot.
// Coherence versions are deliberately NOT serialized: they are scoped to one
// authority generation, so a restored outcome replays with version 0 and the
// reconnecting client refreshes under the new generation instead of comparing
// an old clock value.
type ctlSlotState struct {
	Slot      uint32
	SlotSeq   uint64
	ReqHash   []byte
	Status    int32
	Count     int32
	Offset    int64
	Ino       uint64
	OrphanIno uint64
}

type ctlSessionState struct {
	SessionID  string
	Generation uint64
	Owner      string
	TokenHash  []byte
	Slots      uint32
	ExpiresMs  int64
	Expired    bool
	SlotStates []ctlSlotState
}

// ctlWatermarkRec is one write-back session's flush-dedup watermark: the next
// expected mount-local Seq (Through) under the session generation (Epoch).
type ctlWatermarkRec struct {
	SessionID string
	Epoch     uint64
	Through   uint64
}

type ctlSnapshotRec struct {
	Sessions   []ctlSessionState
	Watermarks []ctlWatermarkRec
	// Allocator fields are an additive gob tail. Valid=true distinguishes a
	// real namespace-zero snapshot from a control snapshot written by an
	// older release, whose absent fields decode as zero.
	AllocatorValid        bool
	AllocatorNamespace    uint32
	AllocatorNextLocal    uint64
	AllocatorMaxInoSeen   uint64
	AllocatorDurableFloor uint64
}

type ctlPayload struct {
	Kind      ctlKind
	Session   *ctlSessionRec
	Renew     *ctlRenewRec
	Expire    *ctlExpireRec
	Outcome   *ctlOutcomeRec
	Snapshot  *ctlSnapshotRec
	Watermark *ctlWatermarkRec
}

func encodeCtlPayload(p ctlPayload) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&p); err != nil {
		return nil, fmt.Errorf("vcs: encode control payload: %w", err)
	}
	return buf.Bytes(), nil
}

func decodeCtlPayload(data []byte) (ctlPayload, error) {
	var p ctlPayload
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&p); err != nil {
		return ctlPayload{}, fmt.Errorf("vcs: decode control payload: %w", err)
	}
	switch p.Kind {
	case ctlKindSession, ctlKindRenew, ctlKindExpire, ctlKindOutcome, ctlKindSnapshot, ctlKindWatermark:
		return p, nil
	default:
		return ctlPayload{}, fmt.Errorf("vcs: unknown control payload kind %d", p.Kind)
	}
}
