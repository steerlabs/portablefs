package pfc2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// Cross-restart projection: the granular typed control map a PFT2
// CONTROL_ROOT stores at an exact journal cut. At a cut the state is NOT
// serialized as one unbounded control object; it becomes one bounded sorted
// entry per session generation/tombstone, exact slot/floor/outcome,
// normalized lock interval, checkout grant, open pin, or flush-ledger item.
// The root carries the schema/feature words, verified per-kind counts, and
// the next checkout epoch. This file implements the entry schema, canonical
// sort keys, deterministic enumeration (Project), strict validated rebuild
// (Rebuild), bounded pagination for CONTROL_LEAF sizing, and the projection
// digest — the controlHash input of RecoveryRootRef installation. Object
// storage, PFT2 node envelopes, and database adoption live elsewhere.

// ProjectionSchema is the frozen schema generation of the entry map.
const ProjectionSchema = 1

// CONTROL_LEAF bounds (matching the PFT2 index-node discipline: 64 KiB
// target, 256 KiB ceiling, at most 4096 leaf entries).
const (
	LeafTargetBytes   = 64 << 10
	LeafCeilingBytes  = 256 << 10
	MaxLeafEntries    = 4096
	MaxEntryBytes     = 8 << 10 // one encoded entry (paths dominate)
	maxTotalEntries   = MaxSessionEntries + MaxSlotStates + MaxLockIntervals + MaxCheckouts + MaxOpenPins + MaxFlushEntries
	projectionDigestT = 0xF2 // domain byte for Projection.Digest
)

// EntryKind tags one granular typed control entry.
type EntryKind uint8

const (
	EntrySession   EntryKind = 1 // one live session generation
	EntryTombstone EntryKind = 2 // one retained terminal tombstone
	EntrySlot      EntryKind = 3 // one exact slot floor/outcome
	EntryLock      EntryKind = 4 // one normalized lock interval
	EntryCheckout  EntryKind = 5 // one checkout grant
	EntryPin       EntryKind = 6 // one durable open pin
	EntryFlush     EntryKind = 7 // one flush-ledger item
)

// SessionEntryValue is one live session generation. Its lease facts are
// exact database-issued times with their source, replayed verbatim so a
// recovered authority re-projects remaining durations from fresh database
// time instead of trusting any host clock.
type SessionEntryValue struct {
	Session     SessionRef
	Owner       string
	TokenHash   [TokenHashBytes]byte
	Slots       uint32
	TimeSource  TimeSource
	IssuedDbMs  int64
	ExpiresDbMs int64
}

// TombstoneEntryValue is one compact terminal tombstone.
type TombstoneEntryValue struct {
	Session SessionRef
	Reason  TerminalReason
}

// SlotEntryValue is one slot's exact floor state. RetiredThrough is carried
// explicitly and re-verified against (NextSeq, latest) on rebuild.
type SlotEntryValue struct {
	Session        SessionRef
	Slot           uint32
	NextSeq        uint64
	RetiredThrough uint64
	HasLatest      bool
	LatestSeq      uint64
	LatestHash     [RequestHashBytes]byte
	LatestOutcome  Outcome
}

// LockEntryValue is one normalized granted interval (Length 0 = through EOF).
type LockEntryValue struct {
	Ino    uint64
	Owner  LockOwner
	Start  uint64
	Length uint64
	Write  bool
}

// CheckoutEntryValue is one checkout grant. Delegation grants carry their
// write-back stream binding and, after holder death, the recovery flag.
type CheckoutEntryValue struct {
	Path        string
	Holder      SessionRef
	Epoch       Epoch
	WritebackID string
	Recovery    bool
}

// PinEntryValue is one durable open pin.
type PinEntryValue struct {
	Session SessionRef
	Ino     uint64
}

// FlushEntryValue is one mount stream's durable flush state.
type FlushEntryValue struct {
	Owner       SessionRef
	WritebackID string
	Through     uint64
	Digest      [DigestBytes]byte
}

// Entry is one typed control-map entry (exactly one arm, matching Kind).
type Entry struct {
	Kind EntryKind

	Session   *SessionEntryValue
	Tombstone *TombstoneEntryValue
	Slot      *SlotEntryValue
	Lock      *LockEntryValue
	Checkout  *CheckoutEntryValue
	Pin       *PinEntryValue
	Flush     *FlushEntryValue
}

// Key returns e's canonical sort key. Keys order the whole map bytewise and
// are unique per entry; live sessions and tombstones share one key space so
// a session id can never appear as both. Strings are NUL-free, so the 0x00
// separator is unambiguous; numbers are fixed-width big-endian.
func (e *Entry) Key() []byte {
	var b []byte
	sep := byte(0x00)
	be64 := func(v uint64) {
		var w [8]byte
		binary.BigEndian.PutUint64(w[:], v)
		b = append(b, w[:]...)
	}
	be32 := func(v uint32) {
		var w [4]byte
		binary.BigEndian.PutUint32(w[:], v)
		b = append(b, w[:]...)
	}
	str := func(s string) { b = append(append(b, s...), sep) }
	switch e.Kind {
	case EntrySession:
		b = append(b, 0x01)
		str(e.Session.Session.SessionID)
	case EntryTombstone:
		b = append(b, 0x01) // shared key space with EntrySession
		str(e.Tombstone.Session.SessionID)
	case EntrySlot:
		b = append(b, 0x03)
		str(e.Slot.Session.SessionID)
		be32(e.Slot.Slot)
	case EntryLock:
		b = append(b, 0x04)
		be64(e.Lock.Ino)
		str(e.Lock.Owner.Session.SessionID)
		be64(e.Lock.Owner.Session.Generation)
		be64(e.Lock.Owner.KernelLockOwner)
		be64(e.Lock.Start)
	case EntryCheckout:
		b = append(b, 0x05)
		str(e.Checkout.Path)
	case EntryPin:
		b = append(b, 0x06)
		be64(e.Pin.Ino)
		str(e.Pin.Session.SessionID)
		be64(e.Pin.Session.Generation)
	case EntryFlush:
		b = append(b, 0x07)
		str(e.Flush.WritebackID)
	}
	return b
}

// Validate enforces every entry-local rule.
func (e *Entry) Validate() error {
	arms := 0
	for _, present := range []bool{
		e.Session != nil, e.Tombstone != nil, e.Slot != nil, e.Lock != nil,
		e.Checkout != nil, e.Pin != nil, e.Flush != nil,
	} {
		if present {
			arms++
		}
	}
	if arms != 1 {
		return malformedf("entry kind %d has %d union arms (want exactly one)", e.Kind, arms)
	}
	switch e.Kind {
	case EntrySession:
		s := e.Session
		if s == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if err := validateSessionRef("session entry", s.Session); err != nil {
			return err
		}
		// TokenHash presence is the entry decoder's field rule; the value
		// rule on top rejects the all-zero credential digest, which no real
		// SHA-256 credential ever produces.
		if s.TokenHash == ([TokenHashBytes]byte{}) {
			return malformedf("session entry: all-zero token hash is never a real credential digest")
		}
		if len(s.Owner) > MaxOwnerBytes {
			return malformedf("session entry: owner exceeds %d bytes", MaxOwnerBytes)
		}
		if s.Slots == 0 || s.Slots > MaxSlots {
			return malformedf("session entry: slots must be in [1,%d]", MaxSlots)
		}
		if !s.TimeSource.valid() {
			return malformedf("session entry: unknown lease time source %d", s.TimeSource)
		}
		// Renewals may have advanced the deadline arbitrarily far past the
		// open, so unlike one record's minted lease there is no span bound
		// here — only plausibility and ordering.
		if !validDbTimeMs(s.IssuedDbMs) || !validDbTimeMs(s.ExpiresDbMs) || s.ExpiresDbMs <= s.IssuedDbMs {
			return malformedf("session entry: implausible or misordered lease times")
		}
	case EntryTombstone:
		t := e.Tombstone
		if t == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if err := validateSessionRef("tombstone entry", t.Session); err != nil {
			return err
		}
		if !t.Reason.valid() {
			return malformedf("tombstone entry: unknown reason %d", t.Reason)
		}
	case EntrySlot:
		s := e.Slot
		if s == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if err := validateSessionRef("slot entry", s.Session); err != nil {
			return err
		}
		if s.Slot >= MaxSlots {
			return malformedf("slot entry: slot %d exceeds bound %d", s.Slot, MaxSlots-1)
		}
		if s.NextSeq < 2 {
			return malformedf("slot entry: a touched slot's next sequence is at least 2")
		}
		if s.HasLatest {
			if s.LatestSeq != s.NextSeq-1 {
				return malformedf("slot entry: latest sequence %d must be nextSeq-1 (%d)", s.LatestSeq, s.NextSeq-1)
			}
			if s.RetiredThrough != s.NextSeq-2 {
				return malformedf("slot entry: floor %d contradicts latest at %d", s.RetiredThrough, s.LatestSeq)
			}
			// LatestHash presence is bound to HasLatest; its value must be a
			// real fingerprint, so the all-zero hash is rejected.
			if s.LatestHash == ([RequestHashBytes]byte{}) {
				return malformedf("slot entry: all-zero latest request hash is never a canonical fingerprint")
			}
		} else {
			if s.RetiredThrough != s.NextSeq-1 {
				return malformedf("slot entry: floor %d must be nextSeq-1 (%d) when no latest is retained", s.RetiredThrough, s.NextSeq-1)
			}
			if s.LatestSeq != 0 || s.LatestHash != ([RequestHashBytes]byte{}) || !s.LatestOutcome.IsZero() {
				return malformedf("slot entry: latest fields present without a latest outcome")
			}
		}
	case EntryLock:
		l := e.Lock
		if l == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if l.Ino == 0 {
			return malformedf("lock entry: inode must be nonzero")
		}
		if err := validateSessionRef("lock entry", l.Owner.Session); err != nil {
			return err
		}
		if l.Length != 0 && l.Start > lockEOF-(l.Length-1) {
			return malformedf("lock entry: range end overflows")
		}
	case EntryCheckout:
		c := e.Checkout
		if c == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if err := ValidateCanonicalPath(c.Path); err != nil {
			return fmt.Errorf("checkout entry: %w", err)
		}
		if err := validateSessionRef("checkout entry", c.Holder); err != nil {
			return err
		}
		if err := c.Epoch.Validate(); err != nil {
			return fmt.Errorf("checkout entry: %w", err)
		}
		if c.WritebackID != "" && !restrictedName(c.WritebackID, MaxWritebackIDBytes) {
			return malformedf("checkout entry: malformed writeback id")
		}
		if c.Recovery && c.WritebackID == "" {
			return malformedf("checkout entry: recovery state requires a stream binding")
		}
	case EntryPin:
		p := e.Pin
		if p == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if err := validateSessionRef("pin entry", p.Session); err != nil {
			return err
		}
		if p.Ino == 0 {
			return malformedf("pin entry: inode must be nonzero")
		}
	case EntryFlush:
		f := e.Flush
		if f == nil {
			return malformedf("entry kind %d without its union arm", e.Kind)
		}
		if err := validateSessionRef("flush entry", f.Owner); err != nil {
			return err
		}
		if !restrictedName(f.WritebackID, MaxWritebackIDBytes) {
			return malformedf("flush entry: malformed writeback id")
		}
		if f.Through == 0 {
			return malformedf("flush entry: through must be nonzero")
		}
		if f.Digest == ([DigestBytes]byte{}) {
			return malformedf("flush entry: all-zero stream digest is never a canonical chain value")
		}
	default:
		return malformedf("unknown entry kind %d", e.Kind)
	}
	return nil
}

// ─── entry codec ────────────────────────────────────────────────────────────
// One entry is a strict pfwire message (no magic: entries are embedded inside
// PFT2 CONTROL_LEAF nodes, which carry their own envelope and digest):
//
//	Entry:      1 kind  2 session  3 tombstone  4 slot  5 lock  6 checkout
//	            7 pin  8 flush   (exactly one of 2..8, matching kind)
//	Session:    1 session  2 owner  3 token_hash[32]  4 slots  5 time_source
//	            6 issued_db_ms(s)  7 expires_db_ms(s)
//	Tombstone:  1 session  2 reason
//	Slot:       1 session  2 slot  3 next_seq  4 retired_through  5 latest_seq
//	            6 latest_hash[32]  7 latest_outcome
//	Lock:       1 ino  2 session  3 lock_owner  4 start  5 length  6 write(b)
//	Checkout:   1 path  2 session  3 epoch  4 writeback_id  5 recovery(b)
//	Pin:        1 session  2 ino
//	Flush:      1 owner_session  2 writeback_id  5 through  6 digest[32]

// EncodeEntry encodes e into its unique canonical byte string.
func EncodeEntry(e *Entry) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var body []byte
	var arm []byte
	var field uint32
	switch e.Kind {
	case EntrySession:
		s := e.Session
		arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, s.Session))
		arm = pfwire.AppendString(arm, 2, s.Owner)
		arm = pfwire.AppendBytes(arm, 3, s.TokenHash[:])
		arm = pfwire.AppendUint(arm, 4, uint64(s.Slots))
		arm = pfwire.AppendUint(arm, 5, uint64(s.TimeSource))
		arm = pfwire.AppendSint(arm, 6, s.IssuedDbMs)
		arm = pfwire.AppendSint(arm, 7, s.ExpiresDbMs)
		field = 2
	case EntryTombstone:
		t := e.Tombstone
		arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, t.Session))
		arm = pfwire.AppendUint(arm, 2, uint64(t.Reason))
		field = 3
	case EntrySlot:
		s := e.Slot
		arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, s.Session))
		arm = pfwire.AppendUint(arm, 2, uint64(s.Slot))
		arm = pfwire.AppendUint(arm, 3, s.NextSeq)
		arm = pfwire.AppendUint(arm, 4, s.RetiredThrough)
		if s.HasLatest {
			arm = pfwire.AppendUint(arm, 5, s.LatestSeq)
			arm = pfwire.AppendBytes(arm, 6, s.LatestHash[:])
			arm = pfwire.AppendBytes(arm, 7, appendOutcome(nil, s.LatestOutcome))
		}
		field = 4
	case EntryLock:
		l := e.Lock
		arm = pfwire.AppendUint(arm, 1, l.Ino)
		arm = pfwire.AppendBytes(arm, 2, appendSessionRef(nil, l.Owner.Session))
		arm = pfwire.AppendUint(arm, 3, l.Owner.KernelLockOwner)
		arm = pfwire.AppendUint(arm, 4, l.Start)
		arm = pfwire.AppendUint(arm, 5, l.Length)
		arm = pfwire.AppendBool(arm, 6, l.Write)
		field = 5
	case EntryCheckout:
		c := e.Checkout
		arm = pfwire.AppendString(arm, 1, c.Path)
		arm = pfwire.AppendBytes(arm, 2, appendSessionRef(nil, c.Holder))
		arm = pfwire.AppendString(arm, 3, string(c.Epoch))
		if c.WritebackID != "" {
			arm = pfwire.AppendString(arm, 4, c.WritebackID)
		}
		arm = pfwire.AppendBool(arm, 5, c.Recovery)
		field = 6
	case EntryPin:
		p := e.Pin
		arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, p.Session))
		arm = pfwire.AppendUint(arm, 2, p.Ino)
		field = 7
	case EntryFlush:
		f := e.Flush
		arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, f.Owner))
		arm = pfwire.AppendString(arm, 2, f.WritebackID)
		arm = pfwire.AppendUint(arm, 5, f.Through)
		arm = pfwire.AppendBytes(arm, 6, f.Digest[:])
		field = 8
	}
	body = pfwire.AppendUint(body, 1, uint64(e.Kind))
	body = pfwire.AppendBytes(body, field, arm)
	if len(body) > MaxEntryBytes {
		return nil, malformedf("entry is %d bytes (max %d)", len(body), MaxEntryBytes)
	}
	return body, nil
}

// DecodeEntry strictly decodes one canonical entry. Every rejection is
// rooted at ErrMalformed (with pfwire.ErrMalformed retained in the chain for
// wire-level violations).
func DecodeEntry(payload []byte) (Entry, error) {
	e, err := decodeEntryPayload(payload)
	if err != nil {
		return Entry{}, asMalformed(err)
	}
	return e, nil
}

func decodeEntryPayload(payload []byte) (Entry, error) {
	if len(payload) > MaxEntryBytes {
		return Entry{}, malformedf("entry is %d bytes (max %d)", len(payload), MaxEntryBytes)
	}
	rd := pfwire.NewReader("pfc2 control entry", payload)
	var e Entry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return Entry{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return Entry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return Entry{}, err
			}
			if v > uint64(EntryFlush) {
				return Entry{}, rd.Malformedf("unknown entry kind %d", v)
			}
			e.Kind = EntryKind(v)
		case field >= 2 && field <= 8 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return Entry{}, err
			}
			if err := decodeEntryArm(&e, field, msg); err != nil {
				return Entry{}, err
			}
		default:
			return Entry{}, rd.RejectUnknown(field)
		}
	}
	armMatches := map[EntryKind]bool{
		EntrySession:   e.Session != nil,
		EntryTombstone: e.Tombstone != nil,
		EntrySlot:      e.Slot != nil,
		EntryLock:      e.Lock != nil,
		EntryCheckout:  e.Checkout != nil,
		EntryPin:       e.Pin != nil,
		EntryFlush:     e.Flush != nil,
	}
	if !armMatches[e.Kind] {
		return Entry{}, rd.Malformedf("entry kind %d without its union arm", e.Kind)
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func decodeEntryArm(e *Entry, field uint32, msg []byte) error {
	switch field {
	case 2:
		v, err := decodeSessionEntryValue(msg)
		if err != nil {
			return err
		}
		e.Session = v
	case 3:
		v, err := decodeTombstoneEntryValue(msg)
		if err != nil {
			return err
		}
		e.Tombstone = v
	case 4:
		v, err := decodeSlotEntryValue(msg)
		if err != nil {
			return err
		}
		e.Slot = v
	case 5:
		v, err := decodeLockEntryValue(msg)
		if err != nil {
			return err
		}
		e.Lock = v
	case 6:
		v, err := decodeCheckoutEntryValue(msg)
		if err != nil {
			return err
		}
		e.Checkout = v
	case 7:
		v, err := decodePinEntryValue(msg)
		if err != nil {
			return err
		}
		e.Pin = v
	case 8:
		v, err := decodeFlushEntryValue(msg)
		if err != nil {
			return err
		}
		e.Flush = v
	}
	return nil
}

func decodeSessionEntryValue(body []byte) (*SessionEntryValue, error) {
	rd := pfwire.NewReader("pfc2 session entry", body)
	var s SessionEntryValue
	tokenSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if s.Session, err = decodeSessionRef("pfc2 session entry session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if s.Owner, err = rd.String(field, MaxOwnerBytes); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &s.TokenHash); err != nil {
				return nil, err
			}
			tokenSeen = true
		case field == 4 && wt == pfwire.TypeVarint:
			if s.Slots, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v > uint64(TimeSourceDB) {
				return nil, rd.Malformedf("unknown lease time source %d", v)
			}
			s.TimeSource = TimeSource(v)
		case field == 6 && wt == pfwire.TypeVarint:
			if s.IssuedDbMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if s.ExpiresDbMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	if !tokenSeen {
		return nil, rd.Malformedf("token hash is required")
	}
	return &s, nil
}

func decodeTombstoneEntryValue(body []byte) (*TombstoneEntryValue, error) {
	rd := pfwire.NewReader("pfc2 tombstone entry", body)
	var t TombstoneEntryValue
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if t.Session, err = decodeSessionRef("pfc2 tombstone entry session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v > uint64(TerminalAdminFence) {
				return nil, rd.Malformedf("unknown terminal reason %d", v)
			}
			t.Reason = TerminalReason(v)
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &t, nil
}

func decodeSlotEntryValue(body []byte) (*SlotEntryValue, error) {
	rd := pfwire.NewReader("pfc2 slot entry", body)
	var s SlotEntryValue
	hashSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if s.Session, err = decodeSessionRef("pfc2 slot entry session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.Slot, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if s.NextSeq, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if s.RetiredThrough, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if s.LatestSeq, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 6 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &s.LatestHash); err != nil {
				return nil, err
			}
			hashSeen = true
		case field == 7 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if s.LatestOutcome, err = decodeOutcome("pfc2 slot entry outcome", msg); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	s.HasLatest = s.LatestSeq != 0
	if s.HasLatest != hashSeen {
		return nil, rd.Malformedf("latest sequence and hash presence must match")
	}
	if !s.HasLatest && !s.LatestOutcome.IsZero() {
		return nil, rd.Malformedf("latest outcome present without a latest sequence")
	}
	return &s, nil
}

func decodeLockEntryValue(body []byte) (*LockEntryValue, error) {
	rd := pfwire.NewReader("pfc2 lock entry", body)
	var l LockEntryValue
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if l.Ino, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if l.Owner.Session, err = decodeSessionRef("pfc2 lock entry session", msg); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if l.Owner.KernelLockOwner, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if l.Start, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if l.Length, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 6 && wt == pfwire.TypeVarint:
			if l.Write, err = rd.Bool(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &l, nil
}

func decodeCheckoutEntryValue(body []byte) (*CheckoutEntryValue, error) {
	rd := pfwire.NewReader("pfc2 checkout entry", body)
	var c CheckoutEntryValue
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if c.Path, err = rd.String(field, MaxPathBytes); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if c.Holder, err = decodeSessionRef("pfc2 checkout entry session", msg); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			s, err := rd.String(field, len(EpochBound))
			if err != nil {
				return nil, err
			}
			c.Epoch = Epoch(s)
		case field == 4 && wt == pfwire.TypeBytes:
			if c.WritebackID, err = rd.String(field, MaxWritebackIDBytes); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if c.Recovery, err = rd.Bool(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &c, nil
}

func decodePinEntryValue(body []byte) (*PinEntryValue, error) {
	rd := pfwire.NewReader("pfc2 pin entry", body)
	var p PinEntryValue
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if p.Session, err = decodeSessionRef("pfc2 pin entry session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if p.Ino, err = rd.Uint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &p, nil
}

func decodeFlushEntryValue(body []byte) (*FlushEntryValue, error) {
	rd := pfwire.NewReader("pfc2 flush entry", body)
	var f FlushEntryValue
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			if f.Owner, err = decodeSessionRef("pfc2 flush entry owner", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if f.WritebackID, err = rd.String(field, MaxWritebackIDBytes); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if f.Through, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 6 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &f.Digest); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &f, nil
}

// ─── projection ─────────────────────────────────────────────────────────────

// ProjectionCounts are the verified per-kind entry counts the root carries.
type ProjectionCounts struct {
	Sessions   uint64
	Tombstones uint64
	Slots      uint64
	Locks      uint64
	Checkouts  uint64
	Pins       uint64
	Flushes    uint64
}

func (c ProjectionCounts) total() uint64 {
	return c.Sessions + c.Tombstones + c.Slots + c.Locks + c.Checkouts + c.Pins + c.Flushes
}

// Projection is the complete typed control map at one exact cut, plus the
// root summary a CONTROL_ROOT stores.
type Projection struct {
	Schema            uint32
	Features          uint64
	NextCheckoutEpoch Epoch
	// DbTimeFloorMs is the durable database-time floor at the cut. Recovery
	// resumes time validation from it, so a replacement authority can never
	// accept a minted time older than anything the retired prefix contained.
	DbTimeFloorMs int64
	Counts        ProjectionCounts
	Entries       []Entry // sorted strictly ascending by Key
}

// Project enumerates the current state deterministically: the same state
// always produces byte-identical entries, keys, counts, and digest.
func (st *State) Project() *Projection {
	st.mu.RLock()
	defer st.mu.RUnlock()
	p := &Projection{Schema: ProjectionSchema, NextCheckoutEpoch: st.nextEpoch, DbTimeFloorMs: st.dbTimeFloorMs}

	for _, s := range st.sessions {
		if s.terminal {
			p.Entries = append(p.Entries, Entry{Kind: EntryTombstone, Tombstone: &TombstoneEntryValue{
				Session: s.ref, Reason: s.reason,
			}})
			p.Counts.Tombstones++
			continue
		}
		p.Entries = append(p.Entries, Entry{Kind: EntrySession, Session: &SessionEntryValue{
			Session: s.ref, Owner: s.owner, TokenHash: s.tokenHash, Slots: s.slots,
			TimeSource: s.timeSource, IssuedDbMs: s.issuedDbMs, ExpiresDbMs: s.expiresDbMs,
		}})
		p.Counts.Sessions++
		for slot, ss := range s.slotStates {
			entry := SlotEntryValue{
				Session: s.ref, Slot: slot, NextSeq: ss.nextSeq, RetiredThrough: ss.retiredThrough(),
			}
			if ss.latest != nil {
				entry.HasLatest = true
				entry.LatestSeq, entry.LatestHash, entry.LatestOutcome = ss.latest.seq, ss.latest.hash, ss.latest.out
			}
			p.Entries = append(p.Entries, Entry{Kind: EntrySlot, Slot: &entry})
			p.Counts.Slots++
		}
	}
	for ino, set := range st.locks {
		for _, h := range set {
			length := uint64(0)
			if h.End != LockRangeEOF {
				length = h.End - h.Start + 1
			}
			p.Entries = append(p.Entries, Entry{Kind: EntryLock, Lock: &LockEntryValue{
				Ino: ino, Owner: h.Owner, Start: h.Start, Length: length, Write: h.Write,
			}})
			p.Counts.Locks++
		}
	}
	for path, g := range st.checkouts {
		p.Entries = append(p.Entries, Entry{Kind: EntryCheckout, Checkout: &CheckoutEntryValue{
			Path: path, Holder: g.holder, Epoch: g.epoch,
			WritebackID: g.writebackID, Recovery: g.recovery,
		}})
		p.Counts.Checkouts++
	}
	for ino, holders := range st.pins {
		for ref := range holders {
			p.Entries = append(p.Entries, Entry{Kind: EntryPin, Pin: &PinEntryValue{Session: ref, Ino: ino}})
			p.Counts.Pins++
		}
	}
	for id, e := range st.ledger {
		p.Entries = append(p.Entries, Entry{Kind: EntryFlush, Flush: &FlushEntryValue{
			Owner: e.owner, WritebackID: id, Through: e.through, Digest: e.digest,
		}})
		p.Counts.Flushes++
	}
	sort.Slice(p.Entries, func(i, j int) bool {
		return bytes.Compare(p.Entries[i].Key(), p.Entries[j].Key()) < 0
	})
	return p
}

// Digest is the canonical projection digest: SHA-256 over "PFC2" || 0xF2 ||
// the root header (schema, features, next epoch, per-kind counts) || every
// entry as length-prefixed (key, value). It is the controlHash input for
// RecoveryRootRef installation.
func (p *Projection) Digest() ([DigestBytes]byte, error) {
	h := sha256.New()
	h.Write(Magic[:])
	h.Write([]byte{projectionDigestT})
	var header []byte
	header = pfwire.AppendUint(header, 1, uint64(p.Schema))
	header = pfwire.AppendUint(header, 2, p.Features)
	header = pfwire.AppendString(header, 3, string(p.NextCheckoutEpoch))
	header = pfwire.AppendSint(header, 4, p.DbTimeFloorMs)
	header = pfwire.AppendUint(header, 5, p.Counts.Sessions)
	header = pfwire.AppendUint(header, 6, p.Counts.Tombstones)
	header = pfwire.AppendUint(header, 7, p.Counts.Slots)
	header = pfwire.AppendUint(header, 8, p.Counts.Locks)
	header = pfwire.AppendUint(header, 9, p.Counts.Checkouts)
	header = pfwire.AppendUint(header, 10, p.Counts.Pins)
	header = pfwire.AppendUint(header, 11, p.Counts.Flushes)
	h.Write(pfwire.AppendVarint(nil, uint64(len(header))))
	h.Write(header)
	for i := range p.Entries {
		value, err := EncodeEntry(&p.Entries[i])
		if err != nil {
			return [DigestBytes]byte{}, err
		}
		key := p.Entries[i].Key()
		h.Write(pfwire.AppendVarint(nil, uint64(len(key))))
		h.Write(key)
		h.Write(pfwire.AppendVarint(nil, uint64(len(value))))
		h.Write(value)
	}
	var out [DigestBytes]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// PaginateEntries splits sorted entries into CONTROL_LEAF-shaped pages under
// explicit entry and byte bounds. Deterministic: greedy fill in key order.
func PaginateEntries(entries []Entry, maxEntries, maxBytes int) ([][]Entry, error) {
	if maxEntries <= 0 || maxEntries > MaxLeafEntries {
		return nil, malformedf("page entry bound %d is outside (0,%d]", maxEntries, MaxLeafEntries)
	}
	if maxBytes <= 0 || maxBytes > LeafCeilingBytes {
		return nil, malformedf("page byte bound %d is outside (0,%d]", maxBytes, LeafCeilingBytes)
	}
	var pages [][]Entry
	var page []Entry
	pageBytes := 0
	for i := range entries {
		enc, err := EncodeEntry(&entries[i])
		if err != nil {
			return nil, err
		}
		cost := len(enc) + len(entries[i].Key())
		if cost > maxBytes {
			return nil, malformedf("entry %d is %d bytes; it cannot fit one %d-byte page", i, cost, maxBytes)
		}
		if len(page) > 0 && (len(page) >= maxEntries || pageBytes+cost > maxBytes) {
			pages = append(pages, page)
			page, pageBytes = nil, 0
		}
		page = append(page, entries[i])
		pageBytes += cost
	}
	if len(page) > 0 {
		pages = append(pages, page)
	}
	return pages, nil
}

// Rebuild validates a complete projection and reconstructs its State. Every
// structural, ordering, referential, normalization, capacity, and count
// invariant is verified before any state is published; a corrupt projection
// fails closed with a typed error.
func Rebuild(p *Projection) (*State, error) {
	if p.Schema != ProjectionSchema {
		return nil, integrityf("projection schema %d is not supported (want %d); refusing to guess", p.Schema, ProjectionSchema)
	}
	if p.Features != 0 {
		return nil, integrityf("projection carries unknown feature bits %#x; refusing to guess", p.Features)
	}
	if err := p.NextCheckoutEpoch.Validate(); err != nil {
		return nil, fmt.Errorf("projection next epoch: %w", err)
	}
	if p.DbTimeFloorMs != 0 && !validDbTimeMs(p.DbTimeFloorMs) {
		return nil, integrityf("projection database-time floor %d is implausible", p.DbTimeFloorMs)
	}
	if got, want := uint64(len(p.Entries)), p.Counts.total(); got != want {
		return nil, integrityf("projection has %d entries but counts claim %d", got, want)
	}
	if len(p.Entries) > maxTotalEntries {
		return nil, capacityf("projection has %d entries (max %d)", len(p.Entries), maxTotalEntries)
	}

	st := NewState()
	st.nextEpoch = p.NextCheckoutEpoch
	st.dbTimeFloorMs = p.DbTimeFloorMs
	var counts ProjectionCounts
	var prevKey []byte
	lockSets := map[uint64][]HeldLock{}

	for i := range p.Entries {
		e := &p.Entries[i]
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("projection entry %d: %w", i, err)
		}
		key := e.Key()
		if prevKey != nil && bytes.Compare(prevKey, key) >= 0 {
			return nil, integrityf("projection entry %d is not strictly ascending by key", i)
		}
		prevKey = key

		switch e.Kind {
		case EntrySession:
			v := e.Session
			// The open and every renewal fed the floor, so a live session's
			// facts must sit inside it: issue at/below the floor and deadline
			// within one bounded TTL of the last possible minting time.
			if v.IssuedDbMs > p.DbTimeFloorMs {
				return nil, integrityf("projection entry %d: session %v was issued at %d, after the database-time floor %d",
					i, v.Session, v.IssuedDbMs, p.DbTimeFloorMs)
			}
			if v.ExpiresDbMs > p.DbTimeFloorMs+MaxSessionLeaseMs {
				return nil, integrityf("projection entry %d: session %v deadline %d exceeds every deadline mintable at the floor %d",
					i, v.Session, v.ExpiresDbMs, p.DbTimeFloorMs)
			}
			st.sessions[v.Session.SessionID] = &sessionState{
				ref: v.Session, owner: v.Owner, tokenHash: v.TokenHash, slots: v.Slots,
				timeSource: v.TimeSource, issuedDbMs: v.IssuedDbMs, expiresDbMs: v.ExpiresDbMs,
				slotStates: map[uint32]*slotState{},
			}
			st.liveSessions++
			counts.Sessions++
		case EntryTombstone:
			v := e.Tombstone
			st.sessions[v.Session.SessionID] = &sessionState{
				ref: v.Session, terminal: true, reason: v.Reason,
			}
			counts.Tombstones++
		case EntrySlot:
			v := e.Slot
			s, err := rebuildLiveSession(st, v.Session, "slot entry")
			if err != nil {
				return nil, fmt.Errorf("projection entry %d: %w", i, err)
			}
			if v.Slot >= s.slots {
				return nil, integrityf("projection entry %d: slot %d outside %v's window of %d", i, v.Slot, s.ref, s.slots)
			}
			ss := &slotState{nextSeq: v.NextSeq}
			if v.HasLatest {
				ss.latest = &latestOutcome{seq: v.LatestSeq, hash: v.LatestHash, out: v.LatestOutcome}
			}
			s.slotStates[v.Slot] = ss
			st.slotStates++
			counts.Slots++
		case EntryLock:
			v := e.Lock
			if _, err := rebuildLiveSession(st, v.Owner.Session, "lock entry"); err != nil {
				return nil, fmt.Errorf("projection entry %d: %w", i, err)
			}
			lockSets[v.Ino] = append(lockSets[v.Ino], HeldLock{
				Owner: v.Owner, Start: v.Start, End: lockEnd(v.Start, v.Length), Write: v.Write,
			})
			counts.Locks++
		case EntryCheckout:
			v := e.Checkout
			if !v.Recovery {
				// A recovery grant's holder is a dead generation (that is
				// what recovery MEANS); only live grants get the liveness
				// referential check.
				if _, err := rebuildLiveSession(st, v.Holder, "checkout entry"); err != nil {
					return nil, fmt.Errorf("projection entry %d: %w", i, err)
				}
			}
			if v.Epoch.Compare(st.nextEpoch) >= 0 {
				return nil, integrityf("projection entry %d: checkout epoch %s is not below the next epoch %s", i, v.Epoch, st.nextEpoch)
			}
			st.checkouts[v.Path] = checkoutGrant{holder: v.Holder, epoch: v.Epoch, writebackID: v.WritebackID, recovery: v.Recovery}
			counts.Checkouts++
		case EntryPin:
			v := e.Pin
			if _, err := rebuildLiveSession(st, v.Session, "pin entry"); err != nil {
				return nil, fmt.Errorf("projection entry %d: %w", i, err)
			}
			holders := st.pins[v.Ino]
			if holders == nil {
				holders = map[SessionRef]struct{}{}
				st.pins[v.Ino] = holders
			}
			holders[v.Session] = struct{}{}
			st.pinCount++
			counts.Pins++
		case EntryFlush:
			v := e.Flush
			// Checkout entries sort before flush entries, so the stream's
			// scopes are already rebuilt: a stream survives either under a
			// live owner or via recovery scopes referencing it.
			recovery := false
			for _, g := range st.checkouts {
				if g.writebackID == v.WritebackID && g.recovery {
					recovery = true
					break
				}
			}
			if !recovery {
				if _, err := rebuildLiveSession(st, v.Owner, "flush entry"); err != nil {
					return nil, fmt.Errorf("projection entry %d: %w", i, err)
				}
			}
			st.ledger[v.WritebackID] = ledgerEntry{through: v.Through, digest: v.Digest, owner: v.Owner}
			counts.Flushes++
		}
	}

	if counts != p.Counts {
		return nil, integrityf("projection per-kind counts %+v do not match entries %+v", p.Counts, counts)
	}
	if st.liveSessions > MaxLiveSessions || len(st.sessions) > MaxSessionEntries ||
		st.slotStates > MaxSlotStates || len(st.checkouts) > MaxCheckouts ||
		st.pinCount > MaxOpenPins || len(st.ledger) > MaxFlushEntries {
		return nil, capacityf("projection exceeds control-state capacity bounds")
	}

	for ino, set := range lockSets {
		sortLocks(set)
		if !isNormalizedLocks(set) {
			return nil, integrityf("projection lock intervals on ino %d are not normalized", ino)
		}
		if len(set) > MaxInodeIntervals {
			return nil, capacityf("projection ino %d holds %d intervals (max %d)", ino, len(set), MaxInodeIntervals)
		}
		st.locks[ino] = set
		st.lockCount += len(set)
	}
	if st.lockCount > MaxLockIntervals {
		return nil, capacityf("projection lock intervals exceed %d", MaxLockIntervals)
	}

	// Checkout grants must be pairwise non-overlapping and carry unique
	// epochs. Ancestor lookups over each path's own prefixes keep this
	// linear in total path bytes rather than quadratic in grants.
	seenEpochs := map[Epoch]string{}
	for path, g := range st.checkouts {
		if prev, dup := seenEpochs[g.epoch]; dup {
			return nil, integrityf("projection checkout epoch %s granted to both %q and %q", g.epoch, prev, path)
		}
		seenEpochs[g.epoch] = path
		for i := 0; i < len(path); i++ {
			if path[i] == '/' {
				if _, overlap := st.checkouts[path[:i]]; overlap {
					return nil, integrityf("projection checkouts %q and %q overlap", path[:i], path)
				}
			}
		}
	}
	return st, nil
}

func rebuildLiveSession(st *State, ref SessionRef, what string) (*sessionState, error) {
	s := st.sessions[ref.SessionID]
	if s == nil || s.terminal || s.ref.Generation != ref.Generation {
		return nil, integrityf("%s references %v, which is not a live projected session", what, ref)
	}
	return s, nil
}
