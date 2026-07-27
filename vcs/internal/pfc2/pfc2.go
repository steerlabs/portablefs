// Package pfc2 implements the PFC2 journaled control format: the frozen
// canonical record codec and the deterministic reducer for exact mount-session
// control state (docs/pfc2-control-format.md, docs/exact-mount-sessions.md).
//
// PFC2 carries exact session lifecycle, durable reply outcomes and floors,
// flush advancement, inode-keyed POSIX locks, canonical-path checkouts, and
// open pins. It deliberately carries NOTHING else: tree/namespace/orphan
// mutations remain PFR1, manager/runtime/access leases remain external fenced
// database facts, and recovery-anchor installation is exact cut adoption, not
// a PFC2 record.
//
// One record is "PFC2" || strict-pfwire-body, at most 64 KiB, with exactly one
// canonical byte representation per value (ascending frozen fields, minimal
// varints, omitted defaults, contiguous repeated fields, strict UTF-8, and
// rejection of unknown/duplicate/misordered/trailing/oversized values).
// Digests are exactly 32 bytes and hashes include the magic.
//
// The reducer (State) applies records in ONE total order. Every record is
// fully validated against immutable state before any mutation; a batch stages
// atomically and rolls back completely on failure. There is no global reclaim
// grace, no time-based pruning of outcomes or tombstones, and no wall-clock
// input anywhere in a transition: replaying the same records always rebuilds
// the same state.
//
// Time discipline: every lease time in PFC2 is an exact database-issued fact
// (millisecond integer, canonical zigzag varint, never a float or JSON
// number) minted by the external fenced SQL admission — never by a client or
// authority host wall clock. The package imports no clock; the reducer only
// validates that time facts are plausible, non-regressive under the journal's
// total order (the durable db-time floor), and consistent with the conditional
// expiry rules. Host clocks may be used by integrations solely to project a
// REMAINING duration onto local monotonic timers (see lease.go); they never
// become durable truth.
package pfc2

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Magic prefixes every canonical PFC2 record. It is part of the canonical
// bytes: request hashes and record digests cover it.
var Magic = [4]byte{'P', 'F', 'C', '2'}

// Codec names this control codec in journal generation metadata. One journal
// generation has exactly one control codec; PFC1 is decode-only elsewhere and
// never mixes with PFC2 in an epoch.
const Codec = "pfc2"

// Frozen bounds. Enforced before allocation on decode and before any state
// mutation on apply. Old bounds are never raised silently: they are part of
// the interoperable format.
const (
	// MaxRecordBytes bounds one whole encoded record including the magic.
	MaxRecordBytes = 64 << 10

	MaxSessionIDBytes   = 128
	MaxOwnerBytes       = 256
	MaxWritebackIDBytes = 128
	MaxPathBytes        = 4096
	MaxNameBytes        = 255

	TokenHashBytes   = 32
	RequestHashBytes = 32
	DigestBytes      = 32
	// FactIDBytes is the exact length of one issued admission-fact identity.
	FactIDBytes = 16

	// MaxSlots bounds one session's slot count (server-clamped window).
	MaxSlots = 4096

	// MaxBatchRecords bounds one atomic reducer batch.
	MaxBatchRecords = 4096

	// MaxDbTimeMs bounds every database-issued time fact (9999-12-31T23:59:59.999Z).
	// A time outside (0, MaxDbTimeMs] is implausible garbage — a corrupted or
	// non-database-minted value — and is rejected before any state effect.
	MaxDbTimeMs = 253_402_300_799_999
	// MaxSessionLeaseMs bounds one lease extension: a deadline more than 24
	// hours past its minting database time cannot have been produced by a
	// correct admission and is rejected as implausible.
	MaxSessionLeaseMs = 86_400_000
)

// State capacity bounds. Capacity is explicit: exhaustion rejects NEW state
// with ErrCapacity rather than forgetting exactness (no time pruning).
const (
	MaxLiveSessions   = 16_384
	MaxSessionEntries = 65_536 // live sessions + retained terminal tombstones
	MaxSlotStates     = 262_144
	MaxLockIntervals  = 262_144
	MaxInodeIntervals = 4_096 // normalized intervals per inode
	MaxCheckouts      = 16_384
	MaxOpenPins       = 262_144
	MaxFlushEntries   = 65_536
)

// Typed error roots. Every failure wraps exactly one of these.
var (
	// ErrMalformed is a record (or projection entry) that is invalid in
	// itself, independent of state. Wire-level canonicality violations carry
	// pfwire.ErrMalformed in the chain as well.
	ErrMalformed = errors.New("pfc2: malformed record")
	// ErrCapacity is an explicit bound exhaustion. State is unchanged.
	ErrCapacity = errors.New("pfc2: control-state capacity exhausted")
	// ErrIntegrity is a record that contradicts reduced state: it cannot have
	// been produced by a correct authority under the one reservation order.
	// Replay fails closed rather than guessing at exactly-once state.
	ErrIntegrity = errors.New("pfc2: control-state integrity violation")
	// ErrFence is a record targeting a terminal, superseded, or credential-
	// mismatched session generation. Live admission maps it to ESTALE/EPERM;
	// during replay it is as fatal as ErrIntegrity.
	ErrFence = errors.New("pfc2: session generation is fenced")
)

func malformedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func capacityf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCapacity, fmt.Sprintf(format, args...))
}

func integrityf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrIntegrity, fmt.Sprintf(format, args...))
}

func fencedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFence, fmt.Sprintf(format, args...))
}

// Kind tags the frozen top-level record union. Implemented enum numbers are
// never reused; runtime and anchor transitions deliberately have no kind.
type Kind uint8

const (
	KindSessionOpen     Kind = 1
	KindSessionRenew    Kind = 2
	KindSessionTerminal Kind = 3
	KindExactOutcome    Kind = 4
	KindOutcomeFloor    Kind = 5
	KindFlushAdvance    Kind = 6
	KindLockChange      Kind = 7
	KindCheckoutChange  Kind = 8
	KindOpenPinChange   Kind = 9
)

func (k Kind) String() string {
	switch k {
	case KindSessionOpen:
		return "SessionOpen"
	case KindSessionRenew:
		return "SessionRenew"
	case KindSessionTerminal:
		return "SessionTerminal"
	case KindExactOutcome:
		return "ExactOutcome"
	case KindOutcomeFloor:
		return "OutcomeFloor"
	case KindFlushAdvance:
		return "FlushAdvance"
	case KindLockChange:
		return "LockChange"
	case KindCheckoutChange:
		return "CheckoutChange"
	case KindOpenPinChange:
		return "OpenPinChange"
	default:
		return fmt.Sprintf("Kind(%d)", uint8(k))
	}
}

// TerminalReason is the frozen SessionTerminal reason enum.
type TerminalReason uint8

const (
	// TerminalClose is an explicit clean close (voluntary unmount).
	TerminalClose TerminalReason = 1
	// TerminalExpire is conditional database-time lease expiry. The record
	// carries the exact observed durable deadline; a renewal ordered first
	// invalidates it (deterministic no-op), expiry ordered first permanently
	// fences any later renewal at admission.
	TerminalExpire TerminalReason = 2
	// TerminalSupersede fences a generation because a higher generation of
	// the same session id was durably opened.
	TerminalSupersede TerminalReason = 3
	// TerminalSlotCorruption fences a generation whose client presented a
	// changed request at an occupied exact identity or a slot-sequence gap.
	TerminalSlotCorruption TerminalReason = 4
	// TerminalAdminFence is an administrative/run-lifecycle fence.
	TerminalAdminFence TerminalReason = 5
)

func (r TerminalReason) valid() bool { return r >= TerminalClose && r <= TerminalAdminFence }

func (r TerminalReason) String() string {
	switch r {
	case TerminalClose:
		return "close"
	case TerminalExpire:
		return "expire"
	case TerminalSupersede:
		return "supersede"
	case TerminalSlotCorruption:
		return "slot-corruption"
	case TerminalAdminFence:
		return "admin-fence"
	default:
		return fmt.Sprintf("reason(%d)", uint8(r))
	}
}

// LockOp is the frozen LockChange operation enum.
type LockOp uint8

const (
	LockSetRead  LockOp = 1
	LockSetWrite LockOp = 2
	LockUnlock   LockOp = 3
)

func (op LockOp) valid() bool { return op >= LockSetRead && op <= LockUnlock }

// CheckoutOp is the frozen CheckoutChange operation enum.
type CheckoutOp uint8

const (
	CheckoutGrant CheckoutOp = 1
	// CheckoutRelease removes the caller's grant; it must name the grant's
	// exact server-issued epoch.
	CheckoutRelease CheckoutOp = 2
	// CheckoutForceTransfer atomically removes every overlapping grant and
	// installs the new one. It carries the digest of the conflict set that was
	// originally recalled, so a timeout against holder A can never revoke a
	// fresh holder C.
	CheckoutForceTransfer CheckoutOp = 3
)

func (op CheckoutOp) valid() bool { return op >= CheckoutGrant && op <= CheckoutForceTransfer }

// SessionRef names one exact session generation.
type SessionRef struct {
	SessionID  string
	Generation uint64
}

func (s SessionRef) String() string { return fmt.Sprintf("%s#%d", s.SessionID, s.Generation) }

// ExactKey is one exact-once mutation identity plus its request fingerprint.
type ExactKey struct {
	Session     SessionRef
	Slot        uint32
	SlotSeq     uint64
	RequestHash [RequestHashBytes]byte
}

// Outcome is the durable essential response of one exact operation. It
// deliberately excludes process-local coherence versions: a replayed result
// may return version zero under the current generation and require re-stat.
type Outcome struct {
	Status    int32
	Count     int32
	Offset    int64
	Ino       uint64
	OrphanIno uint64
}

// IsZero reports whether o is the all-default success outcome.
func (o Outcome) IsZero() bool { return o == Outcome{} }

// TimeSource is the frozen provenance tag for every lease time a record
// carries. PFC2 v1 accepts exactly one source: the external fenced SQL
// admission that commits the record. Client and authority host wall clocks
// are NOT sources; an unknown source fails closed rather than being guessed
// at, so a future source requires an explicit schema step.
type TimeSource uint8

// TimeSourceDB marks times minted by a short-lived capability-bound admission
// fact issued by the fenced database (exact BIGINT milliseconds).
const TimeSourceDB TimeSource = 1

func (s TimeSource) valid() bool { return s == TimeSourceDB }

// TimeFact is one issued admission time fact, frozen verbatim into the record
// bytes: the source tag, the database-issued fact identity, and the exact
// database time observed at issuance. The fact row itself is short-lived SQL
// state — issued under exact tenant/volume/branch/generation/runtime/session
// facts and revalidated (unexpired, matching scope, fresh clock_timestamp not
// behind it) by the SAME append transaction that journals these bytes. The
// reducer replays the frozen values deterministically and never re-checks the
// fact row: consumption happened exactly once at append.
type TimeFact struct {
	Source TimeSource
	FactID [FactIDBytes]byte
	DbMs   int64
}

// Validate rejects facts with an unknown source, an all-zero identity, or an
// implausible time. The fact identity is a REQUIRED cryptographic identifier:
// PostgreSQL mints it from random bytes, so all-zero can only be a fabricated
// or damaged fact and is rejected even when the wire field is present.
// (Presence itself is the decoder's field-level rule; whether a well-formed
// id names a LIVE issued fact is the append transaction's decision.)
func (f TimeFact) Validate() error {
	if !f.Source.valid() {
		return malformedf("time fact: unknown source %d; host wall clocks are not a source", f.Source)
	}
	if f.FactID == ([FactIDBytes]byte{}) {
		return malformedf("time fact: all-zero fact id is never a database-minted identity")
	}
	if !validDbTimeMs(f.DbMs) {
		return malformedf("time fact: database time %d is implausible", f.DbMs)
	}
	return nil
}

// SessionOpen (kind 1) durably establishes the exact idempotent tuple
// (id, generation, owner, tokenHash, slots, fact, expires). Re-sending the
// identical tuple is a no-op; the same generation with a different tuple is a
// credential conflict; a lower generation than the durable one is stale.
// Opening a HIGHER generation atomically supersedes (terminal transition,
// reason supersede) any live lower generation of the same id.
type SessionOpen struct {
	Session   SessionRef
	Owner     string // display/audit label only; never authorizes anything
	TokenHash [TokenHashBytes]byte
	Slots     uint32
	// Fact is the issued admission fact that minted this open. Fact.DbMs is
	// the issue time and the record's entry in the durable db-time floor.
	Fact TimeFact
	// ExpiresDbMs is the database-time lease deadline: Fact.DbMs plus a
	// bounded TTL. Never derived from a host clock.
	ExpiresDbMs int64
}

// SessionRenew (kind 2) carries the same token hash, the issued admission
// fact, and a new database-time deadline. The durable deadline strictly
// advances: a non-advancing renewal is never journaled (the admission check
// suppresses it), so replay rejects one as corruption.
type SessionRenew struct {
	Session   SessionRef
	TokenHash [TokenHashBytes]byte
	Fact      TimeFact
	// ExpiresDbMs is the new deadline: Fact.DbMs plus a bounded TTL.
	ExpiresDbMs int64
}

// SessionTerminal (kind 3) ends one generation for a typed reason and
// atomically: marks it terminal retaining a compact tombstone, retires its
// detailed outcomes, releases its locks, checkouts and open pins, invalidates
// its flush privileges, and reports newly-unpinned inodes for authority-
// internal reap scheduling. Socket close is never this boundary.
type SessionTerminal struct {
	Session SessionRef
	Reason  TerminalReason
	// ObservedDeadlineDbMs is present exactly for TerminalExpire: the durable
	// database-time deadline the sweeper observed. If the session's durable
	// deadline has advanced past it (a renewal ordered first), the record is
	// a deterministic no-op; if it is behind the durable deadline the record
	// is corrupt.
	ObservedDeadlineDbMs int64
	// DecisionFact is present exactly for TerminalExpire: the fresh admission
	// fact re-checked when the expiry was journaled. Its database time proves
	// the deadline actually elapsed (DecisionFact.DbMs >= observed deadline);
	// local timers only SCHEDULE the re-check and never authorize it.
	DecisionFact TimeFact
}

// ExactOutcome (kind 4) durably records the essential outcome of one exact
// identity that produced NO PFC2 state delta: statically malformed requests,
// gate rejections (reserved namespace, checkout EBUSY), rejected coordination
// operations. Slot sequences advance through it, so retries survive restart.
// PFR1 tree records carry their own envelopes and rebuild their outcomes
// during tree replay (State.RecordExternalOutcome); they never get a second
// PFC2 record.
type ExactOutcome struct {
	Key     ExactKey
	Outcome Outcome
}

// OutcomeFloor (kind 5) explicitly acknowledges a slot's idle latest outcome
// and advances the slot's monotonic durable floor, releasing the retained
// outcome detail. Through must equal the slot's latest (unacknowledged)
// sequence.
type OutcomeFloor struct {
	Session SessionRef
	Slot    uint32
	Through uint64
}

// FlushAdvance (kind 6) advances one write-back flush ledger watermark:
// (session, writebackID, checkoutPath, checkoutEpoch) -> throughSequence,
// strictly monotonic per identity. It rides the SAME atomic outer batch as
// the flushed user PFR1 records. The named checkout epoch must be the live
// grant held by the same session: a delayed flush after release/transfer is
// ESTALE even if the path later becomes free.
type FlushAdvance struct {
	Session       SessionRef
	WritebackID   string
	CheckoutPath  string
	CheckoutEpoch Epoch
	Through       uint64
}

// LockChange (kind 7) applies one granted POSIX byte-range transition keyed
// by stable inode with owner (SessionRef, KernelLockOwner). It carries its
// exact request key and outcome; rejected acquires are recorded as
// ExactOutcome records instead. Length 0 means "through EOF" (POSIX l_len=0).
// Wait queues are volatile: clients retry after restart.
type LockChange struct {
	Key             ExactKey
	Outcome         Outcome // must be the zero (success) outcome
	Ino             uint64
	KernelLockOwner uint64
	Op              LockOp
	Start           uint64
	Length          uint64
}

// CheckoutChange (kind 8) grants, releases, or force-transfers one
// canonical-path checkout. Grants receive the server-controlled next decimal
// epoch; release must name its grant's exact epoch. It carries its exact
// request key and outcome; rejections are ExactOutcome records.
type CheckoutChange struct {
	Key     ExactKey
	Outcome Outcome // must be the zero (success) outcome
	Op      CheckoutOp
	Path    string
	Epoch   Epoch
	// RecalledDigest is present exactly for CheckoutForceTransfer: the digest
	// of the overlapping conflict set originally recalled (RecallDigest).
	RecalledDigest [DigestBytes]byte
}

// OpenPinChange (kind 9) acquires or releases the one durable open pin per
// (session, inode). First local open acquires it, last close releases it;
// session renewal owns its liveness (no per-inode renewals). Pin transitions
// are per-owner idempotent at the protocol layer, so the authority journals
// only actual transitions; a duplicate transition record is corruption.
type OpenPinChange struct {
	Session SessionRef
	Ino     uint64
	Unpin   bool
}

// Record is the frozen top-level union: exactly one arm, matching Kind.
type Record struct {
	Kind Kind

	SessionOpen     *SessionOpen
	SessionRenew    *SessionRenew
	SessionTerminal *SessionTerminal
	ExactOutcome    *ExactOutcome
	OutcomeFloor    *OutcomeFloor
	FlushAdvance    *FlushAdvance
	LockChange      *LockChange
	CheckoutChange  *CheckoutChange
	OpenPinChange   *OpenPinChange
}

// restrictedName reports whether s fits the restricted session/writeback id
// alphabet: it appears in logs, keys, and durable records, so it must never
// carry separators, control bytes, or an empty value.
func restrictedName(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
}

func validateSessionRef(what string, s SessionRef) error {
	if !restrictedName(s.SessionID, MaxSessionIDBytes) {
		return malformedf("%s: session id %q is empty, oversized, or outside the restricted alphabet", what, s.SessionID)
	}
	if s.Generation == 0 {
		return malformedf("%s: session generation must be nonzero", what)
	}
	return nil
}

func validateExactKey(what string, k *ExactKey) error {
	if err := validateSessionRef(what, k.Session); err != nil {
		return err
	}
	if k.Slot >= MaxSlots {
		return malformedf("%s: slot %d exceeds bound %d", what, k.Slot, MaxSlots-1)
	}
	if k.SlotSeq == 0 {
		return malformedf("%s: slot sequence must be nonzero", what)
	}
	// RequestHash is a REQUIRED cryptographic identifier. Its wire presence
	// is enforced by the decoder (absence is the missing field, never a
	// sentinel), and the all-zero value is additionally rejected because no
	// canonical request fingerprints to zero: a present zero can only be a
	// fabricated or damaged identity.
	if k.RequestHash == ([RequestHashBytes]byte{}) {
		return malformedf("%s: all-zero request hash is never a canonical fingerprint", what)
	}
	return nil
}

// ValidateCanonicalPath enforces the canonical checkout-path form: nonempty,
// slash-separated, NUL-free valid UTF-8, no empty/"."/".." segments, no
// leading or trailing slash, each segment at most MaxNameBytes, whole path at
// most MaxPathBytes. There is exactly one canonical spelling per path.
func ValidateCanonicalPath(p string) error {
	if p == "" {
		return malformedf("path is empty (root is not checkoutable)")
	}
	if len(p) > MaxPathBytes {
		return malformedf("path is %d bytes (max %d)", len(p), MaxPathBytes)
	}
	if !utf8.ValidString(p) {
		return malformedf("path is not valid UTF-8")
	}
	start := 0
	for i := 0; i <= len(p); i++ {
		if i != len(p) && p[i] != '/' {
			if p[i] == 0 {
				return malformedf("path contains NUL")
			}
			continue
		}
		seg := p[start:i]
		if seg == "" {
			return malformedf("path %q has an empty segment", p)
		}
		if seg == "." || seg == ".." {
			return malformedf("path %q has a %q segment", p, seg)
		}
		if len(seg) > MaxNameBytes {
			return malformedf("path segment is %d bytes (max %d)", len(seg), MaxNameBytes)
		}
		start = i + 1
	}
	return nil
}

// pathsOverlap reports whether two canonical checkout paths cover overlapping
// subtrees (equal, ancestor, or descendant).
func pathsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return strings.HasPrefix(b, a+"/") || strings.HasPrefix(a, b+"/")
}

// lockEnd returns the inclusive end offset for (start, length) with the POSIX
// l_len=0 "through EOF" meaning. EOF is represented as ^uint64(0).
const lockEOF = ^uint64(0)

func lockEnd(start, length uint64) uint64 {
	if length == 0 {
		return lockEOF
	}
	return start + length - 1
}

// validDbTimeMs bounds one exact database-issued time fact: positive, exact
// in int64 milliseconds, and no later than year 9999. Anything else cannot
// have been minted by a correct fenced admission.
func validDbTimeMs(ms int64) bool { return ms > 0 && ms <= MaxDbTimeMs }

// validateMintedLease enforces the shape shared by SessionOpen and
// SessionRenew lease facts: a valid issued fact and a deadline strictly after
// its minting time by at most the bounded TTL.
func validateMintedLease(what string, fact TimeFact, expiresDbMs int64) error {
	if err := fact.Validate(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if !validDbTimeMs(expiresDbMs) {
		return malformedf("%s: lease deadline %d is implausible", what, expiresDbMs)
	}
	if expiresDbMs <= fact.DbMs {
		return malformedf("%s: lease deadline %d does not follow its minting time %d", what, expiresDbMs, fact.DbMs)
	}
	if expiresDbMs-fact.DbMs > MaxSessionLeaseMs {
		return malformedf("%s: lease span %dms exceeds the plausible bound %dms", what, expiresDbMs-fact.DbMs, int64(MaxSessionLeaseMs))
	}
	return nil
}

// Validate enforces every structural (state-independent) rule for r. Encode
// refuses to produce an invalid record and decode re-validates, so both paths
// accept exactly the same value space.
func (r *Record) Validate() error {
	arms := 0
	for _, present := range []bool{
		r.SessionOpen != nil, r.SessionRenew != nil, r.SessionTerminal != nil,
		r.ExactOutcome != nil, r.OutcomeFloor != nil, r.FlushAdvance != nil,
		r.LockChange != nil, r.CheckoutChange != nil, r.OpenPinChange != nil,
	} {
		if present {
			arms++
		}
	}
	if arms != 1 {
		return malformedf("record kind %d has %d union arms (want exactly one)", r.Kind, arms)
	}
	switch r.Kind {
	case KindSessionOpen:
		s := r.SessionOpen
		if s == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateSessionRef("session open", s.Session); err != nil {
			return err
		}
		if s.TokenHash == ([TokenHashBytes]byte{}) {
			return malformedf("session open: all-zero token hash is never a real credential digest")
		}
		if len(s.Owner) > MaxOwnerBytes {
			return malformedf("session open: owner exceeds %d bytes", MaxOwnerBytes)
		}
		if !utf8.ValidString(s.Owner) || strings.IndexByte(s.Owner, 0) >= 0 {
			return malformedf("session open: owner is not NUL-free UTF-8")
		}
		if s.Slots == 0 || s.Slots > MaxSlots {
			return malformedf("session open: slots must be in [1,%d]", MaxSlots)
		}
		if err := validateMintedLease("session open", s.Fact, s.ExpiresDbMs); err != nil {
			return err
		}
	case KindSessionRenew:
		s := r.SessionRenew
		if s == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateSessionRef("session renew", s.Session); err != nil {
			return err
		}
		if s.TokenHash == ([TokenHashBytes]byte{}) {
			return malformedf("session renew: all-zero token hash is never a real credential digest")
		}
		if err := validateMintedLease("session renew", s.Fact, s.ExpiresDbMs); err != nil {
			return err
		}
	case KindSessionTerminal:
		s := r.SessionTerminal
		if s == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateSessionRef("session terminal", s.Session); err != nil {
			return err
		}
		if !s.Reason.valid() {
			return malformedf("session terminal: unknown reason %d", s.Reason)
		}
		if s.Reason == TerminalExpire {
			if !validDbTimeMs(s.ObservedDeadlineDbMs) {
				return malformedf("session terminal: expiry requires a plausible observed durable deadline")
			}
			if err := s.DecisionFact.Validate(); err != nil {
				return fmt.Errorf("session terminal: expiry decision: %w", err)
			}
			if s.DecisionFact.DbMs < s.ObservedDeadlineDbMs {
				return malformedf("session terminal: decision time %d precedes the observed deadline %d; database time never authorized this expiry",
					s.DecisionFact.DbMs, s.ObservedDeadlineDbMs)
			}
		} else if s.ObservedDeadlineDbMs != 0 || s.DecisionFact != (TimeFact{}) {
			return malformedf("session terminal: expiry time facts are only valid for the expire reason")
		}
	case KindExactOutcome:
		o := r.ExactOutcome
		if o == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateExactKey("exact outcome", &o.Key); err != nil {
			return err
		}
	case KindOutcomeFloor:
		f := r.OutcomeFloor
		if f == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateSessionRef("outcome floor", f.Session); err != nil {
			return err
		}
		if f.Slot >= MaxSlots {
			return malformedf("outcome floor: slot %d exceeds bound %d", f.Slot, MaxSlots-1)
		}
		if f.Through == 0 {
			return malformedf("outcome floor: through must be nonzero")
		}
	case KindFlushAdvance:
		f := r.FlushAdvance
		if f == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateSessionRef("flush advance", f.Session); err != nil {
			return err
		}
		if !restrictedName(f.WritebackID, MaxWritebackIDBytes) {
			return malformedf("flush advance: writeback id %q is empty, oversized, or outside the restricted alphabet", f.WritebackID)
		}
		if err := ValidateCanonicalPath(f.CheckoutPath); err != nil {
			return fmt.Errorf("flush advance: %w", err)
		}
		if err := f.CheckoutEpoch.Validate(); err != nil {
			return fmt.Errorf("flush advance: %w", err)
		}
		if f.Through == 0 {
			return malformedf("flush advance: through must be nonzero")
		}
	case KindLockChange:
		l := r.LockChange
		if l == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateExactKey("lock change", &l.Key); err != nil {
			return err
		}
		if !l.Outcome.IsZero() {
			return malformedf("lock change: outcome must be the zero success outcome (rejections are ExactOutcome records)")
		}
		if l.Ino == 0 {
			return malformedf("lock change: inode must be nonzero")
		}
		if !l.Op.valid() {
			return malformedf("lock change: unknown op %d", l.Op)
		}
		if l.Length != 0 && l.Start > lockEOF-(l.Length-1) {
			return malformedf("lock change: range end overflows")
		}
		if want := l.RequestHash(); l.Key.RequestHash != want {
			return malformedf("lock change: request hash does not fingerprint the lock request")
		}
	case KindCheckoutChange:
		c := r.CheckoutChange
		if c == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateExactKey("checkout change", &c.Key); err != nil {
			return err
		}
		if !c.Outcome.IsZero() {
			return malformedf("checkout change: outcome must be the zero success outcome (rejections are ExactOutcome records)")
		}
		if !c.Op.valid() {
			return malformedf("checkout change: unknown op %d", c.Op)
		}
		if err := ValidateCanonicalPath(c.Path); err != nil {
			return fmt.Errorf("checkout change: %w", err)
		}
		if err := c.Epoch.Validate(); err != nil {
			return fmt.Errorf("checkout change: %w", err)
		}
		// The recalled digest exists exactly for force transfer: presence is
		// op-kind-based (the wire field is emitted iff transferring). When
		// required it is a REAL digest — SHA-256 of the canonical conflict
		// set never yields zero — so a present all-zero value is fabricated
		// or damaged and rejected. Non-transfer ops have no such field.
		if c.Op == CheckoutForceTransfer {
			if c.RecalledDigest == ([DigestBytes]byte{}) {
				return malformedf("checkout change: all-zero recalled-conflict digest is never a canonical digest")
			}
		} else if c.RecalledDigest != ([DigestBytes]byte{}) {
			return malformedf("checkout change: recalled digest is only valid for force transfer")
		}
		if want := c.RequestHash(); c.Key.RequestHash != want {
			return malformedf("checkout change: request hash does not fingerprint the checkout request")
		}
	case KindOpenPinChange:
		p := r.OpenPinChange
		if p == nil {
			return malformedf("kind %v without its union arm", r.Kind)
		}
		if err := validateSessionRef("open pin change", p.Session); err != nil {
			return err
		}
		if p.Ino == 0 {
			return malformedf("open pin change: inode must be nonzero")
		}
	default:
		return malformedf("unknown record kind %d", r.Kind)
	}
	return nil
}
