package pfc2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// asMalformed roots a strict-decode rejection at ErrMalformed while keeping
// the pfwire.ErrMalformed chain, so callers match either classification.
func asMalformed(err error) error {
	if errors.Is(err, ErrMalformed) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}

// PFC2 is the FROZEN canonical byte encoding of one control record for the
// managed remote journal. The journal stores these exact bytes, hashes them,
// chains digests over them, deduplicates by them, and replays them; the bytes
// are encoded once at admission and never re-encoded across a boundary.
//
// The format is the strict deterministic protowire subset implemented by
// pfwire: ascending frozen field numbers, minimal varints, zigzag signed
// integers, bool as varint 1, defaults omitted, duplicate/unknown/misordered/
// trailing data rejected — one unique byte representation per record.
//
// ────────────────────────────────────────────────────────────────────────────
// FROZEN SCHEMA — never renumber or reuse a field or enum value.
//
//	Record:
//	  1  kind              uint (1..9, the Kind constants)
//	  2  session_open      message SessionOpen     (kind 1)
//	  3  session_renew     message SessionRenew    (kind 2)
//	  4  session_terminal  message SessionTerminal (kind 3)
//	  5  exact_outcome     message ExactOutcome    (kind 4)
//	  6  outcome_floor     message OutcomeFloor    (kind 5)
//	  7  flush_advance     message FlushAdvance    (kind 6)
//	  8  lock_change       message LockChange      (kind 7)
//	  9  checkout_change   message CheckoutChange  (kind 8)
//	 10  open_pin_change   message OpenPinChange   (kind 9)
//	  (exactly ONE of fields 2..10, and it must match kind)
//
//	SessionRef:      1 session_id  2 generation
//	ExactKey:        1 session  2 slot  3 slot_seq  4 request_hash[32]
//	Outcome:         1 status(s32)  2 count(s32)  3 offset(s64)  4 ino
//	                 5 orphan_ino   (all-zero outcome = omitted message)
//	TimeFact:        1 source  2 fact_id[16]  3 db_ms(s)
//	SessionOpen:     1 session  2 owner  3 token_hash[32]  4 slots
//	                 5 fact  6 expires_db_ms(s)
//	SessionRenew:    1 session  2 token_hash[32]  3 fact  4 expires_db_ms(s)
//	SessionTerminal: 1 session  2 reason  3 observed_deadline_db_ms(s)
//	                 4 decision_fact   (3 and 4 present exactly for expiry)
//
// Required fixed-length hash/token/digest/fact-id fields are ALWAYS emitted
// and their presence is enforced by the decoder. Absence is the MISSING FIELD
// (or the declaring op/kind), never a sentinel byte pattern — and the all-zero
// value is additionally rejected by validation even when the field is present:
// no real SHA-256 credential/fingerprint/digest and no database-minted fact
// identity is ever all-zero, so a present zero can only be fabricated or
// damaged. Optional values (Outcome, expiry facts, recall digests) are
// explicit: they exist exactly when their kind/op declares them.
//	ExactOutcome:    1 key  2 outcome
//	OutcomeFloor:    1 session  2 slot  3 through
//	FlushAdvance:    1 session  2 writeback_id  3 checkout_path
//	                 4 checkout_epoch  5 through  6 digest[32]
//	                 7 lane (absent = legacy single stream)
//	LockChange:      1 key  2 outcome  3 ino  4 lock_owner  5 op
//	                 6 start  7 length (0 = through EOF)
//	CheckoutChange:  1 key  2 outcome  3 op  4 path  5 epoch
//	                 6 recalled_digest[32] (force transfer only)
//	OpenPinChange:   1 session  2 ino  3 unpin(b)
//
// Every encoded record begins with the 4-byte magic "PFC2" (part of the
// canonical bytes: request hashes and record digests cover it).
// ────────────────────────────────────────────────────────────────────────────

// Encode encodes r into its unique canonical PFC2 byte string, enforcing
// every frozen structural bound. The returned slice is freshly allocated; the
// caller owns it and must treat it as immutable from then on (single-encode
// rule: these exact bytes are the record everywhere downstream).
func Encode(r *Record) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	body, err := appendRecord(nil, r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+4)
	out = append(out, Magic[:]...)
	out = append(out, body...)
	if len(out) > MaxRecordBytes {
		return nil, malformedf("record is %d bytes (max %d)", len(out), MaxRecordBytes)
	}
	return out, nil
}

// Decode strictly decodes one canonical record. Any deviation from the unique
// canonical encoding — unknown/duplicate/misordered fields, non-minimal
// varints, explicit defaults, bad UTF-8, bound violations, trailing bytes —
// is rejected (pfwire.ErrMalformed in the chain).
func Decode(payload []byte) (Record, error) {
	if len(payload) > MaxRecordBytes {
		return Record{}, malformedf("record is %d bytes (max %d)", len(payload), MaxRecordBytes)
	}
	if len(payload) < 4 || !bytes.Equal(payload[:4], Magic[:]) {
		return Record{}, malformedf("record does not begin with the PFC2 magic")
	}
	r, err := decodeRecord(payload[4:])
	if err != nil {
		return Record{}, asMalformed(err)
	}
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// Digest is the canonical digest of one encoded record: SHA-256 over the
// exact complete bytes, including the magic.
func Digest(encoded []byte) [DigestBytes]byte { return sha256.Sum256(encoded) }

// Request fingerprints. The canonical request hash of a PFC2 coordination
// operation is SHA-256 over "PFC2" || kind byte || the strict pfwire encoding
// of the request's semantic fields (below). Grant and force transfer share
// the acquire class: they are two outcomes of one contender request, so a
// duplicate retry replays whichever outcome was durably recorded.
//
//	lock request:              1 op  2 ino  3 lock_owner  4 start  5 length
//	checkout acquire request:  1 class(=1)  2 path
//	checkout release request:  1 class(=2)  2 path  3 epoch
const (
	checkoutClassAcquire = 1
	checkoutClassRelease = 2
)

func requestHash(kind Kind, body []byte) [RequestHashBytes]byte {
	h := sha256.New()
	h.Write(Magic[:])
	h.Write([]byte{byte(kind)})
	h.Write(body)
	var out [RequestHashBytes]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RequestHash returns the canonical fingerprint of l's semantic lock request.
// Valid LockChange records carry exactly this hash in their exact key.
func (l *LockChange) RequestHash() [RequestHashBytes]byte {
	var body []byte
	body = pfwire.AppendUint(body, 1, uint64(l.Op))
	body = pfwire.AppendUint(body, 2, l.Ino)
	body = pfwire.AppendUint(body, 3, l.KernelLockOwner)
	body = pfwire.AppendUint(body, 4, l.Start)
	body = pfwire.AppendUint(body, 5, l.Length)
	return requestHash(KindLockChange, body)
}

// RequestHash returns the canonical fingerprint of c's semantic checkout
// request (keyed ops only). Valid keyed CheckoutChange records carry exactly
// this hash in their exact key. A delegation acquire folds the stream's
// writeback id in (field 4, emitted only when present, so plain checkout
// fingerprints are unchanged).
func (c *CheckoutChange) RequestHash() [RequestHashBytes]byte {
	var body []byte
	if c.Op == CheckoutRelease {
		body = pfwire.AppendUint(body, 1, checkoutClassRelease)
		body = pfwire.AppendString(body, 2, c.Path)
		body = pfwire.AppendString(body, 3, string(c.Epoch))
	} else {
		body = pfwire.AppendUint(body, 1, checkoutClassAcquire)
		body = pfwire.AppendString(body, 2, c.Path)
		if c.WritebackID != "" {
			body = pfwire.AppendString(body, 4, c.WritebackID)
		}
	}
	return requestHash(KindCheckoutChange, body)
}

// ─── encoders ───────────────────────────────────────────────────────────────
// All values were already validated by Record.Validate; encoders only
// translate them into canonical bytes.

func appendSessionRef(dst []byte, s SessionRef) []byte {
	dst = pfwire.AppendString(dst, 1, s.SessionID)
	dst = pfwire.AppendUint(dst, 2, s.Generation)
	return dst
}

func appendExactKey(dst []byte, k *ExactKey) []byte {
	dst = pfwire.AppendBytes(dst, 1, appendSessionRef(nil, k.Session))
	dst = pfwire.AppendUint(dst, 2, uint64(k.Slot))
	dst = pfwire.AppendUint(dst, 3, k.SlotSeq)
	dst = pfwire.AppendBytes(dst, 4, k.RequestHash[:])
	return dst
}

func appendOutcome(dst []byte, o Outcome) []byte {
	dst = pfwire.AppendSint(dst, 1, int64(o.Status))
	dst = pfwire.AppendSint(dst, 2, int64(o.Count))
	dst = pfwire.AppendSint(dst, 3, o.Offset)
	dst = pfwire.AppendUint(dst, 4, o.Ino)
	dst = pfwire.AppendUint(dst, 5, o.OrphanIno)
	return dst
}

func appendTimeFact(dst []byte, f TimeFact) []byte {
	dst = pfwire.AppendUint(dst, 1, uint64(f.Source))
	dst = pfwire.AppendBytes(dst, 2, f.FactID[:])
	dst = pfwire.AppendSint(dst, 3, f.DbMs)
	return dst
}

func appendRecord(dst []byte, r *Record) ([]byte, error) {
	dst = pfwire.AppendUint(dst, 1, uint64(r.Kind))
	switch r.Kind {
	case KindSessionOpen:
		s := r.SessionOpen
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendSessionRef(nil, s.Session))
		b = pfwire.AppendString(b, 2, s.Owner)
		b = pfwire.AppendBytes(b, 3, s.TokenHash[:])
		b = pfwire.AppendUint(b, 4, uint64(s.Slots))
		b = pfwire.AppendBytes(b, 5, appendTimeFact(nil, s.Fact))
		b = pfwire.AppendSint(b, 6, s.ExpiresDbMs)
		dst = pfwire.AppendBytes(dst, 2, b)
	case KindSessionRenew:
		s := r.SessionRenew
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendSessionRef(nil, s.Session))
		b = pfwire.AppendBytes(b, 2, s.TokenHash[:])
		b = pfwire.AppendBytes(b, 3, appendTimeFact(nil, s.Fact))
		b = pfwire.AppendSint(b, 4, s.ExpiresDbMs)
		dst = pfwire.AppendBytes(dst, 3, b)
	case KindSessionTerminal:
		s := r.SessionTerminal
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendSessionRef(nil, s.Session))
		b = pfwire.AppendUint(b, 2, uint64(s.Reason))
		b = pfwire.AppendSint(b, 3, s.ObservedDeadlineDbMs)
		if s.Reason == TerminalExpire {
			b = pfwire.AppendBytes(b, 4, appendTimeFact(nil, s.DecisionFact))
		}
		dst = pfwire.AppendBytes(dst, 4, b)
	case KindExactOutcome:
		o := r.ExactOutcome
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendExactKey(nil, &o.Key))
		b = pfwire.AppendBytes(b, 2, appendOutcome(nil, o.Outcome))
		dst = pfwire.AppendBytes(dst, 5, b)
	case KindOutcomeFloor:
		f := r.OutcomeFloor
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendSessionRef(nil, f.Session))
		b = pfwire.AppendUint(b, 2, uint64(f.Slot))
		b = pfwire.AppendUint(b, 3, f.Through)
		dst = pfwire.AppendBytes(dst, 6, b)
	case KindFlushAdvance:
		f := r.FlushAdvance
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendSessionRef(nil, f.Session))
		b = pfwire.AppendString(b, 2, f.WritebackID)
		b = pfwire.AppendString(b, 3, f.CheckoutPath)
		b = pfwire.AppendString(b, 4, string(f.CheckoutEpoch))
		b = pfwire.AppendUint(b, 5, f.Through)
		b = pfwire.AppendBytes(b, 6, f.Digest[:])
		// The legacy lane is field-absent, not field-zero: a pre-round-7
		// journal row and a round-7 row for the same single-stream advance
		// encode to the SAME bytes, so no durable record changes shape at the
		// upgrade and the journal's canonical encoding stays stable.
		if f.Lane != StreamLaneLegacy {
			b = pfwire.AppendUint(b, 7, uint64(f.Lane))
		}
		dst = pfwire.AppendBytes(dst, 7, b)
	case KindLockChange:
		l := r.LockChange
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendExactKey(nil, &l.Key))
		b = pfwire.AppendBytes(b, 2, appendOutcome(nil, l.Outcome))
		b = pfwire.AppendUint(b, 3, l.Ino)
		b = pfwire.AppendUint(b, 4, l.KernelLockOwner)
		b = pfwire.AppendUint(b, 5, uint64(l.Op))
		b = pfwire.AppendUint(b, 6, l.Start)
		b = pfwire.AppendUint(b, 7, l.Length)
		dst = pfwire.AppendBytes(dst, 8, b)
	case KindCheckoutChange:
		c := r.CheckoutChange
		var b []byte
		if c.Op.keyed() {
			b = pfwire.AppendBytes(b, 1, appendExactKey(nil, &c.Key))
		}
		b = pfwire.AppendBytes(b, 2, appendOutcome(nil, c.Outcome))
		b = pfwire.AppendUint(b, 3, uint64(c.Op))
		b = pfwire.AppendString(b, 4, c.Path)
		b = pfwire.AppendString(b, 5, string(c.Epoch))
		if c.Op == CheckoutForceTransfer {
			b = pfwire.AppendBytes(b, 6, c.RecalledDigest[:])
		}
		if c.WritebackID != "" {
			b = pfwire.AppendString(b, 7, c.WritebackID)
		}
		if c.Op == CheckoutRebind {
			b = pfwire.AppendBytes(b, 8, appendSessionRef(nil, c.NewHolder))
		}
		dst = pfwire.AppendBytes(dst, 9, b)
	case KindOpenPinChange:
		p := r.OpenPinChange
		var b []byte
		b = pfwire.AppendBytes(b, 1, appendSessionRef(nil, p.Session))
		b = pfwire.AppendUint(b, 2, p.Ino)
		b = pfwire.AppendBool(b, 3, p.Unpin)
		dst = pfwire.AppendBytes(dst, 10, b)
	default:
		return nil, malformedf("cannot encode unknown kind %d", r.Kind)
	}
	return dst, nil
}

// ─── strict decoders ────────────────────────────────────────────────────────

// fixed32 copies a decoded hash/digest field, requiring exactly 32 bytes.
func fixed32(rd *pfwire.Reader, field uint32, out *[32]byte) error {
	b, err := rd.Bytes(field, 32)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return rd.Malformedf("field %d is %d bytes (want exactly 32)", field, len(b))
	}
	copy(out[:], b)
	return nil
}

// fixed16 copies a decoded fact-id field, requiring exactly 16 bytes.
func fixed16(rd *pfwire.Reader, field uint32, out *[16]byte) error {
	b, err := rd.Bytes(field, 16)
	if err != nil {
		return err
	}
	if len(b) != 16 {
		return rd.Malformedf("field %d is %d bytes (want exactly 16)", field, len(b))
	}
	copy(out[:], b)
	return nil
}

func decodeTimeFact(what string, body []byte) (TimeFact, error) {
	rd := pfwire.NewReader(what, body)
	var f TimeFact
	idSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return TimeFact{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return TimeFact{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return TimeFact{}, err
			}
			if v > uint64(TimeSourceDB) {
				return TimeFact{}, rd.Malformedf("unknown time source %d", v)
			}
			f.Source = TimeSource(v)
		case field == 2 && wt == pfwire.TypeBytes:
			if err := fixed16(rd, field, &f.FactID); err != nil {
				return TimeFact{}, err
			}
			idSeen = true
		case field == 3 && wt == pfwire.TypeVarint:
			if f.DbMs, err = rd.Sint(field); err != nil {
				return TimeFact{}, err
			}
		default:
			return TimeFact{}, rd.RejectUnknown(field)
		}
	}
	if !idSeen {
		return TimeFact{}, rd.Malformedf("fact id is required")
	}
	return f, nil
}

func decodeSessionRef(what string, body []byte) (SessionRef, error) {
	rd := pfwire.NewReader(what, body)
	var s SessionRef
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return SessionRef{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return SessionRef{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if s.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return SessionRef{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.Generation, err = rd.Uint(field); err != nil {
				return SessionRef{}, err
			}
		default:
			return SessionRef{}, rd.RejectUnknown(field)
		}
	}
	return s, nil
}

func decodeExactKey(what string, body []byte) (ExactKey, error) {
	rd := pfwire.NewReader(what, body)
	var k ExactKey
	hashSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ExactKey{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ExactKey{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return ExactKey{}, err
			}
			if k.Session, err = decodeSessionRef(what+" session", msg); err != nil {
				return ExactKey{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if k.Slot, err = rd.Uint32(field); err != nil {
				return ExactKey{}, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if k.SlotSeq, err = rd.Uint(field); err != nil {
				return ExactKey{}, err
			}
		case field == 4 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &k.RequestHash); err != nil {
				return ExactKey{}, err
			}
			hashSeen = true
		default:
			return ExactKey{}, rd.RejectUnknown(field)
		}
	}
	if !hashSeen {
		return ExactKey{}, rd.Malformedf("request hash is required")
	}
	return k, nil
}

func decodeOutcome(what string, body []byte) (Outcome, error) {
	rd := pfwire.NewReader(what, body)
	var o Outcome
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return Outcome{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return Outcome{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if o.Status, err = rd.Sint32(field); err != nil {
				return Outcome{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if o.Count, err = rd.Sint32(field); err != nil {
				return Outcome{}, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if o.Offset, err = rd.Sint(field); err != nil {
				return Outcome{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if o.Ino, err = rd.Uint(field); err != nil {
				return Outcome{}, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if o.OrphanIno, err = rd.Uint(field); err != nil {
				return Outcome{}, err
			}
		default:
			return Outcome{}, rd.RejectUnknown(field)
		}
	}
	return o, nil
}

// subReader dispatches one union-arm message body decode.
func decodeRecord(body []byte) (Record, error) {
	rd := pfwire.NewReader("pfc2 record", body)
	var r Record
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return Record{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return Record{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return Record{}, err
			}
			if v > uint64(KindOpenPinChange) {
				return Record{}, rd.Malformedf("unknown kind %d", v)
			}
			r.Kind = Kind(v)
		case field >= 2 && field <= 10 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return Record{}, err
			}
			if err := decodeArm(&r, field, msg); err != nil {
				return Record{}, err
			}
		default:
			return Record{}, rd.RejectUnknown(field)
		}
	}
	// Union arm/kind congruence: Validate checks arm count and per-kind shape;
	// here we reject an arm that contradicts kind so the error names the wire
	// problem directly.
	want := map[Kind]bool{
		KindSessionOpen:     r.SessionOpen != nil,
		KindSessionRenew:    r.SessionRenew != nil,
		KindSessionTerminal: r.SessionTerminal != nil,
		KindExactOutcome:    r.ExactOutcome != nil,
		KindOutcomeFloor:    r.OutcomeFloor != nil,
		KindFlushAdvance:    r.FlushAdvance != nil,
		KindLockChange:      r.LockChange != nil,
		KindCheckoutChange:  r.CheckoutChange != nil,
		KindOpenPinChange:   r.OpenPinChange != nil,
	}
	if !want[r.Kind] {
		return Record{}, rd.Malformedf("kind %d without its union arm", r.Kind)
	}
	return r, nil
}

func decodeArm(r *Record, field uint32, msg []byte) error {
	var err error
	switch field {
	case 2:
		r.SessionOpen, err = decodeSessionOpen(msg)
	case 3:
		r.SessionRenew, err = decodeSessionRenew(msg)
	case 4:
		r.SessionTerminal, err = decodeSessionTerminal(msg)
	case 5:
		r.ExactOutcome, err = decodeExactOutcome(msg)
	case 6:
		r.OutcomeFloor, err = decodeOutcomeFloor(msg)
	case 7:
		r.FlushAdvance, err = decodeFlushAdvance(msg)
	case 8:
		r.LockChange, err = decodeLockChange(msg)
	case 9:
		r.CheckoutChange, err = decodeCheckoutChange(msg)
	case 10:
		r.OpenPinChange, err = decodeOpenPinChange(msg)
	}
	return err
}

func decodeSessionOpen(body []byte) (*SessionOpen, error) {
	rd := pfwire.NewReader("pfc2 session open", body)
	var s SessionOpen
	tokenSeen, factSeen := false, false
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if s.Session, err = decodeSessionRef("pfc2 session open session", msg); err != nil {
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
		case field == 5 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if s.Fact, err = decodeTimeFact("pfc2 session open fact", msg); err != nil {
				return nil, err
			}
			factSeen = true
		case field == 6 && wt == pfwire.TypeVarint:
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
	if !factSeen {
		return nil, rd.Malformedf("admission fact is required")
	}
	return &s, nil
}

func decodeSessionRenew(body []byte) (*SessionRenew, error) {
	rd := pfwire.NewReader("pfc2 session renew", body)
	var s SessionRenew
	tokenSeen, factSeen := false, false
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if s.Session, err = decodeSessionRef("pfc2 session renew session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &s.TokenHash); err != nil {
				return nil, err
			}
			tokenSeen = true
		case field == 3 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if s.Fact, err = decodeTimeFact("pfc2 session renew fact", msg); err != nil {
				return nil, err
			}
			factSeen = true
		case field == 4 && wt == pfwire.TypeVarint:
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
	if !factSeen {
		return nil, rd.Malformedf("admission fact is required")
	}
	return &s, nil
}

func decodeSessionTerminal(body []byte) (*SessionTerminal, error) {
	rd := pfwire.NewReader("pfc2 session terminal", body)
	var s SessionTerminal
	factSeen := false
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if s.Session, err = decodeSessionRef("pfc2 session terminal session", msg); err != nil {
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
			s.Reason = TerminalReason(v)
		case field == 3 && wt == pfwire.TypeVarint:
			if s.ObservedDeadlineDbMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if s.DecisionFact, err = decodeTimeFact("pfc2 session terminal decision fact", msg); err != nil {
				return nil, err
			}
			factSeen = true
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	// Presence congruence keeps one wire form per value: the decision fact
	// exists exactly for the expire reason.
	if (s.Reason == TerminalExpire) != factSeen {
		return nil, rd.Malformedf("decision fact presence does not match reason %d", s.Reason)
	}
	return &s, nil
}

func decodeExactOutcome(body []byte) (*ExactOutcome, error) {
	rd := pfwire.NewReader("pfc2 exact outcome", body)
	var o ExactOutcome
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if o.Key, err = decodeExactKey("pfc2 exact outcome key", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if o.Outcome, err = decodeOutcome("pfc2 exact outcome outcome", msg); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &o, nil
}

func decodeOutcomeFloor(body []byte) (*OutcomeFloor, error) {
	rd := pfwire.NewReader("pfc2 outcome floor", body)
	var f OutcomeFloor
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if f.Session, err = decodeSessionRef("pfc2 outcome floor session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if f.Slot, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if f.Through, err = rd.Uint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &f, nil
}

func decodeFlushAdvance(body []byte) (*FlushAdvance, error) {
	rd := pfwire.NewReader("pfc2 flush advance", body)
	var f FlushAdvance
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if f.Session, err = decodeSessionRef("pfc2 flush advance session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if f.WritebackID, err = rd.String(field, MaxWritebackIDBytes); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if f.CheckoutPath, err = rd.String(field, MaxPathBytes); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeBytes:
			s, err := rd.String(field, len(EpochBound))
			if err != nil {
				return nil, err
			}
			f.CheckoutEpoch = Epoch(s)
		case field == 5 && wt == pfwire.TypeVarint:
			if f.Through, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 6 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &f.Digest); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v == uint64(StreamLaneLegacy) || v >= StreamLaneCount {
				// Absent means legacy, so an EXPLICIT legacy tag is a
				// non-canonical encoding of the same record and is refused
				// like any other malformed field: the journal has exactly one
				// byte string per state, which is what the projection digest
				// is a statement about.
				return nil, malformedf("pfc2 flush advance: lane %d is not a non-legacy stream lane", v)
			}
			f.Lane = StreamLane(v)
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &f, nil
}

func decodeLockChange(body []byte) (*LockChange, error) {
	rd := pfwire.NewReader("pfc2 lock change", body)
	var l LockChange
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if l.Key, err = decodeExactKey("pfc2 lock change key", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if l.Outcome, err = decodeOutcome("pfc2 lock change outcome", msg); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if l.Ino, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if l.KernelLockOwner, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v > uint64(LockUnlock) {
				return nil, rd.Malformedf("unknown lock op %d", v)
			}
			l.Op = LockOp(v)
		case field == 6 && wt == pfwire.TypeVarint:
			if l.Start, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if l.Length, err = rd.Uint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &l, nil
}

func decodeCheckoutChange(body []byte) (*CheckoutChange, error) {
	rd := pfwire.NewReader("pfc2 checkout change", body)
	var c CheckoutChange
	digestSeen := false
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if c.Key, err = decodeExactKey("pfc2 checkout change key", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if c.Outcome, err = decodeOutcome("pfc2 checkout change outcome", msg); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v > uint64(CheckoutDiscard) {
				return nil, rd.Malformedf("unknown checkout op %d", v)
			}
			c.Op = CheckoutOp(v)
		case field == 4 && wt == pfwire.TypeBytes:
			if c.Path, err = rd.String(field, MaxPathBytes); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeBytes:
			s, err := rd.String(field, len(EpochBound))
			if err != nil {
				return nil, err
			}
			c.Epoch = Epoch(s)
		case field == 6 && wt == pfwire.TypeBytes:
			if err := fixed32(rd, field, &c.RecalledDigest); err != nil {
				return nil, err
			}
			digestSeen = true
		case field == 7 && wt == pfwire.TypeBytes:
			if c.WritebackID, err = rd.String(field, MaxWritebackIDBytes); err != nil {
				return nil, err
			}
		case field == 8 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if c.NewHolder, err = decodeSessionRef("pfc2 checkout change new holder", msg); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	// Presence congruence keeps one wire form per value: force transfer must
	// carry its digest field, other ops must omit it; keyed ops must carry
	// their exact key and rebind its explicit new holder.
	if (c.Op == CheckoutForceTransfer) != digestSeen {
		return nil, rd.Malformedf("recalled digest presence does not match op %d", c.Op)
	}
	if c.Op.keyed() != (c.Key != ExactKey{}) {
		return nil, rd.Malformedf("exact key presence does not match op %d", c.Op)
	}
	if (c.Op == CheckoutRebind) != (c.NewHolder != SessionRef{}) {
		return nil, rd.Malformedf("new holder presence does not match op %d", c.Op)
	}
	if c.WritebackID == "" && !c.Op.keyed() {
		return nil, rd.Malformedf("rebind/discard require a writeback id")
	}
	return &c, nil
}

func decodeOpenPinChange(body []byte) (*OpenPinChange, error) {
	rd := pfwire.NewReader("pfc2 open pin change", body)
	var p OpenPinChange
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
			msg, err := rd.Bytes(field, MaxRecordBytes)
			if err != nil {
				return nil, err
			}
			if p.Session, err = decodeSessionRef("pfc2 open pin change session", msg); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if p.Ino, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if p.Unpin, err = rd.Bool(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &p, nil
}
