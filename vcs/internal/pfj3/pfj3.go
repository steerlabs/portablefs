// Package pfj3 implements the PFJ3 journal-entry envelope: the frozen
// canonical byte encoding of ONE managed journal row for the PFJ3/PFC2
// generation pair (docs/pfc2-control-format.md, docs/live-filesystem-
// semantics.md).
//
// One entry is "PFJ3" || preamble || strict-pfwire-body.
//
// The PREAMBLE is a bounded, SQL-verifiable binding of the row's admission
// facts to these exact bytes. The fenced append transaction cannot run the Go
// PFC2 decoder, so the preamble restates — in a fixed big-endian layout — the
// exact outer LSN and an ordered fact manifest (control index, operation
// purpose, subject session identity and generation, fact id, database
// milliseconds) plus a SHA-256 digest over the manifest. The append
// transaction parses the preamble, verifies the digest/count/order, and
// validates + consumes exactly those issued fact rows in the same commit; the
// Go encoder derives the manifest from the decoded PFC2 controls and the
// decoder re-derives and compares it, so a manifest can never disagree with
// the controls it fronts: no fabricated embedded fact with an empty SQL list,
// and no omitted, extra, reordered, cross-session, or wrong-purpose fact.
//
//	preamble (offsets relative to the whole payload):
//	   4  outer LSN        uint64 BE
//	  12  fact count       uint16 BE (0..128)
//	  14  manifest digest  32 bytes = SHA-256("PFJ3-FACTS\x00" || be16(count) || entries)
//	  46  entries          count × entry, in control order
//	entry:
//	   control index       uint16 BE (index into the ordered control list)
//	   purpose             uint8     (1=session-open 2=session-renew 3=session-expiry-decision)
//	   session id length   uint8     (1..128)
//	   session id          bytes     (restricted alphabet, from the control)
//	   session generation  uint64 BE (nonzero)
//	   fact id             16 bytes  (never all-zero)
//	   db milliseconds     uint64 BE (int64, positive, plausible)
//
// The BODY is the strict deterministic pfwire message:
//
//	1  lsn       uint64 (must equal the preamble LSN; omitted when 0)
//	2  tree      bytes  (optional; one whole canonical PFR1 payload)
//	3  controls  repeated bytes (whole canonical PFC2 payloads, in order)
//
// The exact complete PFJ3 bytes are the database row, hash, chain, receipt,
// retry, and replay unit: they are encoded once at admission and never
// re-encoded across a boundary. An unknown-outcome retry re-sends the
// IDENTICAL bytes; a receipt replay of already-committed identical bytes is
// answered without touching fact rows. Bounds are enforced BEFORE allocation
// on decode: the whole entry is at most 8 MiB, each control at most 64 KiB,
// at most 128 controls and 128 manifest entries.
package pfj3

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Magic prefixes every canonical PFJ3 entry. It is part of the canonical
// bytes: hashes, chains, and receipts cover it.
var Magic = [4]byte{'P', 'F', 'J', '3'}

// factDigestDomain seeds the manifest digest so it can never collide with a
// record or chain digest computed over other bytes.
var factDigestDomain = []byte("PFJ3-FACTS\x00")

// RecordCodec names this entry codec in journal generation metadata. A PFJ3
// generation always pairs with the PFC2 control codec; no generation ever
// mixes codec pairs.
const RecordCodec = "pfj3"

// ControlCodec is the only control codec a PFJ3 generation admits.
const ControlCodec = pfc2.Codec

const (
	// MaxEntryBytes bounds one whole encoded entry including the magic.
	MaxEntryBytes = 8 << 20
	// MaxControls bounds the ordered control list of one entry.
	MaxControls = 128
	// MaxControlBytes bounds one embedded canonical PFC2 record.
	MaxControlBytes = pfc2.MaxRecordBytes
	// MaxFacts bounds one entry's fact manifest. Appends additionally bound
	// the TOTAL fact count of one commit group to the same number.
	MaxFacts = 128

	// preambleFixedBytes is the fixed region after the magic: LSN (8) +
	// fact count (2) + manifest digest (32).
	preambleFixedBytes = 42
	// factEntryFixedBytes is one manifest entry minus its variable session
	// id: index (2) + purpose (1) + id length (1) + generation (8) +
	// fact id (16) + db ms (8).
	factEntryFixedBytes = 36
)

// FactPurpose is the frozen manifest purpose byte (shared with the issuance
// scope): WHY a fact was minted. The issuing SQL records the purpose and the
// append transaction rejects a consume under any other purpose.
type FactPurpose = pfc2.FactPurpose

const (
	FactPurposeSessionOpen   = pfc2.FactPurposeSessionOpen
	FactPurposeSessionRenew  = pfc2.FactPurposeSessionRenew
	FactPurposeSessionExpiry = pfc2.FactPurposeSessionExpiry
)

// FactRef is one manifest entry: the exact issued fact a control freezes,
// bound to its control index, purpose, and subject session.
type FactRef struct {
	ControlIndex uint16
	Purpose      FactPurpose
	Session      pfc2.SessionRef
	FactID       [pfc2.FactIDBytes]byte
	DbMs         int64
}

// ErrMalformed is the classification root for every strict-decode rejection.
var ErrMalformed = errors.New("pfj3: malformed journal entry")

func malformedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func asMalformed(err error) error {
	if err == nil || errors.Is(err, ErrMalformed) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}

// JournalEntry is the uniform decoded unit of one journal row.
type JournalEntry struct {
	// LSN is the exact outer journal sequence of this row.
	LSN uint64
	// Tree is the optional single canonical PFR1 tree intent. Its Seq equals
	// LSN, it is never OpControl, and (when OpBatch) contains no OpControl
	// leaves.
	Tree *wal.Record
	// Controls are the ordered PFC2 control records of this row, applied
	// after the tree intent in the SAME atomic transaction.
	Controls []pfc2.Record
}

// FromLegacyRecord adapts one legacy log record (PFR1 or file-WAL) onto the
// uniform shape: exactly one tree record, no PFJ3 controls. Legacy OpControl
// records (PFC1 payloads inside PFR1) remain tree records here — their
// decoding belongs to the legacy control codec, not to PFC2.
func FromLegacyRecord(r wal.Record) JournalEntry {
	return JournalEntry{LSN: r.Seq, Tree: &r}
}

// treeRecordAllowed rejects PFR1 OpControl anywhere in the tree arm: PFJ3
// carries control state natively as PFC2 records, so a smuggled legacy
// control payload would create a second, unaccountable control channel.
func treeRecordAllowed(r *wal.Record) error {
	if r.Op.IsControl() {
		return malformedf("tree intent must not be PFR1 OpControl (controls ride natively as PFC2 records)")
	}
	for i := range r.Mutations {
		if r.Mutations[i].Op.IsControl() {
			return malformedf("tree batch leaf %d must not be PFR1 OpControl", i)
		}
	}
	return nil
}

// FactManifest derives the ordered fact manifest of e's controls: for every
// control, in order, each database fact its record froze — with the purpose
// implied by the record kind and the subject session named by the record.
// This is the ONLY derivation; the preamble must match it byte for byte.
func (e *JournalEntry) FactManifest() ([]FactRef, error) {
	var out []FactRef
	for i := range e.Controls {
		if i > int(^uint16(0)) {
			return nil, malformedf("control index %d exceeds the manifest index domain", i)
		}
		refs, err := controlFactRefs(uint16(i), &e.Controls[i])
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	if len(out) > MaxFacts {
		return nil, malformedf("entry carries %d facts (max %d)", len(out), MaxFacts)
	}
	return out, nil
}

func controlFactRefs(index uint16, rec *pfc2.Record) ([]FactRef, error) {
	switch rec.Kind {
	case pfc2.KindSessionOpen:
		return []FactRef{{
			ControlIndex: index, Purpose: FactPurposeSessionOpen,
			Session: rec.SessionOpen.Session,
			FactID:  rec.SessionOpen.Fact.FactID, DbMs: rec.SessionOpen.Fact.DbMs,
		}}, nil
	case pfc2.KindSessionRenew:
		return []FactRef{{
			ControlIndex: index, Purpose: FactPurposeSessionRenew,
			Session: rec.SessionRenew.Session,
			FactID:  rec.SessionRenew.Fact.FactID, DbMs: rec.SessionRenew.Fact.DbMs,
		}}, nil
	case pfc2.KindSessionTerminal:
		if rec.SessionTerminal.Reason == pfc2.TerminalExpire {
			return []FactRef{{
				ControlIndex: index, Purpose: FactPurposeSessionExpiry,
				Session: rec.SessionTerminal.Session,
				FactID:  rec.SessionTerminal.DecisionFact.FactID, DbMs: rec.SessionTerminal.DecisionFact.DbMs,
			}}, nil
		}
	}
	return nil, nil
}

// appendFactEntry appends one manifest entry in the frozen layout.
func appendFactEntry(dst []byte, ref FactRef) ([]byte, error) {
	id := ref.Session.SessionID
	if len(id) == 0 || len(id) > pfc2.MaxSessionIDBytes {
		return nil, malformedf("manifest session id length %d is outside [1,%d]", len(id), pfc2.MaxSessionIDBytes)
	}
	if !ref.Purpose.Valid() {
		return nil, malformedf("manifest purpose %d is unknown", ref.Purpose)
	}
	if ref.Session.Generation == 0 {
		return nil, malformedf("manifest session generation must be nonzero")
	}
	if ref.FactID == ([pfc2.FactIDBytes]byte{}) {
		return nil, malformedf("manifest fact id is all-zero; a database-minted identity is never zero")
	}
	if ref.DbMs <= 0 || ref.DbMs > pfc2.MaxDbTimeMs {
		return nil, malformedf("manifest database time %d is implausible", ref.DbMs)
	}
	var u16 [2]byte
	var u64 [8]byte
	binary.BigEndian.PutUint16(u16[:], ref.ControlIndex)
	dst = append(dst, u16[:]...)
	dst = append(dst, byte(ref.Purpose), byte(len(id)))
	dst = append(dst, id...)
	binary.BigEndian.PutUint64(u64[:], ref.Session.Generation)
	dst = append(dst, u64[:]...)
	dst = append(dst, ref.FactID[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(ref.DbMs))
	dst = append(dst, u64[:]...)
	return dst, nil
}

// manifestDigest computes SHA-256("PFJ3-FACTS\x00" || be16(count) || entries).
func manifestDigest(count int, entries []byte) [32]byte {
	h := sha256.New()
	h.Write(factDigestDomain)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(count))
	h.Write(u16[:])
	h.Write(entries)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Validate enforces every structural rule that does not require the encoded
// byte lengths (Encode/Decode additionally enforce byte bounds).
func (e *JournalEntry) Validate() error {
	if e.Tree == nil && len(e.Controls) == 0 {
		return malformedf("entry carries neither a tree intent nor controls")
	}
	if len(e.Controls) > MaxControls {
		return malformedf("entry carries %d controls (max %d)", len(e.Controls), MaxControls)
	}
	if e.Tree != nil {
		if e.Tree.Seq != e.LSN {
			return malformedf("tree intent Seq %d does not equal the outer LSN %d", e.Tree.Seq, e.LSN)
		}
		if err := treeRecordAllowed(e.Tree); err != nil {
			return err
		}
	}
	for i := range e.Controls {
		if err := e.Controls[i].Validate(); err != nil {
			return fmt.Errorf("%w: control %d: %w", ErrMalformed, i, err)
		}
	}
	if _, err := e.FactManifest(); err != nil {
		return err
	}
	return nil
}

// Encode encodes e into its unique canonical PFJ3 byte string. The returned
// slice is freshly allocated; callers own it and treat it as immutable (the
// single-encode rule: these exact bytes are the row everywhere downstream).
func Encode(e *JournalEntry) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	manifest, err := e.FactManifest()
	if err != nil {
		return nil, err
	}
	var entries []byte
	for _, ref := range manifest {
		if entries, err = appendFactEntry(entries, ref); err != nil {
			return nil, err
		}
	}
	digest := manifestDigest(len(manifest), entries)

	var body []byte
	body = pfwire.AppendUint(body, 1, e.LSN)
	if e.Tree != nil {
		tree, err := wal.EncodePFR1(e.Tree)
		if err != nil {
			return nil, asMalformed(err)
		}
		body = pfwire.AppendBytes(body, 2, tree)
	}
	for i := range e.Controls {
		control, err := pfc2.Encode(&e.Controls[i])
		if err != nil {
			return nil, fmt.Errorf("%w: control %d: %w", ErrMalformed, i, err)
		}
		if len(control) > MaxControlBytes {
			return nil, malformedf("control %d is %d bytes (max %d)", i, len(control), MaxControlBytes)
		}
		body = pfwire.AppendBytes(body, 3, control)
	}

	out := make([]byte, 0, 4+preambleFixedBytes+len(entries)+len(body))
	out = append(out, Magic[:]...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], e.LSN)
	out = append(out, u64[:]...)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(manifest)))
	out = append(out, u16[:]...)
	out = append(out, digest[:]...)
	out = append(out, entries...)
	out = append(out, body...)
	if len(out) > MaxEntryBytes {
		return nil, malformedf("entry is %d bytes (max %d)", len(out), MaxEntryBytes)
	}
	return out, nil
}

// Decode strictly decodes one canonical entry. Any deviation — unknown,
// duplicate, misordered, or trailing fields, non-minimal varints, size-bound
// violations (checked before allocation), non-canonical embedded PFR1/PFC2
// bytes, preamble/body LSN mismatch, manifest count/order/digest/content
// disagreement with the decoded controls, smuggled OpControl, empty arms —
// is rejected with ErrMalformed in the chain.
func Decode(payload []byte) (JournalEntry, error) {
	entry, err := decode(payload)
	if err != nil {
		return JournalEntry{}, asMalformed(err)
	}
	return entry, nil
}

// parsedPreamble is the decoded fixed preamble plus the raw entry region.
type parsedPreamble struct {
	lsn        uint64
	count      int
	digest     [32]byte
	entryBytes []byte
	refs       []FactRef
	bodyOffset int
}

// parsePreamble parses and verifies the fixed preamble region (bounds before
// allocation; the digest is verified over the exact entry bytes).
func parsePreamble(payload []byte) (parsedPreamble, error) {
	if len(payload) < 4+preambleFixedBytes {
		return parsedPreamble{}, malformedf("entry is truncated before the preamble")
	}
	var p parsedPreamble
	p.lsn = binary.BigEndian.Uint64(payload[4:12])
	p.count = int(binary.BigEndian.Uint16(payload[12:14]))
	copy(p.digest[:], payload[14:46])
	if p.count > MaxFacts {
		return parsedPreamble{}, malformedf("preamble declares %d facts (max %d)", p.count, MaxFacts)
	}
	off := 4 + preambleFixedBytes
	p.refs = make([]FactRef, 0, p.count)
	for i := 0; i < p.count; i++ {
		if len(payload) < off+4 {
			return parsedPreamble{}, malformedf("manifest entry %d is truncated", i)
		}
		idLen := int(payload[off+3])
		if idLen < 1 || idLen > pfc2.MaxSessionIDBytes {
			return parsedPreamble{}, malformedf("manifest entry %d session id length %d is outside [1,%d]", i, idLen, pfc2.MaxSessionIDBytes)
		}
		total := factEntryFixedBytes + idLen
		if len(payload) < off+total {
			return parsedPreamble{}, malformedf("manifest entry %d is truncated", i)
		}
		ref := FactRef{
			ControlIndex: binary.BigEndian.Uint16(payload[off : off+2]),
			Purpose:      FactPurpose(payload[off+2]),
			Session: pfc2.SessionRef{
				SessionID:  string(payload[off+4 : off+4+idLen]),
				Generation: binary.BigEndian.Uint64(payload[off+4+idLen : off+12+idLen]),
			},
		}
		copy(ref.FactID[:], payload[off+12+idLen:off+28+idLen])
		dbMs := binary.BigEndian.Uint64(payload[off+28+idLen : off+36+idLen])
		if dbMs > uint64(pfc2.MaxDbTimeMs) {
			return parsedPreamble{}, malformedf("manifest entry %d database time is implausible", i)
		}
		ref.DbMs = int64(dbMs)
		if !ref.Purpose.Valid() {
			return parsedPreamble{}, malformedf("manifest entry %d purpose %d is unknown", i, ref.Purpose)
		}
		if ref.FactID == ([pfc2.FactIDBytes]byte{}) {
			return parsedPreamble{}, malformedf("manifest entry %d fact id is all-zero", i)
		}
		p.refs = append(p.refs, ref)
		off += total
	}
	p.entryBytes = payload[4+preambleFixedBytes : off]
	p.bodyOffset = off
	if manifestDigest(p.count, p.entryBytes) != p.digest {
		return parsedPreamble{}, malformedf("manifest digest does not cover the manifest entries")
	}
	return p, nil
}

func decode(payload []byte) (JournalEntry, error) {
	if len(payload) > MaxEntryBytes {
		return JournalEntry{}, malformedf("entry is %d bytes (max %d)", len(payload), MaxEntryBytes)
	}
	if len(payload) < 4 || !bytes.Equal(payload[:4], Magic[:]) {
		return JournalEntry{}, malformedf("entry does not begin with the PFJ3 magic")
	}
	pre, err := parsePreamble(payload)
	if err != nil {
		return JournalEntry{}, err
	}
	rd := pfwire.NewReader("pfj3 entry", payload[pre.bodyOffset:])
	var e JournalEntry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return JournalEntry{}, err
		}
		if !ok {
			break
		}
		if field == 3 {
			if err := rd.RequireRepeated(field); err != nil {
				return JournalEntry{}, err
			}
		} else if err := rd.Require(field); err != nil {
			return JournalEntry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if e.LSN, err = rd.Uint(field); err != nil {
				return JournalEntry{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			raw, err := rd.Bytes(field, wal.MaxPFR1RecordBytes)
			if err != nil {
				return JournalEntry{}, err
			}
			tree, err := wal.DecodePFR1(raw)
			if err != nil {
				return JournalEntry{}, err
			}
			// Canonicality of the embedded payload: the strict PFR1 decoder
			// plus one re-encode guarantees the stored bytes are the unique
			// encoding, so chain digests recompute identically forever.
			re, err := wal.EncodePFR1(&tree)
			if err != nil || !bytes.Equal(re, raw) {
				return JournalEntry{}, malformedf("embedded tree intent is not canonical PFR1")
			}
			e.Tree = &tree
		case field == 3 && wt == pfwire.TypeBytes:
			if len(e.Controls) >= MaxControls {
				return JournalEntry{}, malformedf("more than %d controls", MaxControls)
			}
			raw, err := rd.Bytes(field, MaxControlBytes)
			if err != nil {
				return JournalEntry{}, err
			}
			control, err := pfc2.Decode(raw)
			if err != nil {
				return JournalEntry{}, err
			}
			e.Controls = append(e.Controls, control)
		default:
			return JournalEntry{}, rd.RejectUnknown(field)
		}
	}
	if e.LSN != pre.lsn {
		return JournalEntry{}, malformedf("body LSN %d does not equal the preamble LSN %d", e.LSN, pre.lsn)
	}
	if err := e.Validate(); err != nil {
		return JournalEntry{}, err
	}
	// Manifest congruence: the preamble's fact list must be EXACTLY the list
	// the decoded controls imply — same count, order, control indexes,
	// purposes, sessions, fact ids, and database times.
	derived, err := e.FactManifest()
	if err != nil {
		return JournalEntry{}, err
	}
	if len(derived) != len(pre.refs) {
		return JournalEntry{}, malformedf("preamble declares %d facts; controls imply %d", len(pre.refs), len(derived))
	}
	for i := range derived {
		if derived[i] != pre.refs[i] {
			return JournalEntry{}, malformedf("manifest entry %d does not match the decoded controls", i)
		}
	}
	return e, nil
}

// Digest is the canonical digest of one encoded entry: SHA-256 over the exact
// complete bytes, including the magic. The journal chain digest is computed
// by the shared wal.ChainDigestBytes over the same exact bytes.
func Digest(encoded []byte) [32]byte { return sha256.Sum256(encoded) }
