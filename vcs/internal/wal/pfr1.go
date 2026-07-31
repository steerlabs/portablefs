package wal

import (
	"bytes"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// PFR1 is the FROZEN canonical byte encoding of one wal.Record for the managed
// remote journal. The remote journal stores these exact bytes, hashes them,
// chains digests over them, deduplicates by them, and replays them; the bytes
// are encoded once at admission and never re-encoded across a boundary.
//
// The format is a strict deterministic protowire subset (see pfwire): fields
// in ascending frozen field-number order, minimal varints, zigzag signed
// integers, bool as varint 1, defaults omitted, duplicate/unknown/trailing
// data rejected, one unique byte representation per record.
//
// ────────────────────────────────────────────────────────────────────────────
// FROZEN SCHEMA — never renumber or reuse a field. New fields append new
// numbers; removed fields retire their number forever.
//
//	Record:
//	  1  seq                          uint64   (varint)
//	  2  op                           uint64   (varint; known Op values only)
//	  3  path                         string   (≤ MaxPFR1PathBytes)
//	  4  new_path                     string   (≤ MaxPFR1PathBytes)
//	  5  offset                       sint64   (zigzag)
//	  6  size                         sint64   (zigzag)
//	  7  mode                         uint32   (varint)
//	  8  target                       string   (≤ MaxPFR1PathBytes)
//	  9  data                         bytes    (≤ MaxPFR1DataBytes)
//	 10  mtime_ms                     sint64
//	 11  atime_ms                     sint64
//	 12  chtimes_set_atime            bool
//	 13  uid                          uint32
//	 14  gid                          uint32
//	 15  ino                          uint64
//	 16  inos                         packed repeated uint64 (≤ MaxPFR1Inos; ascending? NO — component
//	                                  order is positional, values are arbitrary; zero values forbidden)
//	 17  orphan_target                bool
//	 18  ts_ms                        sint64
//	 19  chown_set_uid                bool
//	 20  chown_set_gid                bool
//	 21  append                       bool
//	 22  reap_if_lease_expires_by_ms  sint64
//	 23  env                          message Envelope
//	 24  mutations                    repeated message Record (OpBatch only;
//	                                  ≤ MaxPFR1BatchMutations; nesting depth 1 —
//	                                  a nested record must NOT be OpBatch and
//	                                  must NOT carry mutations)
//	 25  excl                         bool (OpCreate/OpMkdir/OpSymlink only:
//	                                  requireAbsent — apply fails EEXIST when the
//	                                  final component already exists; OpMkdir excl
//	                                  additionally creates EXACTLY one component
//	                                  under an existing parent, leaf identity in
//	                                  field 15 ino, field 16 inos must be absent)
//	 26  rename_no_replace            bool (OpRename only: RENAME_NOREPLACE —
//	                                  apply fails EEXIST when NewPath exists at
//	                                  the record's ordered apply position)
//	 27  xattr_name                   string (OpSetxattr/OpRemovexattr only:
//	                                  1..MaxXattrNameBytes bytes; the set VALUE
//	                                  rides field 9 data, bounded by
//	                                  MaxXattrValueBytes AT ENCODE — below the
//	                                  general data ceiling; OpRemovexattr must
//	                                  carry no data)
//	 28  xattr_flags                  uint8 (OpSetxattr only: XattrCreate or
//	                                  XattrReplace; mutually exclusive)
//	 29  chtimes_keep_mtime           bool (OpChtimes only: update atime while
//	                                  preserving the mtime at ordered apply)
//	 30  flags                        uint32 (OpChflags only: the ABSOLUTE new
//	                                  BSD file-flag word — Darwin st_flags —
//	                                  stored unmasked, exactly as the client
//	                                  sent it. 0 is a legal OpChflags value
//	                                  meaning "clear every flag"; the encoding
//	                                  omits it like any other default, and the
//	                                  op itself is what makes the record a
//	                                  chflags. Every other op must carry 0.)
//
//	Envelope:
//	  1  session_id  string (1..MaxPFR1SessionIDBytes)
//	  2  generation  uint64
//	  3  slot        uint32
//	  4  slot_seq    uint64
//	  5  req_hash    bytes (exactly 32)
//
// Frozen Op enum values (wire = the Go constants; frozen here for the record):
// Create=1 Write=2 Truncate=3 Mkdir=4 Remove=5 Rename=6 Symlink=7 Chmod=8
// Chtimes=9 Chown=10 Orphan=11 Reap=12 Control=13 Batch=14 Link=15
// Setxattr=16 Removexattr=17 JournalEntry=18 (NOT a record op — see
// pfr1OpValid) Chflags=19.
// OpChflags addresses its inode by field 15 ino (else field 3 path) and
// carries the absolute new flag word in field 30; a decoder older than the op
// rejects it (unknown op — the sanctioned fencing for appended ops).
// OpLink reuses fields Path (existing source name) and NewPath (new link);
// Ino carries the source inode identity for deterministic replay.
// OpSetxattr/OpRemovexattr address their inode by field 15 ino (else field 3
// path), name the attribute in field 27, and OpSetxattr carries the raw value
// in field 9 data; a decoder older than these ops rejects them (unknown op —
// the sanctioned fencing for appended ops).
//
// Every encoded record begins with the 4-byte magic "PFR1"; the magic is part
// of the canonical payload (hashes and chains cover it).
// ────────────────────────────────────────────────────────────────────────────

// PFR1Magic prefixes every canonical record payload.
var PFR1Magic = [4]byte{'P', 'F', 'R', '1'}

// PFR1Codec names this record codec in journal generation metadata.
const PFR1Codec = "pfr1"

// GobRecordCodec names the legacy gob record framing used by the local file
// WAL. It exists only as a generation label; the remote journal never accepts
// it for new epochs and no epoch may mix codecs.
const GobRecordCodec = "gob"

// Final production bounds (requirement: enforced before allocation/admission).
const (
	// MaxPFR1RecordBytes bounds one whole encoded record — one logical intent
	// (a single mutation or a whole OpBatch), including magic and framing.
	MaxPFR1RecordBytes = 8 << 20
	// MaxPFR1DataBytes bounds one record's Data field. A single user WRITE is
	// admitted at 1 MiB (MaxPFR1WriteDataBytes) by the journal admission path;
	// the codec ceiling is the record bound so control payloads (PFC1, bounded
	// by ctlrec) and batch leaves share the same frozen wire schema.
	MaxPFR1DataBytes = MaxPFR1RecordBytes - 64
	// MaxPFR1WriteDataBytes bounds ONE user write payload (OpWrite Data).
	MaxPFR1WriteDataBytes = 1 << 20
	// MaxPFR1PathBytes bounds Path/NewPath/Target (PATH_MAX-shaped).
	MaxPFR1PathBytes = 4096
	// MaxPFR1BatchMutations bounds OpBatch leaves (matches workfs admission).
	MaxPFR1BatchMutations = 4096
	// MaxPFR1Inos bounds the OpMkdir per-component ino reservation list.
	MaxPFR1Inos = 4096
	// MaxPFR1SessionIDBytes bounds Envelope.SessionID (matches ctlrec).
	MaxPFR1SessionIDBytes = 128
	// PFR1ReqHashBytes is the exact Envelope.ReqHash length.
	PFR1ReqHashBytes = 32
	// MaxPFR1XattrNameBytes bounds one xattr name (frozen, = MaxXattrNameBytes).
	MaxPFR1XattrNameBytes = MaxXattrNameBytes
	// MaxPFR1XattrValueBytes bounds one OpSetxattr value payload (frozen,
	// = MaxXattrValueBytes) — enforced at encode AND decode, well below the
	// general MaxPFR1DataBytes ceiling.
	MaxPFR1XattrValueBytes = MaxXattrValueBytes
)

// maxPFR1Op is the highest frozen Op value the record encoding covers.
const maxPFR1Op = uint64(OpChflags)

// pfr1OpValid reports whether op is a record-shaped op this canonical encoding
// covers. OpJournalEntry (18) sits inside the numeric range but is deliberately
// EXCLUDED: it frames a whole PFJ3 entry for the file-backed entry log and is
// never a journal record, so it must keep failing closed here exactly as it did
// when it sat above the old ceiling.
func pfr1OpValid(op uint64) bool {
	return op != 0 && op <= maxPFR1Op && op != uint64(OpJournalEntry)
}

// PFR1SizeEstimate returns a conservative UPPER bound on len(EncodePFR1(r)).
// Callers use it to split logical batches into bounded intents before any
// reservation; over-estimation only makes chunks slightly smaller. Each of
// the 29 record fields needs at most a two-byte tag plus a ten-byte
// varint/length prefix, so 384 bytes covers every fixed field and the magic
// even for a structurally valid record carrying irrelevant nonzero scalars.
func PFR1SizeEstimate(r Record) int {
	n := 384 + len(r.Path) + len(r.NewPath) + len(r.Target) + len(r.Data) + len(r.XattrName) + 12*len(r.Inos)
	if r.Env != nil {
		n += 96 + len(r.Env.SessionID) + len(r.Env.ReqHash)
	}
	for i := range r.Mutations {
		n += 16 + PFR1SizeEstimate(r.Mutations[i])
	}
	return n
}

// EncodePFR1 encodes r into its unique canonical PFR1 byte string, enforcing
// every frozen structural bound. The returned slice is freshly allocated; the
// caller owns it and must treat it as immutable from then on (single-encode
// rule: these exact bytes are the record everywhere downstream).
func EncodePFR1(r *Record) ([]byte, error) {
	if err := validatePFR1(r, false); err != nil {
		return nil, err
	}
	body, err := appendPFR1Record(nil, r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+4)
	out = append(out, PFR1Magic[:]...)
	out = append(out, body...)
	if len(out) > MaxPFR1RecordBytes {
		return nil, fmt.Errorf("wal: pfr1 record is %d bytes (max %d)", len(out), MaxPFR1RecordBytes)
	}
	return out, nil
}

// DecodePFR1 strictly decodes one canonical record. Any deviation from the
// unique canonical encoding — unknown/duplicate/misordered fields, non-minimal
// varints, explicit defaults, bad UTF-8, bound violations, nested batches,
// trailing bytes — is rejected with pfwire.ErrMalformed in the chain.
func DecodePFR1(payload []byte) (Record, error) {
	if len(payload) > MaxPFR1RecordBytes {
		return Record{}, fmt.Errorf("wal: pfr1 payload is %d bytes (max %d)", len(payload), MaxPFR1RecordBytes)
	}
	if len(payload) < 4 || !bytes.Equal(payload[:4], PFR1Magic[:]) {
		return Record{}, fmt.Errorf("wal: payload does not begin with the PFR1 magic")
	}
	r, err := decodePFR1Record("record", payload[4:], false)
	if err != nil {
		return Record{}, err
	}
	if err := validatePFR1(&r, false); err != nil {
		return Record{}, err
	}
	return r, nil
}

// validatePFR1 enforces the structural rules shared by encode and decode
// (encode refuses to produce a non-canonical record; decode double-checks the
// decoded value so both paths agree exactly). nested marks a batch leaf.
func validatePFR1(r *Record, nested bool) error {
	op := uint64(r.Op)
	if !pfr1OpValid(op) {
		return fmt.Errorf("wal: pfr1 record has unknown op %d", op)
	}
	if len(r.Path) > MaxPFR1PathBytes || len(r.NewPath) > MaxPFR1PathBytes || len(r.Target) > MaxPFR1PathBytes {
		return fmt.Errorf("wal: pfr1 record path field exceeds %d bytes", MaxPFR1PathBytes)
	}
	if len(r.Data) > MaxPFR1DataBytes {
		return fmt.Errorf("wal: pfr1 record data is %d bytes (max %d)", len(r.Data), MaxPFR1DataBytes)
	}
	if len(r.Inos) > MaxPFR1Inos {
		return fmt.Errorf("wal: pfr1 record has %d inos (max %d)", len(r.Inos), MaxPFR1Inos)
	}
	for _, ino := range r.Inos {
		if ino == 0 {
			return fmt.Errorf("wal: pfr1 record has a zero ino reservation")
		}
	}
	if r.Excl {
		switch r.Op {
		case OpCreate, OpMkdir, OpSymlink:
		default:
			return fmt.Errorf("wal: pfr1 excl flag is only legal on create/mkdir/symlink (op %d)", r.Op)
		}
		if r.Op == OpMkdir && len(r.Inos) != 0 {
			return fmt.Errorf("wal: pfr1 exclusive mkdir carries a component ino list (leaf identity rides field 15)")
		}
	}
	if r.RenameNoReplace && r.Op != OpRename {
		return fmt.Errorf("wal: pfr1 rename_no_replace flag is only legal on rename (op %d)", r.Op)
	}
	// The flag word is bound to its op, not sniffed: an OpChflags may carry any
	// uint32 (0 clears every flag), and no other op may carry one at all.
	if r.Flags != 0 && r.Op != OpChflags {
		return fmt.Errorf("wal: pfr1 flags field is only legal on chflags (op %d)", r.Op)
	}
	switch r.Op {
	case OpSetxattr, OpRemovexattr:
		if len(r.XattrName) == 0 || len(r.XattrName) > MaxPFR1XattrNameBytes {
			return fmt.Errorf("wal: pfr1 xattr name is %d bytes (want 1..%d)", len(r.XattrName), MaxPFR1XattrNameBytes)
		}
		if r.Op == OpSetxattr && len(r.Data) > MaxPFR1XattrValueBytes {
			return fmt.Errorf("wal: pfr1 xattr value is %d bytes (max %d)", len(r.Data), MaxPFR1XattrValueBytes)
		}
		if r.Op == OpRemovexattr && len(r.Data) != 0 {
			return fmt.Errorf("wal: pfr1 removexattr record carries data")
		}
		if r.XattrFlags&^XattrFlagMask != 0 || r.XattrFlags == XattrFlagMask {
			return fmt.Errorf("wal: pfr1 xattr flags %#x are invalid", r.XattrFlags)
		}
		if r.Op == OpRemovexattr && r.XattrFlags != 0 {
			return fmt.Errorf("wal: pfr1 removexattr record carries xattr flags")
		}
	default:
		if r.XattrName != "" || r.XattrFlags != 0 {
			return fmt.Errorf("wal: pfr1 xattr fields are only legal on setxattr/removexattr (op %d)", r.Op)
		}
	}
	if r.Env != nil {
		if !r.Env.Valid() {
			return fmt.Errorf("wal: pfr1 envelope has no session id")
		}
		if len(r.Env.SessionID) > MaxPFR1SessionIDBytes {
			return fmt.Errorf("wal: pfr1 envelope session id exceeds %d bytes", MaxPFR1SessionIDBytes)
		}
		if len(r.Env.ReqHash) != PFR1ReqHashBytes {
			return fmt.Errorf("wal: pfr1 envelope req hash is %d bytes (want %d)", len(r.Env.ReqHash), PFR1ReqHashBytes)
		}
	}
	if nested {
		// Leaf Seq fields remain mount-local flush sequence numbers; the only
		// depth rule is that a batch cannot contain another batch.
		if r.Op == OpBatch || len(r.Mutations) != 0 {
			return fmt.Errorf("wal: pfr1 nested batch records are prohibited")
		}
		return nil
	}
	if r.Op == OpBatch {
		if len(r.Mutations) == 0 {
			return fmt.Errorf("wal: pfr1 batch record has no mutations")
		}
		if len(r.Mutations) > MaxPFR1BatchMutations {
			return fmt.Errorf("wal: pfr1 batch has %d mutations (max %d)", len(r.Mutations), MaxPFR1BatchMutations)
		}
		for i := range r.Mutations {
			if err := validatePFR1(&r.Mutations[i], true); err != nil {
				return fmt.Errorf("wal: pfr1 batch mutation %d: %w", i, err)
			}
		}
	} else if len(r.Mutations) != 0 {
		return fmt.Errorf("wal: pfr1 non-batch record carries mutations")
	}
	return nil
}

// appendPFR1Envelope encodes e (non-nil, already validated).
func appendPFR1Envelope(dst []byte, e *Envelope) []byte {
	dst = pfwire.AppendString(dst, 1, e.SessionID)
	dst = pfwire.AppendUint(dst, 2, e.Generation)
	dst = pfwire.AppendUint(dst, 3, uint64(e.Slot))
	dst = pfwire.AppendUint(dst, 4, e.SlotSeq)
	dst = pfwire.AppendBytes(dst, 5, e.ReqHash)
	return dst
}

// appendPFR1Record encodes one record body (no magic), already validated.
func appendPFR1Record(dst []byte, r *Record) ([]byte, error) {
	dst = pfwire.AppendUint(dst, 1, r.Seq)
	dst = pfwire.AppendUint(dst, 2, uint64(r.Op))
	dst = pfwire.AppendString(dst, 3, r.Path)
	dst = pfwire.AppendString(dst, 4, r.NewPath)
	dst = pfwire.AppendSint(dst, 5, r.Offset)
	dst = pfwire.AppendSint(dst, 6, r.Size)
	dst = pfwire.AppendUint(dst, 7, uint64(r.Mode))
	dst = pfwire.AppendString(dst, 8, r.Target)
	dst = pfwire.AppendBytes(dst, 9, r.Data)
	dst = pfwire.AppendSint(dst, 10, r.MtimeMs)
	dst = pfwire.AppendSint(dst, 11, r.AtimeMs)
	dst = pfwire.AppendBool(dst, 12, r.ChtimesSetAtime)
	dst = pfwire.AppendUint(dst, 13, uint64(r.UID))
	dst = pfwire.AppendUint(dst, 14, uint64(r.GID))
	dst = pfwire.AppendUint(dst, 15, r.Ino)
	if len(r.Inos) > 0 {
		var packed []byte
		for _, ino := range r.Inos {
			packed = pfwire.AppendVarint(packed, ino)
		}
		dst = pfwire.AppendBytes(dst, 16, packed)
	}
	dst = pfwire.AppendBool(dst, 17, r.OrphanTarget)
	dst = pfwire.AppendSint(dst, 18, r.TsMs)
	dst = pfwire.AppendBool(dst, 19, r.ChownSetUID)
	dst = pfwire.AppendBool(dst, 20, r.ChownSetGID)
	dst = pfwire.AppendBool(dst, 21, r.Append)
	dst = pfwire.AppendSint(dst, 22, r.ReapIfLeaseExpiresByMs)
	if r.Env != nil {
		env := appendPFR1Envelope(nil, r.Env)
		dst = pfwire.AppendBytes(dst, 23, env)
	}
	for i := range r.Mutations {
		leaf, err := appendPFR1Record(nil, &r.Mutations[i])
		if err != nil {
			return nil, err
		}
		if len(leaf) == 0 {
			return nil, fmt.Errorf("wal: pfr1 batch mutation %d encodes empty", i)
		}
		dst = pfwire.AppendBytes(dst, 24, leaf)
	}
	dst = pfwire.AppendBool(dst, 25, r.Excl)
	dst = pfwire.AppendBool(dst, 26, r.RenameNoReplace)
	dst = pfwire.AppendString(dst, 27, r.XattrName)
	dst = pfwire.AppendUint(dst, 28, uint64(r.XattrFlags))
	dst = pfwire.AppendBool(dst, 29, r.ChtimesKeepMtime)
	dst = pfwire.AppendUint(dst, 30, uint64(r.Flags))
	return dst, nil
}

func decodePFR1Envelope(body []byte) (*Envelope, error) {
	rd := pfwire.NewReader("pfr1 envelope", body)
	var e Envelope
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
		switch field {
		case 1:
			if wt != pfwire.TypeBytes {
				return nil, rd.Malformedf("session_id wire type %d", wt)
			}
			if e.SessionID, err = rd.String(field, MaxPFR1SessionIDBytes); err != nil {
				return nil, err
			}
		case 2:
			if wt != pfwire.TypeVarint {
				return nil, rd.Malformedf("generation wire type %d", wt)
			}
			if e.Generation, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case 3:
			if wt != pfwire.TypeVarint {
				return nil, rd.Malformedf("slot wire type %d", wt)
			}
			if e.Slot, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case 4:
			if wt != pfwire.TypeVarint {
				return nil, rd.Malformedf("slot_seq wire type %d", wt)
			}
			if e.SlotSeq, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case 5:
			if wt != pfwire.TypeBytes {
				return nil, rd.Malformedf("req_hash wire type %d", wt)
			}
			b, err := rd.Bytes(field, PFR1ReqHashBytes)
			if err != nil {
				return nil, err
			}
			if len(b) != PFR1ReqHashBytes {
				return nil, rd.Malformedf("req_hash is %d bytes (want %d)", len(b), PFR1ReqHashBytes)
			}
			e.ReqHash = append([]byte(nil), b...)
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	if e.SessionID == "" {
		return nil, fmt.Errorf("%w: pfr1 envelope: empty session id", pfwire.ErrMalformed)
	}
	return &e, nil
}

// decodePFR1Record strictly decodes one record body. nested guards depth.
func decodePFR1Record(what string, body []byte, nested bool) (Record, error) {
	rd := pfwire.NewReader(what, body)
	var r Record
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return Record{}, err
		}
		if !ok {
			break
		}
		if field == 24 {
			if err := rd.RequireRepeated(field); err != nil {
				return Record{}, err
			}
		} else {
			if err := rd.Require(field); err != nil {
				return Record{}, err
			}
		}
		switch field {
		case 1:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("seq wire type %d", wt)
			}
			if r.Seq, err = rd.Uint(field); err != nil {
				return Record{}, err
			}
		case 2:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("op wire type %d", wt)
			}
			op, err := rd.Uint(field)
			if err != nil {
				return Record{}, err
			}
			if !pfr1OpValid(op) {
				return Record{}, rd.Malformedf("unknown op %d", op)
			}
			r.Op = Op(op)
		case 3:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("path wire type %d", wt)
			}
			if r.Path, err = rd.String(field, MaxPFR1PathBytes); err != nil {
				return Record{}, err
			}
		case 4:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("new_path wire type %d", wt)
			}
			if r.NewPath, err = rd.String(field, MaxPFR1PathBytes); err != nil {
				return Record{}, err
			}
		case 5:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("offset wire type %d", wt)
			}
			if r.Offset, err = rd.Sint(field); err != nil {
				return Record{}, err
			}
		case 6:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("size wire type %d", wt)
			}
			if r.Size, err = rd.Sint(field); err != nil {
				return Record{}, err
			}
		case 7:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("mode wire type %d", wt)
			}
			if r.Mode, err = rd.Uint32(field); err != nil {
				return Record{}, err
			}
		case 8:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("target wire type %d", wt)
			}
			if r.Target, err = rd.String(field, MaxPFR1PathBytes); err != nil {
				return Record{}, err
			}
		case 9:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("data wire type %d", wt)
			}
			b, err := rd.Bytes(field, MaxPFR1DataBytes)
			if err != nil {
				return Record{}, err
			}
			r.Data = append([]byte(nil), b...)
		case 10:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("mtime_ms wire type %d", wt)
			}
			if r.MtimeMs, err = rd.Sint(field); err != nil {
				return Record{}, err
			}
		case 11:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("atime_ms wire type %d", wt)
			}
			if r.AtimeMs, err = rd.Sint(field); err != nil {
				return Record{}, err
			}
		case 12:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("chtimes_set_atime wire type %d", wt)
			}
			if r.ChtimesSetAtime, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 13:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("uid wire type %d", wt)
			}
			if r.UID, err = rd.Uint32(field); err != nil {
				return Record{}, err
			}
		case 14:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("gid wire type %d", wt)
			}
			if r.GID, err = rd.Uint32(field); err != nil {
				return Record{}, err
			}
		case 15:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("ino wire type %d", wt)
			}
			if r.Ino, err = rd.Uint(field); err != nil {
				return Record{}, err
			}
		case 16:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("inos wire type %d", wt)
			}
			packed, err := rd.Bytes(field, MaxPFR1Inos*10)
			if err != nil {
				return Record{}, err
			}
			inner := pfwire.NewReader(what+" inos", packed)
			for !inner.Done() {
				v, err := inner.Uint(field)
				if err != nil {
					return Record{}, err
				}
				if len(r.Inos) >= MaxPFR1Inos {
					return Record{}, rd.Malformedf("more than %d inos", MaxPFR1Inos)
				}
				r.Inos = append(r.Inos, v)
			}
			if len(r.Inos) == 0 {
				return Record{}, rd.Malformedf("packed inos decodes empty")
			}
		case 17:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("orphan_target wire type %d", wt)
			}
			if r.OrphanTarget, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 18:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("ts_ms wire type %d", wt)
			}
			if r.TsMs, err = rd.Sint(field); err != nil {
				return Record{}, err
			}
		case 19:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("chown_set_uid wire type %d", wt)
			}
			if r.ChownSetUID, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 20:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("chown_set_gid wire type %d", wt)
			}
			if r.ChownSetGID, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 21:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("append wire type %d", wt)
			}
			if r.Append, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 22:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("reap_if_lease_expires_by_ms wire type %d", wt)
			}
			if r.ReapIfLeaseExpiresByMs, err = rd.Sint(field); err != nil {
				return Record{}, err
			}
		case 23:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("env wire type %d", wt)
			}
			body, err := rd.Bytes(field, MaxPFR1RecordBytes)
			if err != nil {
				return Record{}, err
			}
			if r.Env, err = decodePFR1Envelope(body); err != nil {
				return Record{}, err
			}
		case 24:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("mutations wire type %d", wt)
			}
			if nested {
				return Record{}, rd.Malformedf("nested batch records are prohibited")
			}
			body, err := rd.Bytes(field, MaxPFR1RecordBytes)
			if err != nil {
				return Record{}, err
			}
			if len(r.Mutations) >= MaxPFR1BatchMutations {
				return Record{}, rd.Malformedf("more than %d batch mutations", MaxPFR1BatchMutations)
			}
			leaf, err := decodePFR1Record(what+" mutation", body, true)
			if err != nil {
				return Record{}, err
			}
			r.Mutations = append(r.Mutations, leaf)
		case 25:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("excl wire type %d", wt)
			}
			if r.Excl, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 26:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("rename_no_replace wire type %d", wt)
			}
			if r.RenameNoReplace, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 27:
			if wt != pfwire.TypeBytes {
				return Record{}, rd.Malformedf("xattr_name wire type %d", wt)
			}
			if r.XattrName, err = rd.String(field, MaxPFR1XattrNameBytes); err != nil {
				return Record{}, err
			}
		case 28:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("xattr_flags wire type %d", wt)
			}
			flags, err := rd.Uint(field)
			if err != nil {
				return Record{}, err
			}
			if flags > uint64(^uint8(0)) {
				return Record{}, rd.Malformedf("xattr_flags overflows uint8")
			}
			r.XattrFlags = uint8(flags)
		case 29:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("chtimes_keep_mtime wire type %d", wt)
			}
			if r.ChtimesKeepMtime, err = rd.Bool(field); err != nil {
				return Record{}, err
			}
		case 30:
			if wt != pfwire.TypeVarint {
				return Record{}, rd.Malformedf("flags wire type %d", wt)
			}
			if r.Flags, err = rd.Uint32(field); err != nil {
				return Record{}, err
			}
		default:
			return Record{}, rd.RejectUnknown(field)
		}
	}
	return r, nil
}
