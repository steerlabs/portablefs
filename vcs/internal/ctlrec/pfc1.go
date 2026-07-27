package ctlrec

import (
	"bytes"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// PFC1 is the FROZEN canonical byte encoding of one control payload for the
// managed remote journal. Control payloads in a PFC1 journal generation are
// encoded exactly once with this codec; the legacy gob encoding (Encode /
// Decode above) remains DECODE-ONLY for explicit local/migration modes and no
// journal generation may mix the two.
//
// The format is the strict deterministic protowire subset implemented by
// pfwire: ascending frozen field numbers, minimal varints, zigzag signed
// integers, bool as varint 1, defaults omitted, duplicate/unknown/trailing
// data rejected — one unique byte representation per payload.
//
// ────────────────────────────────────────────────────────────────────────────
// FROZEN SCHEMA — never renumber or reuse a field.
//
//	Payload:
//	  1  kind             uint (1..6, the Kind constants)
//	  2  session          message Session          (kind 1)
//	  3  session_expire   message SessionExpire    (kind 2)
//	  4  flush_watermark  message FlushWatermark   (kind 3)
//	  5  snapshot         message Snapshot         (kind 4)
//	  6  outcome          message Outcome          (kind 5)
//	  7  session_renew    message SessionRenew     (kind 6)
//	  (exactly ONE of fields 2..7, and it must match kind)
//
//	Session:        1 session_id  2 generation  3 owner  4 token_hash
//	                5 slots  6 at_ms(s)  7 expires_ms(s)
//	SessionExpire:  1 session_id  2 generation  3 at_ms(s)  4 force(b)
//	FlushWatermark: 1 session_id  2 epoch  3 through
//	Snapshot:       1 as_of_lsn  2 sessions[]  3 watermarks[]  4 orphans[]
//	Outcome:        1 session_id  2 generation  3 slot  4 slot_seq
//	                5 req_hash  6 status(s32)
//	SessionRenew:   1 session_id  2 generation  3 token_hash  4 expires_ms(s)
//	SessionState:   1 session_id  2 generation  3 owner  4 token_hash
//	                5 slots  6 expires_ms(s)  7 slot_states[]  8 expired(b)
//	SlotState:      1 slot  2 slot_seq  3 req_hash  4 status(s32)  5 count(s32)
//	                6 version  7 offset(s)  8 ino  9 orphan_ino
//	ChunkState:     1 digest  2 size(s)  3 offset(s)
//	SourceState:    1 blob_digest  2 blob_size(s)  3 blob_compression
//	                4 blob_packed(b)  5 chunks[]  6 size(s)
//	DirtyBlock:     1 index(s)  2 data
//	OrphanState:    1 ino  2 name  3 kind  4 mode  5 mtime_ms(s)  6 ctime_ms(s)
//	                7 atime_ms(s)  8 uid  9 gid  10 link_target  11 source
//	                12 blocks[]  13 size(s)  14 born(b)  15 truncated(b)
//
// Every encoded payload begins with the 4-byte magic "PFC1" (part of the
// canonical bytes: hashes and digests cover it).
// ────────────────────────────────────────────────────────────────────────────

// PFC1Magic prefixes every canonical control payload.
var PFC1Magic = [4]byte{'P', 'F', 'C', '1'}

// PFC1Codec names this control codec in journal generation metadata.
const PFC1Codec = "pfc1"

// GobControlCodec names the legacy version-byte + gob control encoding used by
// the local file WAL. Decode-only outside local modes.
const GobControlCodec = "ctl-gob"

// MaxPFC1Bytes bounds one encoded PFC1 control payload. It is deliberately
// below the 8 MiB whole-record production bound so a control record (payload
// plus record framing) always fits one journal record. Control snapshots that
// exceed it must externalize orphan content (checkpoint auxiliary blobs) or
// shrink; the encoder fails closed rather than emitting a partial payload.
const MaxPFC1Bytes = 6 << 20

const (
	maxPFC1DigestBytes      = 128
	maxPFC1KindBytes        = 16
	maxPFC1CompressionBytes = 32
	maxPFC1NameBytes        = 4096
)

// EncodePFC1 encodes p into its unique canonical PFC1 byte string. The payload
// is validated with the same structural rules as the gob codec first, so both
// codecs accept exactly the same value space.
func EncodePFC1(p Payload) ([]byte, error) {
	if err := validatePayload(p); err != nil {
		return nil, err
	}
	body, err := appendPFC1Payload(nil, &p)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+4)
	out = append(out, PFC1Magic[:]...)
	out = append(out, body...)
	if len(out) > MaxPFC1Bytes {
		return nil, fmt.Errorf("ctlrec: pfc1 control payload is %d bytes (max %d)", len(out), MaxPFC1Bytes)
	}
	return out, nil
}

// DecodePFC1 strictly decodes one canonical control payload and fails closed
// on anything non-canonical, unknown, or out of bounds.
func DecodePFC1(data []byte) (Payload, error) {
	if len(data) > MaxPFC1Bytes {
		return Payload{}, fmt.Errorf("ctlrec: pfc1 control payload is %d bytes (max %d)", len(data), MaxPFC1Bytes)
	}
	if len(data) < 4 || !bytes.Equal(data[:4], PFC1Magic[:]) {
		return Payload{}, fmt.Errorf("ctlrec: control payload does not begin with the PFC1 magic")
	}
	p, err := decodePFC1Payload(data[4:])
	if err != nil {
		return Payload{}, err
	}
	if err := validatePayload(p); err != nil {
		return Payload{}, err
	}
	return p, nil
}

func appendPFC1Payload(dst []byte, p *Payload) ([]byte, error) {
	dst = pfwire.AppendUint(dst, 1, uint64(p.Kind))
	appendMsg := func(field uint32, body []byte) {
		dst = pfwire.AppendBytes(dst, field, body)
	}
	switch p.Kind {
	case KindSession:
		appendMsg(2, appendPFC1Session(nil, p.Session))
	case KindSessionExpire:
		appendMsg(3, appendPFC1SessionExpire(nil, p.SessionExpire))
	case KindFlushWatermark:
		appendMsg(4, appendPFC1FlushWatermark(nil, p.FlushWatermark))
	case KindSnapshot:
		body, err := appendPFC1Snapshot(nil, p.Snapshot)
		if err != nil {
			return nil, err
		}
		appendMsg(5, body)
	case KindOutcome:
		appendMsg(6, appendPFC1Outcome(nil, p.Outcome))
	case KindSessionRenew:
		appendMsg(7, appendPFC1SessionRenew(nil, p.SessionRenew))
	default:
		return nil, fmt.Errorf("ctlrec: pfc1 cannot encode unknown kind %d", p.Kind)
	}
	return dst, nil
}

// Sub-message encoders. All values were already validated by validatePayload;
// encoders only translate them into canonical bytes. Every encoder body may be
// empty when all fields are default — callers using pfwire.AppendBytes then
// omit the message, and validatePayload guarantees that cannot happen for a
// required union arm (each arm carries at least a session id / LSN / slot seq).

func appendPFC1Session(dst []byte, s *Session) []byte {
	dst = pfwire.AppendString(dst, 1, s.SessionID)
	dst = pfwire.AppendUint(dst, 2, s.Generation)
	dst = pfwire.AppendString(dst, 3, s.Owner)
	dst = pfwire.AppendBytes(dst, 4, s.TokenHash)
	dst = pfwire.AppendUint(dst, 5, uint64(s.Slots))
	dst = pfwire.AppendSint(dst, 6, s.AtMs)
	dst = pfwire.AppendSint(dst, 7, s.ExpiresMs)
	return dst
}

func appendPFC1SessionExpire(dst []byte, s *SessionExpire) []byte {
	dst = pfwire.AppendString(dst, 1, s.SessionID)
	dst = pfwire.AppendUint(dst, 2, s.Generation)
	dst = pfwire.AppendSint(dst, 3, s.AtMs)
	dst = pfwire.AppendBool(dst, 4, s.Force)
	return dst
}

func appendPFC1FlushWatermark(dst []byte, w *FlushWatermark) []byte {
	dst = pfwire.AppendString(dst, 1, w.SessionID)
	dst = pfwire.AppendUint(dst, 2, w.Epoch)
	dst = pfwire.AppendUint(dst, 3, w.Through)
	return dst
}

func appendPFC1Outcome(dst []byte, o *Outcome) []byte {
	dst = pfwire.AppendString(dst, 1, o.SessionID)
	dst = pfwire.AppendUint(dst, 2, o.Generation)
	dst = pfwire.AppendUint(dst, 3, uint64(o.Slot))
	dst = pfwire.AppendUint(dst, 4, o.SlotSeq)
	dst = pfwire.AppendBytes(dst, 5, o.ReqHash)
	dst = pfwire.AppendSint(dst, 6, int64(o.Status))
	return dst
}

func appendPFC1SessionRenew(dst []byte, s *SessionRenew) []byte {
	dst = pfwire.AppendString(dst, 1, s.SessionID)
	dst = pfwire.AppendUint(dst, 2, s.Generation)
	dst = pfwire.AppendBytes(dst, 3, s.TokenHash)
	dst = pfwire.AppendSint(dst, 4, s.ExpiresMs)
	return dst
}

func appendPFC1SlotState(dst []byte, s *SlotState) []byte {
	dst = pfwire.AppendUint(dst, 1, uint64(s.Slot))
	dst = pfwire.AppendUint(dst, 2, s.SlotSeq)
	dst = pfwire.AppendBytes(dst, 3, s.ReqHash)
	dst = pfwire.AppendSint(dst, 4, int64(s.Status))
	dst = pfwire.AppendSint(dst, 5, int64(s.Count))
	dst = pfwire.AppendUint(dst, 6, s.Version)
	dst = pfwire.AppendSint(dst, 7, s.Offset)
	dst = pfwire.AppendUint(dst, 8, s.Ino)
	dst = pfwire.AppendUint(dst, 9, s.OrphanIno)
	return dst
}

func appendPFC1SessionState(dst []byte, s *SessionState) []byte {
	dst = pfwire.AppendString(dst, 1, s.SessionID)
	dst = pfwire.AppendUint(dst, 2, s.Generation)
	dst = pfwire.AppendString(dst, 3, s.Owner)
	dst = pfwire.AppendBytes(dst, 4, s.TokenHash)
	dst = pfwire.AppendUint(dst, 5, uint64(s.Slots))
	dst = pfwire.AppendSint(dst, 6, s.ExpiresMs)
	for i := range s.SlotStates {
		dst = pfwire.AppendBytes(dst, 7, appendPFC1SlotState(nil, &s.SlotStates[i]))
	}
	dst = pfwire.AppendBool(dst, 8, s.Expired)
	return dst
}

func appendPFC1ChunkState(dst []byte, c *ChunkState) []byte {
	dst = pfwire.AppendString(dst, 1, c.Digest)
	dst = pfwire.AppendSint(dst, 2, c.Size)
	dst = pfwire.AppendSint(dst, 3, c.Offset)
	return dst
}

func appendPFC1SourceState(dst []byte, s *SourceState) []byte {
	dst = pfwire.AppendString(dst, 1, s.BlobDigest)
	dst = pfwire.AppendSint(dst, 2, s.BlobSize)
	dst = pfwire.AppendString(dst, 3, s.BlobCompression)
	dst = pfwire.AppendBool(dst, 4, s.BlobPacked)
	for i := range s.Chunks {
		dst = pfwire.AppendBytes(dst, 5, appendPFC1ChunkState(nil, &s.Chunks[i]))
	}
	dst = pfwire.AppendSint(dst, 6, s.Size)
	return dst
}

func appendPFC1DirtyBlock(dst []byte, b *DirtyBlock) []byte {
	dst = pfwire.AppendSint(dst, 1, b.Index)
	dst = pfwire.AppendBytes(dst, 2, b.Data)
	return dst
}

func appendPFC1OrphanState(dst []byte, o *OrphanState) []byte {
	dst = pfwire.AppendUint(dst, 1, o.Ino)
	dst = pfwire.AppendString(dst, 2, o.Name)
	dst = pfwire.AppendString(dst, 3, o.Kind)
	dst = pfwire.AppendUint(dst, 4, uint64(o.Mode))
	dst = pfwire.AppendSint(dst, 5, o.MtimeMs)
	dst = pfwire.AppendSint(dst, 6, o.CtimeMs)
	dst = pfwire.AppendSint(dst, 7, o.AtimeMs)
	dst = pfwire.AppendUint(dst, 8, uint64(o.UID))
	dst = pfwire.AppendUint(dst, 9, uint64(o.GID))
	dst = pfwire.AppendString(dst, 10, o.LinkTarget)
	dst = pfwire.AppendBytes(dst, 11, appendPFC1SourceState(nil, &o.Source))
	for i := range o.Blocks {
		dst = pfwire.AppendBytes(dst, 12, appendPFC1DirtyBlock(nil, &o.Blocks[i]))
	}
	dst = pfwire.AppendSint(dst, 13, o.Size)
	dst = pfwire.AppendBool(dst, 14, o.Born)
	dst = pfwire.AppendBool(dst, 15, o.Truncated)
	return dst
}

func appendPFC1Snapshot(dst []byte, s *Snapshot) ([]byte, error) {
	dst = pfwire.AppendUint(dst, 1, s.AsOfLSN)
	for i := range s.Sessions {
		dst = pfwire.AppendBytes(dst, 2, appendPFC1SessionState(nil, &s.Sessions[i]))
	}
	for i := range s.Watermarks {
		dst = pfwire.AppendBytes(dst, 3, appendPFC1FlushWatermark(nil, &s.Watermarks[i]))
	}
	for i := range s.Orphans {
		body := appendPFC1OrphanState(nil, &s.Orphans[i])
		if len(body) == 0 {
			return nil, fmt.Errorf("ctlrec: pfc1 orphan %d encodes empty", i)
		}
		dst = pfwire.AppendBytes(dst, 4, body)
	}
	return dst, nil
}

// ─── strict decoders ────────────────────────────────────────────────────────

func decodePFC1Payload(body []byte) (Payload, error) {
	rd := pfwire.NewReader("pfc1 payload", body)
	var p Payload
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return Payload{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return Payload{}, err
		}
		switch field {
		case 1:
			if wt != pfwire.TypeVarint {
				return Payload{}, rd.Malformedf("kind wire type %d", wt)
			}
			v, err := rd.Uint(field)
			if err != nil {
				return Payload{}, err
			}
			if v > uint64(KindSessionRenew) {
				return Payload{}, rd.Malformedf("unknown kind %d", v)
			}
			p.Kind = Kind(v)
		case 2, 3, 4, 5, 6, 7:
			if wt != pfwire.TypeBytes {
				return Payload{}, rd.Malformedf("union field %d wire type %d", field, wt)
			}
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return Payload{}, err
			}
			switch field {
			case 2:
				if p.Session, err = decodePFC1Session(msg); err != nil {
					return Payload{}, err
				}
			case 3:
				if p.SessionExpire, err = decodePFC1SessionExpire(msg); err != nil {
					return Payload{}, err
				}
			case 4:
				w, err := decodePFC1FlushWatermark("pfc1 flush watermark", msg)
				if err != nil {
					return Payload{}, err
				}
				p.FlushWatermark = &w
			case 5:
				if p.Snapshot, err = decodePFC1Snapshot(msg); err != nil {
					return Payload{}, err
				}
			case 6:
				if p.Outcome, err = decodePFC1Outcome(msg); err != nil {
					return Payload{}, err
				}
			case 7:
				if p.SessionRenew, err = decodePFC1SessionRenew(msg); err != nil {
					return Payload{}, err
				}
			}
		default:
			return Payload{}, rd.RejectUnknown(field)
		}
	}
	// Union arm/kind congruence: validatePayload checks pointer-count and
	// per-kind shape; here we reject an arm that contradicts kind outright so
	// the error names the wire problem.
	switch p.Kind {
	case KindSession:
		if p.Session == nil {
			return Payload{}, rd.Malformedf("kind %d without its union arm", p.Kind)
		}
	case KindSessionExpire:
		if p.SessionExpire == nil {
			return Payload{}, rd.Malformedf("kind %d without its union arm", p.Kind)
		}
	case KindFlushWatermark:
		if p.FlushWatermark == nil {
			return Payload{}, rd.Malformedf("kind %d without its union arm", p.Kind)
		}
	case KindSnapshot:
		if p.Snapshot == nil {
			return Payload{}, rd.Malformedf("kind %d without its union arm", p.Kind)
		}
	case KindOutcome:
		if p.Outcome == nil {
			return Payload{}, rd.Malformedf("kind %d without its union arm", p.Kind)
		}
	case KindSessionRenew:
		if p.SessionRenew == nil {
			return Payload{}, rd.Malformedf("kind %d without its union arm", p.Kind)
		}
	default:
		return Payload{}, rd.Malformedf("missing kind")
	}
	return p, nil
}

func decodePFC1Session(body []byte) (*Session, error) {
	rd := pfwire.NewReader("pfc1 session", body)
	var s Session
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
			if s.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.Generation, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if s.Owner, err = rd.String(field, MaxOwnerBytes); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, TokenHashBytes)
			if err != nil {
				return nil, err
			}
			s.TokenHash = append([]byte(nil), b...)
		case field == 5 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return nil, err
			}
			s.Slots = v
		case field == 6 && wt == pfwire.TypeVarint:
			if s.AtMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if s.ExpiresMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &s, nil
}

func decodePFC1SessionExpire(body []byte) (*SessionExpire, error) {
	rd := pfwire.NewReader("pfc1 session expire", body)
	var s SessionExpire
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
			if s.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.Generation, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if s.AtMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if s.Force, err = rd.Bool(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &s, nil
}

func decodePFC1FlushWatermark(what string, body []byte) (FlushWatermark, error) {
	rd := pfwire.NewReader(what, body)
	var w FlushWatermark
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return FlushWatermark{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return FlushWatermark{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if w.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return FlushWatermark{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if w.Epoch, err = rd.Uint(field); err != nil {
				return FlushWatermark{}, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if w.Through, err = rd.Uint(field); err != nil {
				return FlushWatermark{}, err
			}
		default:
			return FlushWatermark{}, rd.RejectUnknown(field)
		}
	}
	return w, nil
}

func decodePFC1Outcome(body []byte) (*Outcome, error) {
	rd := pfwire.NewReader("pfc1 outcome", body)
	var o Outcome
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
			if o.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if o.Generation, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return nil, err
			}
			o.Slot = v
		case field == 4 && wt == pfwire.TypeVarint:
			if o.SlotSeq, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, RequestHashBytes)
			if err != nil {
				return nil, err
			}
			o.ReqHash = append([]byte(nil), b...)
		case field == 6 && wt == pfwire.TypeVarint:
			if o.Status, err = rd.Sint32(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &o, nil
}

func decodePFC1SessionRenew(body []byte) (*SessionRenew, error) {
	rd := pfwire.NewReader("pfc1 session renew", body)
	var s SessionRenew
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
			if s.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.Generation, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, TokenHashBytes)
			if err != nil {
				return nil, err
			}
			s.TokenHash = append([]byte(nil), b...)
		case field == 4 && wt == pfwire.TypeVarint:
			if s.ExpiresMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &s, nil
}

func decodePFC1SlotState(body []byte) (SlotState, error) {
	rd := pfwire.NewReader("pfc1 slot state", body)
	var s SlotState
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return SlotState{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return SlotState{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return SlotState{}, err
			}
			s.Slot = v
		case field == 2 && wt == pfwire.TypeVarint:
			if s.SlotSeq, err = rd.Uint(field); err != nil {
				return SlotState{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, RequestHashBytes)
			if err != nil {
				return SlotState{}, err
			}
			s.ReqHash = append([]byte(nil), b...)
		case field == 4 && wt == pfwire.TypeVarint:
			if s.Status, err = rd.Sint32(field); err != nil {
				return SlotState{}, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if s.Count, err = rd.Sint32(field); err != nil {
				return SlotState{}, err
			}
		case field == 6 && wt == pfwire.TypeVarint:
			if s.Version, err = rd.Uint(field); err != nil {
				return SlotState{}, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if s.Offset, err = rd.Sint(field); err != nil {
				return SlotState{}, err
			}
		case field == 8 && wt == pfwire.TypeVarint:
			if s.Ino, err = rd.Uint(field); err != nil {
				return SlotState{}, err
			}
		case field == 9 && wt == pfwire.TypeVarint:
			if s.OrphanIno, err = rd.Uint(field); err != nil {
				return SlotState{}, err
			}
		default:
			return SlotState{}, rd.RejectUnknown(field)
		}
	}
	return s, nil
}

func decodePFC1SessionState(body []byte) (SessionState, error) {
	rd := pfwire.NewReader("pfc1 session state", body)
	var s SessionState
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return SessionState{}, err
		}
		if !ok {
			break
		}
		if field == 7 {
			if err := rd.RequireRepeated(field); err != nil {
				return SessionState{}, err
			}
		} else if err := rd.Require(field); err != nil {
			return SessionState{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if s.SessionID, err = rd.String(field, MaxSessionIDBytes); err != nil {
				return SessionState{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.Generation, err = rd.Uint(field); err != nil {
				return SessionState{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if s.Owner, err = rd.String(field, MaxOwnerBytes); err != nil {
				return SessionState{}, err
			}
		case field == 4 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, TokenHashBytes)
			if err != nil {
				return SessionState{}, err
			}
			s.TokenHash = append([]byte(nil), b...)
		case field == 5 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return SessionState{}, err
			}
			s.Slots = v
		case field == 6 && wt == pfwire.TypeVarint:
			if s.ExpiresMs, err = rd.Sint(field); err != nil {
				return SessionState{}, err
			}
		case field == 7 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return SessionState{}, err
			}
			if len(s.SlotStates) >= MaxSlotStates {
				return SessionState{}, rd.Malformedf("more than %d slot states", MaxSlotStates)
			}
			slot, err := decodePFC1SlotState(msg)
			if err != nil {
				return SessionState{}, err
			}
			s.SlotStates = append(s.SlotStates, slot)
		case field == 8 && wt == pfwire.TypeVarint:
			if s.Expired, err = rd.Bool(field); err != nil {
				return SessionState{}, err
			}
		default:
			return SessionState{}, rd.RejectUnknown(field)
		}
	}
	return s, nil
}

func decodePFC1ChunkState(body []byte) (ChunkState, error) {
	rd := pfwire.NewReader("pfc1 chunk", body)
	var c ChunkState
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ChunkState{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ChunkState{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if c.Digest, err = rd.String(field, maxPFC1DigestBytes); err != nil {
				return ChunkState{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if c.Size, err = rd.Sint(field); err != nil {
				return ChunkState{}, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if c.Offset, err = rd.Sint(field); err != nil {
				return ChunkState{}, err
			}
		default:
			return ChunkState{}, rd.RejectUnknown(field)
		}
	}
	return c, nil
}

func decodePFC1SourceState(body []byte) (SourceState, error) {
	rd := pfwire.NewReader("pfc1 source", body)
	var s SourceState
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return SourceState{}, err
		}
		if !ok {
			break
		}
		if field == 5 {
			if err := rd.RequireRepeated(field); err != nil {
				return SourceState{}, err
			}
		} else if err := rd.Require(field); err != nil {
			return SourceState{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if s.BlobDigest, err = rd.String(field, maxPFC1DigestBytes); err != nil {
				return SourceState{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if s.BlobSize, err = rd.Sint(field); err != nil {
				return SourceState{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if s.BlobCompression, err = rd.String(field, maxPFC1CompressionBytes); err != nil {
				return SourceState{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if s.BlobPacked, err = rd.Bool(field); err != nil {
				return SourceState{}, err
			}
		case field == 5 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return SourceState{}, err
			}
			if len(s.Chunks) >= MaxSnapshotSourceChunks {
				return SourceState{}, rd.Malformedf("more than %d chunks", MaxSnapshotSourceChunks)
			}
			chunk, err := decodePFC1ChunkState(msg)
			if err != nil {
				return SourceState{}, err
			}
			s.Chunks = append(s.Chunks, chunk)
		case field == 6 && wt == pfwire.TypeVarint:
			if s.Size, err = rd.Sint(field); err != nil {
				return SourceState{}, err
			}
		default:
			return SourceState{}, rd.RejectUnknown(field)
		}
	}
	return s, nil
}

func decodePFC1DirtyBlock(body []byte) (DirtyBlock, error) {
	rd := pfwire.NewReader("pfc1 dirty block", body)
	var b DirtyBlock
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return DirtyBlock{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return DirtyBlock{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if b.Index, err = rd.Sint(field); err != nil {
				return DirtyBlock{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			data, err := rd.Bytes(field, MaxSnapshotBlockBytes)
			if err != nil {
				return DirtyBlock{}, err
			}
			b.Data = append([]byte(nil), data...)
		default:
			return DirtyBlock{}, rd.RejectUnknown(field)
		}
	}
	return b, nil
}

func decodePFC1OrphanState(body []byte) (OrphanState, error) {
	rd := pfwire.NewReader("pfc1 orphan", body)
	var o OrphanState
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return OrphanState{}, err
		}
		if !ok {
			break
		}
		if field == 12 {
			if err := rd.RequireRepeated(field); err != nil {
				return OrphanState{}, err
			}
		} else if err := rd.Require(field); err != nil {
			return OrphanState{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if o.Ino, err = rd.Uint(field); err != nil {
				return OrphanState{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if o.Name, err = rd.String(field, maxPFC1NameBytes); err != nil {
				return OrphanState{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if o.Kind, err = rd.String(field, maxPFC1KindBytes); err != nil {
				return OrphanState{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return OrphanState{}, err
			}
			o.Mode = v
		case field == 5 && wt == pfwire.TypeVarint:
			if o.MtimeMs, err = rd.Sint(field); err != nil {
				return OrphanState{}, err
			}
		case field == 6 && wt == pfwire.TypeVarint:
			if o.CtimeMs, err = rd.Sint(field); err != nil {
				return OrphanState{}, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if o.AtimeMs, err = rd.Sint(field); err != nil {
				return OrphanState{}, err
			}
		case field == 8 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return OrphanState{}, err
			}
			o.UID = v
		case field == 9 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return OrphanState{}, err
			}
			o.GID = v
		case field == 10 && wt == pfwire.TypeBytes:
			if o.LinkTarget, err = rd.String(field, maxPFC1NameBytes); err != nil {
				return OrphanState{}, err
			}
		case field == 11 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return OrphanState{}, err
			}
			if o.Source, err = decodePFC1SourceState(msg); err != nil {
				return OrphanState{}, err
			}
		case field == 12 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return OrphanState{}, err
			}
			block, err := decodePFC1DirtyBlock(msg)
			if err != nil {
				return OrphanState{}, err
			}
			o.Blocks = append(o.Blocks, block)
		case field == 13 && wt == pfwire.TypeVarint:
			if o.Size, err = rd.Sint(field); err != nil {
				return OrphanState{}, err
			}
		case field == 14 && wt == pfwire.TypeVarint:
			if o.Born, err = rd.Bool(field); err != nil {
				return OrphanState{}, err
			}
		case field == 15 && wt == pfwire.TypeVarint:
			if o.Truncated, err = rd.Bool(field); err != nil {
				return OrphanState{}, err
			}
		default:
			return OrphanState{}, rd.RejectUnknown(field)
		}
	}
	return o, nil
}

func decodePFC1Snapshot(body []byte) (*Snapshot, error) {
	rd := pfwire.NewReader("pfc1 snapshot", body)
	var s Snapshot
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		switch field {
		case 2, 3, 4:
			if err := rd.RequireRepeated(field); err != nil {
				return nil, err
			}
		default:
			if err := rd.Require(field); err != nil {
				return nil, err
			}
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if s.AsOfLSN, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return nil, err
			}
			if len(s.Sessions) >= MaxSessions {
				return nil, rd.Malformedf("more than %d sessions", MaxSessions)
			}
			sess, err := decodePFC1SessionState(msg)
			if err != nil {
				return nil, err
			}
			s.Sessions = append(s.Sessions, sess)
		case field == 3 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return nil, err
			}
			if len(s.Watermarks) >= MaxWatermarks {
				return nil, rd.Malformedf("more than %d watermarks", MaxWatermarks)
			}
			w, err := decodePFC1FlushWatermark("pfc1 snapshot watermark", msg)
			if err != nil {
				return nil, err
			}
			s.Watermarks = append(s.Watermarks, w)
		case field == 4 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxPFC1Bytes)
			if err != nil {
				return nil, err
			}
			if len(s.Orphans) >= MaxSnapshotOrphans {
				return nil, rd.Malformedf("more than %d orphans", MaxSnapshotOrphans)
			}
			orphan, err := decodePFC1OrphanState(msg)
			if err != nil {
				return nil, err
			}
			s.Orphans = append(s.Orphans, orphan)
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &s, nil
}
