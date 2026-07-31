package workfs

import (
	"fmt"
	"math"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// maxIntentMutations bounds one atomic visibility unit. It is deliberately
// generous enough for write-back flushes while preventing a malformed caller
// from making the authority hold fs.mu for an unbounded batch.
const maxIntentMutations = 4096

// The immutable PFT2 acceptance bounds (pft2.MaxSymlinkTargetBytes,
// pft2.MaxLogicalFileBytes) restated as the shared live-ingress contract, so
// a live branch can never hold state a PFT2 materialization would reject.
// They are byte-for-byte the pft2 constants; duplicated here to keep workfs
// free of a pft2 import.
const (
	maxSymlinkTargetBytes = 4096
	maxLogicalFileBytes   = uint64(1) << 62
)

type intentTrust uint8

const (
	// intentUser is one ordinary user-namespace mutation. Control records and
	// batch wrappers are not accepted through this path.
	intentUser intentTrust = iota
	// intentExactUser is intentUser plus one validated protocol-v2 envelope.
	intentExactUser
	// intentWritebackBatch is the trusted server-side write-back assembly of
	// user records (coordination rides PFC2 rows, never in-batch controls).
	intentWritebackBatch
)

type recordFields uint32

const (
	fieldPath recordFields = 1 << iota
	fieldNewPath
	fieldOffset
	fieldSize
	fieldMode
	fieldTarget
	fieldData
	fieldTimes
	fieldOwner
	fieldIno
	fieldInos
	fieldOrphanTarget
	fieldAppend
	fieldReapCutoff
	fieldEnvelope
	fieldExcl
	fieldRenameNoReplace
	fieldXattrName
	fieldXattrFlags
	fieldFlags
)

// normalizeAndValidateIntent is the authoritative live-ingress defense. It
// deep-copies caller-owned slices, canonicalizes namespace paths and control
// payload encodings (transcoding legacy gob control payloads into this log's
// declared control codec exactly once, before any hash/reservation consumes
// the bytes), and rejects malformed semantics before identity allocation or
// WAL reservation. Replay is intentionally separate: it consumes the exact
// historical representation.
func (fs *FS) normalizeAndValidateIntent(records []wal.Record, trust intentTrust) ([]wal.Record, error) {
	if len(records) != 1 {
		return nil, invalidMutation("an intent must contain exactly one WAL frame")
	}
	if err := preflightIntentShape(records[0], trust); err != nil {
		return nil, err
	}
	records = cloneRecords(records)
	r := &records[0]
	if r.Seq != 0 || r.TsMs != 0 {
		return nil, invalidMutation("caller supplied authority sequence or timestamp")
	}

	switch trust {
	case intentWritebackBatch:
		if r.Op != wal.OpBatch {
			return nil, invalidMutation("write-back path requires one batch frame")
		}
		if err := validateBatchWrapper(*r); err != nil {
			return nil, err
		}
		for i := range r.Mutations {
			if err := normalizeAndValidateUserRecord(&r.Mutations[i], true, false); err != nil {
				return nil, fmt.Errorf("batch mutation %d: %w", i, err)
			}
		}
		return records, nil
	case intentUser, intentExactUser:
		if r.Op.IsBatch() || r.Op.IsControl() {
			return nil, invalidMutation("batch/control records require their explicit trusted path")
		}
		if err := normalizeAndValidateUserRecord(r, false, trust == intentExactUser); err != nil {
			return nil, err
		}
		if trust == intentExactUser && !r.Env.Valid() {
			return nil, invalidMutation("exact mutation requires an envelope")
		}
		return records, nil
	default:
		return nil, invalidMutation("unknown mutation trust class")
	}
}

// preflightIntentShape runs before copying caller-owned payloads. In addition
// to rejecting nesting without recursive descent, it bounds the aggregate data
// allocation to the WAL's framing ceiling.
func preflightIntentShape(r wal.Record, trust intentTrust) error {
	const maxIntentPayloadBytes = 256 << 20
	if trust != intentWritebackBatch {
		if len(r.Mutations) != 0 {
			return invalidMutation("non-batch intent carries nested mutations")
		}
		if len(r.Data) > maxIntentPayloadBytes {
			return invalidMutation("mutation payload exceeds %d bytes", maxIntentPayloadBytes)
		}
		if r.Op == wal.OpControl {
			return invalidMutation("control records are retired (coordination rides PFC2 rows)")
		}
		return nil
	}
	if r.Op != wal.OpBatch {
		return invalidMutation("write-back path requires one batch frame")
	}
	if len(r.Mutations) == 0 {
		return invalidMutation("empty batch")
	}
	if len(r.Mutations) > maxIntentMutations {
		return invalidMutation("batch has %d mutations; maximum is %d", len(r.Mutations), maxIntentMutations)
	}
	total := 0
	for i := range r.Mutations {
		leaf := &r.Mutations[i]
		if leaf.Op.IsBatch() || len(leaf.Mutations) != 0 {
			return invalidMutation("nested batch at mutation %d", i)
		}
		if len(leaf.Data) > maxIntentPayloadBytes-total {
			return invalidMutation("batch payload exceeds %d bytes", maxIntentPayloadBytes)
		}
		total += len(leaf.Data)
		if leaf.Op == wal.OpControl {
			return invalidMutation("control records are retired (coordination rides PFC2 rows)")
		}
	}
	return nil
}

func cloneRecords(records []wal.Record) []wal.Record {
	out := make([]wal.Record, len(records))
	for i := range records {
		out[i] = cloneRecordPayload(records[i])
		if len(records[i].Mutations) != 0 {
			out[i].Mutations = make([]wal.Record, len(records[i].Mutations))
			for j := range records[i].Mutations {
				// Valid intents have only this one leaf level (preflight above).
				out[i].Mutations[j] = cloneRecordPayload(records[i].Mutations[j])
			}
		}
	}
	return out
}

func cloneRecordPayload(r wal.Record) wal.Record {
	cloned := r
	cloned.Data = append([]byte(nil), r.Data...)
	cloned.Inos = append([]uint64(nil), r.Inos...)
	if r.Env != nil {
		env := *r.Env
		env.ReqHash = append([]byte(nil), r.Env.ReqHash...)
		cloned.Env = &env
	}
	return cloned
}

func validateBatchWrapper(r wal.Record) error {
	if len(r.Mutations) == 0 {
		return invalidMutation("empty batch")
	}
	if len(r.Mutations) > maxIntentMutations {
		return invalidMutation("batch has %d mutations; maximum is %d", len(r.Mutations), maxIntentMutations)
	}
	if r.Path != "" || r.NewPath != "" || r.Offset != 0 || r.Size != 0 || r.Mode != 0 ||
		r.Target != "" || len(r.Data) != 0 || r.MtimeMs != 0 || r.AtimeMs != 0 || r.ChtimesSetAtime || r.ChtimesKeepMtime ||
		r.UID != 0 || r.GID != 0 || r.Ino != 0 || len(r.Inos) != 0 || r.OrphanTarget ||
		r.ChownSetUID || r.ChownSetGID || r.Append || r.ReapIfLeaseExpiresByMs != 0 || r.Env != nil ||
		r.Excl || r.RenameNoReplace || r.XattrName != "" || r.XattrFlags != 0 || r.Flags != 0 {
		return invalidMutation("batch wrapper carries leaf-only fields")
	}
	for i := range r.Mutations {
		if r.Mutations[i].Op.IsBatch() || len(r.Mutations[i].Mutations) != 0 {
			return invalidMutation("nested batch at mutation %d", i)
		}
		if r.Mutations[i].TsMs != 0 {
			return invalidMutation("batch mutation %d supplied an authority timestamp", i)
		}
	}
	return nil
}

// userNamespaceOp reports whether op is a user-namespace mutation this
// authority admits from a client. Control, batch-wrapper, and entry-framing ops
// are deliberately absent.
func userNamespaceOp(op wal.Op) bool {
	switch op {
	case wal.OpCreate, wal.OpWrite, wal.OpTruncate, wal.OpMkdir, wal.OpRemove,
		wal.OpRename, wal.OpSymlink, wal.OpChmod, wal.OpChtimes, wal.OpChown,
		wal.OpOrphan, wal.OpReap, wal.OpLink, wal.OpSetxattr, wal.OpRemovexattr,
		wal.OpChflags:
		return true
	}
	return false
}

func normalizeAndValidateUserRecord(r *wal.Record, inBatch, allowEnvelope bool) error {
	// The admitted user-namespace ops are enumerated, not range-tested: the op
	// space is not contiguous (OpJournalEntry frames a whole PFJ3 entry for the
	// file-backed entry log and is never a user mutation), so a range check
	// would start admitting it the moment a later op was appended past it.
	if !userNamespaceOp(r.Op) {
		return invalidMutation("unknown or privileged WAL op %d", r.Op)
	}
	if !inBatch && r.Seq != 0 {
		return invalidMutation("caller supplied authority sequence")
	}
	if len(r.Mutations) != 0 {
		return invalidMutation("leaf mutation carries nested mutations")
	}
	if r.Env != nil {
		if !allowEnvelope {
			return invalidMutation("envelope supplied outside exact-mutation path")
		}
		if err := validateEnvelope(r.Env); err != nil {
			return err
		}
	}
	if strings.IndexByte(r.Path, 0) >= 0 || strings.IndexByte(r.NewPath, 0) >= 0 || strings.IndexByte(r.Target, 0) >= 0 {
		return invalidMutation("path or symlink target contains NUL")
	}
	r.Path = cleanPath(r.Path)
	r.NewPath = cleanPath(r.NewPath)

	var allowed recordFields
	switch r.Op {
	case wal.OpCreate:
		allowed = fieldPath | fieldMode | fieldEnvelope | fieldExcl
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
		if err := validateMode(r.Mode); err != nil {
			return err
		}
	case wal.OpWrite:
		allowed = fieldPath | fieldOffset | fieldData | fieldIno | fieldAppend | fieldEnvelope
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
		if r.Append && r.Offset != 0 {
			return invalidMutation("append write carries an ignored offset")
		}
		if err := validateWriteRange(r.Offset, len(r.Data), r.Append); err != nil {
			return err
		}
	case wal.OpTruncate:
		allowed = fieldPath | fieldSize | fieldIno | fieldEnvelope
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
		if r.Size < 0 {
			return invalidMutation("negative truncate size %d", r.Size)
		}
		if uint64(r.Size) > maxLogicalFileBytes {
			return invalidMutation("truncate size %d exceeds the %d-byte logical file bound", r.Size, maxLogicalFileBytes)
		}
	case wal.OpMkdir:
		allowed = fieldPath | fieldMode | fieldEnvelope | fieldExcl
		if r.Path == "" {
			return invalidMutation("mkdir path is empty/root")
		}
		if err := validateMode(r.Mode); err != nil {
			return err
		}
	case wal.OpRemove, wal.OpOrphan:
		allowed = fieldPath | fieldEnvelope
		if r.Path == "" {
			return invalidMutation("remove/orphan path is empty/root")
		}
	case wal.OpRename:
		allowed = fieldPath | fieldNewPath | fieldOrphanTarget | fieldEnvelope | fieldRenameNoReplace
		if r.Path == "" || r.NewPath == "" {
			return invalidMutation("rename source or destination is empty/root")
		}
		if r.RenameNoReplace && r.OrphanTarget {
			return invalidMutation("RENAME_NOREPLACE never parks a replaced destination (nothing may be replaced)")
		}
	case wal.OpLink:
		allowed = fieldPath | fieldNewPath | fieldIno | fieldEnvelope
		if r.Path == "" || r.NewPath == "" {
			return invalidMutation("link source or destination is empty/root")
		}
		if r.Path == r.NewPath {
			return invalidMutation("link source and destination are the same name")
		}
	case wal.OpSymlink:
		allowed = fieldPath | fieldTarget | fieldEnvelope | fieldExcl
		if r.Path == "" {
			return invalidMutation("symlink path is empty/root")
		}
		if len(r.Target) == 0 {
			return invalidMutation("symlink target is empty")
		}
		if len(r.Target) > maxSymlinkTargetBytes {
			return invalidMutation("symlink target exceeds %d bytes", maxSymlinkTargetBytes)
		}
	case wal.OpChmod:
		allowed = fieldPath | fieldMode | fieldIno | fieldEnvelope
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
		if err := validateMode(r.Mode); err != nil {
			return err
		}
	case wal.OpChtimes:
		allowed = fieldPath | fieldTimes | fieldIno | fieldEnvelope
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
		if !r.ChtimesSetAtime && r.AtimeMs != 0 {
			return invalidMutation("atime supplied without ChtimesSetAtime")
		}
		if r.ChtimesKeepMtime && !r.ChtimesSetAtime {
			return invalidMutation("ChtimesKeepMtime requires an atime update")
		}
	case wal.OpChown:
		allowed = fieldPath | fieldOwner | fieldIno | fieldEnvelope
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
	case wal.OpChflags:
		// Every uint32 is a legal flag word — including 0, which clears every
		// flag. Bit POLICY (which flags a mount may set) is decided client-side;
		// the authority persists what it was handed, so there is nothing to
		// validate here beyond the addressing.
		allowed = fieldPath | fieldFlags | fieldIno | fieldEnvelope
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
	case wal.OpReap:
		allowed = fieldIno | fieldReapCutoff | fieldEnvelope
		if r.Ino == 0 || r.Path != "" {
			return invalidMutation("reap requires a stable inode and no path")
		}
	case wal.OpSetxattr, wal.OpRemovexattr:
		allowed = fieldPath | fieldIno | fieldEnvelope | fieldXattrName
		if r.Op == wal.OpSetxattr {
			allowed |= fieldData | fieldXattrFlags
		}
		if err := requirePath(r.Path, r.Ino); err != nil {
			return err
		}
		if len(r.XattrName) == 0 || len(r.XattrName) > wal.MaxXattrNameBytes {
			return fmt.Errorf("vcs: invalid mutation: xattr name is %d bytes (want 1..%d): %w",
				len(r.XattrName), wal.MaxXattrNameBytes, syscall.ERANGE)
		}
		if strings.IndexByte(r.XattrName, 0) >= 0 || !utf8.ValidString(r.XattrName) {
			return invalidMutation("xattr name must be NUL-free UTF-8")
		}
		if r.Op == wal.OpSetxattr && len(r.Data) > wal.MaxXattrValueBytes {
			return fmt.Errorf("vcs: invalid mutation: xattr value is %d bytes (max %d): %w",
				len(r.Data), wal.MaxXattrValueBytes, syscall.E2BIG)
		}
		if r.XattrFlags&^wal.XattrFlagMask != 0 || r.XattrFlags == wal.XattrFlagMask {
			return invalidMutation("xattr flags %#x are invalid", r.XattrFlags)
		}
	default:
		return invalidMutation("unknown WAL op %d", r.Op)
	}
	if err := validateAllowedFields(*r, allowed); err != nil {
		return err
	}
	return validateIntroducedName(*r)
}

func requirePath(path string, ino uint64) error {
	if path == "" && ino == 0 {
		return invalidMutation("path-addressed mutation has an empty/root path")
	}
	return nil
}

func validateMode(mode uint32) error {
	if mode&^uint32(0o7777) != 0 {
		return invalidMutation("mode contains non-permission bits %#o", mode)
	}
	return nil
}

func validateWriteRange(off int64, length int, appendMode bool) error {
	if appendMode {
		// The resolved end offset is bounded at apply (a file cannot grow
		// past maxLogicalFileBytes there); the append payload itself is
		// bounded by the intent framing ceiling.
		return nil
	}
	if off < 0 {
		return invalidMutation("negative write offset %d", off)
	}
	if uint64(length) > uint64(math.MaxInt64) || off > math.MaxInt64-int64(length) {
		return invalidMutation("write range overflows int64")
	}
	// A live branch can never hold a file larger than PFT2 will materialize.
	if end := uint64(off) + uint64(length); end > maxLogicalFileBytes {
		return invalidMutation("write end %d exceeds the %d-byte logical file bound", end, maxLogicalFileBytes)
	}
	return nil
}

func validateEnvelope(env *wal.Envelope) error {
	if env == nil || env.SessionID == "" || len(env.SessionID) > 128 || env.SlotSeq == 0 {
		return invalidMutation("malformed exact-once envelope identity")
	}
	if len(env.ReqHash) != 32 {
		return invalidMutation("exact-once request hash has %d bytes; want 32", len(env.ReqHash))
	}
	return nil
}

func validateAllowedFields(r wal.Record, allowed recordFields) error {
	bad := func(field string) error { return invalidMutation("op %d carries unexpected %s", r.Op, field) }
	if allowed&fieldPath == 0 && r.Path != "" {
		return bad("Path")
	}
	if allowed&fieldNewPath == 0 && r.NewPath != "" {
		return bad("NewPath")
	}
	if allowed&fieldOffset == 0 && r.Offset != 0 {
		return bad("Offset")
	}
	if allowed&fieldSize == 0 && r.Size != 0 {
		return bad("Size")
	}
	if allowed&fieldMode == 0 && r.Mode != 0 {
		return bad("Mode")
	}
	if allowed&fieldTarget == 0 && r.Target != "" {
		return bad("Target")
	}
	if allowed&fieldData == 0 && len(r.Data) != 0 {
		return bad("Data")
	}
	if allowed&fieldTimes == 0 && (r.MtimeMs != 0 || r.AtimeMs != 0 || r.ChtimesSetAtime || r.ChtimesKeepMtime) {
		return bad("time fields")
	}
	if allowed&fieldOwner == 0 && (r.UID != 0 || r.GID != 0 || r.ChownSetUID || r.ChownSetGID) {
		return bad("owner fields")
	}
	if allowed&fieldFlags == 0 && r.Flags != 0 {
		return bad("Flags")
	}
	if allowed&fieldIno == 0 && r.Ino != 0 {
		return bad("Ino")
	}
	if allowed&fieldInos == 0 && len(r.Inos) != 0 {
		return bad("Inos")
	}
	if allowed&fieldOrphanTarget == 0 && r.OrphanTarget {
		return bad("OrphanTarget")
	}
	if allowed&fieldAppend == 0 && r.Append {
		return bad("Append")
	}
	if allowed&fieldReapCutoff == 0 && r.ReapIfLeaseExpiresByMs != 0 {
		return bad("ReapIfLeaseExpiresByMs")
	}
	if allowed&fieldEnvelope == 0 && r.Env != nil {
		return bad("Env")
	}
	if allowed&fieldExcl == 0 && r.Excl {
		return bad("Excl")
	}
	if allowed&fieldRenameNoReplace == 0 && r.RenameNoReplace {
		return bad("RenameNoReplace")
	}
	if allowed&fieldXattrName == 0 && r.XattrName != "" {
		return bad("XattrName")
	}
	if allowed&fieldXattrFlags == 0 && r.XattrFlags != 0 {
		return bad("XattrFlags")
	}
	return nil
}

func invalidMutation(format string, args ...any) error {
	return fmt.Errorf("vcs: invalid mutation: "+format+": %w", append(args, syscall.EINVAL)...)
}
