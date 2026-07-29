package portablefsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

var errLegacyAdoptionConflict = errors.New("portablefsd: legacy adoption conflict")

// legacyAdoptionConflictError is deliberately distinguishable from a
// transient transport/status failure. An attach must park this WAL for
// operator inspection: replay cannot prove that an existing name is the
// object recorded in the adopted log.
type legacyAdoptionConflictError struct {
	Op     wal.Op
	Path   string
	Reason string
}

func (e *legacyAdoptionConflictError) Error() string {
	return fmt.Sprintf("%v: %s %q: %s", errLegacyAdoptionConflict, opName(e.Op), e.Path, e.Reason)
}

func (e *legacyAdoptionConflictError) Unwrap() error { return errLegacyAdoptionConflict }

// Legacy write-back drain: WAL stores written by the retired per-session
// engine hold path-addressed PFR1 records in sess-*.wal files. The v5 engine
// records its own streams as PFW5 segments and never reads these, so an
// attach drains any adopted legacy log itself: replay the surviving records
// through the volume's ordinary (adaptive) mutation surface in order, mark
// durable progress per record, and remove the log after a final authority
// barrier. A record the current tree refuses parks the log — visible in
// status, retried in the background, never silently dropped.

// legacyWALs lists the adopted sess-*.wal logs in this attach's store.
func (a *attach) legacyWALs() []string {
	dir := filepath.Join(a.stateDir, "wal", a.storageID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "sess-") && strings.HasSuffix(name, ".wal") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	sort.Strings(out)
	return out
}

// drainLegacyWALs replays every adopted legacy log before the attach can
// publish its live volume. Any surviving debt blocks readiness: pre-v5 logs
// carry no durable scope fencing, so serving beside an unresolved log could
// race new mutations against an ambiguous replay. Every failed log and its
// sidecar remain in place and the wrapped error stays distinguishable.
func (a *attach) drainLegacyWALs(ctx context.Context, vol *clientcore.Volume) error {
	paths := a.legacyWALs()
	if len(paths) == 0 {
		a.setLegacyParked(nil)
		return nil
	}
	var parked []parkedWAL
	var failures []error
	for _, p := range paths {
		if err := a.drainOneLegacyWAL(ctx, vol, p); err != nil {
			log.Printf("portablefsd: legacy write-back WAL %s not drained: %v (preserved; attach readiness blocked)", p, err)
			parked = append(parked, parkedWAL{WAL: p, LastError: err.Error()})
			failures = append(failures, fmt.Errorf("%s: %w", p, err))
			continue
		}
	}
	a.setLegacyParked(parked)
	if len(failures) > 0 {
		return fmt.Errorf("legacy write-back debt blocks attach readiness: %w", errors.Join(failures...))
	}
	return nil
}

func (a *attach) setLegacyParked(parked []parkedWAL) {
	a.mu.Lock()
	a.legacyParked = parked
	a.mu.Unlock()
}

// legacyDrainState is the per-log sidecar that makes append replay EXACT
// across crashes: appends convert to offset-addressed writes at
// deterministically assigned offsets, so re-applying a record after a crash
// writes the same bytes at the same offset instead of appending twice.
type legacyDrainState struct {
	path string
	// NextOffset is each path's next append offset; LastAppliedSeq is the
	// highest legacy record sequence whose append already applied.
	NextOffset     map[string]int64  `json:"nextOffset"`
	LastAppliedSeq map[string]uint64 `json:"lastAppliedSeq"`
}

func loadLegacyDrainState(walPath string) *legacyDrainState {
	st := &legacyDrainState{
		path:       walPath + ".drain.json",
		NextOffset: map[string]int64{}, LastAppliedSeq: map[string]uint64{},
	}
	if b, err := os.ReadFile(st.path); err == nil {
		_ = json.Unmarshal(b, st)
		if st.NextOffset == nil {
			st.NextOffset = map[string]int64{}
		}
		if st.LastAppliedSeq == nil {
			st.LastAppliedSeq = map[string]uint64{}
		}
	}
	return st
}

// persist writes the sidecar durably (atomic replace + fsync) BEFORE drain
// progress is marked, so the offset assignment survives any crash point.
func (st *legacyDrainState) persist() error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Rename(tmp, st.path)
}

// drainOneLegacyWAL replays one log's surviving records in order and removes
// it after a successful authority barrier. Progress is durable per record
// (CompactThrough), so a crash or parked failure resumes at the exact
// uncovered suffix; the sidecar keeps append replay idempotent across every
// crash point.
func (a *attach) drainOneLegacyWAL(ctx context.Context, vol *clientcore.Volume, path string) error {
	w, err := wal.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	records, err := w.Replay()
	if err != nil {
		_ = w.Close()
		return fmt.Errorf("replay: %w", err)
	}
	drain := loadLegacyDrainState(path)
	for _, r := range records {
		if err := applyLegacyRecord(ctx, vol, drain, r); err != nil {
			_ = w.Close()
			return fmt.Errorf("record %d (%s %q): %w", r.Seq, opName(r.Op), r.Path, err)
		}
		if err := w.CompactThrough(r.Seq + 1); err != nil {
			_ = w.Close()
			return fmt.Errorf("mark progress at %d: %w", r.Seq, err)
		}
	}
	_ = w.Close()
	if err := vol.FlushToAuthority(ctx); err != nil {
		return fmt.Errorf("authority barrier: %w", err)
	}
	if err := wal.RemoveFiles(path); err != nil {
		return fmt.Errorf("remove drained log: %w", err)
	}
	_ = os.Remove(drain.path)
	log.Printf("portablefsd: drained legacy write-back WAL %s (%d record(s))", path, len(records))
	return nil
}

// applyLegacyRecord executes one legacy record through the volume surface.
// Existing create/mkdir/symlink names are adopted only when a stable inode
// identity in the record proves that the existing object is the one this
// replay previously created; kind (and symlink target) must also match.
// Identity-less existing names park with a typed conflict instead of being
// silently merged. Appends are converted to offset-addressed writes at
// deterministically assigned (sidecar-persisted) offsets, so a crash-resumed
// replay re-applies the same bytes at the same offset — never a double
// append. Link EEXIST is accepted only when the existing destination IS the
// source inode.
func applyLegacyRecord(ctx context.Context, vol *clientcore.Volume, drain *legacyDrainState, r wal.Record) error {
	switch r.Op {
	case wal.OpBatch:
		for _, m := range r.Mutations {
			if err := applyLegacyRecord(ctx, vol, drain, m); err != nil {
				return err
			}
		}
		return nil
	case wal.OpMkdir:
		return applyLegacyMkdir(ctx, vol, r)
	case wal.OpCreate:
		return applyLegacyCreate(ctx, vol, r)
	case wal.OpWrite:
		if r.Append {
			return applyLegacyAppend(ctx, vol, drain, r)
		}
		n, st := legacyNode(ctx, vol, r.Path)
		if st != fsproto.OK {
			return legacyStatusErr(st)
		}
		_, st = vol.Write(ctx, r.Path, n, r.Offset, r.Data)
		return legacyStatusErr(st)
	case wal.OpTruncate:
		return legacySetattr(ctx, vol, r.Path, clientcore.SetattrRequest{Size: r.Size, SetSize: true})
	case wal.OpChmod:
		return legacySetattr(ctx, vol, r.Path, clientcore.SetattrRequest{Mode: r.Mode, SetMode: true})
	case wal.OpChtimes:
		return legacySetattr(ctx, vol, r.Path, clientcore.SetattrRequest{MtimeMs: r.MtimeMs, SetMTime: true})
	case wal.OpChown:
		req := clientcore.SetattrRequest{UID: r.UID, GID: r.GID}
		req.SetUID = r.ChownSetUID || (!r.ChownSetUID && !r.ChownSetGID)
		req.SetGID = r.ChownSetGID || (!r.ChownSetUID && !r.ChownSetGID)
		return legacySetattr(ctx, vol, r.Path, req)
	case wal.OpRemove, wal.OpOrphan:
		// The writing process is gone, so an orphan record's open handle is
		// too: the parked inode would only be reaped — remove is the settled
		// outcome.
		if st := vol.Remove(ctx, r.Path, nil); st != fsproto.ENOENT {
			return legacyStatusErr(st)
		}
		return nil
	case wal.OpRename:
		st := vol.Rename(ctx, r.Path, r.NewPath, nil, nil)
		return legacyStatusErr(st)
	case wal.OpSymlink:
		return applyLegacySymlink(ctx, vol, r)
	case wal.OpLink:
		_, st := vol.Link(ctx, r.Path, r.NewPath, nil)
		if st == fsproto.EEXIST {
			// Accept EEXIST only when the existing destination IS the source
			// inode (this link already applied). A different inode at the
			// destination is a conflict — never silently merge with an
			// unrelated existing name.
			src, sst := vol.Lookup(ctx, r.Path)
			dst, dst2 := vol.Lookup(ctx, r.NewPath)
			if sst == fsproto.OK && dst2 == fsproto.OK && src.Ino != 0 && src.Ino == dst.Ino {
				return nil
			}
			return fmt.Errorf("link destination %q exists with a different inode (want %d)", r.NewPath, src.Ino)
		}
		return legacyStatusErr(st)
	case wal.OpSetxattr:
		return legacyStatusErr(vol.Setxattr(ctx, r.Path, nil, r.XattrName, r.Data))
	case wal.OpRemovexattr:
		if st := vol.Removexattr(ctx, r.Path, nil, r.XattrName); st != fsproto.ENODATA {
			return legacyStatusErr(st)
		}
		return nil
	case wal.OpReap, wal.OpControl, wal.OpJournalEntry:
		return nil // lifecycle/control records have no replayable user mutation
	default:
		return fmt.Errorf("unknown legacy op %d", r.Op)
	}
}

func applyLegacyCreate(ctx context.Context, vol *clientcore.Volume, r wal.Record) error {
	exists, err := legacyPreflight(ctx, vol, r)
	if err != nil || exists {
		return err
	}
	if ino, ok := legacyStableIdentity(r); ok {
		// CreateExcl is atomic but cannot prescribe the inode carried by a
		// legacy record. Fail before mutation rather than change identity.
		return legacyConflict(r, "name is absent and create cannot preserve recorded inode %d", ino)
	}
	// Unlike Create, CreateExcl cannot report OK after adopting an unrelated
	// existing name. It closes the check/create race at the strongest
	// available clientcore layer.
	_, st := vol.CreateExcl(ctx, r.Path, r.Mode)
	switch st {
	case fsproto.OK:
		return verifyLegacyShape(ctx, vol, r, 0)
	case fsproto.EEXIST:
		// A concurrent creator won after the preflight. It is safe only if
		// the WAL carries an identity that proves this is a resumed replay.
		return verifyLegacyExisting(ctx, vol, r)
	default:
		return legacyStatusErr(st)
	}
}

func applyLegacyMkdir(ctx context.Context, vol *clientcore.Volume, r wal.Record) error {
	exists, err := legacyPreflight(ctx, vol, r)
	if err != nil || exists {
		return err
	}
	if ino, ok := legacyStableIdentity(r); ok {
		// Volume.Mkdir cannot request a prescribed inode. Creating a
		// different identity would make later handle-addressed records refer
		// to the wrong object, so leave both the namespace and WAL untouched.
		return legacyConflict(r, "name is absent and mkdir cannot preserve recorded inode %d", ino)
	}
	_, st := vol.Mkdir(ctx, r.Path, r.Mode)
	switch st {
	case fsproto.OK:
		// Mkdir is currently non-exclusive and may return OK for an existing
		// object. The absence preflight is the available creation proof; the
		// postflight still rejects a raced wrong-kind object.
		return verifyLegacyShape(ctx, vol, r, 0)
	case fsproto.EEXIST:
		return verifyLegacyExisting(ctx, vol, r)
	default:
		return legacyStatusErr(st)
	}
}

func applyLegacySymlink(ctx context.Context, vol *clientcore.Volume, r wal.Record) error {
	exists, err := legacyPreflight(ctx, vol, r)
	if err != nil || exists {
		return err
	}
	if ino, ok := legacyStableIdentity(r); ok {
		// Volume.Symlink cannot request a prescribed inode. Do not silently
		// replace that identity with a fresh authority allocation.
		return legacyConflict(r, "name is absent and symlink cannot preserve recorded inode %d", ino)
	}
	_, st := vol.Symlink(ctx, r.Target, r.Path)
	switch st {
	case fsproto.OK:
		// Symlink is non-exclusive today. Verify both the resulting kind and
		// target so a raced object with different semantics is never adopted.
		return verifyLegacyShape(ctx, vol, r, 0)
	case fsproto.EEXIST:
		return verifyLegacyExisting(ctx, vol, r)
	default:
		return legacyStatusErr(st)
	}
}

// legacyPreflight reports whether the requested name already existed. When it
// does, err is the verification result: nil only for a provably identical
// object.
func legacyPreflight(ctx context.Context, vol *clientcore.Volume, r wal.Record) (exists bool, err error) {
	_, st := vol.Lookup(ctx, r.Path)
	switch st {
	case fsproto.OK:
		return true, verifyLegacyExisting(ctx, vol, r)
	case fsproto.ENOENT:
		return false, nil
	default:
		return false, legacyStatusErr(st)
	}
}

func verifyLegacyExisting(ctx context.Context, vol *clientcore.Volume, r wal.Record) error {
	ino, ok := legacyStableIdentity(r)
	if !ok {
		return legacyConflict(r, "existing name cannot be proven without a stable recorded inode")
	}
	return verifyLegacyShape(ctx, vol, r, ino)
}

// verifyLegacyShape verifies the observable identity and semantics of a
// create-like object. wantIno == 0 means the immediately preceding operation
// created an identity-less legacy record after an ENOENT preflight.
func verifyLegacyShape(ctx context.Context, vol *clientcore.Volume, r wal.Record, wantIno uint64) error {
	attr, st := vol.Lookup(ctx, r.Path)
	if st != fsproto.OK {
		return legacyStatusErr(st)
	}
	wantKind := ""
	switch r.Op {
	case wal.OpCreate:
		wantKind = "file"
	case wal.OpMkdir:
		wantKind = "directory"
	case wal.OpSymlink:
		wantKind = "symlink"
	default:
		return legacyConflict(r, "cannot verify unsupported create-like op")
	}
	if attr.Kind != wantKind {
		return legacyConflict(r, "existing kind is %q, want %q", attr.Kind, wantKind)
	}
	if wantIno != 0 {
		if attr.Ino == 0 {
			return legacyConflict(r, "existing %s has no stable authority inode, want %d", wantKind, wantIno)
		}
		if attr.Ino != wantIno {
			return legacyConflict(r, "existing inode is %d, want recorded inode %d", attr.Ino, wantIno)
		}
	}
	if r.Op == wal.OpSymlink {
		target, rst := vol.Readlink(ctx, r.Path)
		if rst != fsproto.OK {
			return legacyStatusErr(rst)
		}
		if target != r.Target {
			return legacyConflict(r, "existing symlink target is %q, want %q", target, r.Target)
		}
	}
	return nil
}

func legacyStableIdentity(r wal.Record) (uint64, bool) {
	switch r.Op {
	case wal.OpCreate, wal.OpSymlink:
		return r.Ino, r.Ino != 0
	case wal.OpMkdir:
		if r.Excl {
			return r.Ino, r.Ino != 0
		}
		clean := strings.Trim(r.Path, "/")
		if clean == "" {
			return 0, false
		}
		parts := strings.Split(clean, "/")
		if len(r.Inos) != len(parts) {
			return 0, false
		}
		ino := r.Inos[len(r.Inos)-1]
		return ino, ino != 0
	default:
		return 0, false
	}
}

func legacyConflict(r wal.Record, format string, args ...any) error {
	return &legacyAdoptionConflictError{
		Op: r.Op, Path: r.Path, Reason: fmt.Sprintf(format, args...),
	}
}

// applyLegacyAppend replays one legacy O_APPEND record exactly-once across
// crash resumes: the append converts to an offset write at a
// deterministically assigned offset — persisted BEFORE progress marks — so
// re-applying the record writes the same bytes at the same offset
// (idempotent) instead of appending twice.
func applyLegacyAppend(ctx context.Context, vol *clientcore.Volume, drain *legacyDrainState, r wal.Record) error {
	if last, ok := drain.LastAppliedSeq[r.Path]; ok && r.Seq != 0 && r.Seq <= last {
		return nil // applied before a crash that lost the progress mark
	}
	off, ok := drain.NextOffset[r.Path]
	if !ok {
		// First append for this path in this drain: anchor at the CURRENT
		// authority size and persist the anchor before any apply.
		attr, st := vol.Lookup(ctx, r.Path)
		if st != fsproto.OK {
			return legacyStatusErr(st)
		}
		off = attr.Size
		drain.NextOffset[r.Path] = off
		if err := drain.persist(); err != nil {
			return fmt.Errorf("persist drain anchor: %w", err)
		}
	}
	n, st := legacyNode(ctx, vol, r.Path)
	if st != fsproto.OK {
		return legacyStatusErr(st)
	}
	if _, st := vol.Write(ctx, r.Path, n, off, r.Data); st != fsproto.OK {
		return legacyStatusErr(st)
	}
	drain.NextOffset[r.Path] = off + int64(len(r.Data))
	drain.LastAppliedSeq[r.Path] = r.Seq
	if err := drain.persist(); err != nil {
		return fmt.Errorf("persist drain progress: %w", err)
	}
	return nil
}

func legacyNode(ctx context.Context, vol *clientcore.Volume, path string) (*clientcore.NodeState, int32) {
	attr, st := vol.Lookup(ctx, path)
	if st != fsproto.OK {
		return nil, st
	}
	return clientcore.NewNodeState(attr.Ino, attr.Ino != 0), fsproto.OK
}

func legacySetattr(ctx context.Context, vol *clientcore.Volume, path string, req clientcore.SetattrRequest) error {
	n, st := legacyNode(ctx, vol, path)
	if st != fsproto.OK {
		return legacyStatusErr(st)
	}
	_, st = vol.Setattr(ctx, path, n, req)
	return legacyStatusErr(st)
}

func legacyStatusErr(st int32) error {
	if st == fsproto.OK {
		return nil
	}
	return fmt.Errorf("status %d", st)
}

func opName(op wal.Op) string {
	names := map[wal.Op]string{
		wal.OpCreate: "create", wal.OpWrite: "write", wal.OpTruncate: "truncate",
		wal.OpMkdir: "mkdir", wal.OpRemove: "remove", wal.OpRename: "rename",
		wal.OpSymlink: "symlink", wal.OpChmod: "chmod", wal.OpChtimes: "chtimes",
		wal.OpChown: "chown", wal.OpOrphan: "orphan", wal.OpReap: "reap",
		wal.OpBatch: "batch", wal.OpLink: "link", wal.OpSetxattr: "setxattr",
		wal.OpRemovexattr: "removexattr",
	}
	if n, ok := names[op]; ok {
		return n
	}
	return fmt.Sprintf("op-%d", op)
}
