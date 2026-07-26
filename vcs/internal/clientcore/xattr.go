package clientcore

import (
	"context"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// Extended attributes, capability-gated on FeatXattrs.
//
// Coherence/durability model (documented in docs/consistency-model.md):
//
//   - Reads (get/list) are pure read-through: every call reaches the
//     authority (nothing caches xattr bytes client-side), so a mount
//     observes its own mutations read-after-write and remote mutations as
//     soon as the authority applied them. Remote xattr changes additionally
//     publish an in-place (attr-level) invalidation, which keeps
//     version-gated attr caches honest.
//
//   - Mutations are WRITE-THROUGH even on write-back mounts: sessions never
//     buffer xattr intents at this stage (simpler and honest — a buffered
//     xattr would otherwise need base-image and flush-path carriage). On a
//     write-back-covered path the covering session is flushed FIRST, so a
//     locally buffered create exists at the authority before its xattr
//     lands; the extra flush round-trip is the documented cost.
//
//   - Against an authority without FeatXattrs every op answers EOPNOTSUPP
//     locally (no wire attempt), so kernels keep today's fallback behavior
//     (e.g. macOS AppleDouble ._ sidecars).

// SupportsXattrs reports whether the attached authority serves native
// extended attributes (FeatXattrs).
func (v *Volume) SupportsXattrs() bool { return v.client.SupportsXattrs() }

// xattrHandleIno picks the handle addressing for xattr ops: a parked orphan
// is addressed by its stable ino (the name is gone); named paths stay
// path-addressed like chmod.
func xattrHandleIno(n *NodeState) uint64 { return n.Orphan() }

// Getxattr reads one extended attribute. ENODATA = attribute not present.
func (v *Volume) Getxattr(ctx context.Context, path string, n *NodeState, name string) ([]byte, Status) {
	if !v.SupportsXattrs() {
		return nil, fsproto.EOPNOTSUPP
	}
	value, st, err := v.client.Getxattr(path, xattrHandleIno(n), name)
	if err != nil {
		return nil, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if st2, ok := v.xattrLocalOnly(path); ok {
			return nil, st2 // exists locally, unflushed, has no xattrs: honest ENODATA
		}
	}
	return value, st
}

// Listxattr lists extended-attribute names (sorted; empty = none).
func (v *Volume) Listxattr(ctx context.Context, path string, n *NodeState) ([]string, Status) {
	if !v.SupportsXattrs() {
		return nil, fsproto.EOPNOTSUPP
	}
	names, st, err := v.client.Listxattr(path, xattrHandleIno(n))
	if err != nil {
		return nil, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if _, ok := v.xattrLocalOnly(path); ok {
			return nil, fsproto.OK // exists locally, unflushed: truthfully no xattrs yet
		}
	}
	return names, st
}

// Setxattr creates-or-overwrites one extended attribute, write-through.
func (v *Volume) Setxattr(ctx context.Context, path string, n *NodeState, name string, value []byte) Status {
	return v.SetxattrFlags(ctx, path, n, name, value, 0)
}

// SetxattrFlags evaluates XattrCreate/XattrReplace in the same ordered
// authority mutation as the set. It performs no client-side existence read.
func (v *Volume) SetxattrFlags(ctx context.Context, path string, n *NodeState, name string, value []byte, flags uint8) Status {
	if !v.SupportsXattrs() {
		return fsproto.EOPNOTSUPP
	}
	if flags&^wal.XattrFlagMask != 0 || flags == wal.XattrFlagMask {
		return fsproto.EINVAL
	}
	if flags != 0 && !v.client.SupportsAtomicXattrFlags() {
		return fsproto.EOPNOTSUPP
	}
	if st := v.flushCoveringSession(path); st != fsproto.OK {
		return st
	}
	st, err := v.client.SetxattrFlags(path, xattrHandleIno(n), name, value, flags)
	if err != nil {
		return fsproto.EIO
	}
	if st == fsproto.OK {
		v.recent.record(path)
	}
	return st
}

// Removexattr removes one extended attribute, write-through. ENODATA when absent.
func (v *Volume) Removexattr(ctx context.Context, path string, n *NodeState, name string) Status {
	if !v.SupportsXattrs() {
		return fsproto.EOPNOTSUPP
	}
	if st := v.flushCoveringSession(path); st != fsproto.OK {
		return st
	}
	st, err := v.client.Removexattr(path, xattrHandleIno(n), name)
	if err != nil {
		return fsproto.EIO
	}
	if st == fsproto.OK {
		v.recent.record(path)
	}
	return st
}

// flushCoveringSession makes a write-back-covered path's buffered state
// (typically its create) durable at the authority before a write-through
// xattr mutation targets it. A no-op without sessions, without a covering
// session, or when nothing is pending.
func (v *Volume) flushCoveringSession(path string) Status {
	if v.sessions == nil {
		return fsproto.OK
	}
	s := v.sessions.For(path)
	if s == nil {
		return fsproto.OK
	}
	if err := s.Flush(); err != nil {
		return statusErr(err)
	}
	if s.IsSuperseded() {
		// A superseded session's Flush is a silent no-op; its buffered create
		// may never have reached the authority. Fail the mutation honestly.
		return fsproto.ESTALE
	}
	return fsproto.OK
}

// xattrLocalOnly reports whether path exists ONLY in a covering write-back
// session's buffered state (its create has not flushed). In that window the
// file truthfully has no xattrs — every xattr mutation flushes first — so
// reads answer "no attributes" instead of a confusing ENOENT for a file the
// kernel just created.
func (v *Volume) xattrLocalOnly(path string) (Status, bool) {
	if v.sessions == nil {
		return 0, false
	}
	s := v.sessions.For(path)
	if s == nil {
		return 0, false
	}
	if kind, _, _, _, _, _, ok := s.LocalStat(path); ok && kind != "" {
		return fsproto.ENODATA, true
	}
	return 0, false
}
