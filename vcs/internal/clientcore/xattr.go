package clientcore

import (
	"context"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Extended attributes (baseline in fsproto v6).
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

// xattrHandleIno picks the handle addressing for xattr ops: a parked orphan
// is addressed by its stable ino (the name is gone); named paths stay
// path-addressed like chmod.
func xattrHandleIno(n *NodeState) uint64 { return n.Orphan() }

// Getxattr reads one extended attribute. ENODATA = attribute not present.
func (v *Volume) Getxattr(ctx context.Context, path string, n *NodeState, name string) ([]byte, Status) {
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
	if err := v.beginMutation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	if flags&^wal.XattrFlagMask != 0 || flags == wal.XattrFlagMask {
		return fsproto.EINVAL
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
		n.markDirty()
	}
	return st
}

// Removexattr removes one extended attribute, write-through. ENODATA when absent.
func (v *Volume) Removexattr(ctx context.Context, path string, n *NodeState, name string) Status {
	if err := v.beginMutation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	if st := v.flushCoveringSession(path); st != fsproto.OK {
		return st
	}
	st, err := v.client.Removexattr(path, xattrHandleIno(n), name)
	if err != nil {
		return fsproto.EIO
	}
	if st == fsproto.OK {
		v.recent.record(path)
		n.markDirty()
	}
	return st
}

// flushCoveringSession drains and RELEASES any delegation covering path:
// xattr mutations are write-through only, and a write-through mutation never
// runs inside a held delegation. A no-op without a covering delegation.
func (v *Volume) flushCoveringSession(path string) Status {
	if v.wb == nil {
		return fsproto.OK
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := v.wb.ReleaseFor(ctx, path); err != nil {
		return statusErr(err)
	}
	return fsproto.OK
}

// xattrLocalOnly reports whether path exists ONLY in the engine's
// acknowledged state (its create has not flushed). In that window the file
// truthfully has no xattrs — every xattr mutation flushes first — so reads
// answer "no attributes" instead of a confusing ENOENT for a file the kernel
// just created.
func (v *Volume) xattrLocalOnly(path string) (Status, bool) {
	if v.wb == nil {
		return 0, false
	}
	if ent, res := v.wb.Lookup(path); res == writeback.LookupHit && ent.Kind != "" {
		return fsproto.ENODATA, true
	}
	return 0, false
}
