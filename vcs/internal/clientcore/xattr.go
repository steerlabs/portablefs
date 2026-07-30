package clientcore

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Extended attributes (baseline in fsproto v8).
//
// Coherence/durability model (documented in docs/consistency-model.md):
//
//   - Existing authority objects stay read-through. Objects created under a
//     delegation have a complete empty xattr view from birth, so their
//     get/list/set/remove operations can stay in the same WAL-backed local
//     lane as create/write.
//
//   - Existing objects without a complete xattr view conservatively use the
//     authority lane. This is required to prove conditional flags and the
//     per-inode total-byte limit before acknowledging a local set.

// xattrHandleIno picks the handle addressing for xattr ops: a parked orphan
// is addressed by its stable ino (the name is gone); named paths stay
// path-addressed like chmod.
func xattrHandleIno(n *NodeState) uint64 { return n.Orphan() }

// Getxattr reads one extended attribute. ENODATA = attribute not present.
func (v *Volume) Getxattr(ctx context.Context, path string, n *NodeState, name string) ([]byte, Status) {
	if v.wb != nil && !v.isHardlink(n) && n.Orphan() == 0 {
		if value, result := v.wb.Getxattr(path, name); result != writeback.LookupUndecided {
			if result == writeback.LookupNegative {
				return nil, fsproto.ENODATA
			}
			return value, fsproto.OK
		}
	}
	value, st, err := v.client.Getxattr(path, xattrHandleIno(n), name)
	if err != nil {
		return nil, fsproto.EIO
	}
	return value, st
}

// Listxattr lists extended-attribute names (sorted; empty = none).
func (v *Volume) Listxattr(ctx context.Context, path string, n *NodeState) ([]string, Status) {
	if v.wb != nil && !v.isHardlink(n) && n.Orphan() == 0 {
		if names, ok := v.wb.Listxattr(path); ok {
			return names, fsproto.OK
		}
	}
	names, st, err := v.client.Listxattr(path, xattrHandleIno(n))
	if err != nil {
		return nil, fsproto.EIO
	}
	return names, st
}

// Setxattr creates-or-overwrites one extended attribute. A locally-born
// object's complete xattr map stays in its delegated WAL; all other objects
// use the exact authority lane.
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

	if st := validateXattr(name, value, flags, true); st != fsproto.OK {
		return st
	}
	if v.wb != nil && !v.isHardlink(n) && n.Orphan() == 0 {
		handled, err := v.wb.Setxattr(ctx, path, name, value, flags)
		if handled {
			if err != nil {
				return statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return fsproto.OK
		}
		if err != nil {
			return statusErr(err)
		}
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

// Removexattr removes one extended attribute. ENODATA when absent.
func (v *Volume) Removexattr(ctx context.Context, path string, n *NodeState, name string) Status {
	if err := v.beginMutation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	if st := validateXattr(name, nil, 0, false); st != fsproto.OK {
		return st
	}
	if v.wb != nil && !v.isHardlink(n) && n.Orphan() == 0 {
		handled, err := v.wb.Removexattr(ctx, path, name)
		if handled {
			if err != nil {
				return statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return fsproto.OK
		}
		if err != nil {
			return statusErr(err)
		}
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

func validateXattr(name string, value []byte, flags uint8, set bool) Status {
	if name == "" || strings.IndexByte(name, 0) >= 0 || !utf8.ValidString(name) {
		return fsproto.EINVAL
	}
	if len(name) > wal.MaxXattrNameBytes {
		return fsproto.ERANGE
	}
	if set && len(value) > wal.MaxXattrValueBytes {
		return fsproto.E2BIG
	}
	if flags&^wal.XattrFlagMask != 0 || flags == wal.XattrFlagMask || (!set && flags != 0) {
		return fsproto.EINVAL
	}
	return fsproto.OK
}

// flushCoveringSession drains and releases any delegation before an
// operation that must use the authority lane (existing-object xattrs,
// hardlink aliases, and parked orphans).
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
