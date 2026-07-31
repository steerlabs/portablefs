package clientcore

import (
	"context"
	"strings"
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

// xattrHandleIno picks the handle addressing for ordinary item operations: a
// parked orphan is addressed by its stable ino; named items retain the
// write-back-aware path lane. Detached descriptors use the explicit exact
// methods below instead.
func xattrHandleIno(n *NodeState) uint64 { return n.Orphan() }

func (v *Volume) exactXattrTarget(n *NodeState) (uint64, Status) {
	ino := authHandleIno(n)
	if n == nil || !n.IsOpen() || ino == 0 {
		return 0, fsproto.ENOENT
	}
	return ino, fsproto.OK
}

// GetxattrExactHandle reads xattrs from a retained descriptor's inode without
// consulting the stale pathname or a replacement's write-back view.
func (v *Volume) GetxattrExactHandle(ctx context.Context, n *NodeState, name string) ([]byte, Status) {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer end()
	ino, st := v.exactXattrTarget(n)
	if st != fsproto.OK {
		return nil, st
	}
	value, wireStatus, err := v.client.GetxattrContext(authorityCtx, "", ino, name)
	if err != nil {
		return nil, fsproto.EIO
	}
	return value, wireStatus
}

func (v *Volume) ListxattrExactHandle(ctx context.Context, n *NodeState) ([]string, Status) {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer end()
	ino, st := v.exactXattrTarget(n)
	if st != fsproto.OK {
		return nil, st
	}
	names, wireStatus, err := v.client.ListxattrContext(authorityCtx, "", ino)
	if err != nil {
		return nil, fsproto.EIO
	}
	return names, wireStatus
}

// GetxattrOpenHandle uses path only to join a genuine alias's delegated view;
// the shared authority request is always pinned to the descriptor inode.
func (v *Volume) GetxattrOpenHandle(ctx context.Context, path string, n *NodeState, name string) ([]byte, Status) {
	path = cleanVolumePath(path)
	if path == "" {
		return v.GetxattrExactHandle(ctx, n, name)
	}
	if n == nil || !n.IsOpen() {
		return nil, fsproto.ENOENT
	}
	ino := authHandleIno(n)
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	if v.wb != nil && permit.Covers(path) {
		if ent, result := permit.Lookup(path); result != writeback.LookupHit ||
			(ent.Ino != 0 && ent.Ino != ino) {
			permit.Close()
			return v.GetxattrExactHandle(ctx, n, name)
		}
		if value, result := permit.Getxattr(path, name); result != writeback.LookupUndecided {
			if result == writeback.LookupNegative {
				return nil, fsproto.ENODATA
			}
			return value, fsproto.OK
		}
		permit.Close()
		return v.GetxattrExactHandle(ctx, n, name)
	}
	if ino == 0 {
		return nil, fsproto.ENOENT
	}
	resume := v.suspendAuthorityPublication(ctx)
	value, wireStatus, err := v.client.GetxattrContext(ctx, path, ino, name)
	resume()
	if err != nil {
		return nil, fsproto.EIO
	}
	return value, wireStatus
}

func (v *Volume) ListxattrOpenHandle(ctx context.Context, path string, n *NodeState) ([]string, Status) {
	path = cleanVolumePath(path)
	if path == "" {
		return v.ListxattrExactHandle(ctx, n)
	}
	if n == nil || !n.IsOpen() {
		return nil, fsproto.ENOENT
	}
	ino := authHandleIno(n)
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	if v.wb != nil && permit.Covers(path) {
		if ent, result := permit.Lookup(path); result != writeback.LookupHit ||
			(ent.Ino != 0 && ent.Ino != ino) {
			permit.Close()
			return v.ListxattrExactHandle(ctx, n)
		}
		if names, ok := permit.Listxattr(path); ok {
			return names, fsproto.OK
		}
		permit.Close()
		return v.ListxattrExactHandle(ctx, n)
	}
	if ino == 0 {
		return nil, fsproto.ENOENT
	}
	resume := v.suspendAuthorityPublication(ctx)
	names, wireStatus, err := v.client.ListxattrContext(ctx, path, ino)
	resume()
	if err != nil {
		return nil, fsproto.EIO
	}
	return names, wireStatus
}

func (v *Volume) SetxattrExactHandle(ctx context.Context, n *NodeState, name string, value []byte, flags uint8) Status {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return fsproto.EIO
	}
	defer end()
	if st := validateXattr(name, value, flags, true); st != fsproto.OK {
		return st
	}
	ino, st := v.exactXattrTarget(n)
	if st != fsproto.OK {
		return st
	}
	wireStatus, err := v.client.SetxattrFlagsContext(authorityCtx, "", ino, name, value, flags)
	if err != nil {
		return fsproto.EIO
	}
	return wireStatus
}

// SetxattrOpenHandle keeps locally-born, not-yet-authority-addressable objects
// in their delegated WAL. Once an authority inode exists, descriptor xattr
// mutations always use the pathless exact barrier: xattrs are rare, and no
// pathname scope can prove that an unseen hard-link alias has no acknowledged
// delegated state.
func (v *Volume) SetxattrOpenHandle(ctx context.Context, path string, n *NodeState, name string, value []byte, flags uint8) Status {
	path = cleanVolumePath(path)
	if path == "" || authHandleIno(n) != 0 {
		return v.SetxattrExactHandle(ctx, n, name, value, flags)
	}
	return v.SetxattrFlags(ctx, path, n, name, value, flags)
}

func (v *Volume) RemovexattrExactHandle(ctx context.Context, n *NodeState, name string) Status {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return fsproto.EIO
	}
	defer end()
	if st := validateXattr(name, nil, 0, false); st != fsproto.OK {
		return st
	}
	ino, st := v.exactXattrTarget(n)
	if st != fsproto.OK {
		return st
	}
	wireStatus, err := v.client.RemovexattrContext(authorityCtx, "", ino, name)
	if err != nil {
		return fsproto.EIO
	}
	return wireStatus
}

func (v *Volume) RemovexattrOpenHandle(ctx context.Context, path string, n *NodeState, name string) Status {
	path = cleanVolumePath(path)
	if path == "" || authHandleIno(n) != 0 {
		return v.RemovexattrExactHandle(ctx, n, name)
	}
	return v.Removexattr(ctx, path, n, name)
}

// Getxattr reads one extended attribute. ENODATA = attribute not present.
func (v *Volume) Getxattr(ctx context.Context, path string, n *NodeState, name string) ([]byte, Status) {
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	return v.getxattr(ctx, &permit, path, n, name)
}

func (v *Volume) getxattr(ctx context.Context, permit *readView, path string, n *NodeState, name string) ([]byte, Status) {
	if v.wb != nil && !v.isHardlink(n) && n.Orphan() == 0 {
		if value, result := permit.Getxattr(path, name); result != writeback.LookupUndecided {
			if result == writeback.LookupNegative {
				return nil, fsproto.ENODATA
			}
			return value, fsproto.OK
		}
	}
	covered := v.wb != nil && permit.Covers(path)
	var resume func()
	if !covered {
		resume = v.suspendAuthorityPublication(ctx)
	}
	value, st, err := v.client.GetxattrContext(ctx, path, xattrHandleIno(n), name)
	if resume != nil {
		resume()
	}
	if err != nil {
		return nil, fsproto.EIO
	}
	return value, st
}

// Listxattr lists extended-attribute names (sorted; empty = none).
func (v *Volume) Listxattr(ctx context.Context, path string, n *NodeState) ([]string, Status) {
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	return v.listxattr(ctx, &permit, path, n)
}

func (v *Volume) listxattr(ctx context.Context, permit *readView, path string, n *NodeState) ([]string, Status) {
	if v.wb != nil && !v.isHardlink(n) && n.Orphan() == 0 {
		if names, ok := permit.Listxattr(path); ok {
			return names, fsproto.OK
		}
	}
	covered := v.wb != nil && permit.Covers(path)
	var resume func()
	if !covered {
		resume = v.suspendAuthorityPublication(ctx)
	}
	names, st, err := v.client.ListxattrContext(ctx, path, xattrHandleIno(n))
	if resume != nil {
		resume()
	}
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
	ctx = withHardlinkAdmissionIdentities(ctx, n)
	if err := v.beginMutation(ctx); err != nil {
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
	authorityCtx, endAuthority, releaseErr := v.beginAuthorityMutation(
		ctx, []*NodeState{n}, path,
	)
	if releaseErr != nil {
		return statusErr(releaseErr)
	}
	st, err := v.client.SetxattrFlagsContext(authorityCtx, path, xattrHandleIno(n), name, value, flags)
	endAuthority()
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
	ctx = withHardlinkAdmissionIdentities(ctx, n)
	if err := v.beginMutation(ctx); err != nil {
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
	authorityCtx, endAuthority, releaseErr := v.beginAuthorityMutation(
		ctx, []*NodeState{n}, path,
	)
	if releaseErr != nil {
		return statusErr(releaseErr)
	}
	st, err := v.client.RemovexattrContext(authorityCtx, path, xattrHandleIno(n), name)
	endAuthority()
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
