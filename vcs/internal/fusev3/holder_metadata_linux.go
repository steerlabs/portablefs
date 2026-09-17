//go:build linux

package fusev3

import (
	"context"
	"math"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// holderMetadata pins the exact grant until the physical reply settles. Only
// admission is transferred; operation, metadata and epoch locks never outlive
// this call. Retirement cannot discard an overlay represented by an unwritten
// inode size, and completion never needs a delegation lock acquisition.
func (r *rawFileSystem) holderMetadata(ctx context.Context, unique uint64, parent *inodeRecord, name string, record *inodeRecord, base *authoritypb.Attr, version uint64, out *fuse.Attr, fast bool) (bool, error) {
	m := r.mount.delegations
	for {
		m.epoch.RLock()
		s := m.lookupState(writeback.Identity(record.identity))
		if s == nil || m.incarnation() == 0 {
			m.epoch.RUnlock()
			return false, nil
		}
		if err := s.lockAfterRelease(ctx, delegationOperation); err != nil {
			m.epoch.RUnlock()
			return false, err
		}
		s.admission.RLock()
		unlock := func() { s.admission.RUnlock(); s.operation.Unlock(); m.epoch.RUnlock() }
		if s.ref == nil || fast && s.mode != authoritypb.DelegationMode_DELEGATION_MODE_FULL {
			unlock()
			return false, nil
		}
		s.meta.Lock()
		if base != nil {
			s.installBaseLocked(base, version)
		}
		current := s.base
		if current == nil || s.baseVersion == 0 || s.baseVersion < s.baseInvalidatedThrough {
			s.meta.Unlock()
			unlock()
			if !fast && base != nil {
				return false, syscall.EIO
			}
			return false, nil
		}
		attr := fuse.Attr{}
		fillAttr(current, &attr, r.mount.uid, r.mount.gid)
		overlay := m.buf.OverlayAttributes(s.identity, writeback.Attributes{HasMode: true, Mode: current.GetMode(), HasSize: true, Size: current.GetSize(), HasATime: true, ATimeNS: current.GetAtimeNs(), HasMTime: true, MTimeNS: current.GetMtimeNs(), HasCTime: true, CTimeNS: current.GetCtimeNs()})
		attr.Mode = kindMode(current.GetKind()) | overlay.Mode
		attr.Size = uint64(max(overlay.Size, 0))
		attr.Atime, attr.Atimensec, attr.Mtime, attr.Mtimensec, attr.Ctime, attr.Ctimensec = 0, 0, 0, 0, 0, 0
		setTime(overlay.ATimeNS, &attr.Atime, &attr.Atimensec)
		setTime(overlay.MTimeNS, &attr.Mtime, &attr.Mtimensec)
		setTime(overlay.CTimeNS, &attr.Ctime, &attr.Ctimensec)
		s.meta.Unlock()
		coordinate := publicationCoordinate{kind: publicationItemAttributes, item: record.identity}
		r.mu.Lock()
		p := r.replyPublications[unique]
		var source *sourcePublicationLease
		if p != nil {
			source = p.source
		}
		if record.stale.Load() || record.reclaimed || r.replyTerminal || r.replyTerminalizing || r.mount.revoked.Load() {
			r.mu.Unlock()
			unlock()
			return false, syscall.EIO
		}
		blocked := len(r.cacheReservations[coordinate]) != 0 || r.repairingCoordinates[coordinate] || !r.sourcePublicationAllowedLocked(coordinate, source)
		first, second, count := coordinate, publicationCoordinate{}, 1
		if parent != nil {
			key := nameKey{parent: parent.key.inode, name: name}
			first = publicationCoordinate{kind: publicationNamespaceName, parent: parent.identity, name: r.cachedNameStable[key].name}
			second, count = coordinate, 2
			if r.cachedNames[key] != record || parent.stale.Load() || record.lookups == math.MaxUint64 || !r.cachedCoordinateAllowedLocked(first, r.cachedNameStamps[key], time.Now()) {
				r.mu.Unlock()
				unlock()
				return false, nil
			}
		}
		if blocked {
			if fast {
				r.mu.Unlock()
				unlock()
				return false, nil
			}
			changed := r.sourceChangedWaitLocked()
			r.mu.Unlock()
			unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
		if fast {
			if !r.registerCachedReplyLocked(unique, first, second, count) {
				r.mu.Unlock()
				unlock()
				return false, nil
			}
			p = r.replyPublications[unique]
		} else if p == nil || p.holderAdmission != nil {
			r.mu.Unlock()
			unlock()
			return false, syscall.EIO
		}
		p.cachedCoordinates, p.cachedCount, p.holderAdmission = [2]publicationCoordinate{first, second}, count, s
		if fast && parent != nil {
			record.lookups++
			r.identityIndexLocked(record)[record.key] = record
		}
		*out = attr
		r.mu.Unlock()
		s.operation.Unlock()
		m.epoch.RUnlock()
		return true, nil
	}
}

func (n *node) publishHolderAttr(ctx context.Context, base *authoritypb.Attr, version uint64, out *fuse.AttrOut) (bool, syscall.Errno) {
	r, p := n.mount.raw, replyPublicationFromContext(ctx)
	if r == nil || p == nil {
		return false, 0
	}
	identity, ok := publicationIdentityFromItem(n.item)
	if !ok {
		return false, syscall.EIO
	}
	r.mu.Lock()
	record := r.byIdentityLocked(identity)
	r.mu.Unlock()
	if record == nil {
		if n.mount.delegations.Owns(identity[:]) {
			return false, syscall.EIO
		}
		return false, 0
	}
	owned, err := r.holderMetadata(ctx, p.requestUnique, nil, "", record, base, version, &out.Attr, false)
	if err != nil {
		return false, bufferErrno(err)
	}
	if owned {
		out.SetTimeout(0)
	}
	return owned, 0
}
