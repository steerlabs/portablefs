//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sort"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// A cold fence is recoverable. Read-only publication callers must distinguish
// this interruption from a broken publication invariant which revokes a mount.
var errMetadataInterrupted = errors.New("fusev3: metadata subscription interrupted")

// holderMetadata pins the exact grant until the physical reply settles. Only
// admission and the state reference are transferred; metadata and epoch locks
// never outlive this call. Source coordinates serialize local mutations, so
// sampling needs no operation lock (a directory page may pin several files).
// Retirement cannot discard an overlay represented by an unwritten inode size.
func (r *rawFileSystem) holderMetadata(ctx context.Context, unique uint64, parent *inodeRecord, name string, record *inodeRecord, base *authoritypb.Attr, version uint64, out *fuse.Attr, fast bool) (bool, bool, error) {
	m := r.mount.delegations
	publication := replyPublicationFromContext(ctx)
	var sample uint64
	if publication != nil {
		sample = publication.metadataSample
	}
	for {
		m.epoch.RLock()
		s := m.retainState(writeback.Identity(record.identity), base != nil)
		if m.incarnation() == 0 {
			m.releaseState(s)
			m.epoch.RUnlock()
			if fast {
				return false, false, nil
			}
			// Admission has been interrupted ahead of the callback drain.
			// Falling back to storage here would discard the old overlay before
			// reset accounts for it and could publish an older inode size.
			return false, false, errMetadataInterrupted
		}
		if s == nil {
			m.epoch.RUnlock()
			return false, false, nil
		}
		s.admission.RLock()
		unlock := func() { s.admission.RUnlock(); m.releaseState(s); m.epoch.RUnlock() }
		owned := s.ref != nil
		if fast && (!owned || s.mode != authoritypb.DelegationMode_DELEGATION_MODE_FULL) || !owned && base == nil {
			unlock()
			return false, false, nil
		}
		// Storage can have sampled a holder's unflushed size. If a clean
		// release or replacement crossed that sample, overlaying only the
		// current grant would silently publish the older size. Resample only
		// this identity, with no ownership lock held and the callback's fixed
		// deadline; concurrent churn cannot extend the request indefinitely.
		if base != nil && publication != nil && publication.postState == nil && s.ownershipVersion > sample {
			unlock()
			sample = m.metadataClock.Load()
			response, errno := record.node.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: cloneBytes(record.node.item.GetToken())}}})
			if errno != 0 {
				return false, false, errno
			}
			reply := response.GetGetAttr()
			if reply.GetAttr() == nil || reply.GetObjectVersion() == 0 || reply.GetSnapshotSequence() < reply.GetObjectVersion() {
				return false, false, syscall.EIO
			}
			base, version = reply.GetAttr(), reply.GetObjectVersion()
			publication.metadataResampled = true
			continue
		}
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
			return false, false, syscall.EIO
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
				return false, false, nil
			}
		}
		if blocked {
			if fast {
				r.mu.Unlock()
				unlock()
				return false, false, nil
			}
			changed := r.sourceChangedWaitLocked()
			r.mu.Unlock()
			unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return false, false, ctx.Err()
			}
		}
		attr, valid := r.renderMetadataLocked(s, base, version)
		if !valid {
			r.mu.Unlock()
			unlock()
			if !fast && base != nil {
				return false, false, syscall.EIO
			}
			return false, false, nil
		}
		if fast {
			if !r.registerCachedReplyLocked(unique, first, second, count) {
				r.mu.Unlock()
				unlock()
				return false, false, nil
			}
			p = r.replyPublications[unique]
		} else if p == nil {
			r.mu.Unlock()
			unlock()
			return false, false, syscall.EIO
		}
		r.pinMetadataLocked(p, s, record, first, second, count)
		if fast && parent != nil {
			record.lookups++
			r.identityIndexLocked(record)[record.key] = record
		}
		*out = attr
		r.mu.Unlock()
		m.epoch.RUnlock()
		return true, owned, nil
	}
}

// renderMetadataLocked runs under raw.mu and the identity admission reader.
// Local writes close their source coordinate before accepting bytes, so the
// metadata image and its publication admission are one atomic source cut. No
// operation, epoch writer, or network wait is acquired under raw.mu.
func (r *rawFileSystem) renderMetadataLocked(s *delegationState, base *authoritypb.Attr, version uint64) (fuse.Attr, bool) {
	s.meta.Lock()
	defer s.meta.Unlock()
	if base != nil {
		s.installBaseLocked(base, version)
	}
	owned := s.ref != nil
	current := base
	if owned {
		current = s.base
	}
	if current == nil || owned && (s.baseVersion == 0 || s.baseVersion < s.baseInvalidatedThrough) {
		return fuse.Attr{}, false
	}
	var attr fuse.Attr
	fillAttr(current, &attr, r.mount.uid, r.mount.gid)
	overlay := writeback.Attributes{HasMode: true, Mode: current.GetMode(), HasSize: true, Size: current.GetSize(), HasATime: true, ATimeNS: current.GetAtimeNs(), HasMTime: true, MTimeNS: current.GetMtimeNs(), HasCTime: true, CTimeNS: current.GetCtimeNs()}
	if owned {
		overlay = r.mount.delegations.buf.OverlayAttributes(s.identity, overlay)
	}
	attr.Mode = kindMode(current.GetKind()) | overlay.Mode
	attr.Size = uint64(max(overlay.Size, 0))
	attr.Atime, attr.Atimensec, attr.Mtime, attr.Mtimensec, attr.Ctime, attr.Ctimensec = 0, 0, 0, 0, 0, 0
	setTime(overlay.ATimeNS, &attr.Atime, &attr.Atimensec)
	setTime(overlay.MTimeNS, &attr.Mtime, &attr.Mtimensec)
	setTime(overlay.CTimeNS, &attr.Ctime, &attr.Ctimensec)
	return attr, true
}

func (r *rawFileSystem) pinMetadataLocked(p *replyPublication, s *delegationState, record *inodeRecord, first, second publicationCoordinate, count int) {
	if p.holderAdmission == nil {
		p.cachedCoordinates, p.cachedCount, p.holderAdmission = [2]publicationCoordinate{first, second}, count, s
		return
	}
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: record.identity}
	p.holderAdmissions = append(p.holderAdmissions, s)
	r.publishingInodes[record.key.inode]++
	r.admitSourcePublicationLocked(coordinate)
	p.attrs = append(p.attrs, replyAttrPublication{inode: record.key.inode, identity: record.identity, coordinate: coordinate})
}

type directoryMetadataSample struct {
	record             *inodeRecord
	base               *authoritypb.Attr
	version, ownership uint64
	state              *delegationState
	attr               fuse.Attr
	owned              bool
}

// A directory result first obtains every row without admission pins. Final
// sampling is a local transaction: all identities are checked and all source
// coordinates are admitted together. A changed interval releases the whole
// set before any GETATTR, so a peer multi-file recall can always make progress.
func (r *rawFileSystem) publishDirectoryMetadata(ctx context.Context, candidates []dirPlusCandidate) error {
	if len(candidates) == 0 {
		return nil
	}
	p := replyPublicationFromContext(ctx)
	if p == nil {
		return errors.New("fusev3: directory metadata has no publication")
	}
	byIdentity := make(map[publicationIdentity]*directoryMetadataSample, len(candidates))
	var rows []*directoryMetadataSample
	for _, candidate := range candidates {
		if byIdentity[candidate.record.identity] != nil {
			continue
		}
		row := &directoryMetadataSample{record: candidate.record, base: candidate.item.GetAttr(), version: candidate.item.GetObjectVersion(), ownership: p.metadataSample}
		rows = append(rows, row)
		byIdentity[candidate.record.identity] = row
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].record.identity[:], rows[j].record.identity[:]) < 0 })
	m := r.mount.delegations
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.epoch.RLock()
		locked := 0
		for _, row := range rows {
			row.state = m.retainState(writeback.Identity(row.record.identity), true)
		}
		unlock := func() {
			// Reset can hold the index writer while waiting for any reader.
			// Release every reader before attempting any index operation.
			for i := 0; i < locked; i++ {
				rows[i].state.admission.RUnlock()
			}
			for _, row := range rows {
				m.releaseState(row.state)
			}
			m.epoch.RUnlock()
		}
		var busy *delegationState
		for _, row := range rows {
			if !row.state.admission.TryRLock() {
				busy = row.state
				break
			}
			locked++
		}
		if busy != nil {
			// Keep this state indexed while waiting, but no other admission,
			// epoch, or publication reader. The writer performs only local work.
			busy.users.Add(1)
			unlock()
			busy.admission.RLock()
			busy.admission.RUnlock()
			m.releaseState(busy)
			continue
		}
		if m.incarnation() == 0 {
			unlock()
			return syscall.EIO
		}
		var changed *directoryMetadataSample
		for _, row := range rows {
			if row.state.ownershipVersion > row.ownership {
				changed = row
				break
			}
		}
		if changed != nil {
			unlock()
			changed.ownership = m.metadataClock.Load()
			response, errno := changed.record.node.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: cloneBytes(changed.record.node.item.GetToken())}}})
			if errno != 0 {
				return errno
			}
			reply := response.GetGetAttr()
			if reply.GetAttr() == nil || reply.GetObjectVersion() == 0 || reply.GetSnapshotSequence() < reply.GetObjectVersion() {
				return syscall.EIO
			}
			changed.base, changed.version = reply.GetAttr(), reply.GetObjectVersion()
			p.metadataResampled = true
			continue
		}
		r.mu.Lock()
		blocked, invalid := false, r.replyTerminal || r.replyTerminalizing || r.mount.revoked.Load()
		for _, row := range rows {
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: row.record.identity}
			invalid = invalid || row.record.stale.Load() || row.record.reclaimed
			blocked = blocked || len(r.cacheReservations[coordinate]) != 0 || r.repairingCoordinates[coordinate] || !r.sourcePublicationAllowedLocked(coordinate, p.source)
		}
		if invalid {
			r.mu.Unlock()
			unlock()
			return syscall.EIO
		}
		if blocked {
			wait := r.sourceChangedWaitLocked()
			r.mu.Unlock()
			unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		valid := true
		for _, row := range rows {
			row.attr, valid = r.renderMetadataLocked(row.state, row.base, row.version)
			if !valid {
				break
			}
			row.owned = row.state.ref != nil
		}
		if !valid {
			r.mu.Unlock()
			unlock()
			return syscall.EIO
		}
		for _, row := range rows {
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: row.record.identity}
			r.pinMetadataLocked(p, row.state, row.record, coordinate, publicationCoordinate{}, 1)
		}
		r.mu.Unlock()
		// Physical settlement now owns every admission and state reference.
		m.epoch.RUnlock()
		for i := range candidates {
			row := byIdentity[candidates[i].record.identity]
			candidates[i].entry.Attr, candidates[i].privateAttr = row.attr, row.owned
		}
		return nil
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
	prepared, owned, err := r.holderMetadata(ctx, p.requestUnique, nil, "", record, base, version, &out.Attr, false)
	if err != nil {
		return false, bufferErrno(err)
	}
	if prepared {
		out.SetTimeout(0)
		// An unowned, unchanged sample remains eligible for the shared daemon
		// cache. Resampled replies keep their original namespace stamp and
		// deliberately skip attribute caching for this one physical reply.
		// Mutations admit their exact versioned post-state at callback completion;
		// a versionless read candidate would hide that admission for this identity.
		if base != nil && !owned && !p.metadataResampled && p.postState == nil {
			r.publishAttr(ctx, out, identity, base)
		}
	}
	return prepared, 0
}
