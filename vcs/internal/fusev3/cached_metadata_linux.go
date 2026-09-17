//go:build linux

package fusev3

import (
	"math"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// Waiters create the receipt only while holding raw.mu. A cached hit with no
// concurrent withdrawal therefore needs neither a context nor a channel.
func (p *replyPublication) originalDoneLocked() <-chan struct{} {
	if p.originalDone == nil {
		p.originalDone = make(chan struct{})
	}
	return p.originalDone
}

func (p *replyPublication) closeOriginalDoneLocked() {
	if p.originalDone != nil {
		close(p.originalDone)
	}
}

func (r *rawFileSystem) cachedCoordinateAllowedLocked(coordinate publicationCoordinate, stamp subscriptionStamp, now time.Time) bool {
	return len(r.cacheReservations[coordinate]) == 0 && !r.repairingCoordinates[coordinate] && r.sourcePublicationAllowedLocked(coordinate, nil) &&
		r.mount.subscription.remainingAfterOwnershipCheck(coordinate, stamp, stamp.version, now) > 0
}

// The cache check and registration share the withdrawal lock. These answers
// contain no new daemon fact, but their inode state still reaches the kernel.
// Treat them as finalized immediately: both peer withdrawal and the initiating
// mount's source gate must join their physical reply before completing.
func (r *rawFileSystem) registerCachedReplyLocked(unique uint64, first, second publicationCoordinate, count int) bool {
	if unique == 0 || r.replyTerminal || r.replyTerminalizing || r.replyPublications[unique] != nil || r.mount.revoked.Load() || r.cachedReplyFree == nil {
		return false
	}
	p := r.cachedReplyFree
	r.cachedReplyFree = p.cachedNext
	p.cachedNext = nil
	p.owner, p.requestUnique, p.originalFinalized = r, unique, true
	p.cachedCoordinates, p.cachedCount = [2]publicationCoordinate{first, second}, count
	r.replyPublications[unique] = p
	return true
}

func (r *rawFileSystem) lookupCachedReply(unique uint64, parent *inodeRecord, name string, out *fuse.EntryOut) bool {
	r.mount.epochMu.RLock()
	defer r.mount.epochMu.RUnlock()
	key := nameKey{parent: parent.key.inode, name: name}
	// Delegation ownership requires its own locks. Never nest those under the
	// raw registry lock; revalidate the exact binding after observing ownership.
	r.mu.Lock()
	record := r.cachedNames[key]
	r.mu.Unlock()
	if record != nil && r.mount.delegations.Owns(record.identity[:]) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if parent.stale.Load() || r.cachedNames[key] != record {
		return false
	}
	now := time.Now()
	nameCoordinate := publicationCoordinate{kind: publicationNamespaceName, parent: parent.identity, name: name}
	stamp := r.cachedNameStamps[key]
	negativeName, negative := r.cachedNegatives[key]
	if negative {
		stamp = r.cachedNegativeStamps[key]
		nameCoordinate.name = negativeName
	} else {
		nameCoordinate.name = r.cachedNameStable[key].name
	}
	if !r.cachedCoordinateAllowedLocked(nameCoordinate, stamp, now) {
		return false
	}
	if negative {
		if !r.registerCachedReplyLocked(unique, nameCoordinate, publicationCoordinate{}, 1) {
			return false
		}
		*out = fuse.EntryOut{}
		return true
	}
	if record == nil || record.stale.Load() || record.reclaimed || record.lookups == math.MaxUint64 {
		return false
	}
	attrCoordinate := publicationCoordinate{kind: publicationItemAttributes, item: record.identity}
	payload := r.cachedAttrPayloads[record.identity]
	if payload.attr == nil || r.cachedAttrs[record.identity] != record || !r.cachedCoordinateAllowedLocked(attrCoordinate, payload.stamp, now) {
		return false
	}
	if !r.registerCachedReplyLocked(unique, nameCoordinate, attrCoordinate, 2) {
		return false
	}
	record.lookups++
	r.identityIndexLocked(record)[record.key] = record
	*out = fuse.EntryOut{NodeId: record.id, Generation: 1, Attr: payload.fuseAttr}
	return true
}

func (r *rawFileSystem) attrCachedReply(unique uint64, record *inodeRecord, out *fuse.AttrOut) bool {
	r.mount.epochMu.RLock()
	defer r.mount.epochMu.RUnlock()
	if r.mount.delegations.Owns(record.identity[:]) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.stale.Load() || record.reclaimed {
		return false
	}
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: record.identity}
	payload := r.cachedAttrPayloads[record.identity]
	if payload.attr == nil || r.cachedAttrs[record.identity] != record || !r.cachedCoordinateAllowedLocked(coordinate, payload.stamp, time.Now()) {
		return false
	}
	if !r.registerCachedReplyLocked(unique, coordinate, publicationCoordinate{}, 1) {
		return false
	}
	*out = fuse.AttrOut{Attr: payload.fuseAttr}
	return true
}
