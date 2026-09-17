//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Drop every daemon fact before issuing the first notification. A failed
// notification leaves the entire batch closed; retrying the batch is safe.
func (r *rawFileSystem) invalidateCacheCoordinatesContext(ctx context.Context, withdrawals []subscriptionWithdrawal) error {
	if r == nil {
		return errors.New("fusev3: cache invalidation has no frontend")
	}
	data := make([]publicationCoordinate, 0)
	for _, w := range withdrawals {
		switch w.coordinate.kind {
		case publicationItemData:
			data = append(data, w.coordinate)
		case publicationNamespaceName, publicationItemEnumeration, publicationItemAttributes:
		default:
			return errors.New("fusev3: invalidate unknown cache coordinate")
		}
	}
	if len(data) != 0 {
		if err := r.drainDataPublicationsSet(ctx, data); err != nil {
			return err
		}
	}
	type notification struct {
		inode     uint64
		data      bool
		byteRange *authoritypb.ByteRange
	}
	notifications := make([]notification, 0)
	byIdentity := make(map[publicationIdentity]int)
	enumerations := make(map[publicationIdentity]struct{})
	handles := make([]*dirHandle, 0)
	reclaim := make([][]byte, 0)
	r.mu.Lock()
	for _, w := range withdrawals {
		coordinate := w.coordinate
		switch coordinate.kind {
		case publicationNamespaceName:
			r.dropDirectoryPageHintsLocked(coordinate.parent)
			r.dropCompleteDirectoryLocked(coordinate.parent)
			parent := r.byIdentityLocked(coordinate.parent)
			if parent == nil {
				continue
			}
			key := nameKey{parent: parent.key.inode, name: coordinate.name}
			child := r.cachedNames[key]
			r.dropCachedNameLocked(key)
			r.dropCachedNegativeLocked(key)
			if token := r.collectLocked(child); len(token) != 0 {
				reclaim = append(reclaim, token)
			}
		case publicationItemEnumeration:
			r.dropDirectoryPageHintsLocked(coordinate.item)
			r.dropCompleteDirectoryLocked(coordinate.item)
			enumerations[coordinate.item] = struct{}{}
		case publicationItemAttributes, publicationItemData:
			delete(r.cachedAttrs, coordinate.item)
			delete(r.cachedAttrPayloads, coordinate.item)
			record := r.byIdentityLocked(coordinate.item)
			if record == nil {
				continue
			}
			isData := coordinate.kind == publicationItemData
			if index, ok := byIdentity[coordinate.item]; ok {
				if isData {
					if notifications[index].data {
						notifications[index].byteRange = nil
					} else {
						notifications[index].data = true
						notifications[index].byteRange = w.byteRange
					}
				}
			} else {
				byIdentity[coordinate.item] = len(notifications)
				notifications = append(notifications, notification{inode: record.id, data: isData, byteRange: w.byteRange})
			}
		}
	}
	if len(enumerations) != 0 {
		for _, handle := range r.handles {
			if handle != nil && handle.dir != nil && handle.inode != nil {
				if _, ok := enumerations[handle.inode.identity]; ok {
					handles = append(handles, handle.dir)
				}
			}
		}
	}
	r.mu.Unlock()
	for _, token := range reclaim {
		r.mount.deferReclaim(token)
	}
	for _, handle := range handles {
		handle.invalidateEnumeration()
	}
	// Names have zero kernel validity. EntryNotify cannot participate here: it
	// may require the parent lock held by a CREATE waiting for this withdrawal.
	notifier := r.mount.notifier()
	if len(notifications) != 0 && notifier == nil {
		return errors.New("fusev3: cache invalidation has no kernel notification channel")
	}
	for _, n := range notifications {
		offset, length := int64(-1), int64(0)
		if n.data {
			offset = 0
			b := n.byteRange
			if b != nil && b.GetOffset() <= math.MaxInt64 && b.GetLength() <= math.MaxInt64 && b.GetOffset() <= math.MaxInt64-b.GetLength() {
				offset, length = int64(b.GetOffset()), int64(b.GetLength())
			}
		}
		if status := notifier.InodeNotify(n.inode, offset, length); !status.Ok() && status != fuse.ENOENT {
			return fmt.Errorf("fusev3: invalidate inode %d: %v", n.inode, status)
		}
	}
	return nil
}
