//go:build linux

package fusev3

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type dirPlusPageBoundary struct {
	started    bool
	finished   bool
	generation uint64
	stamp      subscriptionStamp
}

func (p *dirPlusPageBoundary) changedLocked(h *dirHandle) bool {
	return p.started && (p.generation != h.cursorGeneration || p.stamp != h.pageStamp)
}

// takePlus transfers a fitting entry and its capability out of the buffered
// page atomically with provisional cursor advancement. Invalidation can discard
// the rest of the page, but cannot reclaim the transferred capability. No RPC,
// inode lock, or reclaim admission runs while the cursor lock is held.
func (h *dirHandle) takePlus(ctx context.Context, out *fuse.DirEntryList, page *dirPlusPageBoundary) (*fuse.DirEntry, *authoritypb.Dirent, *authoritypb.Item, *fuse.EntryOut, subscriptionStamp, syscall.Errno) {
	for {
		entry, dirent, errno := h.peek(ctx, true, page)
		if errno != 0 || entry == nil {
			return entry, dirent, nil, nil, subscriptionStamp{}, errno
		}
		h.mu.Lock()
		if h.pending != entry || h.pendingDirent != dirent {
			h.mu.Unlock()
			continue
		}
		if dirent == nil {
			h.mu.Unlock()
			return nil, nil, nil, nil, subscriptionStamp{}, syscall.EIO
		}
		// A withdrawal may replace the page between callbacks in this loop.
		// Finish the old page's reply before publishing a different snapshot.
		if page.changedLocked(h) {
			h.mu.Unlock()
			return nil, nil, nil, nil, subscriptionStamp{}, 0
		}
		entryOut := out.AddDirLookupEntry(*entry)
		if entryOut == nil {
			h.mu.Unlock()
			return entry, dirent, nil, nil, subscriptionStamp{}, 0
		}
		// A pooled kernel output buffer may contain a preceding request's metadata.
		*entryOut = fuse.EntryOut{}
		page.started, page.generation, page.stamp = true, h.cursorGeneration, h.pageStamp
		item := dirent.Item
		dirent.Item = nil
		stamp := h.pageStamp
		h.index++
		page.finished = h.index >= len(h.page)
		h.cookie, h.next = h.pendingCookie, entry.Off
		h.pending, h.pendingDirent, h.pendingCookie = nil, nil, nil
		h.mu.Unlock()
		return entry, dirent, item, entryOut, stamp, 0
	}
}
