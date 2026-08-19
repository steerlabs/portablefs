//go:build linux

package fusev3

import (
	"context"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// The kernel's i_size for one of this mount's inodes is derived entirely from
// this daemon's replies, because the portable profile negotiates no writeback
// cache. Exactly three kinds of reply move it:
//
//   - an attribute-bearing reply (LOOKUP, GETATTR, CREATE, READDIRPLUS,
//     SETATTR) assigns it, and
//   - a WRITE, FALLOCATE, or COPY_FILE_RANGE reply raises it to the end of the
//     range the kernel itself computed (fuse_write_update_size takes a max).
//
// Tracking those replies gives an exact shadow S of the kernel's i_size, which
// is what makes an unforwarded per-call RWF_APPEND detectable: the kernel sets
// its offset to i_size for such a write, so a write at S is either an ordinary
// positioned write or a hidden append, and only the authority can tell the two
// apart. See append_placement_linux.go.
//
// One case is genuinely ambiguous. fuse_change_attributes discards an attribute
// reply whose attr_version lost to a write completion on the same inode, and
// which of the two values the kernel kept is not observable from userspace. The
// shadow becomes UNKNOWN there and every write is refused until an attribute
// reply that raced nothing restores it. That is fail-closed by construction: a
// guess would misplace bytes.
type kernelSizeShadow struct {
	mu sync.Mutex
	// tick counts size-raising replies across the mount. A request records the
	// value it started with, so an attribute reply can tell whether a write
	// reply for the same inode overtook it.
	tick    uint64
	entries map[uint64]*kernelSizeEntry
}

type kernelSizeEntry struct {
	size  uint64
	known bool
	// raised is the tick of the most recent size-raising reply for this inode.
	raised uint64
}

func newKernelSizeShadow() *kernelSizeShadow {
	return &kernelSizeShadow{entries: make(map[uint64]*kernelSizeEntry)}
}

// begin stamps a request with the shadow's current tick.
func (s *kernelSizeShadow) begin() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tick++
	return s.tick
}

// observeAttr records an attribute-bearing reply. since is the tick the reply's
// request began with; a zero tick means the provenance is unknown and is treated
// as a race.
func (s *kernelSizeShadow) observeAttr(inode uint64, size int64, since uint64) {
	if inode == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[inode]
	if entry == nil {
		entry = &kernelSizeEntry{}
		s.entries[inode] = entry
	}
	if size < 0 || since == 0 || entry.raised >= since {
		entry.known = false
		return
	}
	entry.size, entry.known = uint64(size), true
}

// observeSet records a reply the kernel applies unconditionally: a SETATTR,
// which it serializes under the inode lock and never version-checks, and an
// atomic O_TRUNC open, which sets i_size to zero with no attributes at all.
func (s *kernelSizeShadow) observeSet(inode, size uint64) {
	if inode == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[inode]
	if entry == nil {
		entry = &kernelSizeEntry{}
		s.entries[inode] = entry
	}
	s.tick++
	entry.raised = s.tick
	entry.size, entry.known = size, true
}

// observeRaise records a reply after which the kernel raised i_size to end. It
// is the userspace mirror of fuse_write_update_size and applies to WRITE,
// FALLOCATE, and COPY_FILE_RANGE alike; end is always the offset the kernel
// itself used, never one the authority assigned.
func (s *kernelSizeShadow) observeRaise(inode, end uint64) {
	if inode == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[inode]
	if entry == nil {
		entry = &kernelSizeEntry{}
		s.entries[inode] = entry
	}
	s.tick++
	entry.raised = s.tick
	if entry.known && end > entry.size {
		entry.size = end
	}
}

func (s *kernelSizeShadow) lookup(inode uint64) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[inode]
	if entry == nil || !entry.known {
		return 0, false
	}
	return entry.size, true
}

// forget drops an inode the kernel has evicted. A later instantiation starts
// from the attribute reply that instantiated it.
func (s *kernelSizeShadow) forget(inode uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, inode)
}

func (s *kernelSizeShadow) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// noteKernelAttr is the single funnel every attribute-bearing reply passes
// through. Only regular files can carry a write, so nothing else is retained.
func (r *rawFileSystem) noteKernelAttr(ctx context.Context, attr *authoritypb.Attr) {
	if r == nil || r.sizes == nil || attr == nil || attr.GetKind() != authoritypb.Attr_REGULAR {
		return
	}
	r.sizes.observeAttr(attr.GetInode(), attr.GetSize(), replyPublicationTick(ctx))
}

// noteKernelSize records a size the kernel adopts unconditionally.
func (r *rawFileSystem) noteKernelSize(inode, size uint64) {
	if r == nil || r.sizes == nil {
		return
	}
	r.sizes.observeSet(inode, size)
}

// noteKernelRaise records that the kernel raised i_size to end after a reply of
// its own accord: WRITE, FALLOCATE, and COPY_FILE_RANGE all do.
func (r *rawFileSystem) noteKernelRaise(inode, end uint64) {
	if r == nil || r.sizes == nil {
		return
	}
	r.sizes.observeRaise(inode, end)
}

// replyPublicationTick is the shadow tick the callback's reply publication was
// registered with. A callback that has no publication states no provenance.
func replyPublicationTick(ctx context.Context) uint64 {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return 0
	}
	return publication.sizeTick
}
