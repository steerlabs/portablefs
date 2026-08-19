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
	// statHandle is the file handle of the GETATTR that established size, when
	// the kernel asked with one and nothing has happened to the inode since. It
	// is the trace an appending write leaves before it arrives: for IOCB_APPEND,
	// fuse_file_write_iter refreshes STATX_SIZE through the writing file, so the
	// refresh carries FUSE_GETATTR_FH with the handle the write then uses.
	statHandle      uint64
	statHandleValid bool
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
func (s *kernelSizeShadow) observeAttr(inode uint64, size int64, since uint64, statHandle uint64, hasStatHandle bool) {
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
	entry.statHandle, entry.statHandleValid = 0, false
	if size < 0 || since == 0 || entry.raised >= since {
		entry.known = false
		return
	}
	entry.size, entry.known = uint64(size), true
	entry.statHandle, entry.statHandleValid = statHandle, hasStatHandle
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
	entry.statHandle, entry.statHandleValid = 0, false
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
	entry.statHandle, entry.statHandleValid = 0, false
	if entry.known && end > entry.size {
		entry.size = end
	}
}

func (s *kernelSizeShadow) lookup(inode uint64) (uint64, bool) {
	size, known, _ := s.placement(inode, 0)
	return size, known
}

// placement reports the shadow together with whether its value came from a
// size refresh the kernel made through this exact file handle and nothing has
// touched the inode since. That is what separates a per-call append the kernel
// did not forward from an ordinary write that merely lands at i_size.
func (s *kernelSizeShadow) placement(inode, handle uint64) (size uint64, known, refreshedForHandle bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[inode]
	if entry == nil || !entry.known {
		return 0, false, false
	}
	return entry.size, true, entry.statHandleValid && entry.statHandle == handle
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
	tick, statHandle, hasStatHandle := uint64(0), uint64(0), false
	if publication := replyPublicationFromContext(ctx); publication != nil {
		tick, statHandle, hasStatHandle = publication.sizeTick, publication.sizeStatHandle, publication.sizeStatHandleSet
	}
	r.sizes.observeAttr(attr.GetInode(), attr.GetSize(), tick, statHandle, hasStatHandle)
}

// markKernelSizeRefresh records that this callback is the kernel refreshing an
// inode's size through one file handle, which stock Linux does immediately
// before an appending write.
func markKernelSizeRefresh(ctx context.Context, handle uint64) {
	if publication := replyPublicationFromContext(ctx); publication != nil {
		publication.sizeStatHandle, publication.sizeStatHandleSet = handle, true
	}
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
