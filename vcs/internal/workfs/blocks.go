package workfs

import (
	"io"
	"math"
	"syscall"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/content"
)

// defaultCacheBytes bounds the shared read cache's resident bytes (256 MiB).
const defaultCacheBytes = 256 << 20

// blockSize is the granularity of dirty tracking and lazy materialisation. A
// write to a backed file fetches only the blocks it touches (not the whole
// file), and a file's resident memory is bounded by its dirty blocks rather than
// its size. 4 MiB matches the backend's chunk size so a future chunked checkpoint
// can map blocks to chunks 1:1.
const blockSize = 4 << 20

const relatimeMaxAge = 24 * time.Hour

func relatimeStale(atime, mtime, ctime, now time.Time) bool {
	if atime.IsZero() {
		return true
	}
	if ctime.IsZero() {
		ctime = mtime
	}
	return !atime.After(mtime) || !atime.After(ctime) || now.Sub(atime) >= relatimeMaxAge
}

func (fs *FS) updateAtimeRelatime(n *inode, mtime, ctime, atime time.Time) {
	now := time.Now()
	if !relatimeStale(atime, mtime, ctime, now) {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if relatimeStale(n.atime, n.mtime, n.ctime, now) {
		n.atime = now
	}
}

// blockLen is the valid byte length of block bi for a file of the given size
// (full blocks are blockSize; the last is the remainder; past EOF is 0).
func blockLen(bi, size int64) int64 {
	start := bi * blockSize
	if start >= size {
		return 0
	}
	if rem := size - start; rem < blockSize {
		return rem
	}
	return blockSize
}

// readBlocks copies bytes [off, off+len(p)) of file n into p. Dirty blocks are
// served from memory, holes (past the base, never written) as zeros, and only
// the base blocks the range actually touches are fetched — outside the lock. It
// snapshots the per-block plan under the lock so a concurrent write cannot race
// the dirty buffers.
func (fs *FS) readBlocks(n *inode, p []byte, off int64) (int, error) {
	if off < 0 || off > math.MaxInt64-int64(len(p)) {
		return 0, syscall.EINVAL
	}
	fs.mu.RLock()
	if n.kind != "file" {
		fs.mu.RUnlock()
		return 0, io.EOF
	}
	size := n.size
	mtime, ctime, atime := n.mtime, n.ctime, n.atime
	if off >= size {
		fs.mu.RUnlock()
		return 0, io.EOF
	}
	end := off + int64(len(p))
	if end > size {
		end = size
	}

	// Per-segment plan: a copied dirty slice, or a base fetch, or a hole.
	type seg struct {
		dst   int    // offset into p
		n     int    // bytes for this segment
		src   int64  // absolute file offset (base fetch)
		dirty []byte // copied dirty bytes (len may be < n; remainder is a hole)
		fetch bool   // fetch base[src : src+n]
	}
	var segs []seg
	baseSize := n.source.Size
	for pos := off; pos < end; {
		bi := pos / blockSize
		within := pos - bi*blockSize
		take := blockSize - within
		if pos+take > end {
			take = end - pos
		}
		s := seg{dst: int(pos - off), n: int(take), src: pos}
		if blk, ok := n.blocks[bi]; ok {
			if within < int64(len(blk)) {
				hi := within + take
				if hi > int64(len(blk)) {
					hi = int64(len(blk))
				}
				s.dirty = append([]byte(nil), blk[within:hi]...)
			} else {
				s.dirty = []byte{} // wholly within a dirty block's trailing hole
			}
		} else if pos < baseSize {
			s.fetch = true
		} // else: hole (zeros)
		segs = append(segs, s)
		pos += take
	}
	src := n.source
	fs.mu.RUnlock()

	// Zero the return window, then fill non-hole segments (base fetches here).
	region := int(end - off)
	for i := 0; i < region; i++ {
		p[i] = 0
	}
	total := 0
	for _, s := range segs {
		switch {
		case s.dirty != nil:
			copy(p[s.dst:s.dst+s.n], s.dirty)
		case s.fetch:
			if _, err := content.ReadAt(fs.blobs, fs.cache, src, p[s.dst:s.dst+s.n], s.src); err != nil && err != io.EOF {
				return total, err
			}
		}
		total += s.n
	}
	if total > 0 {
		fs.updateAtimeRelatime(n, mtime, ctime, atime)
	}
	if off+int64(total) >= size {
		return total, io.EOF
	}
	return total, nil
}

// warmBaseForWrite pre-reads, OUTSIDE fs.mu, the base content of the blocks that a
// write of `length` bytes at `off` will only PARTIALLY overwrite (a read-modify-write
// must first fetch the block's existing bytes). It warms the shared content cache so
// the apply's writeBlocks — which runs under fs.mu — is a fast cache hit instead of a
// backend round-trip that would stall every other writer on the single FS lock.
//
// It is purely an optimization: best-effort (errors ignored — the under-lock read
// retries and surfaces them), and correct regardless of races (if a block is
// materialised or the file changes between the warm and the apply, writeBlocks simply
// does the right thing, hitting the cache when warm and falling back to a backend read
// only in the rare racing case).
func (fs *FS) warmBaseForWrite(name string, off, length int64) {
	if length == 0 {
		return
	}
	fs.mu.RLock()
	n := fs.resolve(name)
	fs.mu.RUnlock()
	fs.warmBaseForWriteNode(n, off, length)
}

// warmBaseForWriteNode is warmBaseForWrite addressed by inode rather than name, so an open-after-unlink
// write to a parked orphan (which has no name) warms its base blocks the same way before the commit.
func (fs *FS) warmBaseForWriteNode(n *inode, off, length int64) {
	if length <= 0 || off < 0 || off > math.MaxInt64-length {
		return
	}
	fs.mu.RLock()
	if n == nil || n.kind != "file" || n.source.Size == 0 {
		fs.mu.RUnlock()
		return // missing, not a file, or a born/empty file: no base content to fetch
	}
	src := n.source
	size := n.size
	end := off + length
	var need []int64
	for pos := off; pos < end; {
		bi := pos / blockSize
		bstart := bi * blockSize
		take := blockSize - (pos - bstart)
		if pos+take > end {
			take = end - pos
		}
		blen := blockLen(bi, size)
		fullCover := pos == bstart && take >= blen
		if _, materialised := n.blocks[bi]; !materialised && !fullCover && bstart < src.Size {
			need = append(need, bi)
		}
		pos += take
	}
	fs.mu.RUnlock()
	if len(need) == 0 {
		return
	}
	scratch := make([]byte, blockSize)
	for _, bi := range need {
		bstart := bi * blockSize
		readN := int64(blockSize)
		if bstart+readN > src.Size {
			readN = src.Size - bstart
		}
		if readN > 0 {
			_, _ = content.ReadAt(fs.blobs, fs.cache, src, scratch[:readN], bstart) // warms fs.cache
		}
	}
}

// writeBlocks applies a write at off, materialising only the blocks it touches
// (a fully-overwritten block needs no base read). Caller holds fs.mu.
func (fs *FS) writeBlocks(n *inode, off int64, data []byte) error {
	if n.blocks == nil {
		n.blocks = map[int64][]byte{}
	}
	newSize := n.size
	if off+int64(len(data)) > newSize {
		newSize = off + int64(len(data))
	}
	start, end := off, off+int64(len(data))
	for pos := start; pos < end; {
		bi := pos / blockSize
		bstart := bi * blockSize
		within := pos - bstart
		take := blockSize - within
		if pos+take > end {
			take = end - pos
		}
		blen := blockLen(bi, newSize)
		blk, ok := n.blocks[bi]
		switch {
		case !ok:
			buf := make([]byte, blen)
			// Read existing base bytes unless the write fully covers the block.
			if !(within == 0 && take >= blen) && bstart < n.source.Size {
				readN := blen
				if bstart+readN > n.source.Size {
					readN = n.source.Size - bstart
				}
				if readN > 0 {
					if _, err := content.ReadAt(fs.blobs, fs.cache, n.source, buf[:readN], bstart); err != nil && err != io.EOF {
						return err
					}
				}
			}
			blk = buf
		case int64(len(blk)) < blen:
			// Grow the block to blen. A file appended in small chunks grows its last block over and
			// over; reallocating + copying the whole block on EVERY grow is O(total^2). Use amortized
			// slice growth: extend in place when the capacity already covers blen, else reallocate with
			// a doubled capacity (capped at blockSize). Makes incremental-append (sqlite, logs) O(total).
			if int64(cap(blk)) >= blen {
				old := len(blk)
				blk = blk[:blen]
				// Zero the newly exposed bytes: a prior truncate-shrink keeps capacity, so it may hold
				// stale data. (A region grown via make below is already zero, making this a no-op there.)
				clear(blk[old:])
			} else {
				nc := int64(cap(blk)) * 2
				if nc < blen {
					nc = blen
				}
				if nc > blockSize {
					nc = blockSize
				}
				grown := make([]byte, blen, nc)
				copy(grown, blk)
				blk = grown
			}
		}
		copy(blk[within:within+take], data[pos-start:pos-start+take])
		n.blocks[bi] = blk
		pos += take
	}
	n.size = newSize
	n.mtime = time.Now()
	return nil
}

// truncateBlocks resizes file n: shrinking drops/trims blocks past size; growing
// leaves a hole; size 0 resets to an empty local file. Caller holds fs.mu.
func (fs *FS) truncateBlocks(n *inode, size int64) {
	if size != n.size {
		// A pure size change (shrink that drops no whole dirty block, or any grow) leaves no dirty
		// block, so without this flag hasLocalContent() reports the file CLEAN and the checkpoint
		// re-commits the STALE source size/bytes — silent durable divergence from the live file.
		n.truncated = true
	}
	switch {
	case size == 0:
		fs.addDirtyBlockBytesLocked(-dirtyBlockBytesOf(n))
		n.blocks = map[int64][]byte{}
		n.source = content.Source{}
		n.born = true
	case size < n.size:
		var released int64
		for bi, blk := range n.blocks {
			if bi*blockSize >= size {
				released += int64(len(blk))
				delete(n.blocks, bi)
			}
		}
		bi := (size - 1) / blockSize
		if blk, ok := n.blocks[bi]; ok {
			if blen := blockLen(bi, size); int64(len(blk)) > blen {
				released += int64(len(blk)) - blen
				n.blocks[bi] = blk[:blen]
			}
		}
		fs.addDirtyBlockBytesLocked(-released)
	}
	if size < n.source.Size {
		// POSIX: bytes discarded by a shrink are GONE. Cap the visible
		// immutable base at the shrink point so a later regrow reads zeros
		// (a hole) instead of resurrecting old base bytes — readBlocks,
		// writeBlocks read-modify-write, checkpoint SnapshotBlock, and
		// mergeFull all gate base reads on source.Size. The cap is monotone
		// (only ever shrinks), so no later operation can widen it back.
		n.source.Size = size
	}
	n.size = size
	n.mtime = time.Now()
}

// CheckpointBlockSize is the chunk granularity a large-file checkpoint streams
// at (matches the backend's 4 MiB chunk size).
const CheckpointBlockSize = blockSize

// SnapshotBlock returns block bi (CheckpointBlockSize-aligned) of a dirty
// snapshot entry, merging its dirty blocks over the backed base. It lets the
// checkpointer stream a large file chunk-by-chunk without holding the whole file
// in memory.
func (fs *FS) SnapshotBlock(e SnapshotEntry, bi int64) ([]byte, error) {
	bstart := bi * blockSize
	blen := blockLen(bi, e.Size)
	if blen <= 0 {
		return nil, nil
	}
	out := make([]byte, blen)
	if blk, ok := e.Blocks[bi]; ok {
		copy(out, blk) // dirty block (a short dirty block leaves a zero tail = hole)
		return out, nil
	}
	if bstart < e.Source.Size {
		readN := blen
		if bstart+readN > e.Source.Size {
			readN = e.Source.Size - bstart
		}
		if readN > 0 {
			if _, err := content.ReadAt(fs.blobs, fs.cache, e.Source, out[:readN], bstart); err != nil && err != io.EOF {
				return nil, err
			}
		}
	}
	return out, nil
}

// mergeFull reconstructs a file's full bytes from a base source + dirty blocks,
// fetching base blocks lazily. Used at checkpoint; takes no lock (it reads only
// immutable inputs).
func mergeFull(blobs content.BlobReader, cache content.Cache, src content.Source, blocks map[int64][]byte, size int64) ([]byte, error) {
	out := make([]byte, size)
	nblocks := (size + blockSize - 1) / blockSize
	for bi := int64(0); bi < nblocks; bi++ {
		bstart := bi * blockSize
		blen := blockLen(bi, size)
		if blk, ok := blocks[bi]; ok {
			copy(out[bstart:bstart+blen], blk)
			continue
		}
		if bstart < src.Size {
			readN := blen
			if bstart+readN > src.Size {
				readN = src.Size - bstart
			}
			if readN > 0 {
				if _, err := content.ReadAt(blobs, cache, src, out[bstart:bstart+readN], bstart); err != nil && err != io.EOF {
					return nil, err
				}
			}
		}
		// else: hole, leave zeros.
	}
	return out, nil
}
