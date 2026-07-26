package clientcore

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const DiskBlockSize = 1 << 20

// diskBlockHeader frames every stored block with its content length and a content digest (M2). A
// block truncated or corrupted on disk after its atomic rename would otherwise be served blindly, and
// GetRange's EOF-short rule would turn a truncated block into a silently shorter file. Verifying the
// digest on read (and the framed length on restart) makes a damaged block a miss that refetches from
// the authority — the repo's Cache Rule: cache hits never change correctness.
const diskBlockHeaderSize = 8 + sha256.Size

// encodeDiskBlock frames content as [uint64 length][sha256 digest][content].
func encodeDiskBlock(content []byte) []byte {
	sum := sha256.Sum256(content)
	out := make([]byte, diskBlockHeaderSize+len(content))
	binary.LittleEndian.PutUint64(out[0:8], uint64(len(content)))
	copy(out[8:diskBlockHeaderSize], sum[:])
	copy(out[diskBlockHeaderSize:], content)
	return out
}

// decodeDiskBlock validates the framing and content digest, returning the content only when the block
// is intact. A short header, a length that disagrees with the framed length, or a digest mismatch all
// return ok=false so the caller discards the block and refetches.
func decodeDiskBlock(raw []byte) ([]byte, bool) {
	if len(raw) < diskBlockHeaderSize {
		return nil, false
	}
	declared := binary.LittleEndian.Uint64(raw[0:8])
	content := raw[diskBlockHeaderSize:]
	if uint64(len(content)) != declared {
		return nil, false
	}
	var want [sha256.Size]byte
	copy(want[:], raw[8:diskBlockHeaderSize])
	if sha256.Sum256(content) != want {
		return nil, false
	}
	return content, true
}

// diskBlockContentLen reads only a block file's header and validates it against the file size,
// returning the content length. It is the cheap restart-time integrity check (no full read): a file
// whose actual size disagrees with its framed length is truncated/corrupt and reported invalid.
func diskBlockContentLen(path string, fileSize int64) (int64, bool) {
	if fileSize < diskBlockHeaderSize {
		return 0, false
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return 0, false
	}
	declared := int64(binary.LittleEndian.Uint64(hdr[:]))
	if declared < 0 || diskBlockHeaderSize+declared != fileSize {
		return 0, false
	}
	return declared, true
}

// DiskBlockCache is a persistent byte-bounded LRU for authority file-content blocks. Keys include
// the authority generation and the content version, so stale blocks are unreachable both after an
// invalidation advances the version and after a new authority incarnation restarts versioning.
type DiskBlockCache struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	curBytes int64
	ll       *list.List
	items    map[string]*list.Element
}

type diskBlockItem struct {
	file string
	size int64
}

// NewDiskBlockCache opens dir and rebuilds the LRU from existing files. A non-positive budget
// disables the cache but still returns a valid object.
func NewDiskBlockCache(dir string, maxBytes int64) (*DiskBlockCache, error) {
	if dir == "" || maxBytes <= 0 {
		return &DiskBlockCache{dir: dir, maxBytes: maxBytes, ll: list.New(), items: map[string]*list.Element{}}, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &DiskBlockCache{dir: dir, maxBytes: maxBytes, ll: list.New(), items: map[string]*list.Element{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type fi struct {
		name string
		size int64 // content length (from the validated header), matching Put's LRU accounting
		mod  int64
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// M2: validate the on-disk file size against its framed content length. A block truncated
		// or corrupted while the process was down is discarded here rather than rebuilt into the
		// index (where GetRange could serve it as a short EOF block and silently truncate the file).
		contentLen, ok := diskBlockContentLen(filepath.Join(dir, e.Name()), info.Size())
		if !ok {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		files = append(files, fi{name: e.Name(), size: contentLen, mod: info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })
	for _, f := range files {
		c.items[f.name] = c.ll.PushFront(&diskBlockItem{file: f.name, size: f.size})
		c.curBytes += f.size
	}
	c.evictLocked()
	return c, nil
}

// diskBlockKey fences by authority GENERATION (C2). Versions restart per authority incarnation
// (workfs gen is a per-process nonce, fs.version restarts at 0) while this cache directory persists,
// so without gen a reused (ino, block, version) tuple from a new incarnation would alias a prior
// incarnation's bytes. We fence in the KEY rather than wiping the directory on a generation change
// because the cache is consulted (in Volume.Read) before the response that would reveal the new
// generation, so a wipe-on-observe would still be racing that very read; a generation-scoped key can
// never be consulted for the wrong generation. It also keeps the cache a pure, lifecycle-free
// content-addressed store — no persisted generation marker, no cross-component wipe hook — and
// stale-generation blocks simply become unreachable keys that the byte-bounded LRU reclaims, so
// garbage stays bounded by maxBytes.
func diskBlockKey(volumeID string, gen, ino, blockIndex, version uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%d", volumeID, gen, ino, blockIndex, version)))
	return hex.EncodeToString(sum[:])
}

func (c *DiskBlockCache) path(file string) string { return filepath.Join(c.dir, file) }

// GetRange composes an arbitrary read from cached version-matched blocks. It
// returns ok only when every requested byte is cached, or when a cached EOF-short
// block proves the read should end early. Entries are whole blocks (except the
// final EOF block) keyed by content version, so this never splices bytes from two
// file versions.
func (c *DiskBlockCache) GetRange(volumeID string, gen, ino uint64, off int64, length int, version uint64) ([]byte, bool) {
	if length == 0 {
		return nil, true
	}
	if off < 0 || length < 0 {
		return nil, false
	}
	var out []byte
	pos := off
	remaining := length
	for remaining > 0 {
		blockIndex := uint64(pos / DiskBlockSize)
		blockOff := int(pos % DiskBlockSize)
		block, ok := c.Get(volumeID, gen, ino, blockIndex, version)
		if !ok {
			return nil, false
		}
		if blockOff >= len(block) {
			return out, true
		}
		n := DiskBlockSize - blockOff
		if n > remaining {
			n = remaining
		}
		avail := len(block) - blockOff
		if avail < n {
			n = avail
		}
		out = append(out, block[blockOff:blockOff+n]...)
		pos += int64(n)
		remaining -= n
		if n < DiskBlockSize-blockOff {
			return out, true
		}
	}
	return out, true
}

// PutRange stores only complete block-shaped slices from an authority read. A
// mid-block slice is intentionally skipped: storing it as a full block would let
// future reads of bytes before the slice falsely hit the cache. A short block is
// stored only when it begins at the block boundary, where it represents EOF for
// that content version.
func (c *DiskBlockCache) PutRange(volumeID string, gen, ino uint64, off int64, version uint64, data []byte, requested int) {
	if off < 0 || len(data) == 0 {
		return
	}
	eofShort := requested > 0 && len(data) < requested
	pos := off
	remaining := data
	for len(remaining) > 0 {
		blockOff := int(pos % DiskBlockSize)
		take := DiskBlockSize - blockOff
		if take > len(remaining) {
			take = len(remaining)
		}
		if blockOff == 0 && (take == DiskBlockSize || (take == len(remaining) && eofShort)) {
			block := append([]byte(nil), remaining[:take]...)
			c.Put(volumeID, gen, ino, uint64(pos/DiskBlockSize), version, block)
		}
		pos += int64(take)
		remaining = remaining[take:]
	}
}

// Get returns a block only when the requested generation+content version exactly matches the key.
func (c *DiskBlockCache) Get(volumeID string, gen, ino, blockIndex, version uint64) ([]byte, bool) {
	if c == nil || c.dir == "" || c.maxBytes <= 0 || version == 0 || ino == 0 {
		return nil, false
	}
	file := diskBlockKey(volumeID, gen, ino, blockIndex, version)
	c.mu.Lock()
	if el, ok := c.items[file]; ok {
		c.ll.MoveToFront(el)
	}
	c.mu.Unlock()
	raw, err := os.ReadFile(c.path(file))
	if err != nil {
		c.drop(file)
		return nil, false
	}
	// M2: verify the framed content digest. A block truncated/corrupted on disk after its rename is
	// discarded as a miss, so the caller refetches the authentic bytes instead of serving a short
	// block (which GetRange would treat as EOF and silently truncate the file).
	content, ok := decodeDiskBlock(raw)
	if !ok {
		c.drop(file)
		return nil, false
	}
	if int64(len(content)) > c.maxBytes {
		c.drop(file)
		return nil, false
	}
	var evicted []string
	c.mu.Lock()
	if _, ok := c.items[file]; !ok {
		c.items[file] = c.ll.PushFront(&diskBlockItem{file: file, size: int64(len(content))})
		c.curBytes += int64(len(content))
		// m4: re-inserting a block found on disk but absent from the index (e.g. after it was
		// evicted from the index while still on disk) can push the cache over budget; evict LRU
		// tail so the byte bound holds. Never drop `file` itself — it is at the front.
		evicted = c.collectEvictionsLocked()
	}
	c.mu.Unlock()
	for _, f := range evicted {
		_ = os.Remove(c.path(f))
	}
	return content, true
}

// Put stores one block atomically and evicts least-recently-used blocks until within budget.
func (c *DiskBlockCache) Put(volumeID string, gen, ino, blockIndex, version uint64, data []byte) {
	if c == nil || c.dir == "" || c.maxBytes <= 0 || version == 0 || ino == 0 || len(data) == 0 {
		return
	}
	if int64(len(data)) > c.maxBytes {
		return
	}
	file := diskBlockKey(volumeID, gen, ino, blockIndex, version)
	framed := encodeDiskBlock(data)
	tmp, err := os.CreateTemp(c.dir, file+".*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(framed); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, c.path(file)); err != nil {
		_ = os.Remove(tmpName)
		return
	}

	var evicted []string
	c.mu.Lock()
	if el, ok := c.items[file]; ok {
		ent := el.Value.(*diskBlockItem)
		c.curBytes += int64(len(data)) - ent.size
		ent.size = int64(len(data))
		c.ll.MoveToFront(el)
	} else {
		c.items[file] = c.ll.PushFront(&diskBlockItem{file: file, size: int64(len(data))})
		c.curBytes += int64(len(data))
	}
	evicted = c.collectEvictionsLocked()
	c.mu.Unlock()
	for _, f := range evicted {
		_ = os.Remove(c.path(f))
	}
}

func (c *DiskBlockCache) drop(file string) {
	c.mu.Lock()
	if el, ok := c.items[file]; ok {
		c.curBytes -= el.Value.(*diskBlockItem).size
		c.ll.Remove(el)
		delete(c.items, file)
	}
	c.mu.Unlock()
	_ = os.Remove(c.path(file))
}

func (c *DiskBlockCache) collectEvictionsLocked() []string {
	var evicted []string
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*diskBlockItem)
		c.ll.Remove(back)
		delete(c.items, ent.file)
		c.curBytes -= ent.size
		evicted = append(evicted, ent.file)
	}
	return evicted
}

func (c *DiskBlockCache) evictLocked() {
	for _, f := range c.collectEvictionsLocked() {
		_ = os.Remove(c.path(f))
	}
}

// Stats returns current bytes and configured capacity for daemon status reporting.
func (c *DiskBlockCache) Stats() (bytes, capBytes int64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.curBytes, c.maxBytes
}
