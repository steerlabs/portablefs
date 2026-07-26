package content

import (
	"container/list"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/trendup-ai/portablefs/vcs/internal/secure"
)

// diskCache is a byte-bounded, persistent second tier for the blob cache: blobs
// spill from RAM to local disk (NVMe), so the working set can far exceed memory
// and survives restarts (a warm cache). It is best-effort — any I/O error is
// treated as a miss, so a raced/evicted file just falls through to the source.
//
// Locking holds only the LRU bookkeeping; file reads/writes happen outside the
// lock, so a large blob read never blocks other cache operations.
type diskCache struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	curBytes int64
	enc      *secure.AtRest // nil = plaintext files
	ll       *list.List     // front = most recently used
	items    map[string]*list.Element
}

type diskItem struct {
	key  string
	size int64
}

// newDiskCache opens (creating if needed) a disk cache at dir and warms its LRU
// from whatever is already there (oldest-first), evicting down to budget. When enc
// is non-nil every cached file is sealed with AES-256-GCM at rest.
func newDiskCache(dir string, maxBytes int64, enc *secure.AtRest) (*diskCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &diskCache{dir: dir, maxBytes: maxBytes, enc: enc, ll: list.New(), items: map[string]*list.Element{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type fileInfo struct {
		key  string
		size int64
		mod  int64
	}
	var files []fileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			// A leftover temp from a crash between write and rename. No in-flight Add
			// survives a restart, so reclaim it now instead of leaking disk forever
			// (it is never indexed, counted, or evicted, so it silently erodes budget).
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{key: keyForFile(e.Name()), size: info.Size(), mod: info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod }) // oldest first
	for _, f := range files {
		c.items[f.key] = c.ll.PushFront(&diskItem{key: f.key, size: f.size})
		c.curBytes += f.size
	}
	c.evictLocked()
	return c, nil
}

// fileForKey / keyForFile map a digest ("sha256:<hex>") to a filename ("<hex>")
// and back (all digests are sha256).
func (c *diskCache) path(key string) string {
	return filepath.Join(c.dir, strings.TrimPrefix(key, "sha256:"))
}

func keyForFile(name string) string { return "sha256:" + name }

// Get returns the cached bytes for key (reading the file outside the lock) and
// marks it most-recently-used. A missing/raced file is a miss.
func (c *diskCache) Get(key string) ([]byte, bool) {
	if c == nil || c.maxBytes <= 0 {
		return nil, false
	}
	c.mu.Lock()
	el, ok := c.items[key]
	if ok {
		c.ll.MoveToFront(el)
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	stored, err := os.ReadFile(c.path(key))
	if err != nil {
		c.drop(key)
		return nil, false
	}
	// Decrypt (a no-op when encryption is off). A file that fails GCM authentication
	// — tampered, bit-rotted, or crash-truncated — is dropped and treated as a miss.
	data, err := c.enc.Open(stored)
	if err != nil {
		c.drop(key)
		return nil, false
	}
	// Re-verify against the content address (defence in depth alongside GCM): a bad
	// file is dropped, so the read falls through to the (re-verified) source instead
	// of serving wrong bytes.
	if verifyDigest(key, data) != nil {
		c.drop(key)
		return nil, false
	}
	return data, true
}

// Add writes key -> val to disk (atomically) and evicts least-recently-used files
// until within budget.
func (c *diskCache) Add(key string, val []byte) {
	if c == nil || c.maxBytes <= 0 {
		return
	}
	// Seal at rest (a no-op when encryption is off). The byte budget accounts for the
	// on-disk (sealed) size, which is what actually occupies the cache directory.
	stored, err := c.enc.Seal(val)
	if err != nil {
		return
	}
	size := int64(len(stored))
	if size > c.maxBytes {
		return // a single entry larger than the whole budget is not cached
	}
	// A UNIQUELY named temp: two concurrent Add calls for the SAME key (a parallel
	// prefetch and an on-demand fetch of one digest) must not write the same temp
	// file and corrupt each other. Each writes its own temp; the rename publishes one
	// complete copy atomically (content-addressed, so either copy is identical).
	f, err := os.CreateTemp(c.dir, strings.TrimPrefix(key, "sha256:")+".*.tmp")
	if err != nil {
		return
	}
	tmp := f.Name()
	if _, err := f.Write(stored); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return
	}
	// fsync before the rename so a crash cannot leave an indexed-but-truncated file.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, c.path(key)); err != nil {
		_ = os.Remove(tmp)
		return
	}

	var evicted []string
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*diskItem)
		c.curBytes += size - ent.size
		ent.size = size
		c.ll.MoveToFront(el)
	} else {
		c.items[key] = c.ll.PushFront(&diskItem{key: key, size: size})
		c.curBytes += size
	}
	evicted = c.collectEvictionsLocked()
	c.mu.Unlock()
	for _, k := range evicted {
		_ = os.Remove(c.path(k))
	}
}

func (c *diskCache) drop(key string) {
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		c.curBytes -= el.Value.(*diskItem).size
		c.ll.Remove(el)
		delete(c.items, key)
	}
	c.mu.Unlock()
	_ = os.Remove(c.path(key))
}

// collectEvictionsLocked removes over-budget entries from the LRU and returns
// their keys (the files are deleted by the caller outside the lock).
func (c *diskCache) collectEvictionsLocked() []string {
	var evicted []string
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*diskItem)
		c.ll.Remove(back)
		delete(c.items, ent.key)
		c.curBytes -= ent.size
		evicted = append(evicted, ent.key)
	}
	return evicted
}

// evictLocked deletes over-budget files (used at construction, no concurrency).
func (c *diskCache) evictLocked() {
	for _, k := range c.collectEvictionsLocked() {
		_ = os.Remove(c.path(k))
	}
}
