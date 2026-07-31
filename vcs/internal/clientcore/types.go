package clientcore

import (
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// Status is an fsproto status code surfaced by the frontend-neutral API.
type Status = int32

// DirEntry is the frontend-neutral directory entry shape. Attr is filled from
// readdir-plus when the authority supplies it.
type DirEntry struct {
	Name string
	Attr fsproto.Attr
	Ino  uint64
}

type dirCacheEntry struct {
	gen      uint64
	version  uint64
	fenceSeq uint64
	entries  []DirEntry
}

// maxDirCacheEntries keeps complete directory snapshots a bounded
// optimization. Eviction is arbitrary because version/fence validation owns
// correctness and a miss simply refetches the listing.
const maxDirCacheEntries = 50_000

// Statfs describes the fixed virtual capacity advertised by PortableFS mounts.
type Statfs struct {
	Blocks, Bfree, Bavail uint64
	Bsize, Frsize         uint32
	Files, Ffree          uint64
	NameLen               uint32
}

// SetattrRequest carries optional POSIX metadata changes without importing any
// frontend-specific flag struct.
type SetattrRequest struct {
	Size    int64
	SetSize bool

	Mode    uint32
	SetMode bool

	MtimeMs  int64
	SetMTime bool
	AtimeMs  int64
	SetATime bool

	UID    uint32
	SetUID bool
	GID    uint32
	SetGID bool

	// Flags/SetFlags is the chflags(2) group: the ABSOLUTE new BSD file-flag
	// word. Zero is a legal value (clear everything), so SetFlags is the only
	// signal of intent. It is legal only against an authority that advertises
	// fsproto.FeatureFlagPersistence — callers check SupportsFlagPersistence
	// first and refuse honestly (ENOTSUP) rather than dropping the change.
	Flags    uint32
	SetFlags bool
}

// NodeState is the frontend-neutral state for one instantiated inode. It tracks
// open-after-unlink routing and open-inode leases; frontends keep their own tree
// shape and pass the current path into Volume ops.
type NodeState struct {
	mu  sync.Mutex
	ino uint64
	// authorityIno is the authority identity proven for this instantiated
	// node. It equals ino for authority-born nodes. A locally-born node gains
	// it when delegation release resolves and pins the flushed create. Keep
	// it separate from ino: frontends may already have published ino as
	// their stable local item identity.
	authorityIno atomic.Uint64
	nopen        int
	// orphanIno is written only under mu (markOrphanLocked / the close-path
	// clear) but read lock-free: the recall/invalidation path consults it
	// while holding attach-level locks, and taking mu there would recreate
	// the attach-lock → node-lock ordering cycle the recall path must never
	// enter (see portablefsd onMarkOrphan).
	orphanIno atomic.Uint64
}

func NewNodeState(ino uint64, authIno bool) *NodeState {
	n := &NodeState{ino: ino}
	if authIno {
		n.authorityIno.Store(ino)
	}
	return n
}

// NewNodeStateWithAuthority restores a frontend-stable item identity whose
// authority identity is different. This is the normal state of a locally-born
// item after its delegated create has drained: FSKit must keep presenting the
// original item ID, while handle-addressed authority operations must use the
// now-proven authority inode.
func NewNodeStateWithAuthority(ino, authorityIno uint64) *NodeState {
	n := &NodeState{ino: ino}
	n.authorityIno.Store(authorityIno)
	return n
}

func (n *NodeState) StableIno() uint64 {
	if n == nil {
		return 0
	}
	return n.ino
}

func (n *NodeState) AuthIno() bool {
	return n != nil && n.AuthorityIno() != 0
}

// AuthorityIno returns the proven authority identity, which may differ from
// StableIno after a locally-born item is published to the authority.
func (n *NodeState) AuthorityIno() uint64 {
	if n == nil {
		return 0
	}
	return n.authorityIno.Load()
}

// RecordAuthorityIno binds a locally-born node to the authority inode proven
// by the delegation-release pin. The binding is immutable for this
// instantiated node; a path recreation receives a fresh NodeState.
func (n *NodeState) RecordAuthorityIno(ino uint64) bool {
	if n == nil || ino == 0 {
		return false
	}
	for {
		current := n.authorityIno.Load()
		if current != 0 {
			return current == ino
		}
		if n.authorityIno.CompareAndSwap(0, ino) {
			return true
		}
	}
}

// MatchesAuthorityIno reports whether an authority notification targets this
// exact instantiated node. Path equality alone is insufficient because an
// orphan notification can arrive after that path has been removed and
// recreated with a fresh local identity.
func (n *NodeState) MatchesAuthorityIno(ino uint64) bool {
	if n == nil || ino == 0 {
		return false
	}
	return n.authorityIno.Load() == ino
}

// Orphan is deliberately lock-free so recall-path guards may call it while
// holding attach-level locks without ordering against mu.
func (n *NodeState) Orphan() uint64 {
	if n == nil {
		return 0
	}
	return n.orphanIno.Load()
}

func (n *NodeState) IsOpen() bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.nopen > 0
}

func (n *NodeState) markOrphanLocked(ino uint64, openOrphans *InodeSet) bool {
	if n == nil || ino == 0 || n.nopen == 0 {
		return false
	}
	n.orphanIno.Store(ino)
	if openOrphans != nil {
		openOrphans.Add(ino)
	}
	return true
}

func (n *NodeState) MarkOrphan(ino uint64, openOrphans *InodeSet) bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.markOrphanLocked(ino, openOrphans)
}

func splitPath(p string) (dir, base string) {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// InoOf maps a path to a stable inode fallback for authorities that predate
// explicit inode identity.
func InoOf(path string) uint64 {
	if path == "" {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	return usableFallbackIno(h.Sum64())
}

func usableFallbackIno(v uint64) uint64 {
	if v > 1 && v != ^uint64(0) {
		return v
	}
	// PortableFS exposes raw item IDs through FSKit's checked successor
	// mapping. UInt64.max has no successor and therefore cannot be a durable
	// frontend identity, even when an authority needs the legacy path-hash
	// fallback.
	if v == ^uint64(0) {
		return ^uint64(0) - 1
	}
	return 2
}

type writeMark struct {
	at time.Time
}

type recentWrites struct {
	mu sync.Mutex
	m  map[string]writeMark
}

const maxRecentWrites = 8192

func newRecentWrites() *recentWrites { return &recentWrites{m: map[string]writeMark{}} }

func (r *recentWrites) record(paths ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, p := range paths {
		r.m[p] = writeMark{at: now}
	}
	if len(r.m) <= maxRecentWrites {
		return
	}
	for p, mk := range r.m {
		if now.Sub(mk.at) > 5*time.Second {
			delete(r.m, p)
		}
	}
	for p := range r.m {
		if len(r.m) <= maxRecentWrites*3/4 {
			break
		}
		delete(r.m, p)
	}
}

func (r *recentWrites) mine(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	mk, ok := r.m[p]
	return ok && time.Since(mk.at) < 3*time.Second
}

func (r *recentWrites) clear() {
	r.mu.Lock()
	r.m = map[string]writeMark{}
	r.mu.Unlock()
}
