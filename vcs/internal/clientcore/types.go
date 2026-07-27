package clientcore

import (
	"hash/fnv"
	"strings"
	"sync"
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
	gen     uint64
	version uint64
	entries []DirEntry
}

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

	UID    uint32
	SetUID bool
	GID    uint32
	SetGID bool
}

// NodeState is the frontend-neutral state for one instantiated inode. It tracks
// open-after-unlink routing and open-inode leases; frontends keep their own tree
// shape and pass the current path into Volume ops.
type NodeState struct {
	mu        sync.Mutex
	ino       uint64
	authIno   bool
	nopen     int
	orphanIno uint64
}

func NewNodeState(ino uint64, authIno bool) *NodeState {
	return &NodeState{ino: ino, authIno: authIno}
}

func (n *NodeState) StableIno() uint64 {
	if n == nil {
		return 0
	}
	return n.ino
}

func (n *NodeState) AuthIno() bool {
	return n != nil && n.authIno
}

func (n *NodeState) Orphan() uint64 {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.orphanIno
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
	n.orphanIno = ino
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
	if v := h.Sum64(); v > 1 {
		return v
	}
	return 2
}

func sessAttr(kind string, mode uint32, size, mtimeMs int64, uid, gid uint32) *fsproto.Attr {
	if mtimeMs == 0 {
		mtimeMs = time.Now().UnixMilli()
	}
	return &fsproto.Attr{Kind: kind, Mode: mode, Size: size, MtimeMs: mtimeMs, CtimeMs: mtimeMs, AtimeMs: mtimeMs, Uid: uid, Gid: gid}
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
