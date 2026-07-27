package clientcore

import (
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// hardlinkAliases is a bounded-by-observation reverse index: it remembers only
// paths this mount has seen with nlink > 1. Authority invalidations carry inode
// identities, allowing an update through one name to evict every other cached
// alias in O(number of locally observed aliases), without a tree scan.
type hardlinkAliases struct {
	mu     sync.Mutex
	byIno  map[uint64]map[string]struct{}
	byPath map[string]uint64
}

func newHardlinkAliases() *hardlinkAliases {
	return &hardlinkAliases{
		byIno:  map[uint64]map[string]struct{}{},
		byPath: map[string]uint64{},
	}
}

func (h *hardlinkAliases) observe(path string, a fsproto.Attr) {
	if h == nil || path == "" || a.Ino == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removePathLocked(path)
	if a.Nlink <= 1 {
		return
	}
	paths := h.byIno[a.Ino]
	if paths == nil {
		paths = map[string]struct{}{}
		h.byIno[a.Ino] = paths
	}
	paths[path] = struct{}{}
	h.byPath[path] = a.Ino
}

func (h *hardlinkAliases) contains(ino uint64) bool {
	if h == nil || ino == 0 {
		return false
	}
	h.mu.Lock()
	_, ok := h.byIno[ino]
	h.mu.Unlock()
	return ok
}

func (h *hardlinkAliases) pathsForInos(inos []uint64) []string {
	if h == nil || len(inos) == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[string]struct{}{}
	for _, ino := range inos {
		for p := range h.byIno[ino] {
			seen[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

func (h *hardlinkAliases) inosForPaths(paths ...string) []uint64 {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[uint64]struct{}{}
	for _, path := range paths {
		if ino := h.byPath[path]; ino != 0 {
			seen[ino] = struct{}{}
		}
	}
	out := make([]uint64, 0, len(seen))
	for ino := range seen {
		out = append(out, ino)
	}
	return out
}

func (h *hardlinkAliases) removePath(path string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.removePathLocked(path)
	h.mu.Unlock()
}

func (h *hardlinkAliases) removePathLocked(path string) {
	ino, ok := h.byPath[path]
	if !ok {
		return
	}
	delete(h.byPath, path)
	delete(h.byIno[ino], path)
	if len(h.byIno[ino]) == 0 {
		delete(h.byIno, ino)
	}
}

func (h *hardlinkAliases) rekey(oldp, newp string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	type movedPath struct {
		old string
		new string
		ino uint64
	}
	var moved []movedPath
	for p, ino := range h.byPath {
		if p == oldp || strings.HasPrefix(p, oldp+"/") {
			moved = append(moved, movedPath{old: p, new: newp + strings.TrimPrefix(p, oldp), ino: ino})
		}
	}
	for _, m := range moved {
		h.removePathLocked(m.old)
		paths := h.byIno[m.ino]
		if paths == nil {
			paths = map[string]struct{}{}
			h.byIno[m.ino] = paths
		}
		paths[m.new] = struct{}{}
		h.byPath[m.new] = m.ino
	}
}
