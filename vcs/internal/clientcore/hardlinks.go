package clientcore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// hardlinkAliases is the mount's authority-identity safety index.
//
// Every observed authority-backed path is retained, including paths first seen
// with nlink == 1. That distinction is important: a peer can add a hard-link
// alias after this mount instantiated the original node. The link invalidation
// carries RelatedInos, so retaining the original identity lets the invalidation
// permanently move that inode to the alias-unsafe (write-through) lane without
// requiring a fresh getattr on the open node.
//
// Identity and alias-unsafe state are coherence facts rather than expendable
// caches. They therefore have no lossy size cap: evicting either could make an
// old live NodeState eligible for path-keyed write-back again. Space is
// O(observed authority identities and paths, plus related identities arriving
// while authority observations are in flight), while hot lookups are O(1) and
// alias fan-out is O(locally observed aliases). The permanent unsafe facts are
// a compact inode set (no per-inode path map); local removes and renames
// prune/rekey path spellings.
type hardlinkAliases struct {
	mu           sync.RWMutex
	namespaceSeq uint64
	active       map[uint64]int
	activeTotal  int
	oldestActive uint64
	pending      map[uint64]uint64
	byIno        map[uint64]*observedInode
	byPath       map[string]uint64
	unsafe       map[uint64]struct{}
}

type observedInode struct {
	paths     map[string]struct{}
	directory bool
}

func newHardlinkAliases() *hardlinkAliases {
	return &hardlinkAliases{
		byIno:   map[uint64]*observedInode{},
		byPath:  map[string]uint64{},
		unsafe:  map[uint64]struct{}{},
		active:  map[uint64]int{},
		pending: map[uint64]uint64{},
	}
}

// releaseHardlinkScopes drains every delegation covering any observed spelling
// of the supplied inode(s), plus the explicit operation operands. A hard-linked
// inode may cross directory delegation scopes; releasing only the spelling
// used by the syscall would let another retained overlay keep stale attrs or
// directory state for the same inode.
func (v *Volume) releaseHardlinkScopes(
	ctx context.Context,
	nodes []*NodeState,
	operands ...string,
) error {
	if v.wb == nil {
		return nil
	}
	return v.wb.ReleaseFor(ctx, v.hardlinkMutationPaths(nodes, operands...)...)
}

// hardlinkMutationPaths returns every known spelling whose delegation view
// can be affected by a path-bearing inode mutation. It is also used by the
// authority/delegation transition gate so an alias grant cannot install in
// the release-to-RPC window.
func (v *Volume) hardlinkMutationPaths(
	nodes []*NodeState,
	operands ...string,
) []string {
	paths, _ := v.hardlinkMutationTargets(nodes, operands...)
	return paths
}

// hardlinkMutationTargets snapshots every known spelling and authority
// identity affected by one mutation under a single index lock. The identity
// set lets the transition coordinator catch a disjoint acquire reply that
// reveals a previously unseen hardlink alias before installing its grant.
func (v *Volume) hardlinkMutationTargets(
	nodes []*NodeState,
	operands ...string,
) ([]string, []uint64) {
	nodeInos := make([]uint64, 0, len(nodes))
	for _, node := range nodes {
		if ino := authHandleIno(node); ino != 0 {
			nodeInos = append(nodeInos, ino)
		}
	}
	return v.hardlinks.mutationTargets(nodeInos, operands...)
}

func (h *hardlinkAliases) mutationTargets(
	nodeInos []uint64,
	operands ...string,
) ([]string, []uint64) {
	seen := make(map[string]struct{}, len(operands))
	paths := make([]string, 0, len(operands))
	for _, path := range operands {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	if h == nil {
		return paths, append([]uint64(nil), nodeInos...)
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	inoSet := make(map[uint64]struct{}, len(nodeInos)+len(operands))
	for _, ino := range nodeInos {
		if ino != 0 {
			inoSet[ino] = struct{}{}
		}
	}
	for _, operand := range operands {
		if ino := h.byPath[operand]; ino != 0 {
			inoSet[ino] = struct{}{}
		}
	}
	inos := make([]uint64, 0, len(inoSet))
	for ino := range inoSet {
		inos = append(inos, ino)
		if observed := h.byIno[ino]; observed != nil {
			for alias := range observed.paths {
				if _, ok := seen[alias]; ok {
					continue
				}
				seen[alias] = struct{}{}
				paths = append(paths, alias)
			}
		}
	}
	return paths, inos
}

type hardlinkAdmissionIdentitiesKey struct{}
type delegatedBindingExpectationKey struct{}

type delegatedBindingExpectation struct {
	path string
	ino  uint64
}

func withHardlinkAdmissionIdentities(ctx context.Context, nodes ...*NodeState) context.Context {
	inos := make([]uint64, 0, len(nodes))
	for _, node := range nodes {
		if ino := authHandleIno(node); ino != 0 {
			inos = append(inos, ino)
		}
	}
	if len(inos) == 0 {
		return ctx
	}
	return context.WithValue(ctx, hardlinkAdmissionIdentitiesKey{}, inos)
}

func withDelegatedBindingExpectation(ctx context.Context, path string, node *NodeState) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if ino := authHandleIno(node); ino != 0 {
		expected := &delegatedBindingExpectation{
			path: cleanVolumePath(path),
			ino:  ino,
		}
		return context.WithValue(ctx, delegatedBindingExpectationKey{}, expected)
	}
	return ctx
}

func (v *Volume) validateDelegatedMutation(
	ctx context.Context,
	path string,
	entry writeback.Entry,
	present bool,
) error {
	if ctx != nil {
		if expected, ok := ctx.Value(delegatedBindingExpectationKey{}).(*delegatedBindingExpectation); ok &&
			expected.path == cleanVolumePath(path) &&
			(!present || entry.Ino != expected.ino) {
			return writeback.ErrDelegatedBindingMismatch
		}
	}
	return nil
}

func (v *Volume) allowDelegatedMutation(ctx context.Context, path string) bool {
	if ctx != nil {
		if inos, ok := ctx.Value(hardlinkAdmissionIdentitiesKey{}).([]uint64); ok {
			for _, ino := range inos {
				if v.hardlinks.contains(ino) {
					return false
				}
			}
		}
	}
	return !v.hardlinks.containsPath(cleanVolumePath(path))
}

func (h *hardlinkAliases) observe(path string, a fsproto.Attr) {
	h.observeLockedAt(path, a, 0, false)
}

type hardlinkObservation struct {
	index  *hardlinkAliases
	seq    uint64
	closed atomic.Bool
}

func (h *hardlinkAliases) beginObservation() *hardlinkObservation {
	guard := &hardlinkObservation{index: h}
	if h == nil {
		return guard
	}
	h.mu.Lock()
	guard.seq = h.namespaceSeq
	h.active[guard.seq]++
	if h.activeTotal == 0 || guard.seq < h.oldestActive {
		h.oldestActive = guard.seq
	}
	h.activeTotal++
	h.mu.Unlock()
	return guard
}

func (g *hardlinkObservation) Observe(path string, a fsproto.Attr) {
	if g == nil || g.closed.Load() || g.index == nil {
		return
	}
	g.index.observeLockedAt(path, a, g.seq, true)
}

func (g *hardlinkObservation) Close() {
	if g == nil || g.index == nil || !g.closed.CompareAndSwap(false, true) {
		return
	}
	h := g.index
	h.mu.Lock()
	if h.active[g.seq] > 1 {
		h.active[g.seq]--
		h.activeTotal--
		h.mu.Unlock()
		return
	}
	delete(h.active, g.seq)
	h.activeTotal--
	if h.activeTotal == 0 {
		h.oldestActive = 0
		clear(h.pending)
		h.mu.Unlock()
		return
	}
	if g.seq == h.oldestActive {
		var oldest uint64
		first := true
		for seq := range h.active {
			if first || seq < oldest {
				oldest = seq
				first = false
			}
		}
		h.oldestActive = oldest
		for ino, eventSeq := range h.pending {
			if eventSeq <= oldest {
				delete(h.pending, ino)
			}
		}
	}
	h.mu.Unlock()
}

// observeLockedAt publishes an authority observation. A guarded observation
// becomes alias-unsafe only when an invalidation for the SAME inode occurred
// after its RPC began. Related inode facts are retained just until all older
// observations close, so unrelated namespace churn neither disables
// delegation nor creates mount-lifetime tombstones.
func (h *hardlinkAliases) observeLockedAt(
	path string,
	a fsproto.Attr,
	observationSeq uint64,
	guarded bool,
) {
	if h == nil || path == "" || a.Ino == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observeAtLocked(path, a, observationSeq, guarded)
}

func (h *hardlinkAliases) observeAtLocked(
	path string,
	a fsproto.Attr,
	observationSeq uint64,
	guarded bool,
) {
	// Do not tear down and recreate an existing same-inode observation: once
	// RelatedInos or an nlink>1 attr has made an inode alias-unsafe, a delayed
	// nlink==1 response must never clear that monotonic safety fact.
	if oldIno := h.byPath[path]; oldIno != 0 && oldIno != a.Ino {
		h.removePathLocked(path)
	}
	observed := h.byIno[a.Ino]
	if observed == nil {
		observed = &observedInode{paths: map[string]struct{}{}}
		h.byIno[a.Ino] = observed
	}
	if a.Kind == "directory" {
		observed.directory = true
	}
	observed.paths[path] = struct{}{}
	h.byPath[path] = a.Ino
	// POSIX directory link counts reflect "." and child ".." entries; they
	// are not user-creatable aliases and never need the hardlink lane.
	pendingSeq := h.pending[a.Ino]
	if a.Kind != "directory" &&
		(a.Nlink > 1 || guarded && pendingSeq > observationSeq) {
		h.unsafe[a.Ino] = struct{}{}
	}
}

// observeAcquireReply publishes a complete delegation decision atomically.
// The transition coordinator holds its own lock first, so an authority
// footprint can never see half of a reply's alias/inode observations.
func (h *hardlinkAliases) observeAcquireReply(
	scope string,
	reply writeback.AcquireReply,
) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if reply.Exists {
		h.observeAtLocked(scope, attrFromEntry(reply.Self), 0, false)
	}
	if reply.HasChildren {
		for _, entry := range reply.Children {
			childPath := entry.Name
			if scope != "" {
				childPath = scope + "/" + entry.Name
			}
			h.observeAtLocked(childPath, attrFromEntry(entry), 0, false)
		}
	}
}

// markAliasUnsafe permanently classifies every already-observed related
// authority inode as unsafe for path-keyed write-back. For unseen identities,
// a compact pending fact lives only while a pre-invalidation authority
// observation is in flight; Observe consumes it by exact inode identity.
func (h *hardlinkAliases) markAliasUnsafe(inos []uint64) {
	if h == nil || len(inos) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.namespaceSeq++
	for _, ino := range inos {
		if ino == 0 {
			continue
		}
		if observed := h.byIno[ino]; observed != nil && !observed.directory {
			h.unsafe[ino] = struct{}{}
		}
		if h.activeTotal != 0 && h.oldestActive < h.namespaceSeq {
			h.pending[ino] = h.namespaceSeq
		}
	}
}

func (h *hardlinkAliases) contains(ino uint64) bool {
	if h == nil || ino == 0 {
		return false
	}
	h.mu.RLock()
	_, unsafe := h.unsafe[ino]
	h.mu.RUnlock()
	return unsafe
}

func (h *hardlinkAliases) containsPath(path string) bool {
	if h == nil || path == "" {
		return false
	}
	h.mu.RLock()
	_, unsafe := h.unsafe[h.byPath[path]]
	h.mu.RUnlock()
	return unsafe
}

func (h *hardlinkAliases) pathsForInos(inos []uint64) []string {
	if h == nil || len(inos) == 0 {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, ino := range inos {
		observed := h.byIno[ino]
		if observed == nil {
			continue
		}
		for p := range observed.paths {
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
	h.mu.RLock()
	defer h.mu.RUnlock()
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

func (h *hardlinkAliases) removePrefix(path string) {
	if h == nil || path == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removePrefixLocked(path)
}

func (h *hardlinkAliases) removePrefixLocked(path string) {
	prefix := path + "/"
	for observedPath := range h.byPath {
		if observedPath == path || strings.HasPrefix(observedPath, prefix) {
			h.removePathLocked(observedPath)
		}
	}
}

func (h *hardlinkAliases) removePathLocked(path string) {
	ino, ok := h.byPath[path]
	if !ok {
		return
	}
	delete(h.byPath, path)
	observed := h.byIno[ino]
	if observed == nil {
		return
	}
	delete(observed.paths, path)
	if len(observed.paths) == 0 {
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
		old       string
		new       string
		ino       uint64
		directory bool
	}
	var moved []movedPath
	for p, ino := range h.byPath {
		if p == oldp || strings.HasPrefix(p, oldp+"/") {
			moved = append(moved, movedPath{
				old:       p,
				new:       newp + strings.TrimPrefix(p, oldp),
				ino:       ino,
				directory: h.byIno[ino] != nil && h.byIno[ino].directory,
			})
		}
	}
	// Rename-over detaches the entire prior destination binding before the
	// source takes its name. Drop those observed spellings first; permanent
	// alias-unsafe inode facts live separately and deliberately survive.
	h.removePrefixLocked(newp)
	for _, m := range moved {
		h.removePathLocked(m.old)
		observed := h.byIno[m.ino]
		if observed == nil {
			observed = &observedInode{
				paths:     map[string]struct{}{},
				directory: m.directory,
			}
			h.byIno[m.ino] = observed
		}
		observed.paths[m.new] = struct{}{}
		h.byPath[m.new] = m.ino
	}
}
