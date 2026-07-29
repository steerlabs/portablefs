package clientcore

import (
	"strings"
	"sync"
)

// openOwner gives a live handle a rename-stable identity. Kernel frontends pass
// a NodeState for normal handles; the path fallback preserves the old behavior
// for callers that do not have one.
type openOwner struct {
	node          *NodeState
	anonymousPath string
}

func openOwnerFor(path string, node *NodeState) openOwner {
	if node != nil {
		return openOwner{node: node}
	}
	return openOwner{anonymousPath: path}
}

type trackedOpen struct {
	path  string
	node  *NodeState
	count int
}

// OpenTracker counts open file handles by stable owner and records their
// current names. Keeping identity separate from path lets a rename re-key a
// live handle without losing its refcount or delegation-release pin.
type OpenTracker struct {
	mu sync.Mutex
	m  map[openOwner]*trackedOpen
}

func NewOpenTracker() *OpenTracker {
	return &OpenTracker{m: map[openOwner]*trackedOpen{}}
}

func (t *OpenTracker) Inc(path string, node *NodeState) {
	t.mu.Lock()
	owner := openOwnerFor(path, node)
	open := t.m[owner]
	if open == nil {
		open = &trackedOpen{node: node}
		t.m[owner] = open
	}
	open.path = path
	open.count++
	t.mu.Unlock()
}

// CurrentPath resolves the rename-current name for one stable handle owner.
// Frontends commonly retain the open-time path and pass it back on fsync or
// close, so callers must consult the tracker before a path-sensitive barrier.
func (t *OpenTracker) CurrentPath(path string, node *NodeState) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[openOwnerFor(path, node)]
	if open == nil {
		return path, false
	}
	return open.path, true
}

// Dec drops one handle and returns the number still owned by the same
// NodeState (or anonymous path), plus its rename-current path. found
// distinguishes an intentionally unnamed orphan from a missing tracker entry.
func (t *OpenTracker) Dec(path string, node *NodeState) (remaining int, currentPath string, found bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	owner := openOwnerFor(path, node)
	open := t.m[owner]
	if open == nil {
		return 0, "", false
	}
	currentPath = open.path
	open.count--
	if open.count <= 0 {
		delete(t.m, owner)
		return 0, currentPath, true
	}
	return open.count, currentPath, true
}

// BusyUnder reports whether any open handle is at or under subtree root (root
// "" = the whole volume). The session sweeper uses it to skip a still-in-use
// subtree.
func (t *OpenTracker) BusyUnder(root string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, open := range t.m {
		if open.path != "" && pathUnderRoot(open.path, root) {
			return true
		}
	}
	return false
}

// ForEachUnder runs fn once for every named handle owner under root while the
// tracker is locked. Delegation release deliberately holds this lock across
// authority pinning, so Open, CloseHandle, and Rename cannot change the set
// between the fail-closed pin check and the durable release.
func (t *OpenTracker) ForEachUnder(root string, fn func(openOwner, string, *NodeState) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for owner, open := range t.m {
		if open.path != "" && pathUnderRoot(open.path, root) {
			if err := fn(owner, open.path, open.node); err != nil {
				return err
			}
		}
	}
	return nil
}

// RekeyPrefix updates the current name of every live handle at or below old.
// Anonymous handles must also be re-keyed because their path is their owner;
// NodeState-backed handles retain their stable owner key.
func (t *OpenTracker) RekeyPrefix(oldPath, newPath string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	type move struct {
		owner openOwner
		open  *trackedOpen
		path  string
	}
	var moves []move
	for owner, open := range t.m {
		moved, ok := rekeyPathPrefix(open.path, oldPath, newPath)
		if !ok {
			continue
		}
		moves = append(moves, move{owner: owner, open: open, path: moved})
	}
	for _, move := range moves {
		move.open.path = move.path
		owner := move.owner
		if owner.node != nil {
			continue
		}
		delete(t.m, owner)
		newOwner := openOwnerFor(move.path, nil)
		if prior := t.m[newOwner]; prior != nil {
			prior.count += move.open.count
		} else {
			t.m[newOwner] = move.open
		}
	}
}

// Unname removes a rename-over destination from namespace tracking while
// retaining its handle count until CloseHandle. Orphan handles must not block
// an unrelated delegation release simply because they once had that name.
func (t *OpenTracker) Unname(node *NodeState) {
	if node == nil {
		return
	}
	t.mu.Lock()
	if open := t.m[openOwnerFor("", node)]; open != nil {
		open.path = ""
	}
	t.mu.Unlock()
}

func pathUnderRoot(path, root string) bool {
	return root == "" || path == root || strings.HasPrefix(path, root+"/")
}

func rekeyPathPrefix(path, oldPath, newPath string) (string, bool) {
	switch {
	case path == oldPath:
		return newPath, true
	case oldPath == "":
		if path == "" {
			return newPath, true
		}
		return newPath + "/" + path, true
	case strings.HasPrefix(path, oldPath+"/"):
		return newPath + path[len(oldPath):], true
	default:
		return path, false
	}
}
