package clientcore

import (
	"context"
	"fmt"
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
	// pending counts open reservations that have entered the tracker but
	// have not yet completed their authority-registration/local-open step.
	// A release barrier waits for these reservations before snapshotting:
	// adopting a prepare pin while the same open is still registering would
	// otherwise count that one handle twice.
	pending     int
	pendingDone chan struct{}
	// registered is the number of this owner's live handles represented by
	// local open-registry refs. A locally-born handle can gain an authority
	// identity asynchronously after open, so AuthorityIno alone does not
	// prove every handle is counted.
	registered int
	// releasePin is the extra authority ref acquired while handing a
	// delegated subtree back to shared mode. It belongs to this stable open
	// owner (not its current path) and is retired atomically with the last
	// tracked close.
	releasePin *releasePin
}

type releasePin struct {
	ino  uint64
	path string
}

type trackedOpenSnapshot struct {
	owner openOwner
	path  string
	node  *NodeState
}

// openReleaseBarrier freezes only namespace additions/rebindings that could
// change the set of open owners covered by one delegation handoff. Closes
// deliberately remain live while authority I/O runs.
type openReleaseBarrier struct {
	root     string
	done     chan struct{}
	released bool
}

// OpenReleaseGuard owns one subtree handoff barrier and its initial stable
// snapshot. End must be called exactly once after the authority's durable
// delegation-release decision (or after a failed attempt).
type OpenReleaseGuard struct {
	tracker   *OpenTracker
	barrier   *openReleaseBarrier
	snapshots []trackedOpenSnapshot
	endOnce   sync.Once
}

// OpenTracker counts open file handles by stable owner and records their
// current names. Keeping identity separate from path lets a rename re-key a
// live handle without losing its refcount or delegation-release pin.
type OpenTracker struct {
	mu       sync.Mutex
	m        map[openOwner]*trackedOpen
	barriers map[*openReleaseBarrier]struct{}
}

func NewOpenTracker() *OpenTracker {
	return &OpenTracker{
		m:        map[openOwner]*trackedOpen{},
		barriers: map[*openReleaseBarrier]struct{}{},
	}
}

// Inc reserves one open owner. A delegation handoff gates only opens inside
// its subtree; unrelated paths proceed and closes never wait on the gate.
func (t *OpenTracker) Inc(ctx context.Context, path string, node *NodeState) (released bool, err error) {
	for {
		t.mu.Lock()
		barrier := t.blockingOpenBarrierLocked(path)
		if barrier == nil {
			owner := openOwnerFor(path, node)
			open := t.m[owner]
			if open == nil {
				open = &trackedOpen{node: node}
				t.m[owner] = open
			}
			open.path = path
			open.count++
			if open.pending == 0 {
				open.pendingDone = make(chan struct{})
			}
			open.pending++
			t.mu.Unlock()
			return released, nil
		}
		done := barrier.done
		t.mu.Unlock()
		select {
		case <-done:
			if !barrier.released {
				return false, fmt.Errorf("clientcore: delegation handoff for %q failed", path)
			}
			released = true
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

// FinishInc resolves the reservation created by Inc. A successful open keeps
// its count; a failed open removes that count atomically with clearing the
// pending state so a release snapshot can never observe a half-open handle.
// On failure, a release-time pin is returned if this was the final owner.
func (t *OpenTracker) FinishInc(path string, node *NodeState, succeeded, registered bool) (remaining int, pin releasePin, pinned bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	owner := openOwnerFor(path, node)
	open := t.m[owner]
	if open == nil || open.pending <= 0 {
		return 0, releasePin{}, false
	}
	open.pending--
	if open.pending == 0 {
		close(open.pendingDone)
		open.pendingDone = nil
	}
	if succeeded {
		if registered {
			open.registered++
		}
		return open.count, releasePin{}, false
	}
	open.count--
	if open.count <= 0 {
		if open.releasePin != nil {
			pin = *open.releasePin
			pinned = true
		}
		delete(t.m, owner)
		return 0, pin, pinned
	}
	return open.count, releasePin{}, false
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
func (t *OpenTracker) Dec(path string, node *NodeState) (
	remaining int,
	currentPath string,
	found bool,
	closeRegistered bool,
	pin releasePin,
	pinned bool,
) {
	t.mu.Lock()
	defer t.mu.Unlock()
	owner := openOwnerFor(path, node)
	open := t.m[owner]
	if open == nil {
		return 0, "", false, false, releasePin{}, false
	}
	currentPath = open.path
	open.count--
	// Handles sharing one stable owner are intentionally indistinguishable.
	// Keep every existing registry ref while it can still represent a live
	// handle; retire one only when the ref count would exceed the remaining
	// handle count. This matters when a locally-born handle was initially
	// unregistered and a later open acquired the owner's first authority ref.
	if open.registered > open.count {
		open.registered--
		closeRegistered = true
	}
	if open.count <= 0 {
		if open.releasePin != nil {
			pin = *open.releasePin
			pinned = true
		}
		delete(t.m, owner)
		return 0, currentPath, true, closeRegistered, pin, pinned
	}
	return open.count, currentPath, true, closeRegistered, releasePin{}, false
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

// ApplyRename atomically updates live open names after a successful rename.
// A rename intersecting a delegation handoff waits until that exact handoff
// resolves; a completed namespace mutation can never publish a partial
// Unname/Rekey transition to the tracker.
func (t *OpenTracker) ApplyRename(oldPath, newPath string, dst *NodeState) {
	for {
		t.mu.Lock()
		barrier := t.blockingRenameBarrierLocked(oldPath, newPath)
		if barrier != nil {
			done := barrier.done
			t.mu.Unlock()
			<-done
			continue
		}
		if dst != nil {
			if open := t.m[openOwnerFor("", dst)]; open != nil {
				open.path = ""
				if open.releasePin != nil {
					open.releasePin.path = ""
				}
			}
		}
		t.rekeyPrefixLocked(oldPath, newPath)
		t.mu.Unlock()
		return
	}
}

// rekeyPrefixLocked updates the current name of every live handle at or below
// old. Anonymous handles must also be re-keyed because their path is their
// owner; NodeState-backed handles retain their stable owner key.
func (t *OpenTracker) rekeyPrefixLocked(oldPath, newPath string) {
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
		if move.open.releasePin != nil {
			move.open.releasePin.path = move.path
		}
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

// BeginRelease installs a scope barrier and snapshots every currently named
// owner below root. Overlapping handoffs serialize, while disjoint subtree
// handoffs may proceed independently.
func (t *OpenTracker) BeginRelease(ctx context.Context, root string) (*OpenReleaseGuard, error) {
	for {
		t.mu.Lock()
		barrier := t.overlappingReleaseBarrierLocked(root)
		if barrier != nil {
			done := barrier.done
			t.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		barrier = &openReleaseBarrier{root: root, done: make(chan struct{})}
		t.barriers[barrier] = struct{}{}
		guard := &OpenReleaseGuard{tracker: t, barrier: barrier}
		for {
			pendingDone := t.pendingOpenUnderLocked(root)
			if pendingDone == nil {
				break
			}
			t.mu.Unlock()
			select {
			case <-pendingDone:
			case <-ctx.Done():
				guard.End(false)
				return nil, ctx.Err()
			}
			t.mu.Lock()
		}
		snapshots := make([]trackedOpenSnapshot, 0)
		for owner, open := range t.m {
			if open.path != "" && pathUnderRoot(open.path, root) {
				snapshots = append(snapshots, trackedOpenSnapshot{
					owner: owner,
					path:  open.path,
					node:  open.node,
				})
			}
		}
		t.mu.Unlock()
		guard.snapshots = snapshots
		return guard, nil
	}
}

func (t *OpenTracker) pendingOpenUnderLocked(root string) <-chan struct{} {
	for _, open := range t.m {
		if open.pending > 0 && open.path != "" && pathUnderRoot(open.path, root) {
			return open.pendingDone
		}
	}
	return nil
}

// AdoptPreparedPin installs one authority-prepared path mapping against the
// snapshot owner that is still live. adoptRefs performs only local registry
// bookkeeping; all authority I/O completed before this method takes the
// tracker mutex.
func (g *OpenReleaseGuard) AdoptPreparedPin(
	snapshot trackedOpenSnapshot,
	ino uint64,
	gen uint64,
	adoptRefs func(path string, ino uint64, refs int, gen uint64) error,
) (active bool, err error) {
	t := g.tracker
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[snapshot.owner]
	if open == nil || open.count <= 0 || open.path != snapshot.path {
		return false, nil
	}
	if open.node != nil && open.node.Orphan() != 0 {
		return false, nil
	}
	if open.node != nil {
		missing := open.count - open.registered
		if missing <= 0 {
			return true, nil
		}
		if existing := open.node.AuthorityIno(); existing != 0 {
			if existing != ino {
				return false, fmt.Errorf(
					"clientcore: prepared open pin for %q changed authority inode from %d to %d",
					snapshot.path, existing, ino,
				)
			}
			// The identity may have become known after the release snapshot
			// was filtered (for example, a flushed local create reached the
			// frontend registry). This prepare still owns the durable pin;
			// adopt the exact live-handle count instead of leaving an
			// unrepresented session hold.
			if err := adoptRefs(snapshot.path, ino, missing, gen); err != nil {
				return false, err
			}
			open.registered += missing
			return true, nil
		}
		if err := adoptRefs(snapshot.path, ino, missing, gen); err != nil {
			return false, err
		}
		if !open.node.RecordAuthorityIno(ino) {
			return false, fmt.Errorf("clientcore: prepared open pin for %q could not bind inode %d", snapshot.path, ino)
		}
		open.registered += missing
		return true, nil
	}
	if open.releasePin != nil {
		if open.releasePin.ino != ino {
			return false, fmt.Errorf(
				"clientcore: prepared anonymous pin for %q changed inode from %d to %d",
				snapshot.path, open.releasePin.ino, ino,
			)
		}
		return true, nil
	}
	if err := adoptRefs(snapshot.path, ino, 1, gen); err != nil {
		return false, err
	}
	open.releasePin = &releasePin{ino: ino, path: snapshot.path}
	return true, nil
}

func (g *OpenReleaseGuard) NeedsPreparedPin(snapshot trackedOpenSnapshot) bool {
	t := g.tracker
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[snapshot.owner]
	if open == nil || open.count <= 0 || open.path != snapshot.path {
		return false
	}
	if open.node != nil {
		return open.node.Orphan() == 0 && open.registered < open.count
	}
	return open.releasePin == nil
}

func (t *OpenTracker) releasePin(owner openOwner) (releasePin, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[owner]
	if open == nil || open.releasePin == nil {
		return releasePin{}, false
	}
	return *open.releasePin, true
}

func (t *OpenTracker) releasePinCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, open := range t.m {
		if open.releasePin != nil {
			count++
		}
	}
	return count
}

func (t *OpenTracker) seedReleasePin(owner openOwner, pin releasePin) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[owner]
	if open == nil {
		return false
	}
	open.releasePin = &pin
	return true
}

func (g *OpenReleaseGuard) Snapshots() []trackedOpenSnapshot {
	return g.snapshots
}

func (g *OpenReleaseGuard) End(released bool) {
	g.endOnce.Do(func() {
		t := g.tracker
		t.mu.Lock()
		if _, ok := t.barriers[g.barrier]; ok {
			g.barrier.released = released
			delete(t.barriers, g.barrier)
			close(g.barrier.done)
		}
		t.mu.Unlock()
	})
}

// InstallOrJoinAnonymousPin atomically gives the anonymous owner its one
// tracker-owned registry ref, or joins the already-installed ref when another
// barrier-woken open won the race. installed tells the caller whether the
// registry ref it acquired became tracker-owned; a joiner must close its extra
// ref while keeping the shared pin live.
func (t *OpenTracker) InstallOrJoinAnonymousPin(path string, ino uint64) (installed, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[openOwnerFor(path, nil)]
	if open == nil || open.count <= 0 || open.path != path {
		return false, false
	}
	if open.releasePin != nil {
		return false, open.releasePin.ino == ino
	}
	open.releasePin = &releasePin{ino: ino, path: path}
	return true, true
}

// AnonymousPin reports the one tracker-owned authority ref shared by all
// anonymous handles for path. It lets an open that was queued behind a
// successful handoff join that existing ref instead of trying to install a
// second tracker pin.
func (t *OpenTracker) AnonymousPin(path string) (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := t.m[openOwnerFor(path, nil)]
	if open == nil || open.releasePin == nil {
		return 0, false
	}
	return open.releasePin.ino, true
}

func (t *OpenTracker) blockingOpenBarrierLocked(path string) *openReleaseBarrier {
	for barrier := range t.barriers {
		if pathUnderRoot(path, barrier.root) {
			return barrier
		}
	}
	return nil
}

func (t *OpenTracker) blockingRenameBarrierLocked(oldPath, newPath string) *openReleaseBarrier {
	for barrier := range t.barriers {
		if pathsOverlap(oldPath, barrier.root) || pathsOverlap(newPath, barrier.root) {
			return barrier
		}
	}
	return nil
}

func (t *OpenTracker) overlappingReleaseBarrierLocked(root string) *openReleaseBarrier {
	for barrier := range t.barriers {
		if pathsOverlap(root, barrier.root) {
			return barrier
		}
	}
	return nil
}

func pathsOverlap(a, b string) bool {
	return pathUnderRoot(a, b) || pathUnderRoot(b, a)
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
