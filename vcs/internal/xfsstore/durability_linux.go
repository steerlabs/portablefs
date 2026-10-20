//go:build linux

package xfsstore

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DurabilityError denotes failed persistence, including a
// restore hydration-map transition, independent of its errno. Its cause is
// diagnostic: ENOSPC from writeback cannot be mistaken for a pre-apply refusal.
type DurabilityError struct{ Cause error }

func (e *DurabilityError) Error() string {
	return fmt.Sprintf("xfsstore: durability sync: %v", e.Cause)
}
func (e *DurabilityError) Is(target error) bool { return target == ErrOutcomeUncertain }

// SyncTarget owns a sync-capable description until Close. Retaining a handle
// takes a reference to its existing description; it never reopens the inode.
type SyncTarget interface {
	Sync() error
	Close() error
}

type syncTarget struct {
	volume  *Volume
	fd      int
	state   *inodeFsyncState
	release func() error
	mu      sync.Mutex
	closed  bool
}

func (t *syncTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.release()
}

func (t *syncTarget) Sync() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrClosed
	}
	_, err := t.volume.syncInode(t.state, t.fd, false)
	return err
}

// syncBarrier is the only persistence-syscall boundary. A group's error cursor
// stays serialized until any failed syscall has fenced the volume. Checking
// again after a successful call also observes failures on other descriptions.
func (v *Volume) syncBarrier(group *syncGroup, fd int, dataOnly bool, fsync, fdatasync func(int) error) (int, error) {
	if err := v.syncHealth(); err != nil {
		return 0, err
	}
	var observation StorageSync
	persist := func(kind string, call func(int) error) func(int) error {
		return func(fd int) error {
			// A queued batch may have outlived a failure on another inode.
			if err := v.syncHealth(); err != nil {
				return err
			}
			var started time.Time
			if v.onStorageSync != nil {
				started = time.Now()
			}
			err := call(fd)
			if v.onStorageSync != nil {
				observation = StorageSync{Kind: kind, Elapsed: time.Since(started)}
			}
			if err != nil {
				err = v.failDurability(err)
			} else {
				err = v.syncHealth()
			}
			return err
		}
	}
	kind := "fsync"
	if group == &v.volumeSync {
		kind = "syncfs"
	}
	return group.barrier(fd, dataOnly, persist(kind, fsync), persist("fdatasync", fdatasync), func(waiters int) {
		if v.onStorageSync != nil && observation.Kind != "" {
			observation.Waiters = waiters
			v.onStorageSync(observation)
		}
	})
}

func (v *Volume) syncInode(state *inodeFsyncState, fd int, dataOnly bool) (int, error) {
	return v.syncBarrier(&state.syncGroup, fd, dataOnly, v.fsync, v.fdatasync)
}

func (v *Volume) syncHealth() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.syncHealthLocked()
}

func (v *Volume) syncHealthLocked() error {
	if v.closed {
		return ErrClosed
	}
	if v.durabilityFailure != nil {
		return v.durabilityFailure
	}
	return v.fenced
}

func (v *Volume) failDurability(err error) error {
	v.Fence(&DurabilityError{Cause: err})
	// Different descriptions may fail concurrently; every barrier returns the
	// first failure, independently of the lifetime of an inode's batch state.
	return v.syncHealth()
}

func (t *writeTarget) Sync() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrClosed
	}
	_, err := t.volume.syncInode(t.fsyncState, t.res.fd, false)
	return err
}

func (v *Volume) PinSyncHandle(id Capability) (SyncTarget, error) {
	opened, err := v.holdOpen(id)
	if err != nil {
		return nil, err
	}
	return &syncTarget{volume: v, fd: opened.fd(), state: opened.fsyncState,
		release: func() error { opened.release(); return nil }}, nil
}

func (v *Volume) PinSyncObject(id Capability) (SyncTarget, error) {
	obj, err := v.holdObject(id)
	if err != nil {
		return nil, err
	}
	defer obj.release()
	flags := unix.O_RDONLY
	if obj.kind == KindDirectory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := v.reopen(obj.fd(), flags, obj.kind)
	if err != nil {
		return nil, err
	}
	state := v.fsyncState(obj.coordinate.Stable)
	return &syncTarget{volume: v, fd: fd, state: state, release: func() error {
		v.releaseFsyncState(state)
		return unix.Close(fd)
	}}, nil
}

// SyncFS uses the root description retained at startup. The shared cursor is
// serialized through fencing; arrivals during a sync share the next syscall.
func (v *Volume) SyncFS() error {
	v.mu.RLock()
	if err := v.syncHealthLocked(); err != nil {
		v.mu.RUnlock()
		return err
	}
	root := v.objects[v.root].res
	root.acquire()
	v.mu.RUnlock()
	defer root.release()
	_, err := v.syncBarrier(&v.volumeSync, root.fd, false, v.syncfs, nil)
	return err
}
