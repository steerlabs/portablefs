//go:build linux

package xfsstore

import (
	"errors"
	"fmt"
	"sync"

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

// persist is the only persistence-syscall boundary. Linux reports writeback
// errors once per description, so every failure must fence before another
// barrier or waiter can consume an apparently successful retry.
func (v *Volume) persist(fd int, call func(int) error) error {
	if err := v.Health(); err != nil {
		return durabilityError(err)
	}
	if err := call(fd); err != nil {
		return v.failDurability(err)
	}
	if err := v.Health(); err != nil {
		return durabilityError(err)
	}
	return nil
}

func (v *Volume) syncInode(state *inodeFsyncState, fd int, dataOnly bool) (int, error) {
	if err := v.Health(); err != nil {
		return 0, durabilityError(err)
	}
	return state.barrier(fd, dataOnly,
		func(fd int) error { return v.persist(fd, v.fsync) },
		func(fd int) error { return v.persist(fd, v.fdatasync) })
}

func durabilityError(err error) error {
	var failure *DurabilityError
	if errors.As(err, &failure) {
		return failure
	}
	return err
}

func (v *Volume) failDurability(err error) error {
	v.Fence(&DurabilityError{Cause: err})
	// Fence preserves the first failure, including when different descriptions
	// fail concurrently. Return that same terminal observation to every caller.
	return durabilityError(v.Health())
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
	if err := v.Health(); err != nil {
		return durabilityError(err)
	}
	v.mu.RLock()
	if v.closed || v.fenced != nil {
		v.mu.RUnlock()
		return durabilityError(v.Health())
	}
	root := v.objects[v.root].res
	root.acquire()
	v.mu.RUnlock()
	defer root.release()
	_, err := v.volumeSync.barrier(root.fd, false,
		func(fd int) error { return v.persist(fd, v.syncfs) }, nil)
	return err
}
