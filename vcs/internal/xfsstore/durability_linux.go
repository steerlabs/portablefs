//go:build linux

package xfsstore

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// DurabilityError denotes failed required post-apply persistence, including a
// restore hydration-map transition, independent of its errno. Its cause is
// diagnostic: ENOSPC from writeback cannot be mistaken for a pre-apply refusal.
type DurabilityError struct{ Cause error }

func (e *DurabilityError) Error() string {
	return fmt.Sprintf("xfsstore: durability sync: %v", e.Cause)
}
func (e *DurabilityError) Is(target error) bool { return target == ErrOutcomeUncertain }

// SyncTarget owns a sync-capable description until Close. Acquisition errors
// precede the durability syscall and may select the volume-wide barrier.
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
	if err := t.volume.Health(); err != nil {
		return &DurabilityError{Cause: err}
	}
	if _, err := t.state.barrierWithFailure(t.fd, false, t.volume.fsync, t.volume.fsync, t.volume.failDurability); err != nil {
		return err
	}
	// A concurrent sync can fence the volume while this syscall succeeds. No
	// waiter may subsequently turn that terminal observation into success.
	if err := t.volume.Health(); err != nil {
		return &DurabilityError{Cause: err}
	}
	return nil
}

// A coalesced barrier's policy may be called by another handle's leader.
// Fence before releasing waiters. This store-local fence can precede the
// handler's terminal drain; racing requests then fail without applying.
func (v *Volume) failDurability(err error) error {
	failure := &DurabilityError{Cause: err}
	v.Fence(failure)
	return failure
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

// SyncMutationFS has a dedicated root description from startup: ordinary
// SyncFS callers cannot consume its superblock writeback error sequence.
func (v *Volume) SyncMutationFS() error { return v.syncFS(true) }

func (v *Volume) syncFS(required bool) error {
	if required {
		if err := v.Health(); err != nil {
			return &DurabilityError{Cause: err}
		}
		// The dedicated description reports errseq once. Publish its fence
		// before another required caller can consume a successful retry.
		v.mutationSyncMu.Lock()
		defer v.mutationSyncMu.Unlock()
	}
	failure := func(err error) error {
		if err != nil && required {
			return v.failDurability(err)
		}
		return err
	}
	v.mu.RLock()
	if v.closed || v.fenced != nil {
		err := v.fenced
		if v.closed {
			err = ErrClosed
		}
		v.mu.RUnlock()
		return failure(err)
	}
	root := v.objects[v.root].res
	if required {
		root = v.mutationRoot
	}
	root.acquire()
	v.mu.RUnlock()
	defer root.release()
	if err := v.syncfs(root.fd); err != nil {
		return failure(err)
	}
	return failure(v.Health())
}
