//go:build linux

package authorityrpc

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// These are the stock Linux FUSE write flag bits accepted by FUSE_WRITE.
const (
	writeLockOwner   uint32 = 1 << 1
	writeKillSUIDGID uint32 = 1 << 2
)

// WriteAdmission qualifies the configured private write-staging directory and
// provides a closeable authority-wide admission dependency. Protocol 6 carries
// each stock WRITE in one retained frame, so payload bytes are never copied to
// a staging object; the documented byte/count limits instead bound those
// retained in-flight frames directly.
type WriteAdmission struct {
	mu     sync.RWMutex
	closed bool
}

func OpenWriteAdmission(path string) (*WriteAdmission, error) {
	dir, err := privatepath.OpenExistingDir(path)
	if err != nil {
		return nil, fmt.Errorf("open write staging directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return nil, fmt.Errorf("close write staging directory: %w", err)
	}
	return &WriteAdmission{}, nil
}

func (a *WriteAdmission) ready() error {
	if a == nil {
		return syscall.EOPNOTSUPP
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return syscall.ESTALE
	}
	return nil
}

func (a *WriteAdmission) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	return nil
}

type writeAdmissionWaiter struct {
	resources *sessionResources
	ready     chan struct{}
	previous  *writeAdmissionWaiter
	next      *writeAdmissionWaiter
	queued    bool
}

func (h *VolumeHandler) writeAdmissionAvailableLocked(resources *sessionResources, bytes uint64) bool {
	return bytes <= h.MaxWriteBytesPerSession && bytes <= h.MaxWriteBytesInFlight &&
		resources.writeReservedBytes <= h.MaxWriteBytesPerSession-bytes &&
		h.totalWriteBytes <= h.MaxWriteBytesInFlight-bytes &&
		resources.writeCount < h.MaxWritesPerSession && h.totalWrites < h.MaxWrites
}

func (h *VolumeHandler) enqueueWriteAdmissionLocked(waiter *writeAdmissionWaiter) {
	if waiter.queued {
		return
	}
	waiter.previous = h.writeAdmissionTail
	if h.writeAdmissionTail == nil {
		h.writeAdmissionHead = waiter
	} else {
		h.writeAdmissionTail.next = waiter
	}
	h.writeAdmissionTail = waiter
	waiter.queued = true
}

func (h *VolumeHandler) removeWriteAdmissionLocked(waiter *writeAdmissionWaiter) {
	if !waiter.queued {
		return
	}
	if waiter.previous == nil {
		h.writeAdmissionHead = waiter.next
	} else {
		waiter.previous.next = waiter.next
	}
	if waiter.next == nil {
		h.writeAdmissionTail = waiter.previous
	} else {
		waiter.next.previous = waiter.previous
	}
	waiter.previous, waiter.next, waiter.queued = nil, nil, false
}

func wakeWriteAdmissionLocked(waiter *writeAdmissionWaiter) {
	if waiter == nil {
		return
	}
	ready := waiter.ready
	waiter.ready = make(chan struct{})
	close(ready)
}

func (h *VolumeHandler) reserveWriteAdmission(ctx context.Context, terminal <-chan struct{}, resources *sessionResources, bytes uint64) error {
	if err := h.WriteAdmission.ready(); err != nil {
		return err
	}
	waiter := &writeAdmissionWaiter{resources: resources, ready: make(chan struct{})}
	waiting := false
	started := time.Now()
	for {
		h.writeAdmissionMu.Lock()
		if resources.writeAdmissionEnded {
			h.removeWriteAdmissionLocked(waiter)
			wakeWriteAdmissionLocked(h.writeAdmissionHead)
			h.writeAdmissionMu.Unlock()
			return volumeserver.ErrSessionExpired
		}
		h.enqueueWriteAdmissionLocked(waiter)
		if h.writeAdmissionHead == waiter && h.writeAdmissionAvailableLocked(resources, bytes) {
			h.removeWriteAdmissionLocked(waiter)
			resources.writeReservedBytes += bytes
			resources.writeCount++
			h.totalWriteBytes += bytes
			h.totalWrites++
			wakeWriteAdmissionLocked(h.writeAdmissionHead)
			h.writeAdmissionMu.Unlock()
			return nil
		}
		waiting = true
		ready := waiter.ready
		h.writeAdmissionMu.Unlock()

		wait := ctx
		cancel := func() {}
		if h.WriteAdmissionProgressTimeout > 0 {
			remaining := h.WriteAdmissionProgressTimeout - time.Since(started)
			if remaining <= 0 {
				h.writeAdmissionMu.Lock()
				h.removeWriteAdmissionLocked(waiter)
				wakeWriteAdmissionLocked(h.writeAdmissionHead)
				h.writeAdmissionMu.Unlock()
				return syscall.EAGAIN
			}
			wait, cancel = context.WithTimeout(ctx, remaining)
		}
		select {
		case <-ready:
			cancel()
			continue
		case <-terminal:
			cancel()
			h.writeAdmissionMu.Lock()
			h.removeWriteAdmissionLocked(waiter)
			wakeWriteAdmissionLocked(h.writeAdmissionHead)
			h.writeAdmissionMu.Unlock()
			return volumeserver.ErrSessionExpired
		case <-wait.Done():
			cancel()
			h.writeAdmissionMu.Lock()
			h.removeWriteAdmissionLocked(waiter)
			wakeWriteAdmissionLocked(h.writeAdmissionHead)
			ended := resources.writeAdmissionEnded
			h.writeAdmissionMu.Unlock()
			if ended {
				return volumeserver.ErrSessionExpired
			}
			if waiting && ctx.Err() == nil {
				return syscall.EAGAIN
			}
			return ctx.Err()
		}
	}
}

func (h *VolumeHandler) releaseWriteAdmission(resources *sessionResources, bytes uint64) {
	h.writeAdmissionMu.Lock()
	defer h.writeAdmissionMu.Unlock()
	if bytes > resources.writeReservedBytes || bytes > h.totalWriteBytes || resources.writeCount == 0 || h.totalWrites == 0 {
		panic("authorityrpc: write admission accounting underflow")
	}
	resources.writeReservedBytes -= bytes
	resources.writeCount--
	h.totalWriteBytes -= bytes
	h.totalWrites--
	wakeWriteAdmissionLocked(h.writeAdmissionHead)
}

func (h *VolumeHandler) endWriteAdmission(resources *sessionResources) {
	h.writeAdmissionMu.Lock()
	resources.writeAdmissionEnded = true
	for waiter := h.writeAdmissionHead; waiter != nil; waiter = waiter.next {
		if waiter.resources == resources {
			wakeWriteAdmissionLocked(waiter)
		}
	}
	h.writeAdmissionMu.Unlock()
}
