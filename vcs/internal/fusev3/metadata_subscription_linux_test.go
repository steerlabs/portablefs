//go:build linux

package fusev3

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type metadataColdInvalidator struct {
	subscriptionInvalidator
	drained, resume chan struct{}
}

func (i *metadataColdInvalidator) InvalidateAllCaches(ctx context.Context) error {
	if err := i.subscriptionInvalidator.InvalidateAllCaches(ctx); err != nil {
		return err
	}
	close(i.drained)
	select {
	case <-i.resume:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A callback can enter after cache withdrawal but before ownership is reset.
// The cold subscription must interrupt the old incarnation before waiting for
// that callback, but cannot reset the delegation index until it has returned.
// An old storage response reaching metadata sampling after interruption fails
// with EIO instead of entering a reset's epoch/index lock cycle.
func TestColdSubscriptionDrainsDirectoryMetadataCallbacks(t *testing.T) {
	testColdSubscriptionDrainsMetadataCallback(t, "readdirplus")
}

func TestColdSubscriptionRejectsDelayedInodeMetadata(t *testing.T) {
	for _, operation := range []string{"getattr", "lookup"} {
		t.Run(operation, func(t *testing.T) { testColdSubscriptionDrainsMetadataCallback(t, operation) })
	}
}

func testColdSubscriptionDrainsMetadataCallback(t *testing.T, operation string) {
	t.Helper()
	f := newStrictFixture(t)
	unique := f.unique.Add(2)
	var call func() fuse.Status
	var lookupRecord *inodeRecord
	var originalLookups uint64
	switch operation {
	case "getattr":
		entry := f.lookup(t, 1, "metadata")
		call = func() fuse.Status {
			return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
		}
	case "lookup":
		entry := f.lookup(t, 1, "existing")
		f.raw.mu.RLock()
		lookupRecord = f.raw.nodesByID[entry.NodeId]
		originalLookups = lookupRecord.lookups
		f.raw.mu.RUnlock()
		call = func() fuse.Status {
			return f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "metadata", &fuse.EntryOut{})
		}
	default:
		dir, _ := testDirHandle(t, f.raw, plusTestPages(2)...)
		call = func() fuse.Status {
			return f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, fuse.NewDirEntryList(make([]byte, 4096), 0))
		}
	}
	delayed := installMetadataDelay(f, func(request *authoritypb.Request) bool {
		switch operation {
		case "getattr":
			return request.GetGetAttr() != nil
		case "lookup":
			return request.GetLookup() != nil
		default:
			return request.GetReadDir() != nil
		}
	})
	var resumeRead, resumeCold sync.Once
	defer resumeRead.Do(func() { close(delayed.resume) })
	done := make(chan fuse.Status, 1)
	waitForResponse := func() {
		t.Helper()
		select {
		case <-delayed.started:
		case status := <-done:
			completeTestReply(t, f.raw, unique, fuse.OK)
			t.Fatalf("metadata request returned %v before the delivery barrier", status)
		case <-time.After(time.Second):
			t.Fatal("metadata response did not reach the delivery barrier")
		}
	}
	// LOOKUP refuses dispatch after subscription deactivation. Its old
	// response must already be in flight when cache withdrawal begins.
	if operation == "lookup" {
		go func() { done <- call() }()
		waitForResponse()
	}
	sub := f.mount.subscription
	sub.mu.Lock()
	sub.active = false
	sub.mu.Unlock()
	barrier := &metadataColdInvalidator{subscriptionInvalidator: sub.config.invalidator, drained: make(chan struct{}), resume: make(chan struct{})}
	sub.config.invalidator = barrier
	defer resumeCold.Do(func() { close(barrier.resume) })
	coldDone := make(chan error, 1)
	go func() { coldDone <- sub.subscribe(t.Context()) }()
	select {
	case <-barrier.drained:
	case <-time.After(time.Second):
		t.Fatal("cache withdrawal did not finish before the metadata request")
	}
	if operation != "lookup" {
		go func() { done <- call() }()
		waitForResponse()
	}
	resumeCold.Do(func() { close(barrier.resume) })
	waitUntil(t, time.Second, "cold-subscription callback fence", func() bool {
		if f.mount.epochMu.TryRLock() {
			f.mount.epochMu.RUnlock()
			return false
		}
		return true
	})
	if f.mount.delegations.incarnation() != 0 {
		t.Fatal("cold subscription waited on callbacks before interrupting admission")
	}
	select {
	case err := <-coldDone:
		t.Fatalf("cold ownership reset crossed an unfinished metadata callback: %v", err)
	default:
	}
	resumeRead.Do(func() { close(delayed.resume) })
	select {
	case status := <-done:
		// EIO is the callback result carried by a successfully written FUSE
		// response, not a failure of the physical reply write itself.
		completeTestReply(t, f.raw, unique, fuse.OK)
		if status != fuse.EIO {
			t.Fatalf("metadata callback crossing the cold boundary returned %v, want EIO", status)
		}
	case <-time.After(time.Second):
		t.Fatal("metadata callback could not finish ahead of the ownership reset")
	}
	select {
	case err := <-coldDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cold subscription did not follow the interrupted metadata callback")
	}
	if f.mount.isRevoked() {
		t.Fatalf("recoverable subscription interruption revoked the mount: %v", f.mount.fatalError())
	}
	if lookupRecord != nil {
		f.raw.mu.RLock()
		lookups := lookupRecord.lookups
		f.raw.mu.RUnlock()
		if lookups != originalLookups {
			t.Fatalf("interrupted LOOKUP retained %d references, want original %d", lookups, originalLookups)
		}
	}
}

// A reply sampled before admission is interrupted still owns every inode pin
// through the physical edge. Reset may wait for those pins after callbacks
// drain; settlement must release them all before reentering the state index.
func TestColdSubscriptionJoinsPreparedDirectoryMetadataReply(t *testing.T) {
	f := newStrictFixture(t)
	dir, _ := testDirHandle(t, f.raw, plusTestPages(2)...)
	sub := f.mount.subscription
	sub.mu.Lock()
	sub.active = false
	sub.mu.Unlock()
	barrier := &metadataColdInvalidator{subscriptionInvalidator: sub.config.invalidator, drained: make(chan struct{}), resume: make(chan struct{})}
	sub.config.invalidator = barrier
	var resumeCold sync.Once
	defer resumeCold.Do(func() { close(barrier.resume) })
	coldDone := make(chan error, 1)
	go func() { coldDone <- sub.subscribe(t.Context()) }()
	select {
	case <-barrier.drained:
	case <-time.After(time.Second):
		t.Fatal("cache withdrawal did not finish before the page was published")
	}
	unique := f.unique.Add(2)
	status := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, fuse.NewDirEntryList(make([]byte, 4096), 0))
	if status != fuse.OK {
		completeTestReply(t, f.raw, unique, fuse.OK)
		t.Fatalf("directory callback before interruption returned %v", status)
	}
	f.raw.mu.Lock()
	p := f.raw.replyPublications[unique]
	pins := 0
	if p != nil && p.holderAdmission != nil {
		pins = 1 + len(p.holderAdmissions)
	}
	f.raw.mu.Unlock()
	if pins != 2 {
		completeTestReply(t, f.raw, unique, fuse.OK)
		t.Fatalf("physical directory pins=%d, want 2", pins)
	}
	resumeCold.Do(func() { close(barrier.resume) })
	waitUntil(t, time.Second, "cold-subscription ownership reset", func() bool {
		if f.mount.delegations.epoch.TryRLock() {
			f.mount.delegations.epoch.RUnlock()
			return false
		}
		return true
	})
	if f.mount.delegations.incarnation() != 0 {
		t.Fatal("cold subscription did not interrupt admission before ownership reset")
	}
	select {
	case err := <-coldDone:
		t.Fatalf("cold ownership reset crossed unwritten directory reply: %v", err)
	default:
	}
	f.raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
	settled := make(chan struct{})
	go func() { completeTestReply(t, f.raw, unique, fuse.OK); close(settled) }()
	select {
	case <-settled:
	case <-time.After(time.Second):
		t.Fatal("physical directory settlement could not release every ownership pin")
	}
	select {
	case err := <-coldDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cold subscription did not follow physical directory settlement")
	}
}
