//go:build linux

package fusev3

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func dirtyHolderMetadataFixture(t *testing.T) (*strictFixture, *fuse.EntryOut) {
	t.Helper()
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "cached")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
	// The first post-grant read installs a base from this grant's storage cut.
	if status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
	}); status != fuse.OK {
		t.Fatal(status)
	}
	return f, entry
}

func TestFullHolderMetadataHasZeroValidityRPCsAndAllocations(t *testing.T) {
	for _, kind := range []string{"lookup", "getattr"} {
		t.Run(kind, func(t *testing.T) {
			f, entry := dirtyHolderMetadataFixture(t)
			f.rpc.mu.Lock()
			before := f.rpc.calls
			f.rpc.mu.Unlock()
			var out fuse.EntryOut
			var attr fuse.AttrOut
			var status fuse.Status
			var bad bool
			allocs := testing.AllocsPerRun(1000, func() {
				unique := f.unique.Add(2)
				if kind == "lookup" {
					status = f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &out)
					bad = bad || out.Size != 4101 || out.EntryValid != 0 || out.EntryValidNsec != 0 || out.AttrValid != 0 || out.AttrValidNsec != 0
				} else {
					status = f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &attr)
					bad = bad || attr.Size != 4101 || attr.AttrValid != 0 || attr.AttrValidNsec != 0
				}
				f.raw.PrepareReplyPayload(unique, 1, 1, nil, nil, 0)
				f.raw.ReplyWritten(unique, fuse.OK)
			})
			if status != fuse.OK || bad {
				t.Fatalf("status=%v incorrect overlay/validity=%v", status, bad)
			}
			if allocs != 0 {
				t.Errorf("holder %s allocations=%g, want zero", kind, allocs)
			}
			f.rpc.mu.Lock()
			defer f.rpc.mu.Unlock()
			if f.rpc.calls != before {
				t.Errorf("holder metadata Authority calls=%d", f.rpc.calls-before)
			}
		})
	}
}

func TestFullHolderMetadataPinsGrantUntilPhysicalSettlement(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		for _, success := range []bool{false, true} {
			name := "arena"
			if fallback {
				name = "fallback"
			}
			if success {
				name += "/written"
			} else {
				name += "/failed"
			}
			t.Run(name, func(t *testing.T) {
				f, entry := dirtyHolderMetadataFixture(t)
				if fallback {
					f.raw.mu.Lock()
					f.raw.cachedReplyFree = nil
					f.raw.mu.Unlock()
				}
				unique := f.unique.Add(2)
				if status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{}); status != fuse.OK {
					t.Fatal(status)
				}
				f.raw.mu.Lock()
				p := f.raw.replyPublications[unique]
				if p == nil || p.holderAdmission == nil || p.cachedArena == fallback {
					f.raw.mu.Unlock()
					t.Fatal("holder reply omitted exact grant pin or used wrong arena")
				}
				coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
				if !f.raw.sourceCoordinateBusyLocked(coordinate, nil) {
					f.raw.mu.Unlock()
					t.Fatal("source gate omitted holder reply")
				}
				s := p.holderAdmission
				f.raw.mu.Unlock()
				f.raw.PrepareReplyPayload(unique, 1, 1, nil, nil, 0)
				if s.admission.TryLock() {
					s.admission.Unlock()
					t.Fatal("unwritten reply released grant")
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := f.mount.delegations.beginRetire(ctx, s); done <- err }()
				select {
				case err := <-done:
					t.Fatalf("retirement crossed unwritten reply: %v", err)
				case <-time.After(10 * time.Millisecond):
				}
				status := fuse.EIO
				if success {
					status = fuse.OK
				}
				f.raw.ReplyWritten(unique, status)
				select {
				case err := <-done:
					if err != nil && (success || !errors.Is(err, writeback.ErrClosed)) {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				f.raw.mu.Lock()
				if p.holderAdmission != nil {
					f.raw.mu.Unlock()
					t.Fatal("settled reply retained grant")
				}
				f.raw.mu.Unlock()
				// A duplicate physical completion must not unlock a successor reader.
				s.admission.RLock()
				f.raw.ReplyWritten(unique, status)
				if s.admission.TryLock() {
					s.admission.Unlock()
					t.Fatal("duplicate settlement unlocked successor reader")
				}
				s.admission.RUnlock()
			})
		}
	}
}

func TestFullHolderMetadataWithdrawalWaitsWithoutDelegationLocks(t *testing.T) {
	f, entry := dirtyHolderMetadataFixture(t)
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	lease, err := f.raw.closeCacheCoordinate(ctx, coordinate)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan fuse.Status, 1)
	unique := f.unique.Add(2)
	go func() {
		done <- f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
	}()
	// A closed coordinate forces the ordinary publication path, which must wait
	// without the operation/admission locks needed to finish that withdrawal.
	for {
		f.raw.mu.Lock()
		p := f.raw.replyPublications[unique]
		waiting := p != nil
		f.raw.mu.Unlock()
		if waiting {
			break
		}
		select {
		case status := <-done:
			t.Fatalf("closed coordinate returned %v", status)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}
		time.Sleep(time.Millisecond)
	}
	s := f.mount.delegations.lookupState(writeback.Identity(coordinate.item))
	locked := make(chan struct{})
	go func() {
		s.operation.Lock()
		s.admission.Lock()
		s.admission.Unlock()
		s.operation.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-ctx.Done():
		t.Fatal("metadata waiter retained delegation locks")
	}
	select {
	case status := <-done:
		t.Fatalf("closed coordinate returned %v", status)
	default:
	}
	lease.Open()
	select {
	case status := <-done:
		if status != fuse.OK {
			t.Fatal(status)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	completeTestReply(t, f.raw, unique, fuse.OK)
}

func TestFullHolderMetadataTerminalizationJoinsPhysicalPin(t *testing.T) {
	for _, connectionGone := range []bool{false, true} {
		name := "reply-written"
		if connectionGone {
			name = "connection-gone"
		}
		t.Run(name, func(t *testing.T) {
			f, entry := dirtyHolderMetadataFixture(t)
			unique := f.unique.Add(2)
			if status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{}); status != fuse.OK {
				t.Fatal(status)
			}
			f.raw.PrepareReplyPayload(unique, 1, 1, nil, nil, 0)
			f.raw.mu.Lock()
			p := f.raw.replyPublications[unique]
			s := p.holderAdmission
			f.raw.mu.Unlock()
			if s == nil {
				t.Fatal("missing holder pin")
			}
			if f.raw.terminalizeReplyCacheOwnership(time.Now()) {
				t.Fatal("terminalization crossed unwritten holder reply")
			}
			if s.admission.TryLock() {
				s.admission.Unlock()
				t.Fatal("terminalization dropped physical pin")
			}
			if connectionGone {
				f.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
			} else {
				f.raw.ReplyWritten(unique, fuse.OK)
			}
			if !f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
				t.Fatal("terminalization did not join holder reply")
			}
			if !s.admission.TryLock() {
				t.Fatal("physical completion retained holder pin")
			}
			s.admission.Unlock()
			f.raw.mu.Lock()
			defer f.raw.mu.Unlock()
			if len(f.raw.replyPublications) != 0 {
				t.Fatal("terminalization leaked holder publication")
			}

		})
	}
}

func TestFullHolderMetadataRefusesStaleAuthorityBase(t *testing.T) {
	for _, kind := range []string{"lookup", "getattr"} {
		t.Run(kind, func(t *testing.T) {
			f, entry := dirtyHolderMetadataFixture(t)
			identity := f.raw.nodesByID[entry.NodeId].identity
			f.mount.delegations.InvalidateBaseAttr(identity[:], 100)
			if kind == "lookup" {
				f.raw.mu.Lock()
				f.raw.dropCachedNameLocked(nameKey{parent: f.raw.nodesByID[1].key.inode, name: "cached"})
				f.raw.mu.Unlock()
			}
			unique := f.unique.Add(2)
			var status fuse.Status
			if kind == "lookup" {
				status = f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{})
			} else {
				status = f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
			}
			want := fuse.EIO
			if kind == "lookup" {
				want = fuse.Status(syscall.ENOTCONN)
			}
			if status != want {
				t.Fatalf("stale holder %s status=%v, want %v", kind, status, want)
			}
			completeTestReply(t, f.raw, unique, fuse.OK)
		})
	}
}
