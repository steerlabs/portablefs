//go:build linux

package fusev3

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// TestAuthorityNegativeLookupRequiresPostVFSPublication proves that admission
// pressure changes only lifetime and registry ownership. Every protocol
// negative remains a successful zero-nodeid entry with its sequence stamp.
func TestAuthorityNegativeLookupRequiresPostVFSPublication(t *testing.T) {
	cases := []struct {
		name      string
		cacheable bool
	}{
		{"cacheable absence", true},
		{"capacity-dropped absence", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStrictFixture(t)
			if !tc.cacheable {
				// The state a saturated absence registry reaches: no absence may
				// be published with a lifetime, so ENOENT is the only answer.
				f.raw.negativeCapacity = 0
			}
			f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
				if request.GetLookup() == nil {
					return nil, errors.New("unexpected non-LOOKUP request")
				}
				return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{
					NegativeSnapshotSequence: 1,
				}}}, nil
			}
			const requestUnique = 6900
			out := &fuse.EntryOut{}
			if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: requestUnique, NodeId: fuse.FUSE_ROOT_ID}, "missing", out); status != fuse.OK {
				t.Fatalf("negative LOOKUP = %v, want structured success", status)
			}
			if out.NodeId != 0 {
				t.Fatalf("negative LOOKUP published NodeId %d, want 0", out.NodeId)
			}
			if cached := out.EntryValid != 0; cached != tc.cacheable {
				t.Fatalf("absence lifetime = %d.%09d, cacheable = %t", out.EntryValid, out.EntryValidNsec, tc.cacheable)
			}
			if !f.raw.ReplyWriteOrdered(requestUnique) {
				t.Fatal("negative LOOKUP did not retain its physical reply ownership")
			}
			payload := make([]byte, fuse.PFSCacheStampSize)
			if n, status := f.raw.PrepareReplyPayload(requestUnique, fuse.FUSE_ROOT_ID, 1, make([]byte, 128), payload, 0); !status.Ok() || n != len(payload) {
				t.Fatalf("negative LOOKUP stamp = (%d, %v), want %d-byte success", n, status, len(payload))
			}
			if got := binary.LittleEndian.Uint64(payload[:8]); got != 1 {
				t.Fatalf("negative LOOKUP snapshot = %d, want 1", got)
			}
			if !f.raw.ReplyPublishMarked(requestUnique, fuse.FUSE_ROOT_ID, testPublicationOpcode) {
				t.Fatal("negative LOOKUP did not request a post-VFS publication receipt")
			}
			f.raw.ReplyWritten(requestUnique, fuse.OK)
			acknowledgeTestPublication(t, f.raw, requestUnique)
			if f.mount.isRevoked() {
				t.Fatalf("valid negative LOOKUP publication revoked mount: %v", f.mount.fatalError())
			}
		})
	}
}

func TestNonENOENTLookupFailureRemainsUnpublished(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetLookup() == nil {
			return nil, errors.New("unexpected non-LOOKUP request")
		}
		return &authoritypb.Response{Errno: int32(syscall.EIO)}, nil
	}
	const requestUnique = 6950
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: requestUnique, NodeId: fuse.FUSE_ROOT_ID}, "failed", &fuse.EntryOut{}); status != fuse.EIO {
		t.Fatalf("failed LOOKUP = %v, want EIO", status)
	}
	if f.raw.ReplyWriteOrdered(requestUnique) || f.raw.ReplyPublishMarked(requestUnique, fuse.FUSE_ROOT_ID, testPublicationOpcode) {
		t.Fatal("non-ENOENT LOOKUP error retained a post-VFS publication")
	}
}

func TestPhysicalReplyLostAfterExactUnmountIsCleanAndConsumesOwnership(t *testing.T) {
	f := newStrictFixture(t)
	f.mount.kernelMount = kernelMount{id: "999999996", device: "0:996", point: "/nonexistent-portablefs-reply-race"}
	// Keep the unit test synchronous. The production path schedules the same
	// teardown after classifying the exact absence; detach itself is covered by
	// the mount-lifecycle tests below.
	f.mount.abort.Do(func() {})
	consumption := &recordingResponseConsumption{}
	publication := &replyPublication{responseConsumptions: []authorityrpc.ResponseConsumption{consumption}}
	const unique = 6970
	if err := f.raw.registerReplyPublication(unique, publication); err != nil {
		t.Fatal(err)
	}
	f.raw.ReplyWritten(unique, fuse.ENOENT)
	if !f.mount.isRevoked() {
		t.Fatal("a lost reply after observed unmount did not close frontend admission")
	}
	if err := f.mount.fatalError(); err != nil {
		t.Fatalf("an exact lazy-unmount reply race became a mount failure: %v", err)
	}
	if got := consumption.calls.Load(); got != 1 {
		t.Fatalf("unmounted reply response consumption = %d, want 1", got)
	}
	f.raw.mu.Lock()
	retained := f.raw.replyPublications[unique]
	f.raw.mu.Unlock()
	if retained != nil {
		t.Fatal("unmounted reply retained publication ownership")
	}
}

func TestEarlyPFSPublishWaitIsCanceledByDisconnect(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"cached": testItem(71, authoritypb.Attr_REGULAR, 71)}
	const requestUnique = 7000
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: requestUnique, NodeId: fuse.FUSE_ROOT_ID}, "cached", &fuse.EntryOut{}); !status.Ok() {
		t.Fatalf("LOOKUP = %v", status)
	}
	markTestReply(t, f.raw, requestUnique)

	const publishUnique = 7002
	in := &fuse.PFSPublishIn{
		InHeader:      fuse.InHeader{Unique: publishUnique},
		RequestUnique: requestUnique,
		PublicationID: 77,
		Nodeid:        testPublicationNodeID,
		Opcode:        testPublicationOpcode,
	}
	done := make(chan fuse.Status, 1)
	go func() { done <- f.raw.PFSPublish(nil, in, &fuse.PFSPublishOut{}) }()
	waitFor(t, "early PFS_PUBLISH to enter its physical-write wait", func() bool {
		f.raw.mu.Lock()
		defer f.raw.mu.Unlock()
		publication := f.raw.replyPublications[requestUnique]
		return publication != nil && publication.publishUnique == publishUnique && !publication.originalWrote
	})
	select {
	case status := <-done:
		t.Fatalf("early PFS_PUBLISH returned before write or disconnect: %v", status)
	default:
	}
	f.mount.cancel()
	select {
	case status := <-done:
		if status != fuse.Status(syscall.ENOTCONN) {
			t.Fatalf("early PFS_PUBLISH after disconnect = %v, want ENOTCONN", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("early PFS_PUBLISH did not wake on disconnect")
	}
	if !f.mount.isRevoked() {
		t.Fatal("disconnect during publication ownership did not leave the mount terminal")
	}
}

func TestSecondPFSPublishCannotReuseUniqueWhileFirstWaitsForOriginalWrite(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"cached": testItem(72, authoritypb.Attr_REGULAR, 72)}
	const requestUnique = 7100
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: requestUnique, NodeId: fuse.FUSE_ROOT_ID}, "cached", &fuse.EntryOut{}); !status.Ok() {
		t.Fatalf("LOOKUP = %v", status)
	}
	markTestReply(t, f.raw, requestUnique)

	const publishUnique = 7102
	first := &fuse.PFSPublishIn{
		InHeader:      fuse.InHeader{Unique: publishUnique},
		RequestUnique: requestUnique,
		PublicationID: 79,
		Nodeid:        testPublicationNodeID,
		Opcode:        testPublicationOpcode,
	}
	done := make(chan fuse.Status, 1)
	go func() { done <- f.raw.PFSPublish(nil, first, &fuse.PFSPublishOut{}) }()
	waitFor(t, "early PFS_PUBLISH to reserve its request identity", func() bool {
		f.raw.mu.Lock()
		defer f.raw.mu.Unlock()
		return f.raw.publishAcks[publishUnique] != nil
	})

	second := *first
	second.RequestUnique = 7104
	second.PublicationID = 81
	if status := f.raw.PFSPublish(nil, &second, &fuse.PFSPublishOut{}); status != fuse.Status(syscall.ENOTCONN) {
		t.Fatalf("duplicate publication request unique = %v, want ENOTCONN", status)
	}
	if !f.mount.isRevoked() {
		t.Fatal("duplicate in-flight publication request identity did not fail closed")
	}
	select {
	case status := <-done:
		if status != fuse.Status(syscall.ENOTCONN) {
			t.Fatalf("first publication after terminal duplicate = %v", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first publication did not wake after duplicate terminalized the mount")
	}
}
