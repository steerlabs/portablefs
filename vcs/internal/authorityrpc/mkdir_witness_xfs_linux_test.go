//go:build linux

package authorityrpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/restorefixture"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type kernelAuthorityFixture struct {
	h       *VolumeHandler
	ctx     context.Context
	store   *xfsstore.Volume
	path    string
	root    []byte
	epoch   []byte
	proof   *authoritypb.SessionProof
	seq     [2]uint64
	request uint64
}

func newKernelAuthorityFixture(t *testing.T) *kernelAuthorityFixture {
	return newObservedKernelAuthorityFixture(t, nil, 2)
}

func newObservedKernelAuthorityFixture(t *testing.T, observer func(xfsstore.StorageSync), slots uint32) *kernelAuthorityFixture {
	t.Helper()
	root := restorefixture.Root(t)
	project, err := strconv.ParseUint(os.Getenv("PORTABLEFS_XFS_TEST_PROJECT"), 10, 32)
	if err != nil {
		t.Skip("privileged XFS gate is not configured")
	}
	store, err := xfsstore.Open(root, xfsstore.Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid()), OnStorageSync: observer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h, ctx, _, _ := newAuthorityTestHandler(t, nil)
	h.Store = store
	attach := fskitAttachRequest(1).GetAttach()
	attach.ReplaySlots = slots
	activation, epoch, proof := attachAndActivateHandler(t, h, ctx, 1, attach)
	f := &kernelAuthorityFixture{h: h, ctx: ctx, store: store, path: root, root: activation.GetRoot().GetToken(), epoch: epoch, proof: proof, request: 10}
	t.Cleanup(func() { var id volumeserver.SessionID; copy(id[:], proof.GetId()); h.Runtime.FenceSession(id) })
	return f
}
func (f *kernelAuthorityFixture) call(t *testing.T, slot uint32, request *authoritypb.Request) *authoritypb.Response {
	t.Helper()
	f.request++
	request.RequestId = f.request
	request.Epoch = f.epoch
	request.Session = f.proof
	switch request.GetBody().(type) {
	case *authoritypb.Request_GetAttr, *authoritypb.Request_Read:
	default:
		f.seq[slot]++
		stampMutation(t, request, slot, f.seq[slot])
	}
	response := f.h.Handle(f.ctx, request)
	if response.GetErrno() != 0 || response.GetUncertain() {
		t.Fatalf("%T: %v", request.GetBody(), response)
	}
	return response
}
func (f *kernelAuthorityFixture) mkdir(t *testing.T, name string, mode uint32) *authoritypb.Response {
	return f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: f.root, Name: []byte(name), Mode: mode}}})
}
func (f *kernelAuthorityFixture) reclaim(t *testing.T, token []byte) {
	f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{token}}}})
}

func TestMkdirSearchWitnessOnXFS(t *testing.T) {
	f := newKernelAuthorityFixture(t)
	if os.Geteuid() == 0 {
		t.Fatal("search evidence requires the actual unprivileged service owner")
	}
	for _, mode := range []uint32{0, 0100, 0300, 0400, 0500, 0700} {
		t.Run(fmt.Sprintf("mode-%03o", mode), func(t *testing.T) {
			name := fmt.Sprintf("mode-%03o", mode)
			reply := f.mkdir(t, name, mode)
			mkdir := reply.GetMkdir()
			item := mkdir.GetItem()
			if mkdir == nil || item == nil || mkdir.GetChildSearchPermitted() != (mode&0100 != 0) {
				t.Fatalf("witness=%v", reply)
			}
			if item.GetObjectVersion() != item.GetSnapshotSequence() || item.GetSnapshotSequence() != reply.GetPostState().GetSnapshotSequence() {
				t.Fatal("witness and PostState have different committed cuts")
			}
			f.reclaim(t, item.GetToken())
		})
	}
	// A restrictive inherited ACL cannot make the private project-validation
	// reopen fail or substitute guessed mode bits for the final kernel check.
	acl := make([]byte, 4+3*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, tag := range []uint16{1, 4, 32} {
		binary.LittleEndian.PutUint16(acl[4+i*8:], tag)
		binary.LittleEndian.PutUint32(acl[8+i*8:], mathMaxUint32)
	}
	if err := unix.Setxattr(f.path, "system.posix_acl_default", acl, 0); err != nil {
		t.Fatalf("install restrictive default ACL: %v", err)
	}
	defer unix.Removexattr(f.path, "system.posix_acl_default")
	if reply := f.mkdir(t, "acl-search", 0100); !reply.GetMkdir().GetChildSearchPermitted() {
		t.Fatal("final searchable child lost kernel witness under inherited ACL")
	}
}

const mathMaxUint32 = ^uint32(0)

type heldMkdirWitnessStore struct {
	*xfsstore.Volume
	observed, release chan struct{}
}

func (s *heldMkdirWitnessStore) SearchPermitted(item xfsstore.Capability) (bool, error) {
	allowed, err := s.Volume.SearchPermitted(item)
	close(s.observed)
	<-s.release
	return allowed, err
}

func TestMkdirWitnessProtectsNewChildThroughCommitOnXFS(t *testing.T) {
	f := newKernelAuthorityFixture(t)
	store := &heldMkdirWitnessStore{Volume: f.store, observed: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-store.release:
		default:
			close(store.release)
		}
	}()
	f.h.Store = store
	mkdir := &authoritypb.Request{RequestId: 21, Epoch: f.epoch, Session: f.proof, Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: f.root, Name: []byte("racing"), Mode: 0100}}}
	lookup := &authoritypb.Request{RequestId: 22, Epoch: f.epoch, Session: f.proof, Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: f.root, Name: []byte("racing")}}}
	stampMutation(t, mkdir, 0, 1)
	stampMutation(t, lookup, 1, 1)
	created, lookedUp := make(chan *authoritypb.Response, 1), make(chan *authoritypb.Response, 1)
	go func() { created <- f.h.Handle(f.ctx, mkdir) }()
	select {
	case <-store.observed:
	case response := <-created:
		t.Fatalf("mkdir did not reach its witness: %v", response)
	case <-time.After(time.Second):
		t.Fatal("mkdir did not reach its witness")
	}
	go func() { lookedUp <- f.h.Handle(f.ctx, lookup) }()
	select {
	case response := <-lookedUp:
		close(store.release)
		<-created
		t.Fatalf("lookup exposed the child before witness/commit: %v", response)
	case <-time.After(20 * time.Millisecond):
	}
	close(store.release)
	first, found := <-created, <-lookedUp
	if first.GetErrno() != 0 || found.GetErrno() != 0 || !first.GetMkdir().GetChildSearchPermitted() || found.GetLookup().GetItem().GetSnapshotSequence() < first.GetMkdir().GetItem().GetSnapshotSequence() {
		t.Fatalf("inconsistent child publication: mkdir=%v lookup=%v", first, found)
	}
	f.seq[0], f.seq[1] = 1, 1
	f.request = 22
	// The first legitimate holder may now change permissions immediately. A
	// delayed original outcome retains the old cut rather than resampling it.
	mode := uint32(0)
	f.call(t, 1, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: found.GetLookup().GetItem().GetToken(), Mode: &mode}}})
	mkdir.RequestId = 24
	replayed := f.h.Handle(f.ctx, mkdir)
	if first.GetMkdir().GetItem().GetSnapshotSequence() >= f.h.coherenceVersionNow() || !first.GetMkdir().GetChildSearchPermitted() {
		t.Fatal("later permission change restamped the original witness")
	}
	first.RequestId = replayed.RequestId
	if !proto.Equal(first, replayed) {
		t.Fatalf("delayed mkdir outcome changed after chmod: %v", replayed)
	}
}

func TestMkdirWitnessReplayAndNewChildOrderingOnXFS(t *testing.T) {
	f := newKernelAuthorityFixture(t)
	f.h.objectVersionLimit = 4
	request := &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: f.root, Name: []byte("held"), Mode: 0100}}}
	first := f.call(t, 1, request)
	child := first.GetMkdir().GetItem()
	// Keep the exact mkdir replay in its independent slot while permission ABA
	// and unrelated create/unlink churn compact the version map repeatedly.
	for i := 0; i < 24; i++ {
		mode := uint32(0)
		if i%2 != 0 {
			mode = 0100
		}
		f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: child.GetToken(), Mode: &mode}}})
		response := f.mkdir(t, fmt.Sprintf("churn-%d", i), 0700)
		f.reclaim(t, response.GetMkdir().GetItem().GetToken())
		f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: f.root, Name: []byte(fmt.Sprintf("churn-%d", i)), Directory: true}}})
	}
	// A newer child mutation can be delivered before the held old mkdir result.
	mode := uint32(0300)
	f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: child.GetToken(), Mode: &mode}}})
	f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: child.GetToken(), Name: []byte("new-child"), Mode: 0700}}})
	if _, err := os.Stat(filepath.Join(f.path, "held", "new-child")); err != nil {
		t.Fatal(err)
	}
	mode = 0
	f.call(t, 0, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: child.GetToken(), Mode: &mode}}})
	replay := proto.Clone(request).(*authoritypb.Request)
	f.request++
	replay.RequestId = f.request
	repeated := f.h.Handle(f.ctx, replay)
	first.RequestId = repeated.RequestId
	if !proto.Equal(first, repeated) {
		t.Fatalf("replay resampled permission/stamps: %v / %v", first, repeated)
	}
	if len(f.h.objectVersions) > 4 || f.h.objectVersionFloor <= 1 {
		t.Fatal("bounded churn did not compact")
	}
	var cap xfsstore.Capability
	copy(cap[:], child.GetToken())
	if allowed, err := f.store.SearchPermitted(cap); err != nil || allowed {
		t.Fatalf("held child capability: %v %v", allowed, err)
	}
	f.reclaim(t, child.GetToken())
	if _, err := f.store.SearchPermitted(cap); err == nil {
		t.Fatal("reclaim left child capability usable")
	}
}

type mkdirAccessFaultStore struct {
	*xfsstore.Volume
	err   error
	syncs int
}

func (s *mkdirAccessFaultStore) SearchPermitted(xfsstore.Capability) (bool, error) {
	return false, s.err
}
func (s *mkdirAccessFaultStore) SyncFS() error { s.syncs++; return s.Volume.SyncFS() }
func TestMkdirWitnessUnexpectedFailureIsAppliedAndSyncedOnXFS(t *testing.T) {
	f := newKernelAuthorityFixture(t)
	fault := &mkdirAccessFaultStore{Volume: f.store, err: syscall.EINTR}
	f.h.Store = fault
	request := &authoritypb.Request{RequestId: 22, Epoch: f.epoch, Session: f.proof, Mutation: &authoritypb.Mutation{Sequence: 1}, Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: f.root, Name: []byte("applied"), Mode: 0700}}}
	response := f.h.Handle(f.ctx, request)
	if response.GetErrno() != int32(syscall.EINTR) || !response.GetUncertain() || response.GetMkdir() != nil || response.GetPostState() == nil || fault.syncs != 1 {
		t.Fatalf("post-apply access failure=%v syncs=%d", response, fault.syncs)
	}
	if _, err := os.Stat(filepath.Join(f.path, "applied")); err != nil {
		t.Fatal(err)
	}
	if f.h.totalItems != 0 {
		t.Fatal("unexposed child capability leaked after failed witness")
	}
	request.RequestId++
	replay := f.h.Handle(f.ctx, request)
	response.RequestId = replay.RequestId
	if !proto.Equal(response, replay) || fault.syncs != 1 {
		t.Fatalf("failed observation was reapplied: %v", replay)
	}
}
