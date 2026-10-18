//go:build linux

package authorityrpc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type observedFskitDurabilityStore struct {
	*xfsstore.Volume
	calls        []string
	retireOnSync bool
}

func (s *observedFskitDurabilityStore) PinSyncHandle(cap xfsstore.Capability) (xfsstore.SyncTarget, error) {
	target, err := s.Volume.PinSyncHandle(cap)
	if err != nil {
		return nil, err
	}
	return observedFskitSyncTarget{SyncTarget: target, observe: func() { s.observeHandle(cap) }}, nil
}
func (s *observedFskitDurabilityStore) observeHandle(cap xfsstore.Capability) {
	s.calls = append(s.calls, "handle")
	if s.retireOnSync {
		s.retireOnSync = false
		if err := s.Volume.CloseOpen(cap); err != nil {
			panic(err)
		}
	}
}

func (s *observedFskitDurabilityStore) SyncFS() error {
	s.calls = append(s.calls, "syncfs")
	return s.Volume.SyncFS()
}

func (s *observedFskitDurabilityStore) PinWriteTarget(cap xfsstore.Capability) (xfsstore.WriteTarget, error) {
	target, err := s.Volume.PinWriteTarget(cap)
	if err != nil {
		return nil, err
	}
	return observedFskitWriteTarget{WriteTarget: target, observe: func() { s.observeHandle(cap) }}, nil
}

type observedFskitWriteTarget struct {
	xfsstore.WriteTarget
	observe func()
}

func (s observedFskitWriteTarget) Sync() error { s.observe(); return s.WriteTarget.Sync() }

type observedFskitSyncTarget struct {
	xfsstore.SyncTarget
	observe func()
}

func (s observedFskitSyncTarget) Sync() error { s.observe(); return s.SyncTarget.Sync() }

// Exhaust only during the actual OPEN. Existing-name CREATE has no creation
// grant, so this reaches the kernel's descriptor allocation before O_TRUNC.
type reopenLimitStore struct {
	*observedFskitDurabilityStore
	calls int
}

func (s *reopenLimitStore) OpenFile(cap xfsstore.Capability, flags xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.calls++
	var saved unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &saved); err != nil {
		return xfsstore.Capability{}, err
	}
	limited := saved
	limited.Cur = 0
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		return xfsstore.Capability{}, err
	}
	handle, err := s.Volume.OpenFile(cap, flags)
	if restoreErr := unix.Setrlimit(unix.RLIMIT_NOFILE, &saved); restoreErr != nil {
		panic(restoreErr)
	}
	return handle, err
}

func TestVolumeHandlerEndToEndOnXFSFskitDurability(t *testing.T) {
	root, projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_ROOT"), os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	if root == "" || projectRaw == "" {
		if os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1" {
			t.Fatal("required XFS gate is unconfigured")
		}
		t.Skip("privileged XFS gate is not configured")
	}
	if os.Geteuid() == 0 {
		t.Fatal("durability permission coverage requires the unprivileged volume owner")
	}
	resetXFSRouteDeclaration(t, root)
	// Descriptor exhaustion changes a process-wide limit. Run this fixture in
	// its own process so unrelated tests and their I/O cannot observe the cut.
	if os.Getenv("PORTABLEFS_TEST_REOPEN_CHILD") != "1" {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestVolumeHandlerEndToEndOnXFSFskitDurability$", "-test.v")
		command.Env = append(os.Environ(), "PORTABLEFS_TEST_REOPEN_CHILD=1")
		output, err := command.CombinedOutput()
		t.Logf("%s", output)
		if err != nil {
			t.Fatalf("isolated descriptor-limit fixture: %v", err)
		}
		return
	}
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := xfsstore.Open(root, xfsstore.Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	defer volume.Close()
	store := &observedFskitDurabilityStore{Volume: volume}
	runtime, err := volumeserver.New("fskit-durability-xfs", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 8, MaxLockRecords: 64})
	if err != nil {
		t.Fatal(err)
	}
	h := testVolumeHandler()
	h.Store = store
	h.Runtime = runtime
	h.Authorizer = allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	testCoordinationWithFencer(t, volume, runtime).Bind(h)
	ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{7})
	active, epoch, proof := attachAndActivateHandler(t, h, ctx, 1, &authoritypb.AttachRequest{VolumeId: "fskit-durability-xfs", AccessToken: []byte("test-only"), ReplaySlots: 2, RoutesRevision: emptyRoutesRevision(), Purpose: authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT, FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE})
	var session volumeserver.SessionID
	copy(session[:], proof.GetId())
	sequence := uint64(0)
	call := func(t *testing.T, req *authoritypb.Request, want ...string) *authoritypb.Response {
		t.Helper()
		sequence++
		req.RequestId = sequence + 20
		req.Epoch = epoch
		req.Session = proof
		stampMutation(t, req, 0, sequence)
		if opened := req.GetOpen(); opened == nil || opened.GetFlags().GetTruncate() {
		}
		before := len(store.calls)
		reply := h.Handle(ctx, req)
		if reply.GetErrno() != 0 || reply.GetUncertain() || reply.GetWrite().GetError() != 0 {
			t.Fatalf("%T = %v", req.GetBody(), reply)
		}
		if !slices.Equal(store.calls[before:], want) {
			t.Fatalf("%T syncs=%v want %v", req.GetBody(), store.calls[before:], want)
		}
		req.RequestId += 1000
		replay := h.Handle(ctx, req)
		reply.RequestId = replay.RequestId
		if !proto.Equal(reply, replay) || len(store.calls) != before+len(want) {
			t.Fatalf("replay repeated durability or changed outcome: %v / %v", reply, replay)
		}
		return reply
	}
	parent := active.GetRoot().GetToken()
	created := call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("durability-file"), Mode: 0, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}, "handle").GetCreate()
	item, handle := created.GetItem().GetToken(), created.GetHandle()
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: handle, Size: 4, Data: []byte("data"), WriteFlags: writeKillSUIDGID}}}, "handle")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Mode: proto.Uint32(0)}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Mode: proto.Uint32(0600)}}}, "syncfs")

	for _, refusal := range []string{"EMFILE", "EACCES"} {
		for _, truncate := range []bool{false, true} {
			t.Run(fmt.Sprintf("create-reopen/%s/truncate=%v", refusal, truncate), func(t *testing.T) {
				want := syscall.EACCES
				limited := &reopenLimitStore{observedFskitDurabilityStore: store}
				if refusal == "EMFILE" {
					h.Store = limited
					want = syscall.EMFILE
				} else {
					if err := os.Chmod(filepath.Join(root, "durability-file"), 0444); err != nil {
						t.Fatal(err)
					}
				}
				defer func() {
					h.Store = store
					if err := os.Chmod(filepath.Join(root, "durability-file"), 0600); err != nil {
						t.Error(err)
					}
				}()
				sequence++
				req := &authoritypb.Request{RequestId: sequence + 20, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("durability-file"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true, Truncate: truncate}}}}
				stampMutation(t, req, 0, sequence)
				before := len(store.calls)
				reply := h.Handle(ctx, req)
				if reply.GetErrno() != int32(want) || reply.GetUncertain() || reply.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE || volume.Health() != nil || len(store.calls) != before {
					t.Fatalf("real reopen refusal=%v health=%v barriers=%v", reply, volume.Health(), store.calls[before:])
				}
				if refusal == "EMFILE" && limited.calls != 1 {
					t.Fatalf("reopen calls=%d", limited.calls)
				}
				post, err := os.Stat(filepath.Join(root, "durability-file"))
				if err != nil || post.Size() != 4 {
					t.Fatalf("refused reopen truncated: %v %v", post, err)
				}
				req.RequestId += 1000
				replay := h.Handle(ctx, req)
				reply.RequestId = replay.RequestId
				if !proto.Equal(reply, replay) || len(store.calls) != before {
					t.Fatalf("reopen replay=%v", replay)
				}
				if refusal == "EMFILE" && limited.calls != 1 {
					t.Fatal("replay reopened the inode")
				}
			})
		}
	}

	for _, opened := range [][]byte{nil, handle} {
		kind := "syncfs"
		if len(opened) != 0 {
			kind = "handle"
		}
		call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Handle: opened, Uid: proto.Uint32(uint32(os.Geteuid())), Gid: proto.Uint32(uint32(os.Getegid()))}}}, kind)
		call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Handle: opened, AtimeNs: proto.Int64(1700000000000000000), MtimeNs: proto.Int64(1700000000000000001)}}}, kind)
	}
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Handle: handle, Mode: proto.Uint32(0)}}}, "handle")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Handle: handle, Mode: proto.Uint32(0600)}}}, "handle")
	if err := unix.Setxattr(filepath.Join(root, "durability-file"), "user.durability", []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	call(t, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{Item: item, Name: []byte("user.durability")}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("durability-file"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}})
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: parent, Name: []byte("durability-readable-dir"), Mode: 0755}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: parent, Name: []byte("durability-readable-dir"), Directory: true}}}, "syncfs")
	directory := call(t, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: parent, Name: []byte("durability-dir"), Mode: 0300}}}, "syncfs").GetMkdir().GetItem().GetToken()
	defer func() { var cap xfsstore.Capability; copy(cap[:], directory); _ = volume.Chmod(cap, 0700) }()
	link := call(t, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: directory, Name: []byte("link"), Target: []byte("missing")}}}, "syncfs").GetLookup().GetItem().GetToken()
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: link, AtimeNow: true}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: link, Uid: proto.Uint32(uint32(os.Geteuid())), Gid: proto.Uint32(uint32(os.Getegid()))}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: directory, MtimeNow: true}}}, "syncfs")

	call(t, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: item, NewParent: parent, NewName: []byte("durability-hardlink")}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: parent, OldName: []byte("durability-hardlink"), NewParent: parent, NewName: []byte("durability-renamed")}}}, "syncfs")

	call(t, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: parent, OldName: []byte("durability-renamed"), NewParent: directory, NewName: []byte("cross-parent")}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: directory, Name: []byte("cross-parent")}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: directory, Name: []byte("link")}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("durability-file"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true, Truncate: true}}}}, "handle")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: item, Flags: &authoritypb.OpenFlags{Read: true, Write: true, Truncate: true}}}}, "handle")

	store.retireOnSync = true
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("retired-create"), Mode: 0, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}, "handle")
	granted := call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("retired-write"), Mode: 0444, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}, "handle").GetCreate()
	store.retireOnSync = true
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: granted.GetHandle(), Size: 4, Data: []byte("data"), WriteFlags: writeKillSUIDGID}}}, "handle")
	unlinked := call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte("unlinked-write"), Mode: 0, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}, "handle").GetCreate()
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: parent, Name: []byte("unlinked-write")}}}, "syncfs")
	call(t, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: unlinked.GetHandle(), Size: 4, Data: []byte("data"), WriteFlags: writeKillSUIDGID}}}, "handle")
	// Real owner permissions exercise the old-mode truncate check. Symlinks
	// cannot have authority open handles; the handle variant presents a live
	// regular-file handle and must refuse the item/handle mismatch.
	for _, test := range []struct {
		name    string
		kind    string
		oldMode os.FileMode
		newMode uint32
	}{
		{"suid readonly", "file", os.ModeSetuid | 0555, 0555},
		{"readonly", "file", 0444, 0600},
		{"remove write", "file", 0600, 0444},
		{"directory", "directory", 0755, 0700},
		{"symlink", "symlink", 0777, 0600},
	} {
		for _, withHandle := range []bool{false, true} {
			t.Run(fmt.Sprintf("setattr/%s/handle=%v", test.name, withHandle), func(t *testing.T) {
				name := fmt.Sprintf("setattr-%s-%v", test.name, withHandle)
				var token, opened []byte
				switch test.kind {
				case "file":
					created := call(t, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent, Name: []byte(name), Mode: 0600, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}, "handle").GetCreate()
					token, opened = created.GetItem().GetToken(), created.GetHandle()
					call(t, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: opened, Size: 4, Data: []byte("data"), WriteFlags: writeKillSUIDGID}}}, "handle")
					if err := os.Chmod(filepath.Join(root, name), test.oldMode); err != nil {
						t.Fatal(err)
					}
				case "directory":
					token = call(t, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: parent, Name: []byte(name), Mode: uint32(test.oldMode)}}}, "syncfs").GetMkdir().GetItem().GetToken()
					if withHandle {
						opened = call(t, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: token, Flags: &authoritypb.OpenFlags{Read: true}}}}).GetOpen().GetHandle()
					}
				case "symlink":
					token = call(t, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: parent, Name: []byte(name), Target: []byte("missing")}}}, "syncfs").GetLookup().GetItem().GetToken()
					opened = handle
				}
				if !withHandle {
					opened = nil
				}
				req := &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: token, Handle: opened, Mode: proto.Uint32(test.newMode), Size: proto.Int64(0)}}}
				if test.kind == "file" && (withHandle || test.oldMode.Perm()&0200 != 0) {
					kind := "syncfs"
					if withHandle {
						kind = "handle"
					}
					call(t, req, kind)
					return
				}
				var cap xfsstore.Capability
				copy(cap[:], token)
				before, err := volume.Getattr(cap)
				if err != nil {
					t.Fatal(err)
				}
				sequence++
				req.RequestId = sequence + 20
				req.Epoch = epoch
				req.Session = proof
				stampMutation(t, req, 0, sequence)

				syncs := len(store.calls)
				reply := h.Handle(ctx, req)
				want := syscall.EACCES
				if test.kind == "directory" {
					want = syscall.EISDIR
				}
				if test.kind == "symlink" {
					want = syscall.EINVAL
				}
				if reply.GetErrno() != int32(want) || reply.GetUncertain() || reply.GetPostState() != nil || len(store.calls) != syncs || volume.Health() != nil {
					t.Fatalf("definite refusal = %v; syncs=%v health=%v", reply, store.calls[syncs:], volume.Health())
				}
				after, err := volume.Getattr(cap)
				if err != nil || after.Mode != before.Mode || after.Size != before.Size {
					t.Fatalf("refusal changed inode: before=%+v after=%+v err=%v", before, after, err)
				}
			})
		}
	}

}
