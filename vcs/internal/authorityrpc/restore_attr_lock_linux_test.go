//go:build linux

package authorityrpc

import (
	"fmt"
	"io/fs"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/restoremode"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

var restoreSampleChild = xfsstore.Capability{0x70}

// The mutation gate is after resolution and preparatory samples. Taking the
// restore lock there proves the apply/post-state path waits independently of
// those earlier samples. Namespace mutations also exercise a post-apply gate.
type restoreSampleStore struct {
	resourceAdmissionFaultStore
	gate       func()
	afterApply bool
	copyNoop   bool
	once       sync.Once
}

func (s *restoreSampleStore) LockMutation([][16]byte) func() {
	if !s.afterApply {
		s.once.Do(s.gate)
	}
	return func() {}
}
func (s *restoreSampleStore) applied() {
	if s.afterApply {
		s.once.Do(s.gate)
	}
}
func (s *restoreSampleStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	kind := xfsstore.KindRegular
	if item[0] == 0x72 {
		kind = xfsstore.KindDirectory
	}
	return xfsstore.Attr{Kind: kind, Ino: uint64(item[0]), Mode: 0600, Size: 64, Nlink: 1, DeviceMinor: 1, MTimeNS: 123}, nil
}
func (s *restoreSampleStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	return s.Getattr(handle)
}
func (s *restoreSampleStore) Lookup(_ xfsstore.Capability, name string) (xfsstore.Capability, xfsstore.Attr, error) {
	if name == "missing" {
		return xfsstore.Capability{}, xfsstore.Attr{}, syscall.ENOENT
	}
	attr, err := s.Getattr(restoreSampleChild)
	return restoreSampleChild, attr, err
}
func (s *restoreSampleStore) LookupOpen(handle xfsstore.Capability, name string) (xfsstore.Capability, xfsstore.Attr, error) {
	return s.Lookup(handle, name)
}
func (s *restoreSampleStore) ReadDirOpen(xfsstore.Capability, uint64, int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	return []xfsstore.Dirent{{Name: "child", Ino: 0x70, Kind: xfsstore.KindRegular, NextCookie: 1}}, 1, [16]byte{1}, true, xfsstore.Capability{0x72}, nil
}
func (s *restoreSampleStore) SetAttr(item, _ xfsstore.Capability, _ xfsstore.SetAttrSpec) (xfsstore.Attr, error) {
	return s.Getattr(item)
}
func (s *restoreSampleStore) Link(item, _ xfsstore.Capability, _ string) (xfsstore.Attr, error) {
	return s.Getattr(item)
}
func (s *restoreSampleStore) Unlink(xfsstore.Capability, string, bool) error { s.applied(); return nil }
func (s *restoreSampleStore) Rename(xfsstore.Capability, string, xfsstore.Capability, string, xfsstore.RenameFlags) error {
	s.applied()
	return nil
}
func (s *restoreSampleStore) Create(xfsstore.Capability, string, fs.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.applied()
	attr, err := s.Getattr(restoreSampleChild)
	return restoreSampleChild, attr, err
}
func (s *restoreSampleStore) OpenFile(item xfsstore.Capability, _ xfsstore.OpenFlags) (xfsstore.Capability, error) {
	return item, nil
}
func (s *restoreSampleStore) CloseOpen(xfsstore.Capability) error { return nil }
func (s *restoreSampleStore) Fallocate(handle xfsstore.Capability, _ xfsstore.FallocateSpec) (xfsstore.Attr, error) {
	return s.Getattr(handle)
}
func (s *restoreSampleStore) CopyFileRange(_, output xfsstore.Capability, spec xfsstore.CopyFileRangeSpec) (uint64, xfsstore.Attr, error) {
	attr, err := s.Getattr(output)
	if spec.InputOffset >= 64 {
		if s.copyNoop {
			return 0, attr, nil
		}
		return 0, attr, xfsstore.ErrWritePostApply
	}
	return 1, attr, err
}
func (s *restoreSampleStore) PinWriteTarget(xfsstore.Capability) (xfsstore.WriteTarget, error) {
	attr, _ := s.Getattr(restoreSampleChild)
	return &restoreSampleWriteTarget{writeTestTarget: writeTestTarget{coordinate: xfsstore.ObjectCoordinate{Stable: [16]byte{0x70}, Ino: 0x70, DeviceMinor: 1}, committed: 1, post: attr}}, nil
}

type restoreSampleWriteTarget struct{ writeTestTarget }

func (t *restoreSampleWriteTarget) Getattr() (xfsstore.Attr, error) { return t.post, nil }

func holdRestoreSampleLock(t *testing.T, mode *restoremode.Mode) func() {
	t.Helper()
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { done <- mode.UserMutation([16]byte{0x70}, func() error { close(held); <-release; return nil }) }()
	select {
	case <-held:
	case err := <-done:
		t.Fatalf("hold restore lock: %v", err)
	case <-time.After(time.Second):
		t.Fatal("restore lock was not acquired")
	}
	return sync.OnceFunc(func() {
		close(release)
		if err := <-done; err != nil {
			t.Errorf("restore lock owner: %v", err)
		}
	})
}

func TestHandlerAttributeSamplesWaitForRestoreEntryLock(t *testing.T) {
	operations := []string{"lookup", "item getattr", "handle getattr", "both getattr", "readdir owning", "readdir nonowning", "setattr", "link", "unlink", "rename", "write", "copy", "copy EOF", "copy EOF no-op", "create existing", "create trunc", "open trunc"}
	modes := []uint32{0, unix.FALLOC_FL_KEEP_SIZE, unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE, unix.FALLOC_FL_ZERO_RANGE, unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE, unix.FALLOC_FL_COLLAPSE_RANGE, unix.FALLOC_FL_INSERT_RANGE, unix.FALLOC_FL_UNSHARE_RANGE, unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE}
	for _, mode := range modes {
		operations = append(operations, fmt.Sprintf("fallocate %d", mode))
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			store := &restoreSampleStore{}
			// Linux's both-field refusal is covered separately; FSKit has the
			// same storage sampling path after its profile-specific admission.
			profile := authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
			if operation == "both getattr" {
				profile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE
			}
			h, ctx, cred, root := resourceAdmissionRequestHarnessForProfile(t, store, 16, 16, profile)
			h.Restore = newRestoreTruncateMode(t, &restoreTruncateSyncFailure{}, false, true)
			for _, item := range []xfsstore.Capability{restoreSampleChild, {0x71}} {
				if err := h.trackItem(cred.ID, item, false); err != nil {
					t.Fatal(err)
				}
			}
			for _, handle := range []xfsstore.Capability{restoreSampleChild, {0x71}, root} {
				if err := h.trackOpen(cred.ID, handle, false); err != nil {
					t.Fatal(err)
				}
			}
			request := coherenceReadRequest(cred)
			read := false
			switch operation {
			case "lookup":
				request.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("child")}}
				read = true
			case "item getattr", "handle getattr", "both getattr":
				get := &authoritypb.GetAttrRequest{}
				if operation != "handle getattr" {
					get.Item = restoreSampleChild[:]
				}
				if operation != "item getattr" {
					get.Handle = restoreSampleChild[:]
				}
				request.Body = &authoritypb.Request_GetAttr{GetAttr: get}
				read = true
			case "readdir owning", "readdir nonowning":
				request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: root[:], MaxEntries: 8, WantItems: operation == "readdir owning"}}
				read = true
			case "setattr":
				request.Body = &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: restoreSampleChild[:], Mode: proto.Uint32(0600)}}
			case "link":
				request.Body = &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: restoreSampleChild[:], NewParent: root[:], NewName: []byte("missing")}}
			case "unlink":
				request.Body = &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: root[:], Name: []byte("child")}}
				store.afterApply = true
			case "rename":
				request.Body = &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: root[:], OldName: []byte("child"), NewParent: root[:], NewName: []byte("missing")}}
				store.afterApply = true
			case "write":
				request.Body = &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: restoreSampleChild[:], Data: []byte("x"), Size: 1}}
			case "copy", "copy EOF", "copy EOF no-op":
				offset := uint64(0)
				if operation != "copy" {
					offset = 64
				}
				store.copyNoop = operation == "copy EOF no-op"
				input := xfsstore.Capability{0x71}
				request.Body = &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{InputHandle: input[:], OutputHandle: restoreSampleChild[:], InputOffset: offset, Length: 1}}
			case "create existing", "create trunc":
				request.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: root[:], Name: []byte("child"), Mode: 0600, Flags: &authoritypb.OpenFlags{Write: true, Truncate: operation == "create trunc"}}}
				store.afterApply = operation == "create existing"
			case "open trunc":
				request.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: restoreSampleChild[:], Flags: &authoritypb.OpenFlags{Write: true, Truncate: true}}}
			default:
				var mode uint32
				if _, err := fmt.Sscanf(operation, "fallocate %d", &mode); err != nil {
					t.Fatal(err)
				}
				request.Body = &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Handle: restoreSampleChild[:], Mode: mode, Offset: 4, Length: 8}}
			}
			if request.GetGetAttr() == nil {
				stampMutation(t, request, 0, 1)
			}
			gated, proceed := make(chan struct{}), make(chan struct{})
			store.gate = func() { close(gated); <-proceed }
			var unlock func()
			if read {
				unlock = holdRestoreSampleLock(t, h.Restore)
				defer unlock()
			}
			done := make(chan *authoritypb.Response, 1)
			go func() { done <- h.Handle(ctx, request) }()
			if !read {
				select {
				case <-gated:
				case reply := <-done:
					t.Fatalf("missing apply gate: %v", reply)
				case <-time.After(time.Second):
					t.Fatal("missing apply gate")
				}
				unlock = holdRestoreSampleLock(t, h.Restore)
				defer unlock()
				close(proceed)
			}
			select {
			case reply := <-done:
				t.Fatalf("published attributes through held restore lock: %v", reply)
			case <-time.After(20 * time.Millisecond):
			}
			unlock()
			select {
			case reply := <-done:
				if reply.GetErrno() != 0 {
					t.Fatalf("after restore unlock: %v", reply)
				}
				if !read && !store.copyNoop && reply.GetPostState() == nil {
					t.Fatalf("missing post-state: %v", reply)
				}
			case <-time.After(time.Second):
				t.Fatal("sample did not finish after restore unlock")
			}
		})
	}
}
