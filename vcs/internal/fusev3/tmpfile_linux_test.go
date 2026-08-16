//go:build linux

package fusev3

import (
	"bytes"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func TestSharedTmpfileMapsSlashAndExclusiveThenPublishesAnonymousInode(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(81, authoritypb.Attr_REGULAR, 181)
	item.Attr.Mode = 0o640
	handleToken := testToken(281)
	var captured *authoritypb.Request
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetTmpfile() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		captured = proto.Clone(request).(*authoritypb.Request)
		return &authoritypb.Response{Body: &authoritypb.Response_Tmpfile{Tmpfile: &authoritypb.TmpfileReply{
			Item: cloneItem(item), Handle: cloneBytes(handleToken),
		}}}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.CreateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Flags:    uint32(unix.O_TMPFILE | unix.O_RDWR | unix.O_EXCL),
		Mode:     0o640,
	}
	out := &fuse.CreateOut{}
	if status := fixture.raw.Tmpfile(nil, in, "/", out); !status.Ok() {
		t.Fatalf("shared TMPFILE = %v", status)
	}
	request := captured.GetTmpfile()
	fixture.raw.mu.Lock()
	parentToken := cloneBytes(fixture.raw.nodesByID[fuse.FUSE_ROOT_ID].node.item.GetToken())
	fixture.raw.mu.Unlock()
	if request == nil || !bytes.Equal(request.GetParent(), parentToken) || request.GetMode() != 0o640 ||
		request.GetFlags() == nil || !request.GetFlags().GetRead() || !request.GetFlags().GetWrite() ||
		request.GetFlags().GetAppend() || request.GetFlags().GetTruncate() || !request.GetExclusive() {
		t.Fatalf("authority TMPFILE mapping = %+v", request)
	}
	if captured.GetSourcePublicationGate() != nil {
		t.Fatalf("unlinked TMPFILE unexpectedly declared a peer-visible source gate: %+v", captured.GetSourcePublicationGate())
	}
	if out.NodeId == 0 || out.Fh == 0 || out.Attr.Ino != 81 || out.Attr.Flags != fuse.FUSE_ATTR_PFS_SHARED ||
		out.OpenFlags != coherentOpenFlags || out.EntryTimeout() != 0 {
		t.Fatalf("shared TMPFILE output = %+v", out)
	}
	finishPrivatePublication(t, fixture, unique, fuse.FUSE_ROOT_ID, 51) // FUSE_TMPFILE
	if fixture.mount.isRevoked() {
		t.Fatalf("valid shared TMPFILE revoked mount: %v", fixture.mount.fatalError())
	}
	fixture.rpc.mu.Lock()
	fixture.rpc.replyOverride = nil
	fixture.rpc.mu.Unlock()
	fixture.raw.Release(nil, &fuse.ReleaseIn{
		InHeader: fuse.InHeader{Unique: fixture.unique.Add(2), NodeId: out.NodeId}, Fh: out.Fh,
	})
	fixture.raw.Forget(out.NodeId, 1)
}

func TestSharedTmpfileRejectsNoncanonicalNameAndReadOnlyOpen(t *testing.T) {
	t.Run("name", func(t *testing.T) {
		fixture := newStrictFixture(t)
		fixture.rpc.mu.Lock()
		baseline := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		in := &fuse.CreateIn{
			InHeader: fuse.InHeader{Unique: fixture.unique.Add(2), NodeId: fuse.FUSE_ROOT_ID},
			Flags:    uint32(unix.O_TMPFILE | unix.O_RDWR), Mode: 0o600,
		}
		if status := fixture.raw.Tmpfile(nil, in, ".", &fuse.CreateOut{}); status != fuse.Status(syscall.ENOTCONN) {
			t.Fatalf("noncanonical TMPFILE name = %v, want ENOTCONN", status)
		}
		fixture.rpc.mu.Lock()
		calls := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		if calls != baseline || !fixture.mount.isRevoked() {
			t.Fatalf("noncanonical TMPFILE calls=%d->%d revoked=%v", baseline, calls, fixture.mount.isRevoked())
		}
	})

	t.Run("read only", func(t *testing.T) {
		fixture := newStrictFixture(t)
		fixture.rpc.mu.Lock()
		baseline := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		unique := fixture.unique.Add(2)
		in := &fuse.CreateIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
			Flags:    uint32(unix.O_TMPFILE | unix.O_RDONLY), Mode: 0o600,
		}
		if status := fixture.raw.Tmpfile(nil, in, "/", &fuse.CreateOut{}); status != fuse.EINVAL {
			t.Fatalf("read-only TMPFILE = %v, want EINVAL", status)
		}
		fixture.rpc.mu.Lock()
		calls := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		if calls != baseline || fixture.mount.isRevoked() {
			t.Fatalf("read-only TMPFILE calls=%d->%d revoked=%v", baseline, calls, fixture.mount.isRevoked())
		}
	})
}
