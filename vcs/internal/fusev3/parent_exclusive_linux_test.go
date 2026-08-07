//go:build linux

package fusev3

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// The PARENT_EXCLUSIVE contract, from this frontend's side.
//
// Making a cached binding unservable on Linux FUSE takes the parent directory's
// i_rwsem for write (fs/fuse/dir.c, unconditionally, with no trylock anywhere in
// fs/fuse), and a namespace syscall holds that same semaphore across this
// frontend's whole authority round trip. So a peer's COMPLETE that needs a name
// invalidated in a directory this mount is parked in cannot be serviced, ever,
// and no reply-carried repair fixes it: the repair would have to ride on a reply
// that does not exist until this mount is granted the order the peer is holding.
//
// The authority decides that exactly, at COMPLETE dispatch, and fences this one
// participant immediately rather than stalling the volume for a repair budget.
// This frontend's half is therefore not plumbing. It is:
//
//  1. declare NAMESPACE_REPAIR_PARENT_EXCLUSIVE at attach, so the authority can
//     tell a proven cycle from a slow lock (the mount binary and the integration
//     fixture do this; an attach that omits it is refused);
//  2. keep track of which directories it is parked in, so the fencing it is
//     handed can be reported as something a person can act on;
//  3. treat that fencing exactly like any other: stop serving, immediately and
//     permanently.

// parkedFixture drives one namespace mutation into the parked state -- submitted
// to the authority, unanswered, with the kernel holding the parent -- and leaves
// it there until the test releases it.
type parkedFixture struct {
	*strictFixture
	parent  *fuse.EntryOut
	release func()
	done    chan struct{}
}

func newParkedMkdir(t *testing.T, directory string) *parkedFixture {
	t.Helper()
	f := newStrictFixture(t)
	// Distinct directories per name, so the mutation parks in a directory with
	// a path of its own rather than in the object every lookup happens to share.
	f.rpc.byName = map[string]*authoritypb.Item{}
	parent := f.lookup(t, fuse.FUSE_ROOT_ID, directory)

	block := make(chan struct{})
	f.rpc.mu.Lock()
	f.rpc.block = block
	f.rpc.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		out := &fuse.EntryOut{}
		f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{NodeId: parent.NodeId}, Mode: 0o755}, "child", out)
	}()
	waitFor(t, "the directory mutation to park in the authority", func() bool {
		return len(f.raw.parkedDirectories()) != 0
	})
	var once sync.Once
	return &parkedFixture{
		strictFixture: f, parent: parent, done: done,
		release: func() { once.Do(func() { close(block) }) },
	}
}

func TestFencingWhileADirectoryMutationIsParkedNamesTheDirectory(t *testing.T) {
	f := newParkedMkdir(t, "packages")
	defer f.release()

	// This is what the authority hands a participant it has proved cannot
	// repair. The errno says nothing about which directory, because the
	// authority knows it only as a coordination identity.
	f.mount.revoke(errors.New("authority fenced this participant: it cannot repair while its own unordered mutation holds the directory"))

	cause := f.mount.fatalError()
	if cause == nil {
		t.Fatal("fencing did not record a terminal cause")
	}
	message := cause.Error()
	if !strings.Contains(message, "packages") {
		t.Fatalf("terminal cause %q does not name the directory this mount was parked in; that name is the one thing the authority could not supply and this frontend could", message)
	}
	if !strings.Contains(message, "i_rwsem") && !strings.Contains(message, "holding") {
		t.Fatalf("terminal cause %q does not explain why the mount could not repair", message)
	}
}

func TestAFencedMountStopsServingImmediately(t *testing.T) {
	f := newParkedMkdir(t, "packages")
	f.mount.revoke(errors.New("authority fenced this participant"))
	f.release()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the parked mutation never completed after the mount was fenced")
	}

	// Every new request is refused synchronously, before revoke returned. A
	// mount that cannot repair must stop serving what it already cached rather
	// than keep answering from it.
	out := &fuse.EntryOut{}
	if status := f.raw.Lookup(nil, &fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, "anything", out); status != fuse.Status(revokedErrno) {
		t.Fatalf("LOOKUP on a fenced mount = %v, want %v", status, revokedErrno)
	}
	if !f.mount.isRevoked() {
		t.Fatal("the mount did not record itself as revoked")
	}
}

func TestParkedDirectoriesAreForgottenWhenTheMutationIsAnswered(t *testing.T) {
	f := newParkedMkdir(t, "packages")
	f.release()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the parked mutation never completed")
	}
	waitFor(t, "the answered mutation to stop being parked", func() bool {
		return len(f.raw.parkedDirectories()) == 0
	})
	// And an ordinary failure with nothing parked says nothing about locks.
	f.mount.failAsync(errors.New("unrelated failure"))
	if message := f.mount.fatalError().Error(); strings.Contains(message, "i_rwsem") {
		t.Fatalf("terminal cause %q blames a lock this mount was not holding", message)
	}
}

func TestAnUncachedMountTracksNoParkedDirectories(t *testing.T) {
	// An uncached mount caches no binding, so no peer's COMPLETE can ever need
	// it to invalidate one, and the whole condition is inapplicable. It must not
	// pay for the bookkeeping either.
	frontend, _, _ := testRawFileSystem(t, 8)
	out := &fuse.EntryOut{}
	if status := frontend.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Mode: 0o755}, "child", out); status != fuse.OK {
		t.Fatalf("MKDIR = %v", status)
	}
	if directories := frontend.parkedDirectories(); len(directories) != 0 {
		t.Fatalf("an uncached mount tracked %v", directories)
	}
}
