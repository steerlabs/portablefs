package portablefsd

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// blockingLookupFS parks the authority inside ONE named lookup, modelling a
// real round trip in flight: not an error, not a hang, just an uplink that has
// not answered yet.
type blockingLookupFS struct {
	*workfs.FS
	target  string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *blockingLookupFS) Lstat(path string) (os.FileInfo, error) {
	if path == f.target {
		blocked := false
		f.once.Do(func() {
			blocked = true
			close(f.entered)
		})
		if blocked {
			<-f.release
		}
	}
	return f.FS.Lstat(path)
}

// serveBlockingAuthority serves an authority whose first lookup of target
// parks until the returned release channel is closed.
func serveBlockingAuthority(t *testing.T, target string) (string, chan struct{}, chan struct{}) {
	t.Helper()
	base := newManagedTestFS(t, daemonTestBlobs{}, filepath.Join(privateTestDir(t), "wal.log"))
	blocked := &blockingLookupFS{
		FS:      base,
		target:  target,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(blocked, base).Serve(ctx, ln) }()
	return ln.Addr().String(), blocked.entered, blocked.release
}

// TestControlWriteMutationHoldsNoMountWideExclusiveGate is the finding-4
// reproduction.
//
// The control plane is a FRONTEND, and the landed dispatcher contract already
// moved its unbounded classification out of the locks (phase 1). What stayed
// inside was the mutation itself — Lookup, Create, Open, Write, Setattr,
// Getattr, six real authority round trips — executed under
// lockExternalNamespaceWrite: frontendSerial.Lock plus nsMu.Lock, both
// EXCLUSIVE and mount-wide, for up to a full operation deadline.
//
// Pre-lock admission does not make those calls nonblocking. And because Go's
// RWMutex is writer-preferring, the exclusive nsMu.Lock parks every subsequent
// nsMu.RLock, so one slow control write stalls every lookup, getattr and read
// on every path in the mount — including paths with nothing to do with it.
//
// The equivalent kernel-frontend handlers (create, setattr, write in ops.go)
// run the same authority calls under the SHARED namespace lock plus the one
// name stripe they mutate. The control plane must obey the same discipline
// rather than a private, heavier one of its own.
func TestControlWriteMutationHoldsNoMountWideExclusiveGate(t *testing.T) {
	const target = "control-gate.txt"
	authority, entered, release := serveBlockingAuthority(t, target)

	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()

	a := newAttach("att-control-gate", "key", ensureAttachRequest{
		VolumeID: "vol-control-gate", Branch: "main",
		MountPath: "/Volumes/ControlGate", AuthorityURL: authority,
	}, privateTestDir(t))
	a.vol = vol
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }

	body := []byte(`{"path":"` + target + `","dataBase64":"` +
		base64.StdEncoding.EncodeToString([]byte("control")) + `"}`)
	recorder := httptest.NewRecorder()
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		(&Server{}).controlFSWrite(
			recorder,
			httptest.NewRequest(http.MethodPost, "/fs/write", bytes.NewReader(body)),
			a,
		)
	}()

	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		close(release)
		<-writeDone
		t.Fatal("the control write never reached the authority")
	}

	// A real authority round trip is in flight. Every ordinary namespace read
	// — lookup, getattr, read, readdir — takes the SHARED namespace lock and
	// depends on nothing this write is waiting for.
	readable := make(chan struct{})
	go func() {
		unlock := a.lockExternalNamespaceRead()
		unlock()
		close(readable)
	}()
	select {
	case <-readable:
	case <-time.After(5 * time.Second):
		close(release)
		<-writeDone
		t.Fatal("an ordinary namespace read could not proceed while a control " +
			"write waited on the authority: the control write holds the mount-wide " +
			"EXCLUSIVE namespace gate across its authority round trips, so one slow " +
			"uplink stalls every lookup, getattr and read in the mount")
	}

	close(release)
	select {
	case <-writeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the control write never completed")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	data, st, err := vol.Client().Read(target, 0, 64)
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify read st=%d err=%v", st, err)
	}
	if string(data) != "control" {
		t.Fatalf("control write content = %q, want %q", string(data), "control")
	}
}

// TestControlWriteSerializesWithItselfOnTheSameName pins what the narrowed
// discipline must still guarantee: two control writes to the SAME path do not
// interleave their create/write/truncate sequences. The mount-wide exclusive
// gate provided that by accident; the per-name stripe must provide it on
// purpose.
func TestControlWriteSerializesWithItselfOnTheSameName(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()

	a := newAttach("att-control-serial", "key", ensureAttachRequest{
		VolumeID: "vol-control-serial", Branch: "main",
		MountPath: "/Volumes/ControlSerial", AuthorityURL: authority,
	}, privateTestDir(t))
	a.vol = vol
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }

	const path = "contended.txt"
	payloads := []string{"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"}
	var wg sync.WaitGroup
	codes := make([]int, len(payloads))
	for i, payload := range payloads {
		wg.Add(1)
		go func(i int, payload string) {
			defer wg.Done()
			body := []byte(`{"path":"` + path + `","dataBase64":"` +
				base64.StdEncoding.EncodeToString([]byte(payload)) + `"}`)
			recorder := httptest.NewRecorder()
			(&Server{}).controlFSWrite(
				recorder,
				httptest.NewRequest(http.MethodPost, "/fs/write", bytes.NewReader(body)),
				a,
			)
			codes[i] = recorder.Code
		}(i, payload)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusNoContent {
			t.Fatalf("control write %d status=%d", i, code)
		}
	}
	data, st, err := vol.Client().Read(path, 0, 64)
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify read st=%d err=%v", st, err)
	}
	// Whichever writer landed last, the file must be exactly one payload —
	// never a torn interleaving of two.
	found := false
	for _, payload := range payloads {
		if string(data) == payload {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("concurrent control writes to one name interleaved: content = %q", string(data))
	}
}
