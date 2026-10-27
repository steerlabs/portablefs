//go:build linux

package fusev3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type appendColdNotifier struct {
	kernelNotifier
	once             sync.Once
	entered, release chan struct{}
}

func (n *appendColdNotifier) EntryNotify(parent uint64, name string) fuse.Status {
	if name == "append" {
		n.once.Do(func() { close(n.entered); <-n.release })
	}
	return n.kernelNotifier.EntryNotify(parent, name)
}

func TestWorkspaceKernelAppendBusyUnmountColdCut(t *testing.T) {
	opusKernelParent(t, workspaceAppendColdCutChild)
}

func workspaceAppendColdCutChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	file := mustOpenFile(t, f.join(0, "append"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	defer file.Close()
	if _, err := file.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("fusermount3", "-u", f.mountPath(0)).CombinedOutput()
	if err == nil || !bytes.Contains(bytes.ToLower(output), []byte("busy")) {
		t.Fatal("held writer did not refuse voluntary unmount", string(output), err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.m.raw.beforeSourceAssignment = func(*sourcePublicationLease) {
		once.Do(func() { close(entered); <-release })
	}
	writes := f.counter.count("write")
	done := make(chan error, 1)
	go func() {
		_, err := file.Write([]byte("after\n"))
		if err == nil {
			err = file.Sync()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("kernel append did not reach pre-assignment seam")
	}
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	close(release)
	select {
	case err := <-done:
		t.Fatal("unassigned kernel append failed across Close", err)
	case <-time.After(25 * time.Millisecond):
	}
	if f.counter.count("write") != writes {
		t.Fatal("closed append reached authority")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	// Widen the notification window while a real holder metadata request
	// crosses the closed gate. GETATTR must refuse promptly; the unanswered
	// append must survive without holding a callback or kernel notification.
	notify := &appendColdNotifier{kernelNotifier: c.m.notifier(), entered: make(chan struct{}), release: make(chan struct{})}
	var releaseNotify sync.Once
	defer releaseNotify.Do(func() { close(notify.release) })
	c.m.setNotifier(notify)
	cold := make(chan error, 1)
	go func() {
		o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(7*time.Second))
		if err == nil && (!o.ColdComplete || len(o.Loss) != 0) {
			err = errors.New("cold cut incomplete or lost acknowledged data")
		}
		cold <- err
	}()
	select {
	case <-notify.entered:
	case <-ctx.Done():
		t.Fatal("cold withdrawal did not reach notification seam", ctx.Err())
	}
	metadata := make(chan error, 1)
	go func() { _, err := file.Stat(); metadata <- err }()
	select {
	case err := <-metadata:
		if !errors.Is(err, syscall.EIO) {
			t.Fatal("closed GETATTR did not refuse promptly", err)
		}
	case <-time.After(time.Second):
		t.Fatal("holder GETATTR blocked cold withdrawal")
	}
	select {
	case err := <-done:
		t.Fatal("append returned during held cold withdrawal", err)
	default:
	}
	releaseNotify.Do(func() { close(notify.release) })
	if err := <-cold; err != nil {
		t.Fatal("append blocked cold withdrawal", err)
	}
	c.recover(serial)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("held append/fsync failed", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if f.counter.count("write") != writes+1 {
		t.Fatal("append was duplicated", writes, f.counter.count("write"))
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.join(1, "append"))
	if err != nil || string(data) != "before\nafter\n" {
		t.Fatal("independent ordinary peer lost or duplicated acknowledged append", string(data), err)
	}
	t.Log("FUSE_WRITE opcode 16: no authority WRITE before cold; exactly one after recovery; held fsync and close succeeded")
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded connection")
	}
}
