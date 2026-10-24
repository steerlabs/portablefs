//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
)

// Pause only the frontend's permission clock and CONTROL delivery; authority,
// peer, XFS and kernel replies keep advancing. This is a falsification seam,
// not qualification of Virtualization.framework or a physical host sleep.
type workspacePausedClock struct {
	start time.Time
	awake atomic.Bool
}

func (c *workspacePausedClock) Now() time.Time {
	if c.awake.Load() {
		return continuous.Time()
	}
	return c.start
}
func (c *workspacePausedClock) NewTimer(d time.Duration) subscriptionTimer {
	if c.awake.Load() {
		return wallSubscriptionTimer{time.NewTimer(d)}
	}
	return &subscriptionTestTimer{fired: make(chan time.Time)}
}
func workspaceKernelPauseChild(t *testing.T) {
	t.Run("unfenced", func(t *testing.T) {
		clock := &workspacePausedClock{start: continuous.Time()}
		f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspaceFirstOnly: true, workspaceClock: clock, beforeServe: func(f *integrationFixture) {
			// Seed before subscription snapshots. A delayed setup CHANGE must
			// not evict the stale answer this negative control needs to retain.
			if err := os.WriteFile(filepath.Join(f.volumeRoot, "pause"), []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
		}})
		file := mustOpenFile(t, f.join(0, "pause"), os.O_RDONLY, 0)
		defer file.Close()
		if info, err := file.Stat(); err != nil || info.Size() != 3 {
			t.Fatal(info, err)
		}
		f.transports[0].hookMu.Lock()
		f.transports[0].afterControlEvent = func(ctx context.Context, _ *authoritypb.ControlEvent) error { <-ctx.Done(); return ctx.Err() }
		f.transports[0].hookMu.Unlock()
		if err := f.mounts[0].subscription.takeWorkspaceOwnership(t.Context()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-time.After(15 * time.Second):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		peer := mustOpenFile(t, f.join(1, "pause"), os.O_WRONLY|os.O_TRUNC, 0)
		if _, err := peer.Write([]byte("peer-completed")); err != nil {
			t.Fatal(err)
		}
		if err := peer.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		attrs := f.counter.count("getattr")
		info, err := file.Stat()
		if err != nil || info.Size() != 3 {
			t.Fatal("negative control did not expose stale frontend success after peer completion", info, err)
		}
		if got := f.counter.count("getattr") - attrs; got != 0 {
			t.Fatalf("negative control did not retain its cached answer: %d authority GETATTR calls", got)
		}
	})
	pid, _ := strconv.ParseInt(os.Getenv("PFS_WORKSPACE_KERNEL_PID"), 10, 32)
	start, _ := strconv.ParseUint(os.Getenv("PFS_WORKSPACE_KERNEL_START"), 10, 64)
	binding := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(pid), SupervisorStart: start}
	var mounted atomic.Pointer[Mount]
	reader, err := workspaceadmission.Adopt(os.NewFile(3, "gate"), os.NewFile(4, "owner"), binding, func() {
		if m := mounted.Load(); m != nil {
			m.revoke(errors.New("workspace pause test owner EOF"))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Retire()
	proof, err := reader.Recovery(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	revoked := make(chan RevocationReport, 2)
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: &proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, onRevoked: func(r RevocationReport) { revoked <- r }})
	mounted.Store(f.mounts[0])
	m := f.mounts[0]
	command := func(want byte) {
		var b [1]byte
		if _, err := io.ReadFull(os.Stdin, b[:]); err != nil || b[0] != want {
			t.Fatal("supervisor command", b, err)
		}
	}
	fmt.Println("prepared")
	command('O')
	opusPollHack(t, f.mountPath(0))
	if err := os.WriteFile(f.join(1, "pause"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	file := mustOpenFile(t, f.join(0, "pause"), os.O_RDONLY, 0)
	defer file.Close()
	if _, err := file.Stat(); err != nil {
		t.Fatal(err)
	}
	dirty := mustOpenFile(t, f.join(0, "dirty-cut"), os.O_CREATE|os.O_RDWR, 0600)
	defer dirty.Close()
	if _, err := dirty.Write([]byte("accepted before Close")); err != nil {
		t.Fatal(err)
	}
	fmt.Println("served")
	command('C')
	o, err := m.SuspendWorkspace(t.Context(), 1, 1, continuous.Time().Add(5*time.Second))
	if err != nil || !o.ColdComplete {
		t.Fatal("cold before pause", o, err)
	}
	select {
	case <-time.After(15 * time.Second):
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	peer := mustOpenFile(t, f.join(1, "pause"), os.O_WRONLY|os.O_TRUNC, 0)
	if _, err := peer.Write([]byte("peer-completed")); err != nil {
		t.Fatal(err)
	}
	if err := peer.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	kernelStatAcrossColdRecovery(t, file.Stat, int64(len("peer-completed")), 0600, func() {
		fmt.Println("closed")
		command('R')
		o, err = m.RecoverWorkspace(t.Context(), 1, 1)
		if err != nil || !o.Prepared {
			t.Fatal("cold recovery", o, err)
		}
		fmt.Println("reprepared")
		command('O')
	})
	info, err := file.Stat()
	if err != nil || info.Size() != int64(len("peer-completed")) {
		t.Fatal("recovery exposed stale metadata", info, err)
	}
	if data, err := os.ReadFile(f.join(1, "dirty-cut")); err != nil || string(data) != "accepted before Close" {
		t.Fatal("cold cut lost accepted bytes", string(data), err)
	}
	fmt.Println("resumed")
	select {
	case <-reader.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("owner EOF not observed")
	}
	select {
	case <-m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded connection")
	}
	waitWorkspaceKernelWithdrawal(t, revoked)
	fmt.Println("owner-exit")
}
