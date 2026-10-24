//go:build linux

package workspacemount

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
)

func TestRootBusyRemovalRetriesAndEscalatesOriginalOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root protected FUSE owner")
	}
	for _, mode := range []string{"retry", "terminal", "power", "cancelled-voluntary"} {
		t.Run(mode, func(t *testing.T) {
			terminal := mode != "retry"
			path := filepath.Join(t.TempDir(), "protected")
			if err := os.Mkdir(path, 0); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			target := os.NewFile(uintptr(fd), "protected backing")
			defer target.Close()
			var st unix.Stat_t
			if err = unix.Fstat(fd, &st); err != nil {
				t.Fatal(err)
			}
			k, err := fusev3.InstallClosedFUSE(target, path, "mnt_AAAAAAAAAAAAAAAAAAAAAA", fusev3.ManagedKernelOptions(1<<20), uint64(st.Dev), st.Ino)
			if k != nil {
				defer func() { _ = k.Remove(true); _ = k.Finalize() }()
			}
			if err != nil {
				t.Fatal(err)
			}
			d := &Driver{kernel: k, manager: &Manager{Inventory: inventory(t)}}
			holder, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if holder >= 0 {
					_ = unix.Close(holder)
				}
			}()
			for range 2 {
				if err = d.removeKernelLocked("voluntary", "2"); !errors.Is(err, unix.EBUSY) {
					t.Fatal("busy original was not retained", err)
				}
				if err = k.Absent(); err == nil {
					t.Fatal("busy mount fabricated absence")
				}
			}
			if terminal {
				d.child = exec.Command("/bin/sleep", "30")
				if err := d.child.Start(); err != nil {
					t.Fatal(err)
				}
				defer d.child.Process.Kill()
				d.exited = make(chan struct{})
				go func() { _ = d.child.Wait(); close(d.exited) }()
				// Neither an old lifecycle nor an automatic finalizer can prevent
				// explicit terminal abort and the exact process join.
				d.opMu.Lock()
				d.cleanupMu.Lock()
				done := make(chan error, 1)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "cancelled-voluntary" {
					if err := unix.Close(holder); err != nil {
						t.Fatal(err)
					}
					holder = -1
					if err := d.removeKernelLocked("voluntary", "2"); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "power" {
					d.terminalCleanup.Store(true)
				}
				go func() {
					if mode == "power" {
						_, err := d.Suspend(context.Background(), &pb.Suspension{Generation: 1})
						done <- err
					} else if mode == "cancelled-voluntary" {
						_, err := d.remove(ctx, "voluntary")
						done <- err
					} else {
						_, err := d.remove(context.Background(), "terminal")
						done <- err
					}
				}()
				if mode == "cancelled-voluntary" {
					cancel()
				}
				select {
				case <-d.exited:
				case <-time.After(time.Second):
					_ = d.forceKernelOwner()
					d.cleanupMu.Unlock()
					d.opMu.Unlock()
					<-done
					t.Fatal("terminal owner queued behind child control or finalization")
				}
				d.cleanupMu.Unlock()
				select {
				case err = <-done:
					// This fixture owns kernel/process resources only. Missing the
					// inventory intent must still prevent claiming full cleanup.
					if err == nil || !strings.Contains(err.Error(), "workspace cleanup intent missing") || mode == "cancelled-voluntary" && !errors.Is(err, context.Canceled) {
						t.Fatal("incomplete inventory fabricated final cleanup", err)
					}
					err = nil
				case <-time.After(time.Second):
					d.opMu.Unlock()
					t.Fatal("forced removal waited for the old lifecycle")
				}
				d.opMu.Unlock()
			} else {
				if err = unix.Close(holder); err != nil {
					t.Fatal(err)
				}
				holder = -1
				err = d.removeKernelLocked("voluntary", "2")
			}
			if err != nil {
				t.Fatal("original removal could not complete", err)
			}
			if err = k.Absent(); err != nil {
				t.Fatal(err)
			}
			if err = k.Finalize(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
