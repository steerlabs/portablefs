//go:build darwin

package cli

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// These tests pin the two live-battery failures against the daemon-v3 umount
// flow: a terminal FSKit mount whose daemon attach is already gone could only
// be removed with the system umount, and a mount path with a symlinked
// ancestor could not even be named once the volume stopped answering lstat.

func v3FSKitMountState(t *testing.T, mountPath string) mountState {
	t.Helper()
	st := staleFSKitMountState(t, mountPath)
	st.Engine = mountEngineDaemonV3
	st.Branch = ""
	return st
}

// stubV3KernelMount publishes the recorded mount's exact kernel identity in
// the stubbed mount table, gated on a flag so the test's platform unmount can
// make it absent. Returns the presence flag.
func stubV3KernelMount(t *testing.T, st mountState) *atomic.Bool {
	t.Helper()
	var present atomic.Bool
	present.Store(true)
	stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
		if present.Load() && path == st.MountPath {
			return []kernelMountIdentity{{
				fsType: fskitidentity.FSType,
				path:   st.MountPath,
				source: fskitidentity.ResourcePrefix + st.AttachRef,
			}}, nil
		}
		return nil, nil
	})
	return &present
}

// stubPlatformUnmount replaces the exec surface of the direct kernel detach
// and flips the stubbed kernel mount to absent when it runs, exactly like a
// successful /sbin/umount. Returns the invocation counter.
func stubPlatformUnmount(t *testing.T, present *atomic.Bool) *atomic.Int32 {
	t.Helper()
	var detaches atomic.Int32
	prior := platformUnmountOpsSource
	platformUnmountOpsSource = func(time.Duration) unmountOps {
		return unmountOps{
			goos: "darwin",
			combinedOut: func(name string, args ...string) ([]byte, error) {
				if name != "/sbin/umount" {
					t.Errorf("direct kernel detach ran %q, want /sbin/umount", name)
				}
				detaches.Add(1)
				present.Store(false)
				return nil, nil
			},
		}
	}
	t.Cleanup(func() { platformUnmountOpsSource = prior })
	return &detaches
}

func TestUmountV3DetachesTerminalMountWhoseDaemonAttachIsGone(t *testing.T) {
	for _, force := range []bool{true, false} {
		t.Run(map[bool]string{true: "force", false: "normal"}[force], func(t *testing.T) {
			e, _, stderr, stateDir := umountTestEnv(t)
			mountPath, err := canonicalMountPath(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			st := v3FSKitMountState(t, mountPath)
			if err := writeMountState(stateDir, st); err != nil {
				t.Fatal(err)
			}
			present := stubV3KernelMount(t, st)
			detaches := stubPlatformUnmount(t, present)
			ctl, calls := serveFSKitReconcileControl(t, st, false, false, http.StatusOK)
			e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }

			args := []string{"umount", mountPath}
			if force {
				args = []string{"umount", "--force", mountPath}
			}
			if rc := e.run(args); rc != 0 {
				t.Fatalf("rc=%d stderr=%q", rc, stderr.String())
			}
			if detaches.Load() != 1 {
				t.Fatalf("direct kernel detaches=%d, want exactly 1", detaches.Load())
			}
			if calls.unmount.Load() != 0 {
				t.Fatalf("daemon unmount endpoint was called %d times for an absent attach", calls.unmount.Load())
			}
			if current, err := readMountState(stateDir, mountPath); err != nil || current != nil {
				t.Fatalf("state after detach=%+v err=%v", current, err)
			}
			if !strings.Contains(stderr.String(), "identity-checked kernel detach") {
				t.Fatalf("the fallback was silent: stderr=%q", stderr.String())
			}
		})
	}
}

func TestUmountV3ForceDetachesWhenTheDaemonIsUnreachable(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	present := stubV3KernelMount(t, st)
	detaches := stubPlatformUnmount(t, present)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
		return nil, errors.New("daemon did not start")
	}

	if rc := e.run([]string{"umount", "--force", mountPath}); rc != 0 {
		t.Fatalf("rc=%d stderr=%q", rc, stderr.String())
	}
	if detaches.Load() != 1 {
		t.Fatalf("direct kernel detaches=%d, want exactly 1", detaches.Load())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current != nil {
		t.Fatalf("state after detach=%+v err=%v", current, err)
	}
}

func TestUmountV3NormalRequiresTheDaemonWhenItsAttachMayBeLive(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	present := stubV3KernelMount(t, st)
	detaches := stubPlatformUnmount(t, present)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
		return nil, errors.New("daemon did not start")
	}

	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatal("a normal unmount succeeded without either the daemon transaction or --force")
	}
	if detaches.Load() != 0 {
		t.Fatalf("a refused normal unmount performed %d kernel detaches", detaches.Load())
	}
	if !strings.Contains(stderr.String(), "--force") {
		t.Fatalf("refusal names no exit: stderr=%q", stderr.String())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("refusal lost state: state=%+v err=%v", current, err)
	}
}

func TestUmountV3NeverOverridesAnAttachIdentityMismatch(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	present := stubV3KernelMount(t, st)
	detaches := stubPlatformUnmount(t, present)
	ctl, _ := serveFSKitReconcileControl(t, st, true, true, http.StatusOK)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }

	if rc := e.run([]string{"umount", "--force", mountPath}); rc == 0 {
		t.Fatal("--force overrode an attach identity mismatch")
	}
	if detaches.Load() != 0 {
		t.Fatalf("an identity mismatch still performed %d kernel detaches", detaches.Load())
	}
	if !strings.Contains(stderr.String(), "identity mismatch") {
		t.Fatalf("refusal does not state the mismatch: stderr=%q", stderr.String())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("mismatch refusal lost state: state=%+v err=%v", current, err)
	}
}

func TestForcedRevocationDetachesTheExactRecordedMount(t *testing.T) {
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := v3FSKitMountState(t, mountPath)
	present := stubV3KernelMount(t, st)
	var forced atomic.Int32
	prior := platformUnmountOpsSource
	platformUnmountOpsSource = func(budget time.Duration) unmountOps {
		// The revocation must never inherit the operator-scale platform
		// budget: one attempt is bounded to a third of the repair budget so
		// a wedged /sbin/umount cannot blow through the fencing grace it
		// exists to honor.
		if budget != mountv3.RepairBudget/3 {
			t.Errorf("forced revocation budget = %v, want %v", budget, mountv3.RepairBudget/3)
		}
		return unmountOps{
			goos: "darwin",
			combinedOut: func(name string, args ...string) ([]byte, error) {
				if name != "/sbin/umount" || len(args) != 2 || args[0] != "-f" || args[1] != st.MountPath {
					t.Errorf("forced revocation ran %s %v; it must be exactly umount -f <recorded path>", name, args)
				}
				forced.Add(1)
				present.Store(false)
				return nil, nil
			},
		}
	}
	t.Cleanup(func() { platformUnmountOpsSource = prior })

	if err := forceRevokeFSKitKernelMount(&st); err != nil {
		t.Fatalf("forced revocation: %v", err)
	}
	if forced.Load() != 1 {
		t.Fatalf("forced unmounts = %d, want exactly 1", forced.Load())
	}
	// Once the exact mount is absent, revocation is idempotently complete and
	// must never run umount against whatever else is now at the path.
	if err := forceRevokeFSKitKernelMount(&st); err != nil {
		t.Fatalf("revocation of an absent mount: %v", err)
	}
	if forced.Load() != 1 {
		t.Fatalf("an absent mount was force-unmounted again (%d total)", forced.Load())
	}
}

func TestCanonicalMountPathResolvesSymlinkedAncestorOfADeadMount(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolvedReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	typed := filepath.Join(link, "mnt")          // the path the user types
	canonical := filepath.Join(resolvedReal, "mnt") // the path the kernel records

	stubMountIdentification(t,
		func(path string) (fs.FileInfo, error) {
			if path == typed || path == canonical {
				return nil, &os.PathError{Op: "lstat", Path: path, Err: syscall.EIO}
			}
			return os.Lstat(path)
		},
		func(path string) ([]kernelMountIdentity, error) {
			if path == canonical {
				return []kernelMountIdentity{{fsType: fskitidentity.FSType, path: canonical, source: fskitidentity.ResourcePrefix + "att_AAAAAAAAAAAAAAAAAAAAAA"}}, nil
			}
			return nil, nil
		})

	got, err := canonicalMountPath(typed)
	if err != nil {
		t.Fatalf("a dead mount under a symlinked ancestor could not be named: %v", err)
	}
	if got != canonical {
		t.Fatalf("canonical path = %q, want the kernel's recorded %q", got, canonical)
	}
}
