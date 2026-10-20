//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"golang.org/x/sys/unix"
)

func TestProbeStartupRejectsMissingAbortDescriptor(t *testing.T) {
	point := t.TempDir()
	root, err := os.Open(point)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fdinfo, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", root.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var mountID string
	for _, line := range strings.Split(string(fdinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			mountID = fields[1]
		}
	}
	if mountID == "" {
		t.Fatal("temporary directory has no kernel mount ID")
	}
	const name = "portablefs:unit-probe"
	prior := readMountInfo
	// Keep the real pinned mount ID while reporting a device minor beyond
	// Linux's 20-bit range: its abort pathname cannot name a real connection.
	readMountInfo = func() ([]byte, error) {
		return fmt.Appendf(nil, "%s 1 0:4294967295 / %s rw - fuse.portablefs %s rw\n", mountID, point, name), nil
	}
	t.Cleanup(func() { readMountInfo = prior })
	// This is the same pre-Serve prerequisite invoked by ProbeKernelFUSE and
	// MountVolume; only the kernel mount inventory is substituted.
	installed, err := captureKernelMount(name, point)
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "mount fusectl at /sys/fs/fuse/connections writable by the mount owner") {
		t.Fatalf("missing abort descriptor = %v", err)
	}
	if installed.abortFile != nil {
		t.Fatal("failed startup retained an abort descriptor")
	}
}

// TestKernelFUSEProbeCompletesInit is the falsifiable half of
// `portablefs mount-check --probe-mount`: a client whose mount options this
// kernel refuses, or whose negotiated interface cannot carry the coherence
// contract, cannot get past INIT here. Missing or unwritable fusectl control
// also refuses the probe through the live-mount startup path.
//
// It runs in the privileged suite, which provisions /dev/fuse and
// fusectl. There is no skip: a run without a real FUSE device is a
// failure of the harness, not a licence to report a pass.
func TestKernelFUSEProbeCompletesInit(t *testing.T) {
	tempRoot := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "tmp")
	if err := os.Symlink(tempRoot, alias); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, tempDir string }{
		{"default", os.TempDir()},
		{"relative", relative},
		{"symlink", alias},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TMPDIR", test.tempDir)
			probe, err := ProbeKernelFUSE()
			if err != nil {
				t.Fatalf("throwaway FUSE probe mount: %v", err)
			}
			if probe.ProtocolMajor != portableFuseMajor || probe.ProtocolMinor < portableFuseMinor {
				t.Fatalf("probe negotiated FUSE %d.%d, want %d.%d or newer",
					probe.ProtocolMajor, probe.ProtocolMinor, portableFuseMajor, portableFuseMinor)
			}
			if probe.MaxWrite != probeMaxIO {
				t.Fatalf("probe negotiated max write %d, want %d", probe.MaxWrite, probeMaxIO)
			}
			if probe.InitFlags == 0 {
				t.Fatal("probe reported no kernel INIT capabilities")
			}
		})
	}
}

func TestKernelFUSEProbeRejectsHiddenFusectl(t *testing.T) {
	const childEnv = "PORTABLEFS_TEST_HIDDEN_FUSECTL"
	if os.Getenv(childEnv) != "1" {
		if os.Getenv(envFUSE) != "1" || os.Geteuid() != 0 {
			t.Skip("run in the privileged suite's root boundary slice for the private mount namespace")
		}
		// Only the root boundary slice can change mount visibility. A child
		// mount namespace isolates the fixture from the suite's fusectl and
		// from every Go thread in the parent.
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestKernelFUSEProbeRejectsHiddenFusectl$", "-test.v")
		command.Env = append(os.Environ(), childEnv+"=1")
		command.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: unix.CLONE_NEWNS,
		}
		output, err := command.CombinedOutput()
		t.Logf("%s", output)
		if err != nil {
			t.Fatalf("isolated hidden-fusectl probe: %v", err)
		}
		if !strings.Contains(string(output), "--- PASS: TestKernelFUSEProbeRejectsHiddenFusectl (") {
			t.Fatal("isolated hidden-fusectl probe did not pass")
		}
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeKernelFUSE(); err != nil {
		t.Fatalf("probe before hiding fusectl: %v", err)
	}
	if err := unix.Mount("tmpfs", "/sys/fs/fuse/connections", "tmpfs", 0, "mode=755"); err != nil {
		t.Fatal(err)
	}
	// The namespace dies with this child; no unmount can expose or mutate the
	// suite's fusectl. Probe cleanup must still remove its own normal mount.
	probeRoot := t.TempDir()
	t.Setenv("TMPDIR", probeRoot)
	probe, err := ProbeKernelFUSE()
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "retain original FUSE abort descriptor") {
		t.Fatalf("hidden fusectl probe = %+v, %v", probe, err)
	}
	if probe != (KernelProbe{}) {
		t.Fatalf("failed probe published kernel evidence: %+v", probe)
	}
	entries, err := os.ReadDir(probeRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed probe left its mountpoint behind: %v, %v", entries, err)
	}
}

// A retained root forces a real EBUSY refusal. It stays open until after the
// probe returns, so only abort plus lazy detach can finish the probe teardown.
func TestKernelFUSEProbeUnmountRefusalTerminatesConnection(t *testing.T) {
	if os.Getenv(envFUSE) != "1" {
		t.Skip("set PORTABLEFS_FUSE_TEST=1 for the real kernel lifecycle proof")
	}
	probeRoot := t.TempDir()
	t.Setenv("TMPDIR", probeRoot)
	type busyMount struct {
		server    *fuse.Server
		root      *os.File
		installed kernelMount
	}
	type result struct {
		probe KernelProbe
		err   error
	}
	ready := make(chan busyMount)
	done := make(chan result, 1)
	connectionDone := make(chan struct{})
	go func() {
		probe, err := probeKernelFUSE(func(raw fuse.RawFileSystem, point string, options *fuse.MountOptions) (*fuse.Server, error) {
			server, err := fuse.NewServer(probeUnmountObserver{RawFileSystem: raw, done: connectionDone}, point, options)
			if err != nil {
				return nil, err
			}
			installed, captureErr := captureKernelMount(options.FsName, point)
			root, rootErr := os.OpenFile(point, unix.O_PATH|unix.O_DIRECTORY, 0)
			// The probe must acquire and close its own descriptor, independently
			// of this fixture's observation of the original control inode.
			closeErr := installed.abortFile.close()
			ready <- busyMount{server: server, root: root, installed: installed}
			return server, errors.Join(captureErr, rootErr, closeErr)
		})
		done <- result{probe, err}
	}()
	var mounted busyMount
	select {
	case mounted = <-ready:
	case result := <-done:
		t.Fatalf("probe failed before installing the busy fixture: %v", result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("probe did not install the busy fixture")
	}
	t.Cleanup(func() {
		if mounted.root != nil {
			_ = mounted.root.Close()
		}
		_ = mounted.server.UnmountLazy()
	})
	select {
	case result := <-done:
		if result.err == nil || !strings.Contains(result.err.Error(), "remove FUSE probe mount") || !strings.Contains(strings.ToLower(result.err.Error()), "busy") {
			t.Fatalf("busy probe = %+v, %v", result.probe, result.err)
		}
		if result.probe != (KernelProbe{}) {
			t.Fatalf("refused cleanup published kernel evidence: %+v", result.probe)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("probe hung after ordinary unmount was refused")
	}
	select {
	case <-connectionDone:
	default:
		t.Fatal("probe returned before Serve terminated")
	}
	if _, err := mounted.installed.absent(); err != nil {
		t.Fatalf("refused unmount left the probe installed: %v", err)
	}
	if mounted.installed.abortFile == nil {
		t.Fatal("fixture did not observe the original abort inode")
	}
	abortPath := mounted.installed.abortFile.file.Name()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err == nil && (target == abortPath || target == abortPath+" (deleted)") {
			t.Fatalf("probe retained abort descriptor %s: %s", fd.Name(), target)
		}
	}
	if entries, err := os.ReadDir(probeRoot); err != nil || len(entries) != 0 {
		t.Fatalf("refused unmount left its mountpoint: %v, %v", entries, err)
	}
}

type probeUnmountObserver struct {
	fuse.RawFileSystem
	done chan struct{}
}

func (p probeUnmountObserver) OnUnmount() { close(p.done) }

func TestKernelFUSEProbeRollsBackFailedNewServer(t *testing.T) {
	if os.Getenv(envFUSE) != "1" {
		t.Skip("set PORTABLEFS_FUSE_TEST=1 for the real kernel lifecycle proof")
	}
	probeRoot := t.TempDir()
	t.Setenv("TMPDIR", probeRoot)
	initErr := errors.New("injected NewServer INIT failure")
	var fsName, mountpoint string
	probe, err := probeKernelFUSE(func(raw fuse.RawFileSystem, point string, options *fuse.MountOptions) (*fuse.Server, error) {
		server, err := fuse.NewServer(raw, point, options)
		if err != nil {
			return nil, err
		}
		fsName, mountpoint = options.FsName, point
		t.Cleanup(func() { _ = server.UnmountLazy() })
		installed, captureErr := captureKernelMount(fsName, mountpoint)
		served := make(chan struct{})
		go func() { server.Serve(); close(served) }()
		if captureErr != nil {
			return nil, captureErr
		}
		defer installed.abortFile.close()
		if err := installed.abortKernelConnection(); err != nil {
			return nil, err
		}
		<-served
		// Model NewServer's failed-INIT boundary exactly: the device is closed
		// but the real kernel mount is still installed when it returns error.
		if _, err := observeExactPlannedKernelMount(fsName, mountpoint); err != nil {
			return nil, err
		}
		return nil, initErr
	})
	if !errors.Is(err, initErr) || probe != (KernelProbe{}) {
		t.Fatalf("post-install NewServer failure = %+v, %v", probe, err)
	}
	if fsName == "" {
		t.Fatal("fixture never installed the kernel mount")
	}
	if _, err := observePlannedKernelMountAbsent(fsName, mountpoint); err != nil {
		t.Fatalf("failed NewServer left a stray kernel mount: %v", err)
	}
	if entries, err := os.ReadDir(probeRoot); err != nil || len(entries) != 0 {
		t.Fatalf("failed NewServer left its mountpoint: %v, %v", entries, err)
	}
}
