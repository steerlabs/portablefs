package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func TestLifecycleHoldSharedHandshakeAndEOF(t *testing.T) {
	e, stdout, _ := testEnv(t)
	e.stdin = strings.NewReader("")
	if rc := e.run([]string{"lifecycle", "hold-shared", "--json"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := stdout.String(); got != "{\"schemaVersion\":1,\"held\":true}\n" {
		t.Fatalf("handshake = %q", got)
	}
}

func TestLifecycleUsage(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = bytes.NewReader(nil)
	if rc := e.run([]string{"lifecycle", "unknown"}); rc != 2 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "expected `hold-shared`, `hold-account-exclusive`, `hold-install-exclusive`, or `identity`") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestLifecycleHoldAccountExclusiveHandshakeAndEOF(t *testing.T) {
	e, stdout, _ := testEnv(t)
	e.stdin = strings.NewReader("")
	if rc := e.run([]string{"lifecycle", "hold-account-exclusive", "--json"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := stdout.String(); got != "{\"schemaVersion\":1,\"held\":true,\"mounts\":0,\"attaches\":0}\n" {
		t.Fatalf("handshake = %q", got)
	}
}

func TestLifecycleHoldAccountExclusiveRejectsLiveKernelMount(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = strings.NewReader("")
	e.kernelInventoryFn = func() ([]string, error) {
		return []string{"/tmp/live-portablefs"}, nil
	}
	if rc := e.run([]string{"lifecycle", "hold-account-exclusive", "--json"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "1 PortableFS kernel mount(s) remain") ||
		!strings.Contains(got, "/tmp/live-portablefs") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestLifecycleHoldInstallExclusiveHandshakeAndEOF(t *testing.T) {
	e, stdout, _ := testEnv(t)
	e.stdin = strings.NewReader("")
	if rc := e.run([]string{"lifecycle", "hold-install-exclusive", "--json"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	want := "{\"schemaVersion\":1,\"held\":true,\"purpose\":\"service-update\",\"kernelMounts\":0,\"mountRecords\":0,\"mountIntents\":0,\"durableAttaches\":0,\"liveAttaches\":0}\n"
	if got := stdout.String(); got != want {
		t.Fatalf("handshake = %q, want %q", got, want)
	}
}

func TestWorkspaceDrainRequiresExactFSKitAbsenceAndPreservesWorkspaceWitness(t *testing.T) {
	for _, condition := range []string{"empty-fskit", "kernel-present", "daemon-busy", "identity-missing"} {
		t.Run(condition, func(t *testing.T) {
			e, stdout, stderr := testEnv(t)
			e.stdin = strings.NewReader("")
			directory := filepath.Join(e.lifecycleStateDir, "workspace")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(directory, "resources.present")
			if err := os.WriteFile(marker, []byte("8\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			e.daemonLifecycleInventoryFn = func(expected *daemonRelease) (int, error) {
				if expected == nil {
					t.Fatal("outgoing daemon identity missing")
				}
				if condition == "daemon-busy" {
					return 1, nil
				}
				return 0, nil
			}
			if condition == "kernel-present" {
				e.kernelInventoryFn = func() ([]string, error) { return []string{"/live-fskit"}, nil }
			}
			args := []string{"lifecycle", "hold-install-exclusive", "--json", "--workspace-drain"}
			if condition != "identity-missing" {
				args = append(args,
					"--expected-daemon-version", "1", "--expected-daemon-sha256", strings.Repeat("a", 64),
					"--expected-daemon-path", "/authenticated/portablefsd", "--expected-daemon-cdhash", strings.Repeat("b", 40))
			}
			code := e.run(args)
			if condition == "empty-fskit" {
				if code != 0 || !strings.Contains(stdout.String(), `"purpose":"workspace-drain"`) {
					t.Fatalf("drain code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
			} else if code == 0 || stdout.Len() != 0 {
				t.Fatalf("unsafe drain accepted: %d %s", code, stdout.String())
			}
			if _, err := os.Lstat(marker); err != nil {
				t.Fatalf("helper changed workspace evidence: %v", err)
			}
		})
	}
}

func TestLifecycleHoldInstallExclusiveHoldsBothGuardsUntilEOF(t *testing.T) {
	e, _, stderr := testEnv(t)
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	e.stdin = stdinReader
	e.stdout = stdoutWriter
	t.Cleanup(func() {
		_ = stdinWriter.Close()
		_ = stdinReader.Close()
		_ = stdoutWriter.Close()
		_ = stdoutReader.Close()
	})
	done := make(chan int, 1)
	go func() {
		done <- e.run([]string{"lifecycle", "hold-install-exclusive", "--json"})
	}()
	line, err := bufio.NewReader(stdoutReader).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `"purpose":"service-update"`) {
		t.Fatalf("handshake = %q", line)
	}
	if guard, err := accountsession.AcquireShared(e.lifecycleStateDir); err == nil {
		_ = guard.Close()
		t.Fatal("account-session shared guard acquired during install-exclusive hold")
	}
	if guard, err := mountlifecycle.AcquireShared(e.lifecycleStateDir); err == nil {
		_ = guard.Close()
		t.Fatal("mount-lifecycle shared guard acquired during install-exclusive hold")
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("rc = %d, stderr = %s", rc, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("install-exclusive hold did not release after stdin EOF")
	}
	accountGuard, err := accountsession.AcquireShared(e.lifecycleStateDir)
	if err != nil {
		t.Fatalf("account-session guard remained held: %v", err)
	}
	_ = accountGuard.Close()
	mountGuard, err := mountlifecycle.AcquireShared(e.lifecycleStateDir)
	if err != nil {
		t.Fatalf("mount-lifecycle guard remained held: %v", err)
	}
	_ = mountGuard.Close()
}

func TestLifecycleHoldInstallExclusiveRefusesExistingMountLifecycle(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = strings.NewReader("")
	shared, err := mountlifecycle.AcquireShared(e.lifecycleStateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if rc := e.run([]string{"lifecycle", "hold-install-exclusive", "--json"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "hold install mount-lifecycle guard") ||
		!strings.Contains(got, "mount lifecycle is busy") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestLifecycleHoldInstallExclusiveRejectsDurableMountRecord(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = strings.NewReader("")
	mountStateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	state := validFSKitMountState(t, filepath.Join(t.TempDir(), "mounted"))
	if err := writeMountState(mountStateDir, state); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"lifecycle", "hold-install-exclusive", "--json"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "1 mount record(s) remain") ||
		!strings.Contains(got, "before updating the PortableFS service") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestLifecycleHoldInstallExclusiveRejectsLiveDaemonAttach(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = strings.NewReader("")
	home, err := resolveFSKitAccountHome()
	if err != nil {
		t.Fatal(err)
	}
	controlSocket := filepath.Join(home, ".local", "state", "portablefs", "portablefsd", "control.sock")
	if err := os.MkdirAll(filepath.Dir(controlSocket), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controlSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(controlSocket) })
	expectedSHA256 := strings.Repeat("a", 64)
	e.daemonLifecycleInventoryFn = func(expected *daemonRelease) (int, error) {
		if expected == nil ||
			expected.identity.DaemonVersion != "0.2.2" ||
			expected.identity.ExecutableSHA256 != expectedSHA256 ||
			expected.path != "/authenticated/portablefsd" ||
			expected.identity.CodeDirectoryHash != strings.Repeat("b", 40) {
			t.Fatalf("expected old daemon identity = %+v", expected)
		}
		return 1, nil
	}
	if rc := e.run([]string{
		"lifecycle", "hold-install-exclusive", "--json",
		"--expected-daemon-version", "0.2.2",
		"--expected-daemon-sha256", expectedSHA256,
		"--expected-daemon-path", "/authenticated/portablefsd",
		"--expected-daemon-cdhash", strings.Repeat("b", 40),
	}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "1 daemon attach(es) remain") ||
		!strings.Contains(got, "before updating the PortableFS service") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestLifecycleHoldInstallExclusiveExpectedDaemonIdentityIsAllOrNone(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = strings.NewReader("")
	if rc := e.run([]string{
		"lifecycle", "hold-install-exclusive", "--json",
		"--expected-daemon-sha256", strings.Repeat("a", 64),
	}); rc != 2 {
		t.Fatalf("rc = %d, want usage refusal", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "requires version, SHA-256, path, and CDHash together") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestExpectedDaemonIdentityIsExactReleaseAndPath(t *testing.T) {
	for _, test := range []struct {
		path, cdhash       string
		lastPresent, valid bool
	}{
		{"/authenticated/portablefsd", strings.Repeat("b", 40), true, true},
		{"relative", strings.Repeat("b", 40), true, false},
		{"/a/../portablefsd", strings.Repeat("b", 40), true, false},
		{"/authenticated/portablefsd", strings.Repeat("B", 40), true, false},
		{"/authenticated/portablefsd", "", true, false},
		{"/authenticated/portablefsd", strings.Repeat("b", 40), false, false},
	} {
		release, err := parseExpectedDaemonIdentity("2.0.0", strings.Repeat("a", 64), test.path, test.cdhash, true, true, true, test.lastPresent)
		if (err == nil) != test.valid {
			t.Fatalf("%+v: release=%+v error=%v", test, release, err)
		}
	}
}

func TestLifecycleHoldInstallExclusiveRejectsDurableDaemonAttach(t *testing.T) {
	e, _, stderr := testEnv(t)
	e.stdin = strings.NewReader("")
	mountStateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	daemonStateDir := filepath.Join(filepath.Dir(mountStateDir), "portablefsd")
	if err := privatepath.EnsureDir(daemonStateDir); err != nil {
		t.Fatal(err)
	}
	attachRef, err := mountid.NewAttachRef()
	if err != nil {
		t.Fatal(err)
	}
	mountPath := filepath.Join(t.TempDir(), "mounted")
	registry := fmt.Sprintf(
		"{\"version\":3,\"attaches\":[{\"ref\":%q,\"volumeId\":\"volume\",\"mountPath\":%q,\"authorityUrl\":\"127.0.0.1:1\",\"dataPlaneTransport\":\"plaintext\",\"identityEpoch\":1}]}\n",
		attachRef,
		mountPath,
	)
	if err := privatepath.WriteFileAtomic(filepath.Join(daemonStateDir, daemonctl.PersistedAttachesFilename), []byte(registry)); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"lifecycle", "hold-install-exclusive", "--json"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "registry entry attaches.json exists") ||
		!strings.Contains(got, "before updating the PortableFS service") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestLifecycleIdentityJSON(t *testing.T) {
	e, stdout, _ := testEnv(t)
	if rc := e.run([]string{"lifecycle", "identity", "--json"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := stdout.String(); !strings.Contains(got, `"schemaVersion": 2`) ||
		!strings.Contains(got, `"fsType": "pfs"`) ||
		!strings.Contains(got, `"resourceScheme": "dev.portablefs.oss"`) ||
		!strings.Contains(got, `"appGroup": "B47U2LLKHW.pfsoss"`) {
		t.Fatalf("identity = %s", got)
	}
}

func TestInstallerGateRejectsStartingIntent(t *testing.T) {
	stateDir := t.TempDir()
	mountDir := filepath.Join(stateDir, "mounts")
	mountPath := filepath.Join(t.TempDir(), "mount")
	operation, err := acquireMountOperation(mountDir, mountPath, "volume", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.close(false)
	err = rejectDurableMountAnchors(stateDir)
	if err == nil || !strings.Contains(err.Error(), "phase starting") ||
		!strings.Contains(err.Error(), "portablefs umount") {
		t.Fatalf("installer gate error = %v", err)
	}
}

func TestInstallerGateRejectsPersistedAttachWithoutDaemon(t *testing.T) {
	stateDir := t.TempDir()
	attachRef, err := mountid.NewAttachRef()
	if err != nil {
		t.Fatal(err)
	}
	daemonStateDir := filepath.Join(stateDir, "portablefsd")
	if err := privatepath.EnsureDir(daemonStateDir); err != nil {
		t.Fatal(err)
	}
	mountPath := filepath.Join(t.TempDir(), "mount")
	registry := fmt.Sprintf(
		"{\"version\":3,\"attaches\":[{\"ref\":%q,\"volumeId\":\"volume\",\"mountPath\":%q,\"authorityUrl\":\"127.0.0.1:1\",\"dataPlaneTransport\":\"plaintext\",\"identityEpoch\":1}]}\n",
		attachRef, mountPath,
	)
	if err := privatepath.WriteFileAtomic(filepath.Join(daemonStateDir, daemonctl.PersistedAttachesFilename), []byte(registry)); err != nil {
		t.Fatal(err)
	}
	err = rejectDurableMountAnchors(stateDir)
	if err == nil || !strings.Contains(err.Error(), "registry entry attaches.json exists") ||
		!strings.Contains(err.Error(), "portablefs umount") {
		t.Fatalf("installer gate error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(daemonStateDir, daemonctl.PersistedAttachesFilename)); err != nil {
		t.Fatal(err)
	}
}

func TestRunningOutgoingInventoryNeverDecodesPrivateRegistry(t *testing.T) {
	for _, grammar := range []string{`{"outgoing_format":900,"different_records":[]}`, `{"version":3,"attaches":[]}`, "not-json"} {
		for _, count := range []int{0, 1} {
			e, _, _ := testEnv(t)
			mountDir, err := e.mountStateDir()
			if err != nil {
				t.Fatal(err)
			}
			daemonDir := filepath.Join(filepath.Dir(mountDir), "portablefsd")
			if err := privatepath.WriteFileAtomic(filepath.Join(daemonDir, daemonctl.PersistedAttachesFilename), []byte(grammar)); err != nil {
				t.Fatal(err)
			}
			expected := testDaemonRelease("/authenticated/portablefsd", "outgoing", strings.Repeat("a", 64))
			calls := 0
			e.daemonLifecycleInventoryFn = func(got *daemonRelease) (int, error) {
				calls++
				if got == nil || *got != expected {
					t.Error("outgoing tuple changed")
				}
				return count, nil
			}
			inventory, err := e.strictAccountInventory("replacement", &expected)
			if (err == nil) != (count == 0) || calls != 1 || inventory.LiveAttaches != count || inventory.attachCount() != count {
				t.Fatalf("grammar=%q count=%d inventory=%+v calls=%d error=%v", grammar, count, inventory, calls, err)
			}
		}
	}
}

func TestOutgoingLifecycleFailureCannotSelectAbsentRegistryShortcut(t *testing.T) {
	e, _, _ := testEnv(t)
	expected := testDaemonRelease("/authenticated/portablefsd", "outgoing", strings.Repeat("a", 64))
	sentinel := fmt.Errorf("outgoing authentication or inventory unavailable")
	e.daemonLifecycleInventoryFn = func(*daemonRelease) (int, error) { return 0, sentinel }
	if _, err := e.strictAccountInventory("replacement", &expected); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestInstallerRegistryPreflightRefusesUnsafeParentsAndExistingKinds(t *testing.T) {
	for _, kind := range []string{"empty", "unknown", "malformed", "symlink", "directory", "fifo", "inaccessible parent", "symlink parent"} {
		t.Run(kind, func(t *testing.T) {
			stateDir := t.TempDir()
			daemonDir := filepath.Join(stateDir, "portablefsd")
			if err := privatepath.EnsureDir(daemonDir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(daemonDir, daemonctl.PersistedAttachesFilename)
			var err error
			switch kind {
			case "empty":
				err = os.WriteFile(path, nil, 0600)
			case "unknown":
				err = os.WriteFile(path, []byte(`{"version":99,"entries":[]}`), 0600)
			case "malformed":
				err = os.WriteFile(path, []byte("bad"), 0600)
			case "symlink":
				err = os.Symlink(filepath.Join(daemonDir, "absent"), path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "inaccessible parent":
				err = os.Chmod(daemonDir, 0)
				t.Cleanup(func() { _ = os.Chmod(daemonDir, 0700) })
			case "symlink parent":
				err = os.Rename(daemonDir, daemonDir+"-real")
				if err == nil {
					err = os.Symlink(daemonDir+"-real", daemonDir)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := rejectDurableMountAnchors(stateDir); err == nil {
				t.Fatal("existing or unsafe registry boundary admitted")
			}
		})
	}
}
