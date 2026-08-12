package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	e.daemonAttachStatusesFn = func(expected *daemonctl.Identity) (map[string]cliAttachStatus, error) {
		if expected == nil ||
			expected.DaemonVersion != "0.2.2" ||
			expected.ExecutableSHA256 != expectedSHA256 ||
			expected.PFSLocalMajor != 1 ||
			expected.PFSLocalMinor != 13 {
			t.Fatalf("expected old daemon identity = %+v", expected)
		}
		return map[string]cliAttachStatus{
			"att_live": {AttachRef: "att_live"},
		}, nil
	}
	if rc := e.run([]string{
		"lifecycle", "hold-install-exclusive", "--json",
		"--expected-daemon-version", "0.2.2",
		"--expected-daemon-sha256", expectedSHA256,
		"--expected-pfslocal-major", "1",
		"--expected-pfslocal-minor", "13",
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
	if got := stderr.String(); !strings.Contains(got, "requires version, SHA-256, pfslocal major, and pfslocal minor together") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestExpectedDaemonIdentityAllowsExplicitMinorZero(t *testing.T) {
	identity, err := parseExpectedDaemonIdentity(
		"2.0.0",
		strings.Repeat("a", 64),
		2,
		0,
		true,
		true,
		true,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity == nil || identity.PFSLocalMajor != 2 || identity.PFSLocalMinor != 0 {
		t.Fatalf("parsed identity = %+v", identity)
	}
	if _, err := parseExpectedDaemonIdentity(
		"2.0.0",
		strings.Repeat("a", 64),
		2,
		0,
		true,
		true,
		true,
		false,
	); err == nil {
		t.Fatal("omitted minor flag was accepted as explicit minor zero")
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
		"{\"version\":2,\"attaches\":[{\"ref\":%q,\"volumeId\":\"volume\",\"branch\":\"main\",\"mountPath\":%q,\"authorityUrl\":\"127.0.0.1:1\",\"dataPlaneTransport\":\"plaintext\",\"options\":{},\"identityEpoch\":1}]}\n",
		attachRef,
		mountPath,
	)
	if err := privatepath.WriteFileAtomic(filepath.Join(daemonStateDir, "attaches.json"), []byte(registry)); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"lifecycle", "hold-install-exclusive", "--json"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := stderr.String(); !strings.Contains(got, "1 durable daemon attach(es) remain") ||
		!strings.Contains(got, attachRef) ||
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
	operation, err := acquireMountOperation(mountDir, mountPath, "volume", "main", "fuse")
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
		"{\"version\":2,\"attaches\":[{\"ref\":%q,\"volumeId\":\"volume\",\"branch\":\"main\",\"mountPath\":%q,\"authorityUrl\":\"127.0.0.1:1\",\"dataPlaneTransport\":\"plaintext\",\"options\":{},\"identityEpoch\":1}]}\n",
		attachRef, mountPath,
	)
	if err := privatepath.WriteFileAtomic(filepath.Join(daemonStateDir, "attaches.json"), []byte(registry)); err != nil {
		t.Fatal(err)
	}
	err = rejectDurableMountAnchors(stateDir)
	if err == nil || !strings.Contains(err.Error(), attachRef) ||
		!strings.Contains(err.Error(), "portablefs umount") {
		t.Fatalf("installer gate error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(daemonStateDir, "attaches.json")); err != nil {
		t.Fatal(err)
	}
}
