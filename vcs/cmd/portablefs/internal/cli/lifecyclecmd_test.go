package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
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
	if !strings.Contains(stderr.String(), "expected `hold-shared`, `hold-account-exclusive`, or `identity`") {
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
