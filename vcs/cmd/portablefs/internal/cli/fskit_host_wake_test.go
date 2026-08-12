package cli

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/apphost"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func serveCompatibleIdentityControl(
	t *testing.T,
	path, version, executableSHA256 string,
) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/v1/identity", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(daemonctl.Identity{
			SchemaVersion:    daemonctl.IdentitySchemaVersion,
			ControlProtocol:  daemonctl.ControlProtocolVersion,
			DaemonVersion:    version,
			ExecutableSHA256: executableSHA256,
			PFSLocalMajor:    pfslocal.ProtocolMajor,
			PFSLocalMinor:    pfslocal.ProtocolMinor,
		})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.Remove(path)
	})
}

func TestEnsurePortablefsdWakesExactHostWithoutSpawningDaemon(t *testing.T) {
	root := shortSocketDir(t)
	stateRoot := filepath.Join(root, "state")
	control := filepath.Join(stateRoot, "portablefsd", "control.sock")
	peer := filepath.Join(root, "portablefsd")
	writeExecutablePeer(t, peer, "exact daemon peer")
	digest, err := daemonctl.FileSHA256(peer)
	if err != nil {
		t.Fatal(err)
	}

	originalLaunch := launchExactPortableFSHost
	t.Cleanup(func() { launchExactPortableFSHost = originalLaunch })
	var launches atomic.Int32
	launchExactPortableFSHost = func() error {
		launches.Add(1)
		serveCompatibleIdentityControl(t, control, "test-version", digest)
		return nil
	}

	ctl, err := ensurePortablefsd(fskitConfig{
		controlSock:       control,
		daemonPathForTest: peer,
	}, stateRoot, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	if ctl.socketPath != control || launches.Load() != 1 {
		t.Fatalf("control=%q launches=%d", ctl.socketPath, launches.Load())
	}
}

func TestEnsurePortablefsdResolvesAmbiguousHostLaunchOnlyWithExactDaemonProof(t *testing.T) {
	root := shortSocketDir(t)
	stateRoot := filepath.Join(root, "state")
	control := filepath.Join(stateRoot, "portablefsd", "control.sock")
	peer := filepath.Join(root, "portablefsd")
	writeExecutablePeer(t, peer, "exact daemon peer")
	digest, err := daemonctl.FileSHA256(peer)
	if err != nil {
		t.Fatal(err)
	}

	originalLaunch := launchExactPortableFSHost
	t.Cleanup(func() { launchExactPortableFSHost = originalLaunch })
	launchExactPortableFSHost = func() error {
		serveCompatibleIdentityControl(t, control, "test-version", digest)
		return apphost.ErrLaunchCompletionAmbiguous
	}
	ctl, err := ensurePortablefsd(fskitConfig{
		controlSock:       control,
		daemonPathForTest: peer,
	}, stateRoot, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	if ctl.socketPath != control {
		t.Fatalf("control = %q, want %q", ctl.socketPath, control)
	}
}

func TestEnsurePortablefsdRefusesRejectedHostLaunch(t *testing.T) {
	root := shortSocketDir(t)
	stateRoot := filepath.Join(root, "state")
	control := filepath.Join(stateRoot, "portablefsd", "control.sock")
	peer := filepath.Join(root, "portablefsd")
	writeExecutablePeer(t, peer, "exact daemon peer")

	originalLaunch := launchExactPortableFSHost
	t.Cleanup(func() { launchExactPortableFSHost = originalLaunch })
	rejected := errors.New("request rejected")
	launchExactPortableFSHost = func() error { return rejected }
	_, err := ensurePortablefsd(fskitConfig{
		controlSock:       control,
		daemonPathForTest: peer,
	}, stateRoot, "test-version")
	if !errors.Is(err, rejected) {
		t.Fatalf("launch error = %v", err)
	}
}

func TestEnsurePortablefsdAdoptsCompatibleAgentWithoutHostWake(t *testing.T) {
	root := shortSocketDir(t)
	stateRoot := filepath.Join(root, "state")
	control := filepath.Join(stateRoot, "portablefsd", "control.sock")
	peer := filepath.Join(root, "portablefsd")
	writeExecutablePeer(t, peer, "exact daemon peer")
	digest, err := daemonctl.FileSHA256(peer)
	if err != nil {
		t.Fatal(err)
	}
	serveCompatibleIdentityControl(t, control, "test-version", digest)

	originalLaunch := launchExactPortableFSHost
	t.Cleanup(func() { launchExactPortableFSHost = originalLaunch })
	launchExactPortableFSHost = func() error {
		t.Fatal("healthy compatible agent triggered host wake")
		return nil
	}
	if _, err := ensurePortablefsd(fskitConfig{
		controlSock:       control,
		daemonPathForTest: peer,
	}, stateRoot, "test-version"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsurePortablefsdRefusesSplitControlRootBeforeWake(t *testing.T) {
	originalLaunch := launchExactPortableFSHost
	t.Cleanup(func() { launchExactPortableFSHost = originalLaunch })
	launchExactPortableFSHost = func() error {
		t.Fatal("split control root triggered host wake")
		return nil
	}
	_, err := ensurePortablefsd(fskitConfig{
		controlSock: filepath.Join(t.TempDir(), "control.sock"),
	}, t.TempDir(), "test-version")
	if err == nil {
		t.Fatal("split control root was accepted")
	}
}

func TestControlIdentityRequiresExactPFSLocalMinor(t *testing.T) {
	root := shortSocketDir(t)
	control := filepath.Join(root, "control.sock")
	digest := strings.Repeat("a", 64)
	serveCompatibleIdentityControl(t, control, "test-version", digest)
	ctl := newFsdControl(control)
	err := ctl.requireExactIdentityWithin(daemonctl.Identity{
		SchemaVersion:    daemonctl.IdentitySchemaVersion,
		ControlProtocol:  daemonctl.ControlProtocolVersion,
		DaemonVersion:    "test-version",
		ExecutableSHA256: digest,
		PFSLocalMajor:    pfslocal.ProtocolMajor,
		PFSLocalMinor:    pfslocal.ProtocolMinor - 1,
	}, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "pfslocal") {
		t.Fatalf("minor mismatch error = %v", err)
	}
}
