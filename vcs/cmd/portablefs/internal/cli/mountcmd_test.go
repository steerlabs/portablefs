package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func TestStartedChildIdentityFailurePreservesAdvancedIntent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	mountPath := filepath.Join(t.TempDir(), "mount")
	operation, err := acquireMountOperation(stateDir, mountPath, "volume", "main", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.close(false)
	identity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	operation.mountInstanceID = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
	operation.mountMechanism = "direct"
	if err := operation.writeIntent("mounting", os.Getpid(), identity); err != nil {
		t.Fatal(err)
	}
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	err = terminateUnidentifiedStartedMount(child, operation, fmt.Errorf("injected identity read failure"))
	if err == nil || !strings.Contains(err.Error(), "explicit exact reconciliation") {
		t.Fatalf("termination error = %v", err)
	}
	intent, err := readMountIntent(operation.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if intent == nil || intent.Phase != "mounting" || intent.MountInstanceID != operation.mountInstanceID {
		t.Fatalf("advanced intent was removed or changed: %+v", intent)
	}
}

func TestIsMountpoint(t *testing.T) {
	dir := t.TempDir()
	if isMountpoint(dir) {
		t.Fatalf("ordinary directory %s must not be a mountpoint", dir)
	}
	if isMountpoint(filepath.Join(dir, "does-not-exist")) {
		t.Fatal("nonexistent path must not be a mountpoint")
	}
	if runtime.GOOS == "darwin" && !isMountpoint("/dev") {
		t.Fatal("/dev (devfs) must be a mountpoint on macOS")
	}
}

// umountTestEnv is testEnv plus an isolated mount state dir, the setup every
// umount test needs.
func umountTestEnv(t *testing.T) (e *cmdEnv, stdout, stderr *bytes.Buffer, stateDir string) {
	t.Helper()
	e, stdout, stderr = testEnv(t)
	stateHome := t.TempDir()
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return baseGetenv(k)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	return e, stdout, stderr, stateDir
}

type fsKitReconcileCalls struct {
	unmount     atomic.Int32
	credential  atomic.Int32
	pendingOnly atomic.Bool
	token       atomic.Value
}

func serveFSKitReconcileControl(
	t *testing.T,
	st mountState,
	attachPresent bool,
	identityMismatch bool,
	unmountStatus int,
) (*fsdControl, *fsKitReconcileCalls) {
	t.Helper()
	dir := shortSocketDir(t)
	socketPath := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	calls := &fsKitReconcileCalls{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attaches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !attachPresent {
			_, _ = w.Write([]byte(`{"attaches":[]}`))
			return
		}
		volumeID := st.VolumeID
		if identityMismatch {
			volumeID = "vol_other"
		}
		_, _ = fmt.Fprintf(
			w,
			`{"attaches":[{"attachRef":%q,"mountPath":%q,"volumeId":%q,"branch":%q,"state":"degraded"}]}`,
			st.AttachRef,
			st.MountPath,
			volumeID,
			st.Branch,
		)
	})
	mux.HandleFunc("/v1/attaches/"+st.AttachRef+"/credential", func(w http.ResponseWriter, r *http.Request) {
		calls.credential.Add(1)
		var request struct {
			AuthToken     string `json:"authToken"`
			OnlyIfPending bool   `json:"onlyIfPending"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		calls.pendingOnly.Store(request.OnlyIfPending)
		calls.token.Store(request.AuthToken)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/attaches/"+st.AttachRef+"/unmount", func(w http.ResponseWriter, r *http.Request) {
		calls.unmount.Add(1)
		if unmountStatus >= 200 && unmountStatus < 300 {
			if r.URL.Query().Get("force") == "1" {
				_, _ = w.Write([]byte(`{"recoveryJob":""}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(unmountStatus)
		_, _ = w.Write([]byte(`{"error":"normal detach requires an active credential"}`))
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return newFsdControl(socketPath), calls
}

func staleFSKitMountState(t *testing.T, mountPath string) mountState {
	t.Helper()
	st := validFSKitMountState(t, mountPath)
	st.PID = 4_194_000
	st.ProcessStartIdentity = "dead-process"
	return st
}

func TestUmountStaleFSKitStartsExactDaemonAndForceReconciles(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := staleFSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	ctl, calls := serveFSKitReconcileControl(t, st, true, false, http.StatusOK)
	var ensures atomic.Int32
	e.ensurePortablefsdFn = func(_ fskitConfig, stateRoot, version string) (*fsdControl, error) {
		ensures.Add(1)
		if stateRoot != filepath.Dir(stateDir) || version != e.version {
			t.Fatalf("ensure args = (%q, %q), want (%q, %q)", stateRoot, version, filepath.Dir(stateDir), e.version)
		}
		return ctl, nil
	}

	if rc := e.run([]string{"umount", "--force", mountPath}); rc != 0 {
		t.Fatalf("forced stale FSKit reconciliation rc=%d stderr=%q", rc, stderr.String())
	}
	if ensures.Load() != 1 || calls.unmount.Load() != 1 {
		t.Fatalf("ensure calls=%d force calls=%d, want 1 each", ensures.Load(), calls.unmount.Load())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current != nil {
		t.Fatalf("reconciled state=%+v err=%v", current, err)
	}
}

func TestUmountStaleFSKitNormalRefusalPreservesEvidenceAndGuidesForce(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := staleFSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	ctl, calls := serveFSKitReconcileControl(t, st, true, false, http.StatusConflict)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
		return ctl, nil
	}

	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatalf("credential-pending normal reconciliation succeeded, stderr=%q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--force") || calls.unmount.Load() != 1 {
		t.Fatalf("normal refusal lacks deterministic force guidance: calls=%d stderr=%q", calls.unmount.Load(), stderr.String())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("normal refusal lost state: state=%+v err=%v", current, err)
	}
	if calls.credential.Load() != 0 {
		t.Fatalf("direct-address mount unexpectedly restored %d persisted credentials", calls.credential.Load())
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Lstat(intentPath); err != nil {
		t.Fatalf("normal refusal lost intent: %v", err)
	}
}

func TestUnmountRecordedAttachReactivatesManagedLeaseBeforeDrain(t *testing.T) {
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := staleFSKitMountState(t, mountPath)
	st.AccessLease = &leaseState{
		AccessLeaseID: "pfal_restart",
		AccessToken:   "lease_restart_token",
		ExpiresAtMs:   time.Now().Add(time.Hour).UnixMilli(),
		ControlSeq:    "7",
	}
	ctl, calls := serveFSKitReconcileControl(t, st, true, false, http.StatusNoContent)

	if err := ctl.unmountRecordedAttach(&st); err != nil {
		t.Fatalf("managed restart detach: %v", err)
	}
	if calls.credential.Load() != 1 || calls.unmount.Load() != 1 {
		t.Fatalf("credential calls=%d unmount calls=%d, want one ordered lifecycle call each",
			calls.credential.Load(), calls.unmount.Load())
	}
	if !calls.pendingOnly.Load() {
		t.Fatal("managed restart used a non-atomic credential rotation instead of pending-only activation")
	}
	if token, _ := calls.token.Load().(string); token != st.AccessLease.AccessToken {
		t.Fatalf("restored token=%q, want exact persisted access-lease credential", token)
	}
}

func TestUmountStaleFSKitPreservesEvidenceOnMismatchOrParkFailure(t *testing.T) {
	for _, test := range []struct {
		name             string
		identityMismatch bool
		status           int
		want             string
		wantCalls        int32
	}{
		{
			name:             "attach identity mismatch",
			identityMismatch: true,
			status:           http.StatusOK,
			want:             "identity mismatch",
		},
		{
			name:      "durable park refused",
			status:    http.StatusConflict,
			want:      "normal detach requires an active credential",
			wantCalls: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, _, stderr, stateDir := umountTestEnv(t)
			mountPath, err := canonicalMountPath(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			st := staleFSKitMountState(t, mountPath)
			if err := writeMountState(stateDir, st); err != nil {
				t.Fatal(err)
			}
			ctl, calls := serveFSKitReconcileControl(t, st, true, test.identityMismatch, test.status)
			e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
				return ctl, nil
			}

			if rc := e.run([]string{"umount", "--force", mountPath}); rc == 0 {
				t.Fatalf("unsafe reconciliation succeeded, stderr=%q", stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr=%q, want %q", stderr.String(), test.want)
			}
			if calls.unmount.Load() != test.wantCalls {
				t.Fatalf("detach calls=%d, want %d", calls.unmount.Load(), test.wantCalls)
			}
			if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
				t.Fatalf("failed reconciliation lost state: state=%+v err=%v", current, err)
			}
			_, intentPath := mountOperationPaths(stateDir, mountPath)
			if _, err := os.Lstat(intentPath); err != nil {
				t.Fatalf("failed reconciliation lost intent: %v", err)
			}
		})
	}
}

func TestUmountStaleFSKitConvergesAfterDaemonAlreadyDetached(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := staleFSKitMountState(t, mountPath)
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	ctl, calls := serveFSKitReconcileControl(t, st, false, false, http.StatusOK)
	e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) {
		return ctl, nil
	}

	if rc := e.run([]string{"umount", "--force", mountPath}); rc != 0 {
		t.Fatalf("idempotent stale reconciliation rc=%d stderr=%q", rc, stderr.String())
	}
	if calls.unmount.Load() != 0 {
		t.Fatalf("absent attach was mutated %d times", calls.unmount.Load())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current != nil {
		t.Fatalf("converged state=%+v err=%v", current, err)
	}
}

func TestMountOwnershipTreatsDeadSocketAsUnavailable(t *testing.T) {
	e, _, _, stateDir := umountTestEnv(t)
	e.kernelInventoryFn = func() ([]string, error) { return nil, nil }
	socketDir := shortSocketDir(t)
	frontendSock := filepath.Join(socketDir, "pfs.sock")
	controlSock := filepath.Join(socketDir, "control.sock")
	leaveCLIStaleUnixSocket(t, controlSock)
	baseGetenv := e.getenv
	e.getenv = func(key string) string {
		switch key {
		case fskitSocketEnv:
			return frontendSock
		case fskitControlEnv:
			return controlSock
		default:
			return baseGetenv(key)
		}
	}
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := e.validateMountOwnership(stateDir, "vol_fresh", "main", mountPath); err != nil {
		t.Fatalf("dead socket pathname was treated as a live daemon: %v", err)
	}
	if info, err := os.Lstat(controlSock); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("ownership check mutated stale socket: mode=%v err=%v", info, err)
	}
}

func writeMountOwnershipV3Attach(t *testing.T, stateDir, mountPath, volumeID string) (string, string) {
	t.Helper()
	attachRef := "att_AAAAAAAAAAAAAAAAAAAAAA"
	daemonStateDir := filepath.Join(filepath.Dir(stateDir), "portablefsd")
	if err := privatepath.EnsureDir(daemonStateDir); err != nil {
		t.Fatal(err)
	}
	registry, err := json.Marshal(map[string]any{
		"version": 2,
		"attaches": []any{map[string]any{
			"ref":                 attachRef,
			"volumeId":            volumeID,
			"branch":              "",
			"mountPath":           mountPath,
			"authorityUrl":        "127.0.0.1:2050",
			"dataPlaneTransport":  dataPlaneTransportTLSSystemPKI,
			"dataPlaneServerName": "authority.example",
			"options":             map[string]any{},
			"identityEpoch":       1,
			"v3": map[string]any{
				"cachedNameCapacity": uint64(1 << 16),
				"repairBudgetMillis": uint64(15_000),
				"cachePolicy":        portablefsd.V3CachePolicyMacOS26,
				"routesRevision":     emptyRoutesRevision(),
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(daemonStateDir, "attaches.json")
	if err := privatepath.WriteFileAtomic(registryPath, append(registry, '\n')); err != nil {
		t.Fatal(err)
	}
	return attachRef, registryPath
}

// A watchdog may remove an unresponsive FSKit kernel mount without retiring
// the daemon-owned attach. The durable attach remains the recovery authority
// for umount; it is not permission for mount to spend another capability.
func TestMountOwnershipRejectsSamePathDurableAttach(t *testing.T) {
	e, _, _, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	attachRef, registryPath := writeMountOwnershipV3Attach(t, stateDir, mountPath, "vol_old")
	before, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}

	err = e.validateMountOwnership(stateDir, "vol_old", "", mountPath)
	if err == nil {
		t.Fatal("same-path durable daemon attach was accepted for remount")
	}
	for _, want := range []string{attachRef, "durable daemon attach", "portablefs umount " + mountPath} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("ownership refusal %q does not contain %q", err, want)
		}
	}
	after, readErr := os.ReadFile(registryPath)
	if readErr != nil || !bytes.Equal(after, before) {
		t.Fatalf("mount preflight changed durable recovery evidence: err=%v before=%q after=%q", readErr, before, after)
	}
}

func TestMountCommandRejectsSamePathAttachBeforeCreatingIntent(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	attachRef, _ := writeMountOwnershipV3Attach(t, stateDir, mountPath, "vol_old")
	o := v3MountOpts(t)
	args := []string{
		"mount", "vol_new", mountPath,
		"--addr", o.addr,
		"--mount-token", o.mountToken,
		"--data-plane-transport", o.dataPlaneTransport,
		"--data-plane-server-name", o.dataPlaneServerName,
		"--client-cert", o.clientCertPath,
		"--client-key", o.clientKeyPath,
		// Ownership preflight precedes strategy resolution. Keeping this invalid
		// makes a regression fail without ever starting a mount child.
		"--strategy", "invalid",
	}
	if rc := e.run(args); rc == 0 {
		t.Fatal("mount accepted a path still owned by a daemon attach")
	}
	for _, want := range []string{attachRef, "portablefs umount " + mountPath} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("mount refusal %q does not contain %q", stderr.String(), want)
		}
	}
	intents, err := listMountIntents(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 0 {
		t.Fatalf("same-path attach preflight created mount intents: %+v", intents)
	}
}

// TestUmountOrphanedMountWithoutAttachRefFailsClosed is the production incident:
// the platform mount was torn down externally (forced diskutil unmount,
// extension crash) while the recorded daemon pid stayed alive. Without an
// attachRef PortableFS cannot prove the drain and must preserve both daemon
// and state.
func TestUmountOrphanedMountWithoutAttachRefFailsClosed(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir()) // ordinary directory: nothing mounted on it
	if err != nil {
		t.Fatal(err)
	}

	// A fake mount daemon that is genuinely alive. Reap it in the background
	// so pidAlive flips false the moment it dies, like a real daemon that
	// init/launchd reaps after reparenting.
	daemon := exec.Command("sleep", "60")
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	daemonDone := make(chan struct{})
	go func() { _ = daemon.Wait(); close(daemonDone) }()
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		<-daemonDone
	})

	daemonIdentity, err := processStartIdentity(daemon.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	invalidState := mountState{
		MountPath: mountPath, VolumeID: "vol_orphan", Branch: "main",
		PID: daemon.Process.Pid, ProcessStartIdentity: daemonIdentity, Strategy: "fskit",
	}
	writeRawMountState(t, stateDir, invalidState)
	statePath := mountStatePath(stateDir, mountPath)
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "incomplete mount instance identity") ||
		!strings.Contains(stderr.String(), "nothing was unmounted") {
		t.Fatalf("fail-closed explanation missing: %q", stderr.String())
	}
	select {
	case <-daemonDone:
		t.Fatal("fail-closed unmount stopped the daemon")
	case <-time.After(100 * time.Millisecond):
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("invalid mount-state evidence changed: err=%v before=%q after=%q", err, before, after)
	}
}

// TestUmountDeadDaemonWithoutDrainProofFailsClosed pins stale-state handling.
func TestUmountDeadDaemonWithoutDrainProofFailsClosed(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	invalidState := mountState{
		MountPath: mountPath, VolumeID: "vol_stale", Branch: "main",
		PID: 4194000, ProcessStartIdentity: "dead-process", Strategy: "fuse",
	}
	writeRawMountState(t, stateDir, invalidState)
	statePath := mountStatePath(stateDir, mountPath)
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath, "--json"}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "incomplete mount instance identity") ||
		!strings.Contains(stderr.String(), "nothing was unmounted") {
		t.Fatalf("fail-closed detail missing: %q", stderr.String())
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("invalid mount-state evidence changed: err=%v before=%q after=%q", err, before, after)
	}
}

// TestUmountUntrackedFailsClosed: without recorded identity and durability
// state PortableFS never substitutes a plain platform unmount.
func TestUmountUntrackedFailsClosed(t *testing.T) {
	e, _, stderr, _ := umountTestEnv(t)
	mountPath := t.TempDir()
	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing an unverified plain unmount") {
		t.Fatalf("fail-closed detail missing: %q", stderr.String())
	}
}
