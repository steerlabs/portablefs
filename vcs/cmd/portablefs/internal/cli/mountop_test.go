package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedMountIntent(t *testing.T, stateDir, mountPath, phase, strategy, attachRef string) {
	t.Helper()
	op, err := acquireMountOperation(stateDir, mountPath, "vol_intent", strategy)
	if err != nil {
		t.Fatal(err)
	}
	op.strategy = strategy
	op.attachRef = attachRef
	if phase != "starting" {
		op.mountInstanceID = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
		op.mountTarget = mountTargetIdentity{device: 1, inode: 2}
		op.startedAtMs = 1
		op.authorityURL = "127.0.0.1:1"
		op.transportMode = dataPlaneTransportPlaintext
	}
	if strategy == "fuse" {
		op.mountMechanism = "direct"
		op.engine = mountEngineFuseV3
	} else if strategy == "fskit" {
		op.mountMechanism = "fskit-system"
		op.engine = mountEngineDaemonV3
		op.fsType = defaultFskitType
	}
	if err := op.writeIntent(phase, 0, ""); err != nil {
		_ = op.close(false)
		t.Fatal(err)
	}
	if err := op.close(false); err != nil {
		t.Fatal(err)
	}
}

func TestDecidePostUnmount(t *testing.T) {
	tests := []struct {
		name                    string
		mounted                 bool
		outcome                 detachOutcome
		wantPlatformUnmount     bool
		wantStaleReconciliation bool
		wantError               string
		rejectError             string
	}{
		{
			name:                "ordinary live mount needs platform detach",
			mounted:             true,
			wantPlatformUnmount: true,
		},
		{
			name:                    "unacknowledged absent mount is stale",
			wantStaleReconciliation: true,
		},
		{
			name:    "acknowledged FSKit absence is normal completion",
			outcome: detachFSKitDaemon,
		},
		{
			name:    "cooperative FUSE absence is normal completion",
			outcome: detachFUSECooperative,
		},
		{
			name:        "acknowledged FSKit mount remaining is FSKit failure",
			mounted:     true,
			outcome:     detachFSKitDaemon,
			wantError:   "FSKit unmount acknowledged completion",
			rejectError: "FUSE",
		},
		{
			name:        "cooperative FUSE mount remaining is a completion failure",
			mounted:     true,
			outcome:     detachFUSECooperative,
			wantError:   "cooperative FUSE unmount completed",
			rejectError: "FSKit",
		},
		{
			name:      "unknown completion outcome fails closed",
			outcome:   detachOutcome(255),
			wantError: "unknown detach outcome",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			platformUnmount, reconcileStale, err := decidePostUnmount(
				tc.mounted,
				tc.outcome,
			)
			if platformUnmount != tc.wantPlatformUnmount ||
				reconcileStale != tc.wantStaleReconciliation {
				t.Fatalf(
					"decision=(platform=%v stale=%v), want (platform=%v stale=%v)",
					platformUnmount,
					reconcileStale,
					tc.wantPlatformUnmount,
					tc.wantStaleReconciliation,
				)
			}
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error=%v, want substring %q", err, tc.wantError)
			}
			if tc.rejectError != "" && strings.Contains(err.Error(), tc.rejectError) {
				t.Fatalf("error=%q contains rejected substring %q", err, tc.rejectError)
			}
		})
	}
}

func TestReconcileFSKitIntentStartsExactDaemon(t *testing.T) {
	e, _, _, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedMountIntent(t, stateDir, mountPath, "attached", "fskit", "att_AAAAAAAAAAAAAAAAAAAAAA")
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	intent, err := readMountIntent(intentPath, mountPath)
	if err != nil || intent == nil {
		t.Fatalf("read intent: intent=%+v err=%v", intent, err)
	}
	st := mountState{
		MountPath: intent.MountPath,
		VolumeID:  intent.VolumeID,
		AttachRef: intent.AttachRef,
	}
	ctl, calls := serveFSKitReconcileControl(t, st, true, false, 200)
	ensures := 0
	e.ensurePortablefsdFn = func(_ fskitConfig, stateRoot, _ string) (*fsdControl, error) {
		ensures++
		if stateRoot != filepath.Dir(stateDir) {
			t.Fatalf("state root=%q want %q", stateRoot, filepath.Dir(stateDir))
		}
		return ctl, nil
	}

	if err := e.reconcileMountIntent(intent, true); err != nil {
		t.Fatalf("reconcile FSKit intent: %v", err)
	}
	if ensures != 1 || calls.unmount.Load() != 1 || calls.forceUnmount.Load() != 1 {
		t.Fatalf("ensure calls=%d force calls=%d, want 1 each", ensures, calls.unmount.Load())
	}
}

func TestNewMountRefusesPriorNonterminalIntent(t *testing.T) {
	for _, phase := range []string{"starting", "attached", "kernel-mounted"} {
		t.Run(phase, func(t *testing.T) {
			_, _, _, stateDir := umountTestEnv(t)
			mountPath, err := canonicalMountPath(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			seedMountIntent(t, stateDir, mountPath, phase, "fskit", "att_AAAAAAAAAAAAAAAAAAAAAA")
			if op, err := acquireMountOperation(stateDir, mountPath, "vol_new", "fskit"); err == nil {
				_ = op.close(false)
				t.Fatal("new mount overwrote prior nonterminal intent")
			} else if !strings.Contains(err.Error(), "portablefs umount") {
				t.Fatalf("refusal lacks reconciliation guidance: %v", err)
			}
			_, intentPath := mountOperationPaths(stateDir, mountPath)
			if _, err := os.Lstat(intentPath); err != nil {
				t.Fatalf("prior intent was removed: %v", err)
			}
		})
	}
}

func TestUmountExplicitlyReconcilesStartingIntent(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedMountIntent(t, stateDir, mountPath, "starting", "fuse", "")

	if rc := e.run([]string{"umount", mountPath}); rc != 0 {
		t.Fatalf("starting intent reconciliation rc = %d: %s", rc, stderr.String())
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Lstat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("explicitly reconciled starting intent remains: %v", err)
	}
}

func TestUmountNoStatePreservesUnreconciledIntent(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedMountIntent(t, stateDir, mountPath, "attached", "fskit", "att_AAAAAAAAAAAAAAAAAAAAAA")
	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatal("unmount claimed an unverified attach was reconciled")
	}
	if !strings.Contains(stderr.String(), "intent was preserved") {
		t.Fatalf("missing preserved-intent guidance: %q", stderr.String())
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Lstat(intentPath); err != nil {
		t.Fatalf("unreconciled intent was removed: %v", err)
	}
}

func TestUmountNoStateRemovesProvenEmptyIntent(t *testing.T) {
	e, _, _, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// cleanup-unverified with no process, kernel mount, or attach is exactly
	// reconcilable on both supported platforms.
	seedMountIntent(t, stateDir, mountPath, "cleanup-unverified", "fuse", "")
	if rc := e.run([]string{"umount", mountPath}); rc != 0 {
		t.Fatalf("empty intent reconciliation rc = %d", rc)
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Lstat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("proven-clean intent remains: %v", err)
	}
}

func TestMountOperationCloseSurfacesDurableIntentRemovalFailure(t *testing.T) {
	_, _, _, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	op, err := acquireMountOperation(stateDir, mountPath, "vol", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(op.intentPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := op.close(true); err == nil {
		t.Fatal("unsafe intent removal failure was swallowed")
	}
}

func TestForceFSKitUnmountRefusesWithoutExactDaemonAndPreservesAnchors(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := validFSKitMountState(t, mountPath)
	st.VolumeID = "vol_force"
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", "--force", mountPath}); rc == 0 {
		t.Fatal("forced FSKit unmount succeeded without exact daemon acknowledgement")
	}
	if !strings.Contains(stderr.String(), "exact FSKit attach") &&
		!strings.Contains(stderr.String(), "daemon") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if current, err := readMountState(stateDir, mountPath); err != nil || current == nil {
		t.Fatalf("mount state was not preserved: state=%+v err=%v", current, err)
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Lstat(intentPath); err != nil {
		t.Fatalf("unmount intent was not preserved: %v", err)
	}
}

func TestReconcileFSKitIntentWithAbsentKernelHonorsForce(t *testing.T) {
	for _, phase := range []string{"attached", "kernel-mounted"} {
		for _, force := range []bool{false, true} {
			for _, forceFailure := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/force=%t/failure=%t", phase, force, forceFailure), func(t *testing.T) {
					e, _, stderr, stateDir := umountTestEnv(t)
					mountPath, err := canonicalMountPath(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					const ref = "att_AAAAAAAAAAAAAAAAAAAAAA"
					seedMountIntent(t, stateDir, mountPath, phase, "fskit", ref)
					stubMountIdentification(t, nil, func(string) ([]kernelMountIdentity, error) { return nil, nil })
					unmounts := 0
					ctl := &fsdControl{httpClient: &http.Client{Transport: lifecycleRoundTrip(func(r *http.Request) (*http.Response, error) {
						status, body := http.StatusOK, fmt.Sprintf(`{"attaches":[{"attachRef":%q,"mountPath":%q,"volumeId":"vol_intent"}]}`, ref, mountPath)
						switch r.URL.Path {
						case "/v2/attaches":
						case "/v2/attaches/" + ref + "/unmount":
							unmounts++
							if got := r.URL.Query().Get("force") == "1"; got != force {
								t.Errorf("force query=%t, want %t", got, force)
							}
							status, body = http.StatusConflict, `{"error":"detach refused"}`
							if force && !forceFailure {
								status, body = http.StatusNoContent, ""
							}
						default:
							t.Errorf("unexpected path %s", r.URL.Path)
						}
						return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
					})}}
					e.ensurePortablefsdFn = func(fskitConfig, string, string) (*fsdControl, error) { return ctl, nil }
					args := []string{"umount", mountPath}
					if force {
						args = append(args, "--force")
					}
					rc := e.run(args)
					wantSuccess := force && !forceFailure
					if (rc == 0) != wantSuccess || unmounts != 1 {
						t.Fatalf("rc=%d unmounts=%d stderr=%s", rc, unmounts, stderr.String())
					}
					_, intentPath := mountOperationPaths(stateDir, mountPath)
					_, statErr := os.Stat(intentPath)
					if wantSuccess {
						if !os.IsNotExist(statErr) {
							t.Fatalf("completed intent remains: %v", statErr)
						}
					} else {
						if statErr != nil {
							t.Fatal(statErr)
						}
						if !strings.Contains(stderr.String(), "kernel mount is absent") || strings.Contains(stderr.String(), "mount remains live") {
							t.Fatalf("wrong absence outcome: %s", stderr.String())
						}
					}
				})
			}
		}
	}
}
