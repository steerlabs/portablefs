package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedMountIntent(t *testing.T, stateDir, mountPath, phase, strategy, attachRef string) {
	t.Helper()
	op, err := acquireMountOperation(stateDir, mountPath, "vol_intent", "main", strategy)
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
	} else if strategy == "fskit" {
		op.mountMechanism = "fskit-system"
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

func TestDetachFUSEPublishesPreparedAndDurablyAborts(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	mountPath := t.TempDir()
	op, err := acquireMountOperation(stateDir, mountPath, "vol-intent", "main", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	defer op.close(false)
	op.mountInstanceID = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
	op.kernelMountID = "42"
	op.mountTarget = mountTargetIdentity{device: 1, inode: 2}
	op.mountMechanism = "direct"
	op.startedAtMs = 1
	op.authorityURL = "127.0.0.1:1"
	op.transportMode = dataPlaneTransportPlaintext
	if err := op.writeIntent("live", 123, "owner-start"); err != nil {
		t.Fatal(err)
	}

	called := 0
	if err := detachFUSEWithPreparedIntent(op, 123, "owner-start", func() error {
		called++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	intent, err := readMountIntent(op.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 || intent.Phase != "drain-prepared" {
		t.Fatalf("called=%d intent=%+v", called, intent)
	}

	if err := op.writeIntent("live", 123, "owner-start"); err != nil {
		t.Fatal(err)
	}
	detachErr := errors.New("injected exact detach refusal")
	if err := detachFUSEWithPreparedIntent(op, 123, "owner-start", func() error {
		return detachErr
	}); !errors.Is(err, detachErr) {
		t.Fatalf("detach error=%v", err)
	}
	intent, err = readMountIntent(op.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Phase != "live" {
		t.Fatalf("failed detach did not durably restore prior phase: %+v", intent)
	}

	if err := op.writeIntent("force-prepared", 123, "owner-start"); err != nil {
		t.Fatal(err)
	}
	if err := detachFUSEWithPreparedIntent(op, 123, "owner-start", func() error {
		return detachErr
	}); !errors.Is(err, detachErr) {
		t.Fatalf("forced detach error=%v", err)
	}
	intent, err = readMountIntent(op.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Phase != "force-prepared" {
		t.Fatalf("failed forced detach lost durable force proof: %+v", intent)
	}

	if err := op.writeIntent("live", 123, "owner-start"); err != nil {
		t.Fatal(err)
	}
	durableIntentPath := op.intentPath
	if err := detachFUSEWithPreparedIntent(op, 123, "owner-start", func() error {
		// Simulate the durable intent directory becoming unavailable only
		// after drain-prepared was published and exact detach failed.
		op.intentPath = stateDir
		return detachErr
	}); err == nil {
		t.Fatal("rollback persistence failure returned success")
	} else {
		var keepFrozen interface{ KeepWritebackFrozen() bool }
		if !errors.As(err, &keepFrozen) || !keepFrozen.KeepWritebackFrozen() {
			t.Fatalf("rollback persistence failure did not request a fail-frozen mutation gate: %v", err)
		}
	}
	op.intentPath = durableIntentPath
	intent, err = readMountIntent(durableIntentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Phase != "drain-prepared" {
		t.Fatalf("failed rollback destroyed the durable prepared marker: %+v", intent)
	}
}

func TestPreparedIntentRefusesResumeWhileExactOwnerLives(t *testing.T) {
	identity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	intent := &mountIntent{
		Phase:                       "drain-prepared",
		OperationOwnerPID:           os.Getpid(),
		OperationOwnerStartIdentity: identity,
	}
	if !mountIntentOperationOwnerMatches(intent) {
		t.Fatal("live exact operation owner was treated as abandoned")
	}
	intent.OperationOwnerStartIdentity = "different-process-incarnation"
	if mountIntentOperationOwnerMatches(intent) {
		t.Fatal("stale operation-owner identity was treated as live")
	}
}

func TestPreparedFUSELiveRetryDecision(t *testing.T) {
	if _, err := preparedFUSERetryDecision("drain-prepared", true, false, false); err == nil {
		t.Fatal("live fail-frozen drain resumed without explicit force")
	}
	if advance, err := preparedFUSERetryDecision("drain-prepared", true, true, false); err != nil || !advance {
		t.Fatalf("explicit force did not advance live fail-frozen drain: advance=%v err=%v", advance, err)
	}
	if advance, err := preparedFUSERetryDecision("force-prepared", true, false, true); err != nil || advance {
		t.Fatalf("acknowledged force-prepared retry was refused: advance=%v err=%v", advance, err)
	}
	if _, err := preparedFUSERetryDecision("force-prepared", true, true, false); err == nil {
		t.Fatal("live force-prepared retry bypassed missing park acknowledgement")
	}
}

func TestDecidePostUnmount(t *testing.T) {
	tests := []struct {
		name                    string
		mounted                 bool
		fuseForceCompleted      bool
		fskitUnmountCompleted   bool
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
			name:                  "acknowledged FSKit absence is normal completion",
			fskitUnmountCompleted: true,
		},
		{
			name:               "acknowledged forced FUSE absence is normal completion",
			fuseForceCompleted: true,
		},
		{
			name:                  "acknowledged FSKit mount remaining is FSKit failure",
			mounted:               true,
			fskitUnmountCompleted: true,
			wantError:             "FSKit unmount acknowledged completion",
			rejectError:           "FUSE",
		},
		{
			name:               "acknowledged forced FUSE mount remaining is FUSE failure",
			mounted:            true,
			fuseForceCompleted: true,
			wantError:          "forced FUSE owner acknowledged parking",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			platformUnmount, reconcileStale, err := decidePostUnmount(
				tc.mounted,
				tc.fuseForceCompleted,
				tc.fskitUnmountCompleted,
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

func TestOwnerlessForceRequestRequiresExactOfflineStoreProof(t *testing.T) {
	e, _, _ := testEnv(t)
	stateDir := filepath.Join(t.TempDir(), "mounts")
	mountPath := t.TempDir()
	op, err := acquireMountOperation(stateDir, mountPath, "vol-force-request", "main", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	defer op.close(false)
	state := validFuseMountState(t, mountPath)
	state.PID = 4_194_000
	state.ProcessStartIdentity = "dead-owner"
	hydrateMountOperationFromState(op, &state)
	if err := op.writeIntent("force-requested", state.PID, state.ProcessStartIdentity); err != nil {
		t.Fatal(err)
	}
	intent, err := readMountIntent(op.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.reconcileMountIntent(intent, true); err == nil ||
		!strings.Contains(err.Error(), "abandoned FUSE store") {
		t.Fatalf("ownerless force request bypassed exact offline store proof: %v", err)
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
		Branch:    intent.Branch,
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

	if _, err := e.reconcileMountIntent(intent, true); err != nil {
		t.Fatalf("reconcile FSKit intent: %v", err)
	}
	if ensures != 1 || calls.unmount.Load() != 1 {
		t.Fatalf("ensure calls=%d force calls=%d, want 1 each", ensures, calls.unmount.Load())
	}
}

func TestForceDetachForUnmountStartsExactDaemon(t *testing.T) {
	e, _, _, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := validFSKitMountState(t, mountPath)
	ctl, calls := serveFSKitReconcileControl(t, st, true, false, 200)
	ensures := 0
	e.ensurePortablefsdFn = func(_ fskitConfig, stateRoot, _ string) (*fsdControl, error) {
		ensures++
		if stateRoot != filepath.Dir(stateDir) {
			t.Fatalf("state root=%q want %q", stateRoot, filepath.Dir(stateDir))
		}
		return ctl, nil
	}

	if _, err := e.forceDetachForUnmount(&st); err != nil {
		t.Fatalf("force detach: %v", err)
	}
	if ensures != 1 || calls.unmount.Load() != 1 {
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
			if op, err := acquireMountOperation(stateDir, mountPath, "vol_new", "main", "fskit"); err == nil {
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
	op, err := acquireMountOperation(stateDir, mountPath, "vol", "main", "fuse")
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
