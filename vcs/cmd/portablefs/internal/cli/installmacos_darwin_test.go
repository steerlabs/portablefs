//go:build darwin

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"golang.org/x/sys/unix"
)

func TestActivationAdmissionRequiresTheEntireResidualReserve(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	operation := 20 * time.Second
	reserve := 85 * time.Second
	for _, test := range []struct {
		name      string
		remaining time.Duration
		wantError bool
	}{
		{"exact budget", operation + reserve, false},
		{"one nanosecond short", operation + reserve - time.Nanosecond, true},
		{"expired", -time.Nanosecond, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotOperation, gotReserve, err := activationAdmission(
				now, now.Add(test.remaining), operation, reserve,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("admission error = %v, wantError %t", err, test.wantError)
			}
			if err == nil && (gotOperation != operation || gotReserve != reserve) {
				t.Fatalf("admitted budgets = %s/%s, want %s/%s", gotOperation, gotReserve, operation, reserve)
			}
		})
	}
}

func TestMacOSActivationBudgetCompositionAdmitsEveryIrreversibleEdge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name      string
		operation time.Duration
		reserve   time.Duration
	}{
		{
			"target ready",
			macOSActivationReadyRequestTimeout,
			macOSActivationPostLaunchReserve,
		},
		{
			"rollback ready",
			macOSActivationReadyRequestTimeout,
			macOSRollbackPostLaunchReserve,
		},
		{
			"target accept",
			macOSActivationAcceptReconcileTimeout,
			macOSActivationFenceAndRollbackReserve,
		},
		{
			"rollback accept",
			macOSActivationAcceptReconcileTimeout,
			macOSActivationCompletionReserve,
		},
		{
			"initial complete",
			macOSActivationCompletionRequestTimeout,
			macOSActivationCompletionReconcileTimeout - macOSActivationCompletionRequestTimeout,
		},
		{
			"resume active",
			macOSActivationResumeRequestTimeout,
			macOSActivationCompletionRequestTimeout + macOSActivationTerminalProofTimeout,
		},
		{
			"complete resumed active",
			macOSActivationCompletionRequestTimeout,
			macOSActivationTerminalProofTimeout,
		},
		{
			"fence and absence",
			macOSActivationFenceAndAbsenceTimeout / 2,
			macOSActivationFenceAndAbsenceTimeout / 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			required := test.operation + test.reserve
			if _, _, err := activationAdmission(
				now, now.Add(required), test.operation, test.reserve,
			); err != nil {
				t.Fatalf("exact composed budget was rejected: %v", err)
			}
			if _, _, err := activationAdmission(
				now, now.Add(required-time.Nanosecond), test.operation, test.reserve,
			); err == nil {
				t.Fatal("one-nanosecond-short composed budget was admitted")
			}
		})
	}

	if macOSActivationCompletionReserve <= macOSActivationCompletionReconcileTimeout {
		t.Fatal("outer acceptance reserve has no deadline-boundary margin")
	}
}

func TestActivationAdmissionRetainsReserveAfterChildDeadline(t *testing.T) {
	operation := 20 * time.Millisecond
	reserve := 40 * time.Millisecond
	parent, cancel := context.WithTimeout(context.Background(), operation+reserve+20*time.Millisecond)
	defer cancel()
	child, childCancel, err := activationChildContext(parent, operation, reserve)
	if err != nil {
		t.Fatal(err)
	}
	defer childCancel()
	<-child.Done()
	// This models a host action crossing immediately after the client-side
	// request deadline: the child is expired, but the parent token holder still
	// owns the explicitly admitted reconciliation reserve.
	remaining, err := remainingContextDuration(parent)
	if err != nil {
		t.Fatal(err)
	}
	if remaining < reserve-10*time.Millisecond {
		t.Fatalf("remaining parent reserve = %s, want approximately %s", remaining, reserve)
	}
}

func TestActivationAdmissionRejectsIrreversibleEdgesWithoutADeadline(t *testing.T) {
	ctx, cancel, err := activationChildContext(
		context.Background(), time.Second, time.Second,
	)
	if err == nil || ctx != nil || cancel != nil {
		t.Fatalf("deadline-free admission = %v/%v/%v, want fail-closed", ctx, cancel, err)
	}
}

func TestLostCompletionReplyRequiresEveryExactReconciliationProof(t *testing.T) {
	type counters struct {
		lease       int
		finalized   int
		destination int
		live        int
	}
	makeProofs := func(counts *counters, fail string) completedMacOSActivationProofs {
		proof := func(name string, count *int) func() error {
			return func() error {
				*count++
				if fail == name {
					return errors.New("injected ambiguity")
				}
				return nil
			}
		}
		return completedMacOSActivationProofs{
			requireCompletedLease: proof("lease", &counts.lease),
			requireFinalized:      proof("finalized", &counts.finalized),
			requireDestination:    proof("destination", &counts.destination),
			requireLive:           proof("live", &counts.live),
		}
	}

	for _, failedProof := range []string{"lease", "finalized", "destination", "live"} {
		t.Run(failedProof, func(t *testing.T) {
			var counts counters
			if err := reconcileCompletedMacOSActivationProofs(makeProofs(&counts, failedProof)); err == nil {
				t.Fatalf("lost completion reply accepted without %s proof", failedProof)
			}
		})
	}
	var counts counters
	if err := reconcileCompletedMacOSActivationProofs(makeProofs(&counts, "")); err != nil {
		t.Fatalf("complete exact reconciliation was rejected: %v", err)
	}
	if counts.lease != 2 || counts.finalized != 1 || counts.destination != 2 || counts.live != 1 {
		t.Fatalf("proof/recheck counts = %+v", counts)
	}
}

func TestAcceptedCommitAckLossUsesTokenForPrepublicationRollback(t *testing.T) {
	commitFailure := errors.New("commit reply lost")
	rollbackResult := errors.New("old release reactivated")
	waited := 0
	rolledBack := 0
	decided, err := reconcileFailedMacOSCommitOutcome(
		failedMacOSCommitRecoveryProofs{
			requireOldAbsent:        func() error { return nil },
			requireRollbackComplete: func() error { return errors.New("not rollback-complete") },
			waitHostProcessAbsent: func() error {
				waited++
				return nil
			},
			rollbackOld: func() error {
				rolledBack++
				return rollbackResult
			},
			requireRollbackCompleteLive: func() error {
				t.Fatal("old-absent recovery consulted rollback-complete live proof")
				return nil
			},
		},
		commitFailure,
	)
	if !decided || !errors.Is(err, rollbackResult) {
		t.Fatalf("recovery = decided %t, %v; want tokenized rollback result", decided, err)
	}
	if waited != 1 || rolledBack != 1 {
		t.Fatalf("process waits/rollbacks = %d/%d, want 1/1", waited, rolledBack)
	}
}

func TestAcceptedCommitRecoveryDoesNotTreatAStaleSocketNameAsAuthority(t *testing.T) {
	// The recovery contract intentionally has no update-socket-absence proof.
	// Once the exact host execution is gone, the relaunched host owns safe stale
	// inode reclamation. Requiring name absence here would reproduce the live
	// token-loss failure this boundary prevents.
	rolledBack := 0
	decided, _ := reconcileFailedMacOSCommitOutcome(
		failedMacOSCommitRecoveryProofs{
			requireOldAbsent:        func() error { return nil },
			requireRollbackComplete: func() error { return errors.New("not rollback-complete") },
			waitHostProcessAbsent:   func() error { return nil },
			rollbackOld: func() error {
				rolledBack++
				return errors.New("expected installation failure after safe rollback")
			},
			requireRollbackCompleteLive: func() error { return nil },
		},
		errors.New("commit reply lost"),
	)
	if !decided || rolledBack != 1 {
		t.Fatalf("stale-name recovery = decided %t, rollbacks %d; want true/1", decided, rolledBack)
	}
}

func TestPreAcceptCommitFailureRequiresExactRollbackCompleteLiveProof(t *testing.T) {
	for _, liveFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "ambiguous"}[liveFailure], func(t *testing.T) {
			liveProofs := 0
			decided, err := reconcileFailedMacOSCommitOutcome(
				failedMacOSCommitRecoveryProofs{
					requireOldAbsent:        func() error { return errors.New("not old-absent") },
					requireRollbackComplete: func() error { return nil },
					waitHostProcessAbsent: func() error {
						t.Fatal("rollback-complete recovery waited for committed host exit")
						return nil
					},
					rollbackOld: func() error {
						t.Fatal("rollback-complete recovery attempted a second rollback")
						return nil
					},
					requireRollbackCompleteLive: func() error {
						liveProofs++
						if liveFailure {
							return errors.New("old live identity ambiguous")
						}
						return nil
					},
				},
				errors.New("commit was not accepted"),
			)
			if !decided || liveProofs != 1 {
				t.Fatalf("rollback-complete recovery = decided %t, proofs %d", decided, liveProofs)
			}
			if liveFailure && !strings.Contains(err.Error(), "did not prove") {
				t.Fatalf("ambiguous live proof error = %v", err)
			}
			if !liveFailure && !strings.Contains(err.Error(), "durably restored and live-proved") {
				t.Fatalf("exact rollback-complete result = %v", err)
			}
		})
	}
}

func makeFakeMacOSApp(t *testing.T, root, marker string) string {
	t.Helper()
	return makeFakeMacOSAppWithLayout(t, root, marker, productionMacOSInstallLayout)
}

func makeFakeMacOSAppWithLayout(
	t *testing.T,
	root string,
	marker string,
	layout macOSInstallLayout,
) string {
	t.Helper()
	app := filepath.Join(root, layout.appName)
	helperDir := filepath.Join(app, "Contents", "Helpers")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperDir, macOSCLIName), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "marker"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	return app
}

func writeTestBundleInfo(t *testing.T, path, bundleID, executable string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
<key>CFBundleExecutable</key><string>` + executable + `</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>
`
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
}

func addTestBundleIdentity(t *testing.T, app, appID string) {
	t.Helper()
	addTestBundleIdentityWithLayout(t, app, appID, productionMacOSInstallLayout)
}

func addTestBundleIdentityWithLayout(
	t *testing.T,
	app string,
	appID string,
	layout macOSInstallLayout,
) {
	t.Helper()
	writeTestBundleInfo(
		t,
		filepath.Join(app, "Contents", "Info.plist"),
		appID,
		layout.appExecutable,
	)
	writeTestBundleInfo(
		t,
		filepath.Join(
			app,
			"Contents",
			"Extensions",
			layout.extensionExecutable+".appex",
			"Contents",
			"Info.plist",
		),
		appID+"."+layout.extensionExecutable,
		layout.extensionExecutable,
	)
}

func writeTestFSKitRegistration(
	t *testing.T,
	extensionPath, shortName string,
	schemes []string,
) {
	t.Helper()
	infoPath := filepath.Join(extensionPath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	schemeXML := ""
	for _, scheme := range schemes {
		schemeXML += "<string>" + scheme + "</string>"
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>EXAppExtensionAttributes</key><dict>
<key>EXExtensionPointIdentifier</key><string>com.apple.fskit.fsmodule</string>
<key>FSShortName</key><string>` + shortName + `</string>
<key>FSSupportedSchemes</key><array>` + schemeXML + `</array>
</dict>
</dict></plist>
`
	if err := os.WriteFile(infoPath, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionClaimsPFSUsesTypeOrResourceScheme(t *testing.T) {
	for _, test := range []struct {
		name      string
		shortName string
		schemes   []string
		want      bool
	}{
		{
			name:      "exact OSS identity",
			shortName: fskitidentity.FSType,
			schemes:   []string{fskitidentity.ResourceScheme},
			want:      true,
		},
		{
			name:      "same filesystem type",
			shortName: fskitidentity.FSType,
			schemes:   []string{"org.example.foreign"},
			want:      true,
		},
		{
			name:      "same resource scheme case insensitive",
			shortName: "foreign",
			schemes:   []string{strings.ToUpper(fskitidentity.ResourceScheme)},
			want:      true,
		},
		{
			name:      "OpenSteer legacy tuple",
			shortName: "portablefs",
			schemes:   []string{"pfs"},
			want:      false,
		},
		{
			name:      "unrelated provider",
			shortName: "foreign",
			schemes:   []string{"org.example.foreign"},
			want:      false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			extension := filepath.Join(t.TempDir(), "Provider.appex")
			writeTestFSKitRegistration(t, extension, test.shortName, test.schemes)
			got, err := extensionClaimsPFS(extension)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("claims = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCommitMacOSInstallPublishesAndUpdatesWholeBundle(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	var stableLink pathSnapshot

	for index, marker := range []string{"one", "two"} {
		sourceRoot := t.TempDir()
		source := makeFakeMacOSApp(t, sourceRoot, marker)
		prepared, err := prepareMacOSInstall(source, destination, link)
		if err != nil {
			t.Fatalf("prepare update %d: %v", index, err)
		}
		if err := commitMacOSInstall(prepared, destination); err != nil {
			prepared.cleanup()
			t.Fatalf("commit update %d: %v", index, err)
		}
		if prepared.stageRoot != "" {
			t.Fatalf("successful commit retained app transaction %s", prepared.stageRoot)
		}
		prepared.cleanup()
		got, err := os.ReadFile(filepath.Join(destination, "marker"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != marker {
			t.Fatalf("marker after update %d = %q, want %q", index, got, marker)
		}
		target, err := os.Readlink(link)
		if err != nil {
			t.Fatal(err)
		}
		wantTarget := filepath.Join(destination, "Contents", "Helpers", macOSCLIName)
		if target != wantTarget {
			t.Fatalf("CLI link = %q, want %q", target, wantTarget)
		}
		if index == 0 {
			stableLink, err = snapshotPath(link)
			if err != nil {
				t.Fatal(err)
			}
		} else if err := requireUnchangedPath(link, stableLink); err != nil {
			t.Fatalf("canonical CLI link was needlessly replaced: %v", err)
		}
	}
}

func TestPublishedMacOSUpdateRetainsDisplacedReleaseUntilFinalized(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := makeFakeMacOSApp(t, appDir, "old")
	link := filepath.Join(linkDir, macOSCLIName)
	if err := os.Symlink(
		filepath.Join(destination, "Contents", "Helpers", macOSCLIName),
		link,
	); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareMacOSInstall(
		makeFakeMacOSApp(t, t.TempDir(), "new"),
		destination,
		link,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := publishMacOSInstall(prepared, destination); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		destination:       "new",
		prepared.stageApp: "old",
	} {
		marker, err := os.ReadFile(filepath.Join(path, "marker"))
		if err != nil {
			t.Fatal(err)
		}
		if string(marker) != want {
			t.Fatalf("marker at %s = %q, want %q", path, marker, want)
		}
	}
	if prepared.stageRoot == "" {
		t.Fatal("publication retired the rollback release before activation proof")
	}
	if err := finalizePublishedMacOSInstall(prepared, destination); err != nil {
		t.Fatal(err)
	}
	if prepared.stageRoot != "" {
		t.Fatalf("finalized publication retained transaction %s", prepared.stageRoot)
	}
}

func TestPublishedMacOSUpdateRollsBackExactDisplacedRelease(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := makeFakeMacOSApp(t, appDir, "old")
	link := filepath.Join(linkDir, macOSCLIName)
	if err := os.Symlink(
		filepath.Join(destination, "Contents", "Helpers", macOSCLIName),
		link,
	); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareMacOSInstall(
		makeFakeMacOSApp(t, t.TempDir(), "rejected"),
		destination,
		link,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := publishMacOSInstall(prepared, destination); err != nil {
		t.Fatal(err)
	}
	if err := rollbackPublishedMacOSInstall(prepared, destination); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(destination, "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != "old" {
		t.Fatalf("restored marker = %q, want old", marker)
	}
	if prepared.stageRoot != "" {
		t.Fatalf("rollback retained rejected transaction %s", prepared.stageRoot)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(destination, "Contents", "Helpers", macOSCLIName) {
		t.Fatalf("stable CLI link changed during rollback: %s", target)
	}
}

func TestPublishedMacOSRollbackPreservesTransactionOnDestinationRace(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := makeFakeMacOSApp(t, appDir, "old")
	link := filepath.Join(linkDir, macOSCLIName)
	if err := os.Symlink(
		filepath.Join(destination, "Contents", "Helpers", macOSCLIName),
		link,
	); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareMacOSInstall(
		makeFakeMacOSApp(t, t.TempDir(), "new"),
		destination,
		link,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := publishMacOSInstall(prepared, destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(destination, destination+".raced"); err != nil {
		t.Fatal(err)
	}
	makeFakeMacOSApp(t, appDir, "counterfeit")

	err = rollbackPublishedMacOSInstall(prepared, destination)
	if err == nil || !strings.Contains(err.Error(), "published app changed") {
		t.Fatalf("destination race result = %v", err)
	}
	if !prepared.preserve {
		t.Fatal("raced rollback transaction was not marked for preservation")
	}
	marker, readErr := os.ReadFile(filepath.Join(prepared.stageApp, "marker"))
	if readErr != nil || string(marker) != "old" {
		t.Fatalf("displaced release was mutated after refused rollback: %q, %v", marker, readErr)
	}
	marker, readErr = os.ReadFile(filepath.Join(destination, "marker"))
	if readErr != nil || string(marker) != "counterfeit" {
		t.Fatalf("racing destination was mutated: %q, %v", marker, readErr)
	}
}

func TestPreparedMacOSBundleNeverUsesAppSuffix(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareMacOSInstall(
		makeFakeMacOSApp(t, t.TempDir(), "source"),
		filepath.Join(appDir, macOSAppName),
		filepath.Join(linkDir, macOSCLIName),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if filepath.Ext(prepared.stageApp) == ".app" {
		t.Fatalf("staged provider is discoverable as an app bundle: %s", prepared.stageApp)
	}
}

func TestRejectOrphanedMacOSInstallTransactions(t *testing.T) {
	appDir := t.TempDir()
	orphan := filepath.Join(appDir, ".portablefs-install-orphan")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	err := rejectOrphanedMacOSInstallTransactions(appDir, "")
	if err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("orphaned install was not refused precisely: %v", err)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Fatalf("orphan was mutated: %v", statErr)
	}
	if err := rejectOrphanedMacOSInstallTransactions(appDir, orphan); err != nil {
		t.Fatalf("current transaction was refused: %v", err)
	}
}

func TestRejectOrphanedMacOSLinkTransactions(t *testing.T) {
	linkDir := t.TempDir()
	orphan := filepath.Join(linkDir, ".portablefs-link-orphan")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	err := rejectOrphanedMacOSLinkTransactions(linkDir, "")
	if err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("orphaned CLI-link transaction was not refused: %v", err)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Fatalf("orphan was mutated: %v", statErr)
	}
}

func TestPrepareMacOSInstallRefusesUnrelatedCLIFile(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	link := filepath.Join(linkDir, macOSCLIName)
	if err := os.WriteFile(link, []byte("user file"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := prepareMacOSInstall(source, filepath.Join(appDir, macOSAppName), link)
	if err == nil || !strings.Contains(err.Error(), "is not a symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCommitMacOSInstallRefusesLinkThatAppearedAfterPreparation(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	prepared, err := prepareMacOSInstall(source, destination, link)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.WriteFile(link, []byte("appeared"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = commitMacOSInstall(prepared, destination)
	if err == nil || !strings.Contains(err.Error(), "CLI link changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination app was published despite link race: %v", err)
	}
}

func TestCommitMacOSInstallRefusesChangedStagedLink(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	prepared, err := prepareMacOSInstall(source, destination, link)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.Remove(prepared.linkTemp); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/not-portablefs", prepared.linkTemp); err != nil {
		t.Fatal(err)
	}
	err = commitMacOSInstall(prepared, destination)
	if err == nil || !strings.Contains(err.Error(), "staged CLI link changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination app was published despite staged-link race: %v", err)
	}
}

func TestPublishPreparedCLILinkDoesNotOverwriteAppearedDestination(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	prepared, err := prepareMacOSInstall(
		source,
		filepath.Join(appDir, macOSAppName),
		filepath.Join(linkDir, macOSCLIName),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.WriteFile(prepared.linkPath, []byte("appeared"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceParent, err := openSnapshottedDirectory(prepared.linkRoot, prepared.linkRootID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sourceParent)
	destinationParent, err := openSnapshottedDirectory(filepath.Dir(prepared.linkPath), prepared.linkParentID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(destinationParent)

	if err := publishPreparedCLILink(prepared, sourceParent, destinationParent); err == nil {
		t.Fatal("appeared destination was overwritten")
	}
	got, err := os.ReadFile(prepared.linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "appeared" {
		t.Fatalf("appeared destination changed to %q", got)
	}
	if err := requireUnchangedPath(prepared.linkTemp, prepared.linkStageID); err != nil {
		t.Fatalf("staged link changed after refused publication: %v", err)
	}
}

func TestPublishPreparedAppRollsBackDisplacedAppRace(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	makeFakeMacOSApp(t, appDir, "old")
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	prepared, err := prepareMacOSInstall(source, destination, link)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.RemoveAll(destination); err != nil {
		t.Fatal(err)
	}
	makeFakeMacOSApp(t, appDir, "raced")
	parent, err := openSnapshottedDirectory(appDir, prepared.appParentID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)

	err = publishPreparedApp(
		prepared,
		parent,
		filepath.Join(filepath.Base(prepared.stageRoot), macOSStagedAppName),
		macOSAppName,
	)
	if err == nil || !strings.Contains(err.Error(), "exchange rolled back") {
		t.Fatalf("unexpected result: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "raced" {
		t.Fatalf("destination marker = %q, want raced", got)
	}
	got, err = os.ReadFile(filepath.Join(prepared.stageApp, "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "source" {
		t.Fatalf("staged marker = %q, want source", got)
	}
}

func TestOpenSnapshottedDirectoryRefusesReplacement(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "Applications")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotPath(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, directory+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if fd, err := openSnapshottedDirectory(directory, snapshot); err == nil {
		_ = os.NewFile(uintptr(fd), directory).Close()
		t.Fatal("replaced directory was accepted")
	}
}

func TestOpenSnapshottedDirectoryRefusesSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	realRoot := filepath.Join(root, "real")
	directory := filepath.Join(realRoot, "Applications")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Fatal(err)
	}
	throughAlias := filepath.Join(alias, "Applications")
	snapshot, err := snapshotPath(throughAlias)
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := openSnapshottedDirectory(throughAlias, snapshot); err == nil {
		_ = unix.Close(fd)
		t.Fatal("symlinked ancestor was accepted")
	}
}

func TestRemoveSnapshottedTreePreservesReplacementAfterPin(t *testing.T) {
	parentPath := t.TempDir()
	transaction := filepath.Join(parentPath, ".portablefs-install-transaction")
	if err := os.Mkdir(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transaction, "owned"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := snapshotPath(transaction)
	if err != nil {
		t.Fatal(err)
	}
	parentSnapshot, err := snapshotPath(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openSnapshottedDirectory(parentPath, parentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)
	moved := transaction + ".moved"
	err = removeSnapshottedTreeAt(parent, filepath.Base(transaction), expected, func() {
		if renameErr := os.Rename(transaction, moved); renameErr != nil {
			t.Fatal(renameErr)
		}
		if mkdirErr := os.Mkdir(transaction, 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		if writeErr := os.WriteFile(filepath.Join(transaction, "preserve"), []byte("replacement"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "replacement was preserved") {
		t.Fatalf("replacement race error = %v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(transaction, "preserve"))
	if readErr != nil || string(data) != "replacement" {
		t.Fatalf("replacement tree was changed: %q, %v", data, readErr)
	}
	entries, readErr := os.ReadDir(moved)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("pinned original transaction was not the cleaned inode: %v", entries)
	}
}

func TestSourceMacOSBundleIdentitySupportsExactCustomForkIdentity(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	const appID = "org.example.portablefs"
	addTestBundleIdentity(t, app, appID)
	got, err := sourceMacOSBundleIdentity(app)
	if err != nil {
		t.Fatal(err)
	}
	if got != appID {
		t.Fatalf("app id = %q, want %q", got, appID)
	}
}

func TestMacOSInstallLayoutRejectsInvalidCompiledIdentity(t *testing.T) {
	valid := productionMacOSInstallLayout
	for _, mutate := range []func(*macOSInstallLayout){
		func(layout *macOSInstallLayout) { layout.appName = "../PortableFS.app" },
		func(layout *macOSInstallLayout) { layout.appName = "PortableFS" },
		func(layout *macOSInstallLayout) { layout.stagedAppName = "PortableFS.next.app" },
		func(layout *macOSInstallLayout) { layout.appExecutable = "" },
		func(layout *macOSInstallLayout) { layout.extensionExecutable = "PortableFS/Ext" },
		func(layout *macOSInstallLayout) { layout.serviceMinimumOS = "" },
		func(layout *macOSInstallLayout) { layout.serviceMinimumOS = "28.0" },
		func(layout *macOSInstallLayout) { layout.requiredAppID = "invalid" },
		func(layout *macOSInstallLayout) { layout.codeIdentity = 0 },
	} {
		layout := valid
		mutate(&layout)
		if err := layout.validate(); err == nil {
			t.Fatalf("invalid layout was accepted: %+v", layout)
		}
	}
}

func TestExactJSONValueEqualAcceptsEquivalentEscapesAndRejectsTypeChanges(t *testing.T) {
	if !exactJSONValueEqual(
		json.RawMessage(`"Contents\/Library\/LaunchAgents"`),
		exactJSONString("Contents/Library/LaunchAgents"),
	) {
		t.Fatal("equivalent escaped slash spellings were rejected")
	}
	if exactJSONValueEqual(json.RawMessage(`true`), json.RawMessage(`"true"`)) {
		t.Fatal("different JSON value types were accepted")
	}
}

func TestSignedEntitlementPayloadDecodingUsesLiteralDottedKeys(t *testing.T) {
	const group = "B47U2LLKHW.pfsoss"
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.application-groups</key>
<array><string>` + group + `</string></array>
</dict></plist>`)
	entitlements, err := decodeExactCodeEntitlements(payload, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExactMacOSAppGroupEntitlementDictionary(
		entitlements, "fixture", group,
	); err != nil {
		t.Fatalf("literal dotted entitlement key was rejected: %v", err)
	}
	if _, ok := entitlements["com"]; ok {
		t.Fatal("literal dotted entitlement key was interpreted as a key path")
	}
}

func TestSignedEmptyEntitlementPayloadIsAnExactEmptyDictionary(t *testing.T) {
	entitlements, err := decodeExactCodeEntitlements(nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAbsentMacOSAppGroupEntitlementDictionary(entitlements, "CLI"); err != nil {
		t.Fatalf("unentitled signed CLI was rejected: %v", err)
	}
	if err := validateExactEntitlementDictionary(entitlements, map[string]any{}, "CLI"); err != nil {
		t.Fatalf("empty signed entitlement policy was rejected: %v", err)
	}
}

func TestSignedEntitlementPoliciesRejectMissingWrongTypeExtraAndMalformed(t *testing.T) {
	const group = "B47U2LLKHW.pfsoss"
	valid := map[string]any{
		"com.apple.security.application-groups": []any{group},
	}
	missing := map[string]any{
		"com.apple.security.get-task-allow": true,
	}
	wrongType := map[string]any{
		"com.apple.security.application-groups": group,
	}
	extra := map[string]any{
		"com.apple.security.application-groups": []any{group},
		"unexpected":                            true,
	}
	if err := validateExactMacOSAppGroupEntitlementDictionary(missing, "host", group); err == nil {
		t.Fatal("missing app-group entitlement was accepted")
	}
	if err := validateExactMacOSAppGroupEntitlementDictionary(wrongType, "host", group); err == nil {
		t.Fatal("wrong-type app-group entitlement was accepted")
	}
	if err := validateAbsentMacOSAppGroupEntitlementDictionary(missing, "CLI"); err == nil {
		t.Fatal("unknown nonempty CLI entitlement dictionary was accepted")
	}
	if err := validateExactEntitlementDictionary(extra, valid, "service"); err == nil {
		t.Fatal("extra entitlement key was accepted by an exact policy")
	}
	if _, err := decodeExactCodeEntitlements([]byte("not a property list"), t.TempDir()); err == nil {
		t.Fatal("malformed signed entitlement payload was accepted")
	}
}

func TestExactCodeEntitlementsReadsAdHocSignedEmptyNonemptyAndMissingFixtures(t *testing.T) {
	const group = "B47U2LLKHW.pfsoss"
	root := t.TempDir()
	trueExecutable, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	sign := func(name, entitlementBody string) string {
		t.Helper()
		code := filepath.Join(root, name)
		if err := os.WriteFile(code, trueExecutable, 0o755); err != nil {
			t.Fatal(err)
		}
		args := []string{"--force", "--sign", "-"}
		if entitlementBody != "" {
			entitlementPath := filepath.Join(root, name+".entitlements")
			payload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>` + entitlementBody + `</dict></plist>`
			if err := os.WriteFile(entitlementPath, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--entitlements", entitlementPath)
		}
		args = append(args, code)
		if output, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput(); err != nil {
			t.Fatalf("ad-hoc sign %s: %v (%s)", name, err, output)
		}
		return code
	}

	empty, err := exactCodeEntitlements(sign("empty", ""), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAbsentMacOSAppGroupEntitlementDictionary(empty, "empty"); err != nil {
		t.Fatalf("signed empty fixture was rejected: %v", err)
	}

	groupCode := sign("group", `<key>com.apple.security.application-groups</key>
<array><string>`+group+`</string></array>`)
	groupEntitlements, err := exactCodeEntitlements(groupCode, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExactMacOSAppGroupEntitlementDictionary(
		groupEntitlements, "group", group,
	); err != nil {
		t.Fatalf("signed literal dotted-key fixture was rejected: %v", err)
	}

	missingCode := sign("missing", `<key>com.apple.security.get-task-allow</key><true/>`)
	missingEntitlements, err := exactCodeEntitlements(missingCode, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExactMacOSAppGroupEntitlementDictionary(
		missingEntitlements, "missing", group,
	); err == nil {
		t.Fatal("signed missing app-group fixture was accepted")
	}
	if err := validateAbsentMacOSAppGroupEntitlementDictionary(
		missingEntitlements, "missing",
	); err == nil {
		t.Fatal("signed nonempty fixture was accepted as unentitled")
	}
}

func TestPortableFSDLaunchAgentBinaryPlistUsesSemanticExactValues(t *testing.T) {
	const appID = "dev.portablefs.oss.KitDev"
	path := filepath.Join(t.TempDir(), "portablefsd.plist")
	writeLaunchAgent := func(bundleProgram any, extra bool) {
		t.Helper()
		object := map[string]any{
			"Label":         appID + ".portablefsd",
			"BundleProgram": bundleProgram,
			"RunAtLoad":     true,
			"KeepAlive":     true,
		}
		if extra {
			object["Unexpected"] = true
		}
		data, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(
			"/usr/bin/plutil", "-convert", "binary1", path,
		).CombinedOutput()
		if err != nil {
			t.Fatalf("convert fixture to binary plist: %v (%s)", err, output)
		}
	}

	exactProgram := "Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd"
	writeLaunchAgent(exactProgram, false)
	if err := validatePortableFSDLaunchAgentPlist(path, appID); err != nil {
		t.Fatalf("exact binary LaunchAgent plist rejected: %v", err)
	}

	writeLaunchAgent("Contents/Library/LaunchAgents/Wrong.app/Contents/MacOS/portablefsd", false)
	if err := validatePortableFSDLaunchAgentPlist(path, appID); err == nil {
		t.Fatal("wrong BundleProgram was accepted")
	}

	writeLaunchAgent(true, false)
	if err := validatePortableFSDLaunchAgentPlist(path, appID); err == nil {
		t.Fatal("wrong BundleProgram type was accepted")
	}

	writeLaunchAgent(exactProgram, true)
	if err := validatePortableFSDLaunchAgentPlist(path, appID); err == nil {
		t.Fatal("extra LaunchAgent key was accepted")
	}
}

func TestPortableFSDServiceInfoRequiresTheLayoutMinimumSystemVersion(t *testing.T) {
	const (
		serviceID = "dev.portablefs.oss.KitDev.PortableFSDService"
		version   = "0.2.3"
	)
	path := filepath.Join(t.TempDir(), "Info.plist")
	writeInfo := func(minimumSystemVersion string) {
		t.Helper()
		object := map[string]any{
			"CFBundleDevelopmentRegion":     "en",
			"CFBundleExecutable":            "portablefsd",
			"CFBundleIdentifier":            serviceID,
			"CFBundleInfoDictionaryVersion": "6.0",
			"CFBundleName":                  "PortableFSDService",
			"CFBundlePackageType":           "APPL",
			"CFBundleShortVersionString":    version,
			"CFBundleVersion":               "1",
			"LSBackgroundOnly":              true,
			"LSMinimumSystemVersion":        minimumSystemVersion,
		}
		data, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name    string
		minimum string
		other   string
	}{
		{"production", "26.0", "27.0"},
		{"macOS 27 qualification", "27.0", "26.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeInfo(test.minimum)
			if err := validatePortableFSDServiceInfo(
				path, serviceID, version, test.minimum,
			); err != nil {
				t.Fatalf("exact minimum system version rejected: %v", err)
			}
			if err := validatePortableFSDServiceInfo(
				path, serviceID, version, test.other,
			); err == nil {
				t.Fatalf("%s service Info accepted by %s policy", test.minimum, test.other)
			}
		})
	}
}

func TestValidateStagedBundleRequiresRealExtensionExecutable(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	for _, executable := range []string{
		filepath.Join(app, "Contents", "MacOS", macOSAppExecutable),
		filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath)),
	} {
		if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(
		app,
		"Contents",
		"Extensions",
		macOSExtensionExecutable+".appex",
		"Contents",
		"MacOS",
		macOSExtensionExecutable,
	)
	if err := os.MkdirAll(filepath.Dir(missing), 0o755); err != nil {
		t.Fatal(err)
	}
	err := validateStagedBundleForPublication(app, "1.2.3", "dev.portablefs.test")
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing extension executable error = %v", err)
	}
}

func TestSourceMacOSBundleIdentityRejectsMismatchedExtension(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	addTestBundleIdentity(t, app, "org.example.portablefs")
	writeTestBundleInfo(
		t,
		filepath.Join(
			app,
			"Contents",
			"Extensions",
			macOSExtensionExecutable+".appex",
			"Contents",
			"Info.plist",
		),
		"org.example.counterfeit",
		macOSExtensionExecutable,
	)
	if _, err := sourceMacOSBundleIdentity(app); err == nil {
		t.Fatal("mismatched extension identity was accepted")
	}
}

func TestValidateExistingManagedMacOSAppRejectsCounterfeitDirectory(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "counterfeit")
	const appID = "org.example.portablefs"
	addTestBundleIdentity(t, app, appID)
	err := validateExistingManagedMacOSApp(app, appID)
	if err == nil || !strings.Contains(err.Error(), "remove it explicitly") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestPortableFSMacOSProcessNamesCoverReleaseAndDevRuntime(t *testing.T) {
	for _, name := range []string{
		"PortableFS",
		"PortableFSApp",
		"PortableFSExt",
		"PortableFSKitDev",
		"PortableFSKitMac",
		"PortableFSDev",
		"portablefs",
		"portablefsd",
	} {
		if !isPortableFSMacOSProcessName(name) {
			t.Fatalf("PortableFS process name %q was not recognized", name)
		}
	}
	if isPortableFSMacOSProcessName("unrelated") {
		t.Fatal("unrelated process was classified as PortableFS")
	}
}

func TestDarwinProcessNameUsesTheExactMAXCOMLENContract(t *testing.T) {
	if got := len(unix.ExternProc{}.P_comm); got != 17 {
		t.Fatalf("extern_proc.p_comm bytes = %d, want MAXCOMLEN+1 = 17", got)
	}
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "123456789012345", want: "123456789012345"},
		{name: "PortableFSKitDev", want: "PortableFSKitDev"},
		{name: "PortableFSKitMacOS27Dev", want: "PortableFSKitMac"},
	} {
		if got := truncatedProcessName(test.name); got != test.want {
			t.Fatalf("truncatedProcessName(%q) = %q, want %q", test.name, got, test.want)
		}
	}
	if isPortableFSMacOSProcessName("PortableFSKitDe") {
		t.Fatal("obsolete 15-byte truncation was accepted as a Darwin p_comm")
	}
}

func TestPreparedMacOSProcessInventoryAdmitsTheExactSixteenByteHostOnly(t *testing.T) {
	const installerPID = 40
	const hostPID = 42
	process := func(pid int, name string) unix.KinfoProc {
		var info unix.KinfoProc
		info.Proc.P_pid = int32(pid)
		copy(info.Proc.P_comm[:], name)
		return info
	}
	liveStyle := []unix.KinfoProc{
		process(installerPID, macOSCLIName),
		process(hostPID, "PortableFSKitDev"),
		process(99, "unrelated"),
	}
	if err := rejectPreparedMacOSProcessInventory(liveStyle, installerPID, hostPID); err != nil {
		t.Fatalf("exact 16-byte prepared host was rejected: %v", err)
	}
	withRacer := append(append([]unix.KinfoProc{}, liveStyle...), process(43, "portablefsd"))
	if err := rejectPreparedMacOSProcessInventory(withRacer, installerPID, hostPID); err == nil ||
		!strings.Contains(err.Error(), "pid 43") {
		t.Fatalf("second PortableFS process result = %v", err)
	}
	departedOrReused := []unix.KinfoProc{
		process(installerPID, macOSCLIName),
		process(hostPID, "unrelated"),
	}
	if err := rejectPreparedMacOSProcessInventory(departedOrReused, installerPID, hostPID); err == nil ||
		!strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("departed/reused host result = %v", err)
	}
}

func TestMakeStagedMacOSAppDurableRejectsSymlink(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	if err := os.Symlink("/tmp", filepath.Join(app, "unexpected")); err != nil {
		t.Fatal(err)
	}
	err := makeStagedMacOSAppDurable(app)
	if err == nil || !strings.Contains(err.Error(), "unexpected symlink") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestMakeStagedMacOSAppDurableSyncsRegularTree(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	if err := makeStagedMacOSAppDurable(app); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureOwnedDirectoryTreeRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	err := ensureOwnedDirectoryTree(home, filepath.Join(home, ".local", "bin"))
	if err == nil ||
		(!strings.Contains(err.Error(), "not a real directory") &&
			!strings.Contains(err.Error(), "not a directory")) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstallPathsMustBeStrictlyContainedAndNonOverlapping(t *testing.T) {
	home := t.TempDir()
	if err := validateContainedPath(home, home); err == nil {
		t.Fatal("account home itself was accepted as an install directory")
	}
	appDir := filepath.Join(home, "Applications")
	if !pathsOverlap(appDir, filepath.Join(appDir, "bin")) {
		t.Fatal("nested app/link roots were not detected")
	}
	if pathsOverlap(appDir, filepath.Join(home, ".local", "bin")) {
		t.Fatal("independent app/link roots were reported as overlapping")
	}
}

func TestContainingAppPath(t *testing.T) {
	path := "/Applications/PortableFS.app/Contents/Extensions/PortableFSExt.appex"
	if got := containingAppPath(path); got != "/Applications/PortableFS.app" {
		t.Fatalf("containing app = %q", got)
	}
}

func TestExactCodesignFieldRejectsMissingAndDuplicateIdentity(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef01234567"
	value, err := exactCodesignField(
		"Executable=/tmp/portablefsd\nIdentifier=dev.portablefs.service\nCDHash="+hash+"\n",
		"CDHash",
	)
	if err != nil || value != hash {
		t.Fatalf("exact CDHash = %q, %v", value, err)
	}
	if _, err := exactCodesignField("Identifier=dev.portablefs.service\n", "CDHash"); err == nil {
		t.Fatal("missing CDHash was accepted")
	}
	if _, err := exactCodesignField(
		"CDHash="+hash+"\nCDHash="+hash+"\n",
		"CDHash",
	); err == nil {
		t.Fatal("duplicate CDHash was accepted")
	}
}
