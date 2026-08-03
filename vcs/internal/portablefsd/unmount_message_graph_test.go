package portablefsd

// ROUND 21b, DEFECT 2: the in-progress verdict prescribed the caller's own
// command.
//
// Live, `portablefs umount --force` was run seven times over four minutes and
// every one of them answered:
//
//	"unmount is still running after 40s, waiting on the authority drain
//	 barrier ... run portablefs umount --force"
//
// A progress report that prescribes the command the caller is already running
// is not advice; it is a loop with a delay in it.

import (
	"strings"
	"testing"
)

func TestForcedUnmountVerdictNeverPrescribesAnotherForce(t *testing.T) {
	stateDir := privateTestDir(t)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	req := ensureAttachRequest{
		VolumeID:           "vol-forced",
		Branch:             "main",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		MountPath:          "/Volumes/Forced",
	}
	a, err := newRevivedAttach(
		testFSKitAttachRef, attachKey(req.VolumeID, req.Branch, req.MountPath),
		req, stateDir, 1, false, false, "", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	r.byRef[a.ref] = a
	r.byKey[a.key] = a

	forced := r.unmountInProgressVerdict(testFSKitAttachRef, true, nil)
	if forced == nil {
		t.Fatal("no verdict for a forced transaction still running")
	}
	msg := forced.Error()

	// It must not read as "run --force" to somebody who just ran --force.
	if strings.Contains(msg, "or `portablefs umount --force`") {
		t.Fatalf("REPRO: the verdict for a FORCED transaction still prescribes a "+
			"force as the next step, which is the command the caller just ran:\n%s", msg)
	}
	// It must say the force is already durable and running — that is the fact
	// that makes re-running it pointless rather than merely redundant.
	if !strings.Contains(msg, "already durable") {
		t.Fatalf("the forced verdict does not say the force is already in flight:\n%s", msg)
	}
	// And it must name a next step that is genuinely different.
	if !strings.Contains(msg, "portablefs daemon stop") {
		t.Fatalf("the forced verdict names no escalation that differs from re-running "+
			"the same command:\n%s", msg)
	}
	if !strings.Contains(msg, "portablefs recovery resolve") {
		t.Fatalf("the forced verdict does not name the resolution that unblocks an "+
			"offline force refused by a terminal recovery job:\n%s", msg)
	}

	// The NON-forced verdict is unchanged: for a caller who has not forced,
	// --force is a real next step.
	plain := r.unmountInProgressVerdict(testFSKitAttachRef, false, nil)
	if plain == nil || !strings.Contains(plain.Error(), "portablefs umount --force") {
		t.Fatalf("the plain verdict lost its escalation: %v", plain)
	}
}
