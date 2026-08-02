package portablefsd

// ── ROUND 16, DEFECT B: THE MOUNT LIED ABOUT BEING FENCED ───────────────────
//
// Measured live, after a write burst fenced the session: every open, read and
// mkdir on the mount returned ESTALE, and `portablefs mounts --json` reported
//
//	state=attached  lastErr=""  degraded=None  health=live  alive=True
//
// for minutes, until umount finally surfaced "mount session fenced (stale
// generation)" from the final barrier's error.
//
// Nothing was consulting the fence. attach.status() asked exactly two
// predicates, both credential-shaped; the write-back watchdog can only latch
// degraded when it has pending records to be stuck on, and a fenced authority
// lane leaves none; and the CLI's health is pid liveness plus the kernel mount
// table. A mount that answers every request with ESTALE is not attached, and it
// must say so at the moment it stops serving rather than at teardown.

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func TestFencedSessionIsReportedDegradedImmediately(t *testing.T) {
	a, vol, _, _ := newMutationSeqAttach(t)
	a.ref = "fenced-status"
	a.volumeID = "mutation-seq-volume"
	a.mountPath = "/unused-test-mount"

	healthy := a.status()
	if healthy.State != stateString(pfslocal.AttachStateAttached) {
		t.Fatalf("a healthy attach reported state=%q, want attached", healthy.State)
	}
	if vol == nil {
		t.Fatal("the test attach has no volume")
	}

	fenced := false
	a.testSessionFenced = func() bool { return fenced }
	fenced = true

	st := a.status()
	if st.State != stateString(pfslocal.AttachStateDegraded) {
		t.Fatalf("a FENCED mount reported state=%q, want degraded.\n"+
			"Every operation on it returns ESTALE; reporting it as attached sends "+
			"the operator looking for a problem somewhere else while the mount is "+
			"already unrecoverable without a remount.", st.State)
	}
	if st.LastError == "" {
		t.Fatal("a FENCED mount reported an empty lastErr")
	}
	if !strings.Contains(strings.ToUpper(st.LastError), "FENCED") {
		t.Fatalf("the fenced mount's lastErr does not name the fence: %q", st.LastError)
	}
	if !strings.Contains(st.LastError, "ESTALE") {
		t.Fatalf("the fenced mount's lastErr does not say what the operator will "+
			"actually observe: %q", st.LastError)
	}
	if !strings.Contains(st.LastError, "Remount") {
		t.Fatalf("the fenced mount's lastErr does not name the one recovery that "+
			"works: %q", st.LastError)
	}
}

// TestFenceOutranksTheCredentialBranches keeps the ordering honest. A fence is
// the strongest statement available about a mount — nothing short of a remount
// changes it — so it must not be masked by a credential reason that suggests
// `portablefs login` would help.
func TestFenceOutranksTheCredentialBranches(t *testing.T) {
	a, _, _, _ := newMutationSeqAttach(t)
	a.ref = "fenced-precedence"
	a.mountPath = "/unused-test-mount"
	a.testSessionFenced = func() bool { return true }

	st := a.status()
	if st.Credential != "" {
		t.Fatalf("a fenced mount reported credential=%q: the fence is not a "+
			"credential problem and login will not fix it", st.Credential)
	}
	if !strings.Contains(strings.ToUpper(st.LastError), "FENCED") {
		t.Fatalf("a fenced mount reported %q instead of the fence", st.LastError)
	}
}
