package mountenrollment

import (
	"testing"
	"time"
)

// The safe cutoff is wall-derived (deadline from Unix seconds). After the
// cutoff has been reached but before the Run loop latches terminal (e.g. while
// an attempt is in flight), a backward wall correction re-publishes serving
// readiness. The PR's clock owner is the source of such steps.
func TestBackwardCorrectionCannotReadmitObservedCutoff(t *testing.T) {
	base := time.Unix(1_900_000_000, 0)
	now := base
	deadline := base.Add(100 * time.Second)
	p := Permit{Generation: 1, GateSerial: 1}
	inst := RenewalReadiness{State: "installed", InstalledSequence: 1, Permit: p, SessionID: "s", AuthorizationDeadline: deadline}
	r := &Renewer{Now: func() time.Time { return now }, initialized: true, running: true, session: "s", sequence: 2,
		authorizedAt: base, deadline: deadline, installed: inst, readiness: inst, installedDisposition: installationCurrent, permit: p}
	if r.Readiness().State != "installed" {
		t.Fatal("fixture not serving")
	}
	now = deadline.Add(-9 * time.Second) // reached safe cutoff (10% margin = 10s)
	if r.Readiness().State == "installed" {
		t.Fatal("serving after cutoff")
	}
	now = now.Add(-3 * time.Second) // backward wall correction, elapsed time kept advancing
	r.WallCorrected()
	if r.Readiness().State == "installed" {
		t.Fatal("backward wall correction re-published serving readiness after the safe cutoff had been reached")
	}
}
