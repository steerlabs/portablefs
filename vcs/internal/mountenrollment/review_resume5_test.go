package mountenrollment

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// A managed install races Park: the remote install succeeds but the permit
// closed first (ErrPermitClosedInstallation from the Linux installer). The driver
// then Resumes under a new permit almost immediately (short suspend). How long
// until Readiness publishes again?
func TestO5ResumeAfterPermitObsoleteInstallDelay(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	now := start
	var nowMu atomic.Pointer[time.Time]
	nowMu.Store(&now)
	clockNow := func() time.Time { return *nowMu.Load() }
	jump := func(to time.Time) {
		if to.After(clockNow()) {
			x := to
			nowMu.Store(&x)
		}
	}
	var serial atomic.Uint64
	serial.Store(1)
	r := &Renewer{Managed: true, Now: clockNow, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		return grantFor(s, n, clockNow().Add(10*time.Minute).Truncate(time.Second)), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	phase := 0
	var resumedAt, nextAfterResume time.Time
	var afterResume, beforePark RenewalReadiness
	var installsAtResume uint64
	var installs atomic.Uint64
	r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
		if c.Err() != nil {
			return c.Err()
		}
		switch {
		case installs.Load() == 2 && phase == 0:
			phase = 1
			beforePark = r.Readiness()
			if err := r.Park(context.Background()); err != nil {
				t.Fatal(err)
			}
			serial.Store(2)
			jump(clockNow().Add(30 * time.Second)) // short suspend
			if err := r.Resume(Permit{GateSerial: 2}); err != nil {
				t.Fatal(err)
			}
			resumedAt = clockNow()
			afterResume = r.Readiness()
			installsAtResume = installs.Load()
			return nil
		case phase == 1:
			phase = 2
			nextAfterResume = target
			cancel()
			return c.Err()
		}
		if !target.IsZero() {
			jump(target)
		}
		return nil
	}
	if err := r.Resume(Permit{GateSerial: 1}); err != nil {
		t.Fatal(err)
	}
	err := r.Run(ctx, "session", start.Add(5*time.Minute), func(_ context.Context, _ string, seq uint64, _ []byte) (time.Time, error) {
		installs.Store(seq)
		d := time.Unix(clockNow().Add(10*time.Minute).Truncate(time.Second).Unix(), 0)
		if seq == 2 {
			return d, ErrPermitClosedInstallation // permit closed while the remote install ran
		}
		return d, nil
	})
	wait := nextAfterResume.Sub(resumedAt)
	t.Logf("permit-obsolete install then short suspend: run=%v beforePark=%s/%d afterResume=%s/%d installsAtResume=%d nextAttemptAfterResume=+%v",
		err, beforePark.State, beforePark.InstalledSequence, afterResume.State, afterResume.InstalledSequence, installsAtResume, wait)
	if beforePark.State != "pending" || afterResume.State != "installed" || afterResume.InstalledSequence != 2 || afterResume.Permit.GateSerial != 2 || installsAtResume != 2 {
		t.Fatalf("permit-closed success must republish seq 2 immediately: before=%+v after=%+v installs=%d", beforePark, afterResume, installsAtResume)
	}

}

func TestPermitClosedResumeRequiresExactSafeProofAndLaterPermit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name   string
		mutate func(*Renewer)
		permit Permit
		ready  bool
	}{
		{"later-current-permit", func(*Renewer) {}, Permit{GateSerial: 2}, true},
		{"same-permit", func(*Renewer) {}, Permit{GateSerial: 1}, false},
		{"session-changed-outcome", func(r *Renewer) { r.installedDisposition = installationSessionChanged }, Permit{GateSerial: 2}, false},
		{"foreign-session", func(r *Renewer) { r.installed.SessionID = "foreign" }, Permit{GateSerial: 2}, false},
		{"wrong-deadline", func(r *Renewer) { r.installed.AuthorizationDeadline = r.deadline.Add(time.Second) }, Permit{GateSerial: 2}, false},
		{"zero-sequence", func(r *Renewer) { r.installed.InstalledSequence = 0 }, Permit{GateSerial: 2}, false},
		{"safety-cutoff", func(r *Renewer) { r.Now = func() time.Time { return r.deadline.Add(-time.Second) } }, Permit{GateSerial: 2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := Permit{GateSerial: 1}
			deadline := now.Add(10 * time.Minute)
			proof := RenewalReadiness{State: "installed", Permit: old, InstalledSequence: 2, SessionID: "session", AuthorizationDeadline: deadline}
			r := &Renewer{Managed: true, running: true, parked: true, session: "session", installed: proof, readiness: RenewalReadiness{State: "pending", Permit: old}, installedDisposition: installationPermitClosed, deadline: deadline, authorizedAt: now, Now: func() time.Time { return now }, CheckPermit: func(p Permit) bool { return p == tc.permit }}
			tc.mutate(r)
			if err := r.Resume(tc.permit); err != nil {
				t.Fatal(err)
			}
			got := r.Readiness()
			if (got.State == "installed") != tc.ready {
				t.Fatalf("unexpected proof: %+v", got)
			}
			if tc.ready && (!got.Ready(false, tc.permit, "session", deadline) || got.InstalledSequence != 2) {
				t.Fatalf("wrong proof republished: %+v", got)
			}
		})
	}
}
