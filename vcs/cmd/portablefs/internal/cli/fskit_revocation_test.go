package cli

import (
	"testing"
	"time"
)

func watchdogWithResults(results ...fskitRevocationProbeResult) *fskitRevocationWatchdog {
	i := 0
	w := newFSKitRevocationWatchdog(func() fskitRevocationProbeResult {
		r := results[i%len(results)]
		i++
		return r
	})
	return w
}

func advanceObserve(t *testing.T, w *fskitRevocationWatchdog, steps int) (bool, string) {
	t.Helper()
	now := w.last
	if now.IsZero() {
		now = time.Unix(1000, 0)
	}
	var revoke bool
	var reason string
	for s := 0; s < steps; s++ {
		now = now.Add(w.interval)
		revoke, reason = w.observe(now)
		if revoke {
			return revoke, reason
		}
	}
	return revoke, reason
}

func TestRevocationWatchdogRunsAtOneThirdOfTheRepairBudget(t *testing.T) {
	probes := 0
	w := newFSKitRevocationWatchdog(func() fskitRevocationProbeResult {
		probes++
		return fskitRevocationProbeResult{daemonHealthy: true, attachPresent: true}
	})
	base := time.Unix(1000, 0)
	// Ticks far faster than the interval must not multiply probes.
	for i := 0; i < 100; i++ {
		w.observe(base.Add(time.Duration(i) * 200 * time.Millisecond))
	}
	elapsed := 99 * 200 * time.Millisecond
	want := int(elapsed/w.interval) + 1
	if probes != want {
		t.Fatalf("probes = %d over %v, want %d at interval %v", probes, elapsed, want, w.interval)
	}
}

func TestRevocationWatchdogRevokesATerminalSessionOnOneProbe(t *testing.T) {
	w := watchdogWithResults(fskitRevocationProbeResult{
		daemonHealthy: true, attachPresent: true, sessionTerminal: true,
	})
	revoke, reason := advanceObserve(t, w, 1)
	if !revoke {
		t.Fatal("a terminal session was not revoked on its first probe; every extra interval is served stale cache")
	}
	if reason == "" {
		t.Fatal("a revocation carried no reason")
	}
}

func TestRevocationWatchdogConfirmsDaemonDeathBeforeRevoking(t *testing.T) {
	w := watchdogWithResults(fskitRevocationProbeResult{})
	if revoke, _ := advanceObserve(t, w, 1); revoke {
		t.Fatal("one failed probe revoked the mount; a briefly busy daemon must not cost the kernel mount")
	}
	if revoke, _ := advanceObserve(t, w, 1); !revoke {
		t.Fatalf("%d consecutive failed probes did not revoke", fskitRevocationConfirmations)
	}
}

func TestRevocationWatchdogRevokesWhenTheDaemonForgotTheAttach(t *testing.T) {
	w := watchdogWithResults(fskitRevocationProbeResult{daemonHealthy: true})
	revoke, reason := advanceObserve(t, w, fskitRevocationConfirmations)
	if !revoke {
		t.Fatal("a daemon that no longer owns the attach cannot repair the kernel; the mount must be revoked")
	}
	if reason == "" {
		t.Fatal("a revocation carried no reason")
	}
}

func TestRevocationWatchdogRecoversAfterATransientFailure(t *testing.T) {
	w := watchdogWithResults(
		fskitRevocationProbeResult{},
		fskitRevocationProbeResult{daemonHealthy: true, attachPresent: true},
		fskitRevocationProbeResult{},
	)
	// fail, recover, fail: the counter must reset on the healthy probe.
	if revoke, _ := advanceObserve(t, w, 3); revoke {
		t.Fatal("non-consecutive failures accumulated into a revocation")
	}
}

func TestRevocationWatchdogTreatsADetachingAttachAsHealthy(t *testing.T) {
	w := watchdogWithResults(fskitRevocationProbeResult{
		daemonHealthy: true, attachPresent: true, attachDetaching: true,
	})
	if revoke, _ := advanceObserve(t, w, 3); revoke {
		t.Fatal("a running daemon-owned unmount transaction was revoked out from under itself")
	}
}

func TestRevocationWatchdogFinalizationFollowsTheLastObservation(t *testing.T) {
	w := watchdogWithResults(fskitRevocationProbeResult{})
	if !w.daemonCanFinalize() {
		t.Fatal("before any probe the daemon barrier must still be attempted")
	}
	advanceObserve(t, w, 1)
	if w.daemonCanFinalize() {
		t.Fatal("with the daemon gone the barrier must not be retried forever")
	}
}
