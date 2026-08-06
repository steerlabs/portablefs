package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// The macOS 26 revocation watchdog.
//
// A strict mount commits to a repair budget: when that budget elapses without
// an authority round trip, the mount must make its own kernel's cached state
// unservable. Linux FUSE self-revokes — Mount.revoke withdraws every binding
// and aborts the connection. macOS 26 FSKit exposes no API that proves
// already-cached kernel state became unservable, so the Swift runner can only
// detect and terminate; pages the kernel already holds keep answering reads
// on open descriptors with no callback the extension could refuse.
//
// The one mechanism macOS does provide is forced unmount: revoking the
// covered vnodes at the VFS layer dead-ends every cached page, which is
// exactly the semantic the contract needs. The forced unmount cannot live in
// portablefsd — a dead daemon cannot unmount anything — so it lives here, in
// the per-mount supervisor process, which is already daemon-independent,
// already owns the mount's state record, and already watches the kernel
// mount table. The supervisor probes the daemon at one third of the repair
// budget (the same ratio the coherence contract fixes for the frontend's
// authority-contact watchdog) and force-unmounts the exact kernel mount when
// the session is terminal, the daemon is gone, or the daemon no longer owns
// the attach.
//
// What this bounds: the stale window of a cached read on an already-open
// descriptor after the daemon dies is at most probe-confirmation time plus
// one forced unmount, which fits inside the authority's one-budget fencing
// grace. What it cannot bound — bytes a process already copied into its own
// memory — no platform bounds; Linux cannot either.

// fskitRevocationProbeResult is one observation of the daemon and attach.
type fskitRevocationProbeResult struct {
	daemonHealthy   bool
	attachPresent   bool
	attachDetaching bool
	sessionTerminal bool
}

// fskitRevocationConfirmations is how many consecutive failed probes prove
// the daemon (or its ownership of the attach) is gone rather than briefly
// busy. Two probes at a third of the budget keep detection under one budget.
const fskitRevocationConfirmations = 2

type fskitRevocationWatchdog struct {
	probe    func() fskitRevocationProbeResult
	interval time.Duration
	last     time.Time
	// unhealthy counts consecutive probes with the daemon or attach missing.
	unhealthy int
	// lastResult is the newest observation, for the caller's finalization
	// decision after the kernel mount is gone.
	lastResult fskitRevocationProbeResult
}

func newFSKitRevocationWatchdog(probe func() fskitRevocationProbeResult) *fskitRevocationWatchdog {
	return &fskitRevocationWatchdog{
		probe:    probe,
		interval: mountv3.RepairBudget / 3,
		lastResult: fskitRevocationProbeResult{
			daemonHealthy: true, attachPresent: true,
		},
	}
}

// observe runs at the supervisor's tick rate and rate-limits real probes to
// the watchdog interval. It reports whether the kernel mount must be revoked
// NOW, and why.
func (w *fskitRevocationWatchdog) observe(now time.Time) (revoke bool, reason string) {
	if !w.last.IsZero() && now.Sub(w.last) < w.interval {
		return false, ""
	}
	w.last = now
	result := w.probe()
	w.lastResult = result
	return w.decide(result)
}

func (w *fskitRevocationWatchdog) decide(result fskitRevocationProbeResult) (bool, string) {
	switch {
	case result.daemonHealthy && result.attachPresent && result.sessionTerminal:
		// Definitive on one probe: the daemon itself reports the session can
		// never repair the kernel's caches again.
		w.unhealthy = 0
		return true, "the v3 authority session is terminal and can never repair this kernel's caches again"
	case result.daemonHealthy && result.attachPresent:
		// A detaching attach is owned by a running unmount transaction whose
		// own barrier ends in an exact kernel detach; healthy either way.
		w.unhealthy = 0
		return false, ""
	}
	w.unhealthy++
	if w.unhealthy < fskitRevocationConfirmations {
		return false, ""
	}
	if !w.lastResult.daemonHealthy {
		return true, "portablefsd stopped answering; nothing can repair this kernel's caches"
	}
	return true, "portablefsd no longer owns this attach; nothing can repair this kernel's caches"
}

// daemonCanFinalize reports whether the daemon-owned detach barrier is worth
// attempting once the kernel mount is gone. With the daemon or its attach
// gone there is nothing to drain in v3 — every acknowledged write is already
// durable at the authority — and the session ends fenced either way.
func (w *fskitRevocationWatchdog) daemonCanFinalize() bool {
	return w.lastResult.daemonHealthy && w.lastResult.attachPresent
}

// fskitRevocationProber builds the production probe against the daemon's
// control socket. The probe timeout is deliberately far below the watchdog
// interval so a wedged daemon reads as unhealthy rather than stalling the
// supervisor loop.
func fskitRevocationProber(controlSock string, st *mountState) func() fskitRevocationProbeResult {
	return func() fskitRevocationProbeResult {
		ctl := newFsdControl(controlSock)
		ctl.httpClient.Timeout = 2 * time.Second
		attach, err := recordedFskitAttachStatus(ctl, st)
		switch {
		case err != nil && errors.Is(err, errFskitAttachIdentityMismatch):
			// The ref names somebody else's mount now; ours is unrepairable.
			return fskitRevocationProbeResult{daemonHealthy: true}
		case err != nil:
			return fskitRevocationProbeResult{}
		case attach == nil:
			return fskitRevocationProbeResult{daemonHealthy: true}
		default:
			return fskitRevocationProbeResult{
				daemonHealthy:   true,
				attachPresent:   true,
				attachDetaching: attach.State == "detaching",
				sessionTerminal: attach.SessionTerminal,
			}
		}
	}
}

// forceRevokeFSKitKernelMount makes the exact recorded kernel mount
// unservable with a forced unmount: MNT_FORCE revokes the covered vnodes, so
// a subsequent read on an already-open descriptor fails instead of answering
// from cache. Identity is re-proven from the kernel mount table immediately
// before the detach — never through the filesystem — so a reused path can
// never make this revoke somebody else's mount. The caller observes absence
// through its own next mount-table check.
func forceRevokeFSKitKernelMount(st *mountState) error {
	present, err := recordedKernelMountPresent(st)
	if err != nil {
		return fmt.Errorf("refuse forced revocation because exact kernel identity is not proven: %w", err)
	}
	if !present {
		return nil
	}
	ops := platformUnmountOpsSource()
	argv := []string{"/sbin/umount", "-f", st.MountPath}
	out, err := ops.combinedOut(argv[0], argv[1:]...)
	if err != nil {
		return commandUnmountError(argv, out, err)
	}
	return nil
}
