package cli

import (
	"errors"
	"fmt"
	"time"
)

// The supervisor observes terminal daemon state independently of the daemon
// process. Forced detach is best effort kernel enforcement after a confirmed
// terminal/absent owner; it supplies no immediate cache-revocation guarantee.
const fskitStatusProbeInterval = 5 * time.Second
const fskitForcedDetachTimeout = 5 * time.Second

// fskitRevocationProbeResult is one observation of the daemon and attach.
type fskitRevocationProbeResult struct {
	daemonHealthy   bool
	attachPresent   bool
	attachDetaching bool
	sessionTerminal bool
}

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
		interval: fskitStatusProbeInterval,
		lastResult: fskitRevocationProbeResult{
			daemonHealthy: true, attachPresent: true,
		},
	}
}

// fskitRevocationVerdict is one decision to revoke: the machine-readable class
// a supervisor persists into the mount state record, and the sentence it
// prints. The class tokens are the shared cross-platform vocabulary defined in
// mountstate.go, so a Linux and a macOS revocation are readable by one
// consumer.
type fskitRevocationVerdict struct {
	reason   string
	sentence string
}

// observe runs at the supervisor's tick rate and rate-limits real probes to
// the watchdog interval. It reports whether the kernel mount must be revoked
// NOW, and why.
func (w *fskitRevocationWatchdog) observe(now time.Time) (revoke bool, verdict fskitRevocationVerdict) {
	if !w.last.IsZero() && now.Sub(w.last) < w.interval {
		return false, fskitRevocationVerdict{}
	}
	w.last = now
	result := w.probe()
	w.lastResult = result
	return w.decide(result)
}

func (w *fskitRevocationWatchdog) decide(result fskitRevocationProbeResult) (bool, fskitRevocationVerdict) {
	switch {
	case result.daemonHealthy && result.attachPresent && result.sessionTerminal:
		// Definitive on one probe: the daemon itself reports the session can
		// never serve this mount again.
		w.unhealthy = 0
		return true, fskitRevocationVerdict{
			reason:   mountRevokedSessionTerminal,
			sentence: "the v3 authority session is terminal and can never serve this mount again",
		}
	case result.daemonHealthy && result.attachPresent:
		// A detaching attach is owned by a running unmount transaction whose
		// own barrier ends in an exact kernel detach; healthy either way.
		w.unhealthy = 0
		return false, fskitRevocationVerdict{}
	}
	w.unhealthy++
	if w.unhealthy < fskitRevocationConfirmations {
		return false, fskitRevocationVerdict{}
	}
	if !w.lastResult.daemonHealthy {
		return true, fskitRevocationVerdict{
			reason:   mountRevokedDaemonUnreachable,
			sentence: "portablefsd stopped answering; no live daemon owns this mount",
		}
	}
	return true, fskitRevocationVerdict{
		reason:   mountRevokedAttachNotOwned,
		sentence: "portablefsd no longer owns this attach; no live daemon owns this mount",
	}
}

// daemonCanFinalize reports whether the daemon-owned detach barrier is worth
// attempting once the kernel mount is gone. With the daemon or its attach
// gone there is nothing to drain in v3 — every acknowledged write is already
// durable at the authority — and the session ends fenced either way.
//
// It probes NOW rather than trusting the last observation. The kernel mount
// can disappear before the watchdog's first interval ever elapses — daemon
// and extension dying together does exactly that — and the stored observation
// is then still the optimistic initial one. Deciding on it left a supervisor
// retrying a dead daemon's barrier forever: a zombie process guarding a
// mount that no longer existed.
func (w *fskitRevocationWatchdog) daemonCanFinalize() bool {
	w.lastResult = w.probe()
	w.last = time.Now()
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
			// The ref names somebody else's mount now; ours is terminal.
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
	ops := platformUnmountOpsSource(fskitForcedDetachTimeout)
	argv := []string{"/sbin/umount", "-f", st.MountPath}
	out, err := ops.combinedOut(argv[0], argv[1:]...)
	if err != nil {
		return commandUnmountError(argv, out, err)
	}
	return nil
}
