package cli

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// credentialWatch turns a terminal lease-renewal outcome into ONE log line
// and a persisted status transition for `portablefs mounts`. Without
// it a revoked key degrades the filesystem silently: bare EIO to
// applications, an empty mount log, and `mounts` still claiming "live".
type credentialWatch struct {
	logf     func(format string, args ...any)
	onChange func(status string, atMs int64)
	now      func() time.Time

	once sync.Once
}

func newCredentialWatch(logf func(string, ...any), onChange func(string, int64)) *credentialWatch {
	return &credentialWatch{logf: logf, onChange: onChange, now: time.Now}
}

// noteRejected records a definitive credential rejection once.
func (w *credentialWatch) noteRejected(err error) {
	if w == nil {
		return
	}
	w.once.Do(func() {
		at := w.now()
		if w.logf != nil {
			w.logf("%s", leaseEndMessage(err))
		}
		if w.onChange != nil {
			w.onChange(mountStatusCredentialExpired, at.UnixMilli())
		}
	})
}

// ── A LEASE THAT ENDED IS NOT A CREDENTIAL THAT WAS REVOKED ──────────────────
//
// The keeper reaches this line for five typed answers, and ONE of them is
// about the account credential:
//
//	401 ACCESS_LEASE_UNAUTHORIZED  our token no longer authenticates — log in
//	404 ACCESS_LEASE_NOT_FOUND     )
//	409 ACCESS_LEASE_REVOKED       ) the LEASE ended. The saved account
//	409 ACCESS_LEASE_RELEASED      ) credential may be perfectly good; a lease
//	410 ACCESS_LEASE_EXPIRED       ) is minted by a MOUNT, not by a login
//
// plus a renewal still unresolved at the lease's own expiry, which is the last
// four again. All five rendered as "credentials revoked or expired ... run
// `portablefs login` and remount", so four out of five sent the operator to
// re-authenticate a credential that was not the problem, and buried the action
// that was (remount) at the end of the sentence as an afterthought.
func leaseEndMessage(err error) string {
	var he *httpError
	if errors.As(err, &he) && he.Code == "ACCESS_LEASE_UNAUTHORIZED" {
		return fmt.Sprintf("credentials revoked or expired (%v); filesystem access "+
			"is degraded until re-authenticated — run `portablefs login` and remount", err)
	}
	return fmt.Sprintf("this mount's access lease ENDED and cannot be renewed (%v); "+
		"filesystem access is degraded until the mount is re-established — REMOUNT "+
		"this path. A lease is minted by a mount, so `portablefs login` does not "+
		"renew one and will not change this; re-run it only if `portablefs doctor` "+
		"reports the saved account credential itself rejected", err)
}

// ── THE CREDENTIAL HANDOFF IS A TWO-PARTY TRANSITION ────────────────────────
//
// An FSKit mount's data plane lives in portablefsd, not in this process, so a
// renewed or rotated access-lease credential is only actually in force once the
// DAEMON has it. That made the push a two-party transition — committed at the
// manager, then delivered and acknowledged at the daemon — and it was written
// as one fire-and-forget line inside the lease keeper's update hook:
//
//	if err := ctl.setCredential(...); err != nil { fmt.Fprintf(stderr, ...) }
//
// The error went to stderr and was dropped, and it ran AFTER the keeper had
// already committed the new lease and cleared its unresolved flag. So a failed
// push left the keeper believing the daemon held a credential it had never
// received: the manager's ledger moved on, the daemon went on presenting the
// superseded token, and the first anybody heard of it was the authority
// refusing a handshake — by which time the mount was fenced and its backlog
// stranded.
//
// It failed routinely under load, too, and not by chance: the push takes the
// daemon's registry mutation lock, which an unmount transaction holds across an
// entire drain barrier, so a flooded mount burned the push's whole control
// timeout and dropped it.
//
// So delivery is retried until the daemon ACKNOWLEDGES it or the attempt
// reaches a definite end, and "definite end" is bounded by the credential's OWN
// expiry — the same house rule the lease keeper follows for renewal and
// release. Past that expiry the credential is worthless and redelivering it
// cannot help anyone; that is a definite failure, reported, never a silent one.
type credentialHandoff struct {
	// push performs ONE delivery attempt. A nil error is the daemon's
	// acknowledgement; anything else is an undelivered credential.
	push func(leaseState) error
	logf func(format string, args ...any)
	// onFailed is called once per credential that could not be delivered
	// before its own expiry.
	onFailed func(error)
	now      func() time.Time
	after    func(time.Duration) <-chan time.Time

	mu sync.Mutex
	// want is the newest COMMITTED credential and wantSeq its monotone
	// sequence; ackSeq is the newest sequence the daemon has acknowledged (or
	// that has definitely failed). A newer credential supersedes an
	// undelivered older one: the daemon only ever needs the current one.
	want     leaseState
	wantSeq  uint64
	ackSeq   uint64
	reported uint64 // wantSeq whose failure has already been logged
	wake     chan struct{}
}

const (
	handoffRetryMin = 250 * time.Millisecond
	handoffRetryMax = 5 * time.Second
)

func newCredentialHandoff(push func(leaseState) error, logf func(string, ...any), onFailed func(error)) *credentialHandoff {
	return &credentialHandoff{
		push:     push,
		logf:     logf,
		onFailed: onFailed,
		now:      time.Now,
		after:    time.After,
		wake:     make(chan struct{}, 1),
	}
}

// deliver publishes a committed credential for handoff. It NEVER blocks on the
// daemon: the lease keeper's renewal path must not queue behind data-plane
// work, which is the same disease this fix exists to cure one layer down.
func (h *credentialHandoff) deliver(lease leaseState) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.wantSeq++
	h.want = lease
	h.mu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// outstanding reports whether a committed credential has yet to be
// acknowledged by the daemon.
func (h *credentialHandoff) outstanding() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.wantSeq != 0 && h.wantSeq != h.ackSeq
}

// run drives delivery until ctx is cancelled.
func (h *credentialHandoff) run(ctx context.Context) {
	if h == nil {
		return
	}
	backoff := handoffRetryMin
	for {
		h.mu.Lock()
		want, seq, ack := h.want, h.wantSeq, h.ackSeq
		h.mu.Unlock()
		if seq == 0 || seq == ack {
			// Nothing outstanding: wait for the next commit.
			select {
			case <-ctx.Done():
				return
			case <-h.wake:
				backoff = handoffRetryMin
			}
			continue
		}
		if err := h.push(want); err == nil {
			h.settle(seq)
			backoff = handoffRetryMin
			continue
		} else if !h.now().Before(time.UnixMilli(want.ExpiresAtMs)) {
			// DEFINITE FAILURE. The credential reached its own expiry
			// undelivered; nothing this loop sends can make it useful now.
			h.reportFailure(fmt.Errorf(
				"access lease %s reached its own expiry before portablefsd acknowledged it: %w",
				want.AccessLeaseID, err))
			h.settle(seq)
			continue
		} else if h.claimReport(seq) && h.logf != nil {
			// One line per credential, not one per attempt.
			h.logf("portablefsd has not acknowledged the renewed access credential yet; retrying until it does or the credential expires: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-h.wake:
			backoff = handoffRetryMin
			continue
		case <-h.after(backoff):
		}
		if backoff *= 2; backoff > handoffRetryMax {
			backoff = handoffRetryMax
		}
	}
}

func (h *credentialHandoff) settle(seq uint64) {
	h.mu.Lock()
	if h.ackSeq < seq {
		h.ackSeq = seq
	}
	h.mu.Unlock()
}

// claimReport reports whether seq's ongoing failure still needs a log line.
func (h *credentialHandoff) claimReport(seq uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reported >= seq {
		return false
	}
	h.reported = seq
	return true
}

func (h *credentialHandoff) reportFailure(err error) {
	if h.logf != nil {
		h.logf("access credential handoff to portablefsd FAILED definitively: %v", err)
	}
	if h.onFailed != nil {
		h.onFailed(err)
	}
}
