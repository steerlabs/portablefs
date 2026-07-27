package cli

import (
	"errors"
	"sync"
	"time"
)

// credentialRejected reports whether an error is a DEFINITIVE control-plane
// credential rejection — the manager (or API) refusing this client's identity
// outright, as opposed to a lease that merely expired or an outage. This is
// what a key revocation looks like from the mount daemon: renewals turn
// terminal and every re-acquire answers 401/403 or the typed
// ACCESS_LEASE_UNAUTHORIZED envelope.
func credentialRejected(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return false
	}
	return he.Status == 401 || he.Status == 403 || he.Code == "ACCESS_LEASE_UNAUTHORIZED"
}

// credentialWatch turns the stream of credential outcomes a mount observes
// (lease renewals, lease re-acquires, session re-resolves) into edge-triggered
// state: ONE log line when credentials become rejected, one when they
// recover, and a persisted status transition for `portablefs mounts`. Without
// it a revoked key degrades the filesystem silently: bare EIO to
// applications, an empty mount log, and `mounts` still claiming "live".
type credentialWatch struct {
	logf     func(format string, args ...any)
	onChange func(status string, atMs int64)
	now      func() time.Time

	mu       sync.Mutex
	degraded bool
}

func newCredentialWatch(logf func(string, ...any), onChange func(string, int64)) *credentialWatch {
	return &credentialWatch{logf: logf, onChange: onChange, now: time.Now}
}

// noteRejected records a definitive credential rejection. Only the first
// rejection of a degraded episode logs and persists; repeats are silent so a
// renew loop cannot spam the mount log.
func (w *credentialWatch) noteRejected(err error) {
	if w == nil {
		return
	}
	w.mu.Lock()
	first := !w.degraded
	w.degraded = true
	w.mu.Unlock()
	if !first {
		return
	}
	at := w.now()
	if w.logf != nil {
		w.logf("credentials revoked or expired (%v); filesystem access is degraded until re-authenticated — run `portablefs login` and remount", err)
	}
	if w.onChange != nil {
		w.onChange(mountStatusCredentialExpired, at.UnixMilli())
	}
}

// noteHealthy records a credential success. If the mount was degraded this is
// the recovery edge: log once and clear the persisted status.
func (w *credentialWatch) noteHealthy() {
	if w == nil {
		return
	}
	w.mu.Lock()
	recovered := w.degraded
	w.degraded = false
	w.mu.Unlock()
	if !recovered {
		return
	}
	at := w.now()
	if w.logf != nil {
		w.logf("credentials accepted again; filesystem access restored")
	}
	if w.onChange != nil {
		w.onChange("", at.UnixMilli())
	}
}
