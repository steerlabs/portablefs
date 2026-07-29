package cli

import (
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
			w.logf("credentials revoked or expired (%v); filesystem access is degraded until re-authenticated — run `portablefs login` and remount", err)
		}
		if w.onChange != nil {
			w.onChange(mountStatusCredentialExpired, at.UnixMilli())
		}
	})
}
