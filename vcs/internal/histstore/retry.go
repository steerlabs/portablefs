package histstore

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"syscall"
	"time"
)

// RetryPolicy bounds how one store absorbs TRANSIENT backend failures before
// the error surfaces to its caller. It exists because S3-compatible history
// buckets rate-limit bursts: a fold uploads thousands of objects, and a
// single SlowDown (HTTP 503) on a single PUT used to fail the whole
// materialization attempt, which then restarted the fold from scratch and
// re-hammered the same bucket — a per-attempt amplification loop that walked
// a large cut to the dead letter without the store ever being unhealthy.
//
// The retries here are BOUNDED and change nothing about what is written: a
// re-issued PUT sends the identical bytes to the identical exact key, so the
// fold stays deterministic and the read-after-write proof is unaffected. When
// the budget runs out the error surfaces exactly as it did before, and the
// cut-level retry remains the outer loop.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts including the first
	// (default 6). 1 disables retrying entirely.
	MaxAttempts int
	// Base is the first backoff delay (default 250ms); it doubles per
	// attempt up to Cap.
	Base time.Duration
	// Cap bounds one backoff delay (default 8s).
	Cap time.Duration
	// NoJitter sleeps the full computed delay instead of full jitter. It
	// exists for tests that need a deterministic pause; production always
	// jitters so a throttled fleet does not resynchronize on the retry.
	NoJitter bool
}

// Retry defaults: six attempts spend at most 250ms+500ms+1s+2s+4s = 7.75s of
// backoff (about half that on average under full jitter) on top of the
// per-attempt operation deadline — long enough to ride out a throttling
// burst, short enough that a genuinely broken domain still fails the attempt
// promptly.
const (
	defaultRetryAttempts = 6
	defaultRetryBase     = 250 * time.Millisecond
	defaultRetryCap      = 8 * time.Second
)

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaultRetryAttempts
	}
	if p.Base <= 0 {
		p.Base = defaultRetryBase
	}
	if p.Cap <= 0 {
		p.Cap = defaultRetryCap
	}
	if p.Cap < p.Base {
		p.Cap = p.Base
	}
	return p
}

// delay computes the wait after a failed attempt (1-based): exponential
// growth clamped to Cap, then full jitter — uniform in [0, delay] — which is
// what keeps a fleet of workers from retrying in lockstep.
func (p RetryPolicy) delay(attempt int) time.Duration {
	d := p.Cap
	if attempt >= 1 && attempt < 62 {
		if scaled := p.Base << (attempt - 1); scaled > 0 && scaled < p.Cap {
			d = scaled
		}
	}
	if p.NoJitter {
		return d
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}

// RetryEvent describes one absorbed transient failure. Stores hand it to the
// optional observer so a caller with a logger or a metrics registry can
// count throttling without this package depending on either.
type RetryEvent struct {
	Domain  string // failure domain id of the store
	Op      string // HTTP method
	Key     string // exact key
	Attempt int    // the attempt that failed (1-based)
	Status  int    // HTTP status when the failure was a response, else 0
	Delay   time.Duration
	Err     error // transport error, nil when Status carries the failure
}

// RetryStats is one store's running count of absorbed transient failures.
type RetryStats struct {
	// Retries counts backoff retries actually performed.
	Retries int64
	// Exhausted counts operations that spent the whole budget and still
	// failed (each one is an error the caller saw).
	Exhausted int64
}

// RetryReporter is implemented by stores that absorb transient backend
// failures internally. Callers type-assert to it to surface throttling in
// their own logs and metrics; backends with no transient failure mode (the
// local filesystem) simply do not implement it.
type RetryReporter interface {
	RetryStats() RetryStats
}

// retriableStatus reports the HTTP statuses an exact-key operation may
// safely re-issue. 503 (SlowDown / SlowDownWrite on S3-compatible history
// buckets) and 429 are the throttling responses this exists for; 500, 502
// and 504 are the transient server/gateway failures every S3 client treats
// the same way. Everything else — including 403 (credentials/clock), 404
// (proven absence) and 400 (a malformed request) — is deterministic: a retry
// would reproduce it exactly, so it surfaces immediately.
func retriableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retriableTransportError reports the transport failures that are cleanly
// transient: a peer that reset, aborted, or closed the connection before
// answering. Deliberately NOT retried:
//
//   - context cancellation — a fenced claim must stop instantly;
//   - deadline expiry (the per-attempt operation timeout, or the caller's
//     own deadline) — re-issuing would multiply an already long timeout;
//   - DNS/TLS/refused-connection failures — a misconfigured or down endpoint
//     is operator work, not a burst to ride out.
func retriableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch {
	case errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EPIPE):
		return true
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// net/http surfaces a server that closed the connection before
		// responding (including a dropped keep-alive) as EOF.
		return true
	}
	return false
}

// sleepBackoff waits out one backoff delay and aborts the instant ctx is
// done. Fencing correctness depends on this: a worker whose lease is lost
// mid-backoff must stop immediately, never after the remaining delay.
func sleepBackoff(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
