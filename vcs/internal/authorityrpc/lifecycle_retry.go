package authorityrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// LifecycleResult carries the policy verdict separately from its diagnostic.
// An independent failure wins over cancellation, including in joined errors.
type LifecycleDisposition uint8

const (
	LifecycleFailed LifecycleDisposition = iota
	LifecycleCompleted
	LifecycleOvertaken
)

type LifecycleResult struct {
	Disposition LifecycleDisposition
	Err         error
}

type lifecycleOwnerKey struct{}
type LifecycleOwner struct{ overtaken atomic.Bool }

func WithLifecycleOwner(ctx context.Context) (context.Context, *LifecycleOwner) {
	owner := &LifecycleOwner{}
	return context.WithValue(ctx, lifecycleOwnerKey{}, owner), owner
}
func (o *LifecycleOwner) Overtake() {
	if o != nil {
		o.overtaken.Store(true)
	}
}
func (o *LifecycleOwner) Overtaken() bool { return o != nil && o.overtaken.Load() }
func LifecycleOwnerOvertaken(ctx context.Context) bool {
	owner, _ := ctx.Value(lifecycleOwnerKey{}).(*LifecycleOwner)
	return owner.Overtaken()
}

// everyCause requires every branch of a joined error to satisfy the predicate.
// Wrappers add context; they do not erase an independent sibling cause.
func everyCause(err error, accept func(error) bool) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !everyCause(cause, accept) {
				return false
			}
		}
		return true
	}
	if accept(err) {
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return everyCause(wrapped.Unwrap(), accept)
	}
	return false
}

// TransientTransport classifies every cause, never just a matching member.
func TransientTransport(err error) bool {
	return everyCause(err, func(cause error) bool {
		if cause == ErrSessionEnded || cause == ErrAuthorityChanged || cause == ErrTransportBinding || cause == ErrReplayDesynchronized || frameDefect(cause) {
			return false
		}
		if _, joined := cause.(interface{ Unwrap() []error }); joined {
			return false
		}
		if cause == ErrTransportUncertain || cause == io.EOF || cause == io.ErrUnexpectedEOF || cause == context.DeadlineExceeded {
			return true
		}
		_, network := cause.(net.Error)
		return network
	})
}

// LifecycleCompletion is called where cancellation is owned. Drivers consume
// Disposition directly; errors.Is on Err cannot reconstruct this decision.
func LifecycleCompletion(ctx context.Context, err error) LifecycleResult {
	if err == nil && ctx.Err() == nil {
		return LifecycleResult{Disposition: LifecycleCompleted}
	}
	cancellation := ctx.Err()
	if cancellation != nil && (err == nil || everyCause(err, func(e error) bool { return e == cancellation })) {
		if err == nil {
			err = cancellation
		}
		return LifecycleResult{Disposition: LifecycleOvertaken, Err: err}
	}
	return LifecycleResult{Disposition: LifecycleFailed, Err: errors.Join(err, cancellation)}
}

// LifecycleAttemptDisposition describes the next phase of the same logical
// job. A cold/reset attempt is not a transport failure or a failed incarnation.
type LifecycleAttemptDisposition uint8

const (
	AttemptFailed LifecycleAttemptDisposition = iota
	AttemptComplete
	AttemptPending
	AttemptColdReset
	AttemptOvertaken
)

type LifecycleAttempt struct {
	Disposition LifecycleAttemptDisposition
	Err         error
}

func ClassifyLifecycleAttempt(err error) LifecycleAttempt {
	if err == nil {
		return LifecycleAttempt{Disposition: AttemptComplete}
	}
	if TransientTransport(err) {
		return LifecycleAttempt{Disposition: AttemptPending, Err: err}
	}
	return LifecycleAttempt{Disposition: AttemptFailed, Err: err}
}

// RetryLifecycle classifies bounded network attempts. Frontends with an
// explicit cold/reset or readiness phase use RetryLifecycleAttempts directly.
func RetryLifecycle(ctx context.Context, timeout time.Duration, attempt func(context.Context) error) LifecycleResult {
	return RetryLifecycleAttempts(ctx, timeout, func(call context.Context) LifecycleAttempt { return ClassifyLifecycleAttempt(attempt(call)) })
}

func RetryLifecycleAttempts(ctx context.Context, timeout time.Duration, attempt func(context.Context) LifecycleAttempt) LifecycleResult {
	if timeout <= 0 {
		return LifecycleResult{Err: errors.New("authorityrpc: lifecycle attempt needs a positive bound")}
	}
	backoff := 100 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return LifecycleCompletion(ctx, nil)
		}
		call, cancel := context.WithTimeout(ctx, timeout)
		result := attempt(call)
		cancel()
		// Retain independent failure before applying generation cancellation.
		switch result.Disposition {
		case AttemptFailed:
			if result.Err == nil {
				result.Err = errors.New("authorityrpc: lifecycle attempt failed without a cause")
			}
			return LifecycleCompletion(ctx, result.Err)
		case AttemptComplete:
			if result.Err != nil {
				return LifecycleCompletion(ctx, result.Err)
			}
		case AttemptOvertaken:
			return LifecycleResult{Disposition: LifecycleOvertaken, Err: result.Err}
		case AttemptPending, AttemptColdReset:
			// The phase owner has classified these causes as nonterminal.
		default:
			return LifecycleResult{Err: errors.New("authorityrpc: invalid lifecycle attempt disposition")}
		}
		if ctx.Err() != nil {
			return LifecycleCompletion(ctx, nil)
		}
		if result.Disposition == AttemptComplete {
			return LifecycleResult{Disposition: LifecycleCompleted}
		}
		if err := waitLifecycleRetry(ctx, &backoff); err != nil {
			return LifecycleCompletion(ctx, err)
		}
	}
}
func waitLifecycleRetry(ctx context.Context, backoff *time.Duration) error {
	timer := time.NewTimer(*backoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	*backoff = min(time.Second, *backoff*2)
	return nil
}
