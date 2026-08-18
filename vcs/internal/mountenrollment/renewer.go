package mountenrollment

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type GrantSource interface {
	Refresh(context.Context, string, uint64) (controlplane.MountAuthorization, error)
}

type GrantInstaller func(context.Context, string, uint64, []byte) (time.Time, error)

type RenewalStatus struct {
	AuthorizationDeadline time.Time
	LastSuccess           time.Time
	NextAttempt           time.Time
	Sequence              uint64
	ConsecutiveFailures   uint64
	LastError             string
}

type RenewalEventKind string

const (
	RenewalScheduled RenewalEventKind = "scheduled"
	RenewalSucceeded RenewalEventKind = "succeeded"
	RenewalRetrying  RenewalEventKind = "retrying"
	RenewalDenied    RenewalEventKind = "denied"
	RenewalCutoff    RenewalEventKind = "cutoff"
	RenewalStopped   RenewalEventKind = "stopped"
)

// RenewalEvent is one fact emitted by the single renewal owner. Status is a
// complete snapshot after that fact, never a sparse collection of fields that
// each platform has to interpret differently.
type RenewalEvent struct {
	Kind       RenewalEventKind
	ObservedAt time.Time
	Status     RenewalStatus
}

type Renewer struct {
	Source  GrantSource
	Now     func() time.Time
	Observe func(RenewalEvent)
	Timeout time.Duration
	// MinimumSafetyMargin reserves enough time for a platform owner to make
	// cached kernel state unservable after renewal fails. FSKit sets this to its
	// full repair budget; Linux uses the default five-second floor.
	MinimumSafetyMargin time.Duration
}

// Run owns the one monotonic reauthorization sequence for a mount. It refreshes
// immediately, then once near the middle of each installed grant. A failed
// request is retried with the same sequence and therefore the same durable
// Manager response until the safe cutoff, at which point the mount owner must
// fail closed while the last authorization is still valid.
func (renewer *Renewer) Run(ctx context.Context, sessionID string, initialDeadline time.Time, install GrantInstaller) error {
	if renewer == nil || renewer.Source == nil || sessionID == "" || !initialDeadline.After(renewer.now()) || install == nil {
		return errors.New("complete automatic mount renewal configuration is required")
	}
	timeout := renewer.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := initialDeadline
	authorizedAt := renewer.now()
	var sequence uint64 = 1
	status := RenewalStatus{AuthorizationDeadline: deadline, Sequence: sequence}
	stop := func() error {
		status.NextAttempt = time.Time{}
		status.ConsecutiveFailures = 0
		status.LastError = ""
		renewer.observe(RenewalStopped, status)
		return nil
	}
	for {
		if ctx.Err() != nil {
			return stop()
		}
		status.AuthorizationDeadline = deadline
		status.Sequence = sequence
		if sequence > 1 {
			next := refreshTime(renewer.now(), deadline, sessionID, sequence)
			status.NextAttempt = next
			status.ConsecutiveFailures = 0
			status.LastError = ""
			renewer.observe(RenewalScheduled, status)
			if err := waitUntil(ctx, renewer.now, next); err != nil {
				return stop()
			}
		}
		backoff := 500 * time.Millisecond
		var failures uint64
		cutoff := safeCutoff(authorizedAt, deadline, renewer.MinimumSafetyMargin)
		for {
			if ctx.Err() != nil {
				return stop()
			}
			now := renewer.now()
			if !now.Before(cutoff) {
				err := errors.New("automatic mount reauthorization reached its safe cutoff")
				status.NextAttempt = time.Time{}
				status.ConsecutiveFailures = failures
				status.LastError = boundedError(err)
				renewer.observe(RenewalCutoff, status)
				return err
			}
			attemptDeadline := now.Add(timeout)
			if cutoff.Before(attemptDeadline) {
				attemptDeadline = cutoff
			}
			attemptCtx, cancel := context.WithDeadline(ctx, attemptDeadline)
			grant, err := renewer.Source.Refresh(attemptCtx, sessionID, sequence)
			if err == nil {
				var installed time.Time
				installed, err = install(attemptCtx, grant.Capability, sequence, []byte(grant.ClientCertificatePEM))
				if err == nil {
					if installed.Unix() != grant.ExpiresUnix || !installed.After(renewer.now()) {
						err = errors.New("authority installed a deadline different from the Manager grant")
					} else {
						deadline = installed
						authorizedAt = renewer.now()
					}
				}
			}
			cancel()
			if ctx.Err() != nil {
				return stop()
			}
			if err == nil {
				status.AuthorizationDeadline = deadline
				status.LastSuccess = authorizedAt
				status.NextAttempt = time.Time{}
				status.ConsecutiveFailures = 0
				status.LastError = ""
				renewer.observe(RenewalSucceeded, status)
				sequence++
				break
			}
			if errors.Is(err, ErrDefinitiveDenial) {
				resultErr := fmt.Errorf("automatic mount enrollment was denied: %w", err)
				status.NextAttempt = time.Time{}
				status.ConsecutiveFailures = failures + 1
				status.LastError = boundedError(resultErr)
				renewer.observe(RenewalDenied, status)
				return resultErr
			}
			failures++
			now = renewer.now()
			if !now.Add(backoff).Before(cutoff) {
				resultErr := fmt.Errorf("automatic mount reauthorization could not complete before the safe cutoff: %w", err)
				status.NextAttempt = time.Time{}
				status.ConsecutiveFailures = failures
				status.LastError = boundedError(resultErr)
				renewer.observe(RenewalCutoff, status)
				return resultErr
			}
			next := now.Add(backoff)
			status.NextAttempt = next
			status.ConsecutiveFailures = failures
			status.LastError = boundedError(err)
			renewer.observe(RenewalRetrying, status)
			if err := waitUntil(ctx, renewer.now, next); err != nil {
				return stop()
			}
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(strings.ReplaceAll(strings.ToValidUTF8(err.Error(), "?"), "\x00", "?"))
	if value == "" {
		value = "automatic renewal failed"
	}
	for len(value) > 1024 {
		_, size := utf8.DecodeLastRuneInString(value)
		if size == 0 {
			return "renewal error exceeded its presentation bound"
		}
		value = value[:len(value)-size]
	}
	return value
}

func (renewer *Renewer) now() time.Time {
	if renewer.Now != nil {
		return renewer.Now()
	}
	return time.Now()
}

func (renewer *Renewer) observe(kind RenewalEventKind, status RenewalStatus) {
	if renewer.Observe != nil {
		renewer.Observe(RenewalEvent{Kind: kind, ObservedAt: renewer.now(), Status: status})
	}
}

func refreshTime(now, deadline time.Time, sessionID string, sequence uint64) time.Time {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return now
	}
	// A stable per-session offset spreads many mounts over the middle 20% of
	// their windows without a global random source or timer polling.
	seed := sha256.Sum256([]byte("schedule\x00" + sessionID + "\x00" + fmt.Sprint(sequence)))
	percent := 40 + int(seed[len(seed)-1])%21
	return now.Add(time.Duration(int64(remaining) * int64(percent) / 100))
}

func safeCutoff(authorizedAt, deadline time.Time, minimum time.Duration) time.Time {
	window := deadline.Sub(authorizedAt)
	margin := window / 10
	if minimum < 5*time.Second {
		minimum = 5 * time.Second
	}
	if margin < minimum {
		margin = minimum
	}
	if margin > time.Minute && minimum <= time.Minute {
		margin = time.Minute
	}
	return deadline.Add(-margin)
}

func waitUntil(ctx context.Context, now func() time.Time, target time.Time) error {
	delay := target.Sub(now())
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
