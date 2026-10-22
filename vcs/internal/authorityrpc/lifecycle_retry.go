package authorityrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// TransientTransport classifies evidence, not elapsed recovery time. Authenticated
// denials, epoch changes, protocol defects and terminal client latches never retry.
func TransientTransport(err error) bool {
	if err == nil || errors.Is(err, ErrSessionEnded) || errors.Is(err, ErrAuthorityChanged) || errors.Is(err, ErrTransportBinding) || errors.Is(err, ErrReplayDesynchronized) || frameDefect(err) {
		return false
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, ErrTransportUncertain) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded)
}

// RetryLifecycle owns one logical Prepare/Recover. Only attempts have deadlines.
// The generation's context is the sole cancellation boundary for transient loss.
func RetryLifecycle(ctx context.Context, timeout time.Duration, attempt func(context.Context) error) error {
	if timeout <= 0 {
		return errors.New("authorityrpc: lifecycle attempt needs a positive bound")
	}
	backoff := 100 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		call, cancel := context.WithTimeout(ctx, timeout)
		err := attempt(call)
		cancel()
		if err == nil {
			return ctx.Err()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !TransientTransport(err) {
			return err
		}
		if err := waitLifecycleRetry(ctx, &backoff); err != nil {
			return err
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
