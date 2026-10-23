package authorityrpc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExpiredDrainReleasesForegroundAndRetainsCleanup(t *testing.T) {
	f := NewDispatchFence()
	if err := f.Drain(func() error { return ErrDispatchExpired }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	foreground := make(chan error, 1)
	go func() {
		done, err := f.begin(WithDispatchTimeout(ctx, time.Second), false)
		if done != nil {
			done()
		}
		foreground <- err
	}()
	select {
	case err := <-foreground:
		if !errors.Is(err, ErrDispatchExpired) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("expired foreground wait obstructed the cold cohort")
	}
	cleanup := make(chan error, 1)
	go func() {
		done, err := f.begin(ctx, false)
		if done != nil {
			done()
		}
		cleanup <- err
	}()
	select {
	case err := <-cleanup:
		t.Fatal("cleanup owner was discarded", err)
	case <-time.After(20 * time.Millisecond):
	}
	if s := f.Snapshot(); s.InFlightIO != 0 {
		t.Fatal("expired permission admitted I/O", s)
	}
	if err := f.Resume(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cleanup:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
