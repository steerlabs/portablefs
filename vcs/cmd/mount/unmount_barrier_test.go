package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type flushBarrierStub struct{ err error }

func (f flushBarrierStub) FlushToAuthority(context.Context) error { return f.err }

// TestUnmountFlushBarrierLogsFailure pins m2: a failed unmount flush barrier must be logged loudly
// with the WAL-recovery hint, not silently discarded.
func TestUnmountFlushBarrierLogsFailure(t *testing.T) {
	var logged string
	runUnmountFlushBarrier(flushBarrierStub{err: errors.New("authority unreachable")}, 50*time.Millisecond, func(format string, a ...any) {
		logged = format
		for range a {
		}
	})
	if logged == "" {
		t.Fatal("a barrier failure must be logged, not discarded")
	}
	if !strings.Contains(logged, "flush barrier") || !strings.Contains(strings.ToUpper(logged), "WAL") {
		t.Fatalf("log line must name the flush barrier and the WAL-recovery hint, got %q", logged)
	}
}

// TestUnmountFlushBarrierSilentOnSuccess: a clean barrier logs nothing.
func TestUnmountFlushBarrierSilentOnSuccess(t *testing.T) {
	called := false
	runUnmountFlushBarrier(flushBarrierStub{err: nil}, 50*time.Millisecond, func(string, ...any) { called = true })
	if called {
		t.Fatal("a successful barrier must not log")
	}
	_ = time.Second
}
