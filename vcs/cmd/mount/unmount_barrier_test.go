package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type flushBarrierStub struct {
	err         error
	unreachable bool
	fenced      bool
	localErr    error
	flushCalled bool
	localCalled bool
}

func (f *flushBarrierStub) FlushToAuthority(context.Context) error {
	f.flushCalled = true
	return f.err
}

func (f *flushBarrierStub) AuthorityUnreachable() bool { return f.unreachable }

func (f *flushBarrierStub) SessionFenced() bool { return f.fenced }

func (f *flushBarrierStub) SyncLocalDurable() error {
	f.localCalled = true
	return f.localErr
}

// TestUnmountFlushBarrierLogsFailure pins m2: a failed unmount flush barrier must be logged loudly
// with the WAL-recovery hint, not silently discarded.
func TestUnmountFlushBarrierLogsFailure(t *testing.T) {
	var logged string
	stub := &flushBarrierStub{err: errors.New("authority unreachable")}
	runUnmountFlushBarrier(stub, 50*time.Millisecond, func(format string, a ...any) {
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
	if !stub.localCalled {
		t.Fatal("a failed authority flush must still fsync the local WAL (journal-first fallback)")
	}
}

// TestUnmountFlushBarrierSilentOnSuccess: a clean barrier logs nothing.
func TestUnmountFlushBarrierSilentOnSuccess(t *testing.T) {
	called := false
	runUnmountFlushBarrier(&flushBarrierStub{}, 50*time.Millisecond, func(string, ...any) { called = true })
	if called {
		t.Fatal("a successful barrier must not log")
	}
}

// TestUnmountFlushBarrierJournalFirstWhenUnavailable pins the journal-first unmount contract: with
// the authority CONFIRMED unreachable (or the session fenced), the barrier never touches the
// network — it fsyncs the local session WALs and logs the recovery hint instead.
func TestUnmountFlushBarrierJournalFirstWhenUnavailable(t *testing.T) {
	var logged string
	stub := &flushBarrierStub{unreachable: true, err: errors.New("must not be called")}
	runUnmountFlushBarrier(stub, 50*time.Millisecond, func(format string, a ...any) {
		logged = format
		for range a {
		}
	})
	if stub.flushCalled {
		t.Fatal("an unreachable/fenced authority must not receive a network flush at unmount")
	}
	if !stub.localCalled {
		t.Fatal("journal-first unmount must fsync the local session WALs")
	}
	if !strings.Contains(strings.ToUpper(logged), "WAL") {
		t.Fatalf("journal-first unmount must log the WAL-recovery hint, got %q", logged)
	}
}

// TestUnmountFlushBarrierJournalFirstLocalFailure: EIO-shaped local durability failures are logged
// loudly too (the operator must know the un-flushed tail may not survive a machine crash).
func TestUnmountFlushBarrierJournalFirstLocalFailure(t *testing.T) {
	var logged string
	stub := &flushBarrierStub{unreachable: true, localErr: errors.New("wal poisoned")}
	runUnmountFlushBarrier(stub, 50*time.Millisecond, func(format string, a ...any) {
		logged = format
		for range a {
		}
	})
	if !strings.Contains(logged, "fsync failed") {
		t.Fatalf("a failed local WAL fsync must be named in the log, got %q", logged)
	}
}

// TestUnmountFlushBarrierFencedNamesTheDefiniteCause: a fenced session goes journal-first too (the
// network flush is futile), but the log must name the FENCE — a definite verdict whose fix is a
// remount, not connectivity — rather than blaming reachability.
func TestUnmountFlushBarrierFencedNamesTheDefiniteCause(t *testing.T) {
	var lines []string
	stub := &flushBarrierStub{fenced: true, err: errors.New("must not be called")}
	runUnmountFlushBarrier(stub, 50*time.Millisecond, func(format string, a ...any) {
		lines = append(lines, fmt.Sprintf(format, a...))
	})
	if stub.flushCalled {
		t.Fatal("a fenced session must not receive a network flush at unmount")
	}
	if !stub.localCalled {
		t.Fatal("a fenced journal-first unmount must still fsync the local session WALs")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "fenced") || !strings.Contains(joined, "remount") {
		t.Fatalf("the log must name the fence and the remount fix, got %q", joined)
	}
	if !strings.Contains(strings.ToUpper(joined), "WAL") {
		t.Fatalf("the WAL-recovery hint must survive the fenced wording, got %q", joined)
	}
}
