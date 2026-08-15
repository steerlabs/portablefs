// Copyright 2026 Steer Labs. All rights reserved.
// Use of this source code is governed by the BSD-style license in LICENSE.

package fuse

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

type testReplyWriteLifecycle struct {
	ordered       bool
	marked        bool
	writeReturned *atomic.Bool
	written       chan Status
	early         atomic.Bool
}

func (l *testReplyWriteLifecycle) ReplyWriteOrdered(uint64) bool { return l.ordered }

func (l *testReplyWriteLifecycle) ReplyPublishMarked(uint64, uint64, uint32) bool {
	return l.marked
}

func (l *testReplyWriteLifecycle) ReplyWritten(_ uint64, status Status) {
	if !l.writeReturned.Load() {
		l.early.Store(true)
	}
	l.written <- status
}

func TestPhysicalReplySerializesPublicationMarkerAfterLifecycleDecision(t *testing.T) {
	input := make([]byte, unsafe.Sizeof(InHeader{}))
	header := (*InHeader)(unsafe.Pointer(&input[0]))
	header.Unique = 42
	header.NodeId = 7
	header.Opcode = _OP_CREATE
	req := &request{
		inputBuf:     input,
		outHeaderBuf: make([]byte, sizeOfOutHeader),
		status:       OK,
	}

	// This is the ordering used by the real server: the generic protocol
	// handler serializes before the filesystem's publication decision exists.
	req.serializeHeader(0)
	if got := req.outHeader().Unique; got != header.Unique {
		t.Fatalf("pre-lifecycle unique = %#x, want %#x", got, header.Unique)
	}

	lifecycle := &testReplyWriteLifecycle{
		ordered:       true,
		marked:        true,
		writeReturned: &atomic.Bool{},
		written:       make(chan Status, 1),
	}
	server := &Server{replyWriteLifecycle: lifecycle}
	if status := server.prepareReplyForWrite(req); status != OK {
		t.Fatalf("prepare reply = %v", status)
	}
	if got, want := req.outHeader().Unique, header.Unique|PFS_UNIQUE_PUBLISH; got != want {
		t.Fatalf("physical reply unique = %#x, want marked %#x", got, want)
	}
}

func TestOrderedReplyLifecycleFollowsWriteAndExcludesNotification(t *testing.T) {
	var writeReturned atomic.Bool
	lifecycle := &testReplyWriteLifecycle{ordered: true, writeReturned: &writeReturned, written: make(chan Status, 1)}
	var writeMu sync.Mutex
	writeEntered := make(chan struct{})
	allowWrite := make(chan struct{})
	done := make(chan Status, 1)
	go func() {
		done <- runReplyWriteLifecycle(lifecycle, 41, &writeMu, func() Status {
			close(writeEntered)
			<-allowWrite
			writeReturned.Store(true)
			return OK
		})
	}()
	<-writeEntered

	// notifyWrite uses this exact mutex in Server. The selected writer is known
	// to be inside its callback, so TryLock is a deterministic proof that it
	// owns the notification boundary while the physical write is blocked.
	if writeMu.TryLock() {
		writeMu.Unlock()
		t.Fatal("selected response writer did not own the notification mutex")
	}
	notifyEntered := make(chan struct{})
	go func() {
		writeMu.Lock()
		close(notifyEntered)
		writeMu.Unlock()
	}()
	select {
	case <-lifecycle.written:
		t.Fatal("ReplyWritten ran before the response writer returned")
	default:
	}

	close(allowWrite)
	if status := <-done; status != OK {
		t.Fatalf("write status = %v, want OK", status)
	}
	if status := <-lifecycle.written; status != OK {
		t.Fatalf("observed status = %v, want OK", status)
	}
	if lifecycle.early.Load() {
		t.Fatal("ReplyWritten observed a pre-return writer state")
	}
	select {
	case <-notifyEntered:
	case <-time.After(time.Second):
		t.Fatal("notification did not resume after the response write")
	}
}

func TestOrderedReplyLifecycleReportsWriterFailureAfterReturn(t *testing.T) {
	var writeReturned atomic.Bool
	lifecycle := &testReplyWriteLifecycle{ordered: true, writeReturned: &writeReturned, written: make(chan Status, 1)}
	var writeMu sync.Mutex
	want := Status(5)
	status := runReplyWriteLifecycle(lifecycle, 73, &writeMu, func() Status {
		writeReturned.Store(true)
		return want
	})
	if status != want {
		t.Fatalf("write status = %v, want %v", status, want)
	}
	if observed := <-lifecycle.written; observed != want {
		t.Fatalf("observed status = %v, want %v", observed, want)
	}
	if lifecycle.early.Load() {
		t.Fatal("ReplyWritten observed a pre-return writer state")
	}
}

func TestUnselectedReplyRetainsParallelWritePath(t *testing.T) {
	lifecycle := &testReplyWriteLifecycle{writeReturned: &atomic.Bool{}, written: make(chan Status, 1)}
	var writeMu sync.Mutex
	writeMu.Lock()
	done := make(chan Status, 1)
	go func() {
		done <- runReplyWriteLifecycle(lifecycle, 9, &writeMu, func() Status { return OK })
	}()
	select {
	case status := <-done:
		if status != OK {
			t.Fatalf("write status = %v, want OK", status)
		}
	case <-time.After(time.Second):
		t.Fatal("an unselected reply serialized behind notification traffic")
	}
	writeMu.Unlock()
	select {
	case <-lifecycle.written:
		t.Fatal("unselected reply produced a lifecycle callback")
	default:
	}
}
