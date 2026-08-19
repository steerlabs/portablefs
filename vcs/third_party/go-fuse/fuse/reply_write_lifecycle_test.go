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
	writeReturned *atomic.Bool
	written       chan Status
	early         atomic.Bool
}

func (l *testReplyWriteLifecycle) ReplyWriteOrdered(uint64) bool { return l.ordered }

func (l *testReplyWriteLifecycle) ReplyWritten(_ uint64, status Status) {
	if !l.writeReturned.Load() {
		l.early.Store(true)
	}
	l.written <- status
}

type testVariableReplyLifecycle struct {
	*testReplyWriteLifecycle
	prepared chan struct{}
}

func (l *testVariableReplyLifecycle) PrepareReplyPayload(_ uint64, _ uint64, _ uint32, _ []byte, payload []byte, priorSize int) (int, Status, Status) {
	if priorSize != 0 || len(payload) < 5 {
		return 0, OK, EIO
	}
	copy(payload, "trail")
	close(l.prepared)
	return 5, OK, OK
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
	if writeMu.TryLock() {
		writeMu.Unlock()
		t.Fatal("selected response writer did not own the notification mutex")
	}
	close(allowWrite)
	if status := <-done; status != OK {
		t.Fatalf("write status = %v", status)
	}
	if status := <-lifecycle.written; status != OK || lifecycle.early.Load() {
		t.Fatalf("ReplyWritten = %v, early=%t", status, lifecycle.early.Load())
	}
}

func TestOrderedReplyLifecycleFinalizesPayloadAtWriterBoundary(t *testing.T) {
	var writeReturned atomic.Bool
	base := &testReplyWriteLifecycle{ordered: true, writeReturned: &writeReturned, written: make(chan Status, 1)}
	lifecycle := &testVariableReplyLifecycle{testReplyWriteLifecycle: base, prepared: make(chan struct{})}
	input := make([]byte, unsafe.Sizeof(InHeader{}))
	header := (*InHeader)(unsafe.Pointer(&input[0]))
	header.Unique, header.NodeId, header.Opcode = 91, 7, _OP_CREATE
	req := &request{inputBuf: input, outHeaderBuf: make([]byte, sizeOfOutHeader), outPayload: make([]byte, 0, 16), variableReply: true, status: OK}
	server := &Server{replyWriteLifecycle: lifecycle}
	var writeMu sync.Mutex
	status := runReplyWriteLifecycle(lifecycle, header.Unique, &writeMu, func() Status {
		if status := server.prepareReplyForWrite(req); !status.Ok() || string(req.outPayload) != "trail" {
			return EIO
		}
		writeReturned.Store(true)
		return OK
	})
	if status != OK || <-lifecycle.written != OK || lifecycle.early.Load() {
		t.Fatalf("writer lifecycle = %v, early=%t", status, lifecycle.early.Load())
	}
}

func TestUnselectedReplyRetainsParallelWritePath(t *testing.T) {
	lifecycle := &testReplyWriteLifecycle{writeReturned: &atomic.Bool{}, written: make(chan Status, 1)}
	var writeMu sync.Mutex
	writeMu.Lock()
	done := make(chan Status, 1)
	go func() { done <- runReplyWriteLifecycle(lifecycle, 9, &writeMu, func() Status { return OK }) }()
	select {
	case status := <-done:
		if status != OK {
			t.Fatalf("write status = %v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("unselected reply serialized behind notification traffic")
	}
	writeMu.Unlock()
	select {
	case status := <-lifecycle.written:
		t.Fatalf("unselected reply produced ReplyWritten(%v)", status)
	default:
	}
}
