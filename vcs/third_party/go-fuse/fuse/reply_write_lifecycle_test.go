package fuse

import (
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type testReplyWriteLifecycle struct {
	tracked       bool
	writeReturned *atomic.Bool
	written       chan Status
	early         atomic.Bool
	afterWrite    func()
}

func (l *testReplyWriteLifecycle) ReplyWriteTracked(uint64) bool { return l.tracked }

func (l *testReplyWriteLifecycle) ReplyWritten(_ uint64, status Status) {
	if l.writeReturned != nil && !l.writeReturned.Load() {
		l.early.Store(true)
	}
	if l.afterWrite != nil {
		l.afterWrite()
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

func TestTrackedReplyLifecycleFollowsWrite(t *testing.T) {
	var writeReturned atomic.Bool
	lifecycle := &testReplyWriteLifecycle{tracked: true, writeReturned: &writeReturned, written: make(chan Status, 1)}
	writeEntered := make(chan struct{})
	allowWrite := make(chan struct{})
	done := make(chan Status, 1)
	go func() {
		done <- runReplyWriteLifecycle(lifecycle, 41, func() Status {
			close(writeEntered)
			<-allowWrite
			writeReturned.Store(true)
			return OK
		})
	}()
	<-writeEntered
	close(allowWrite)
	if status := <-done; status != OK {
		t.Fatalf("write status = %v", status)
	}
	if status := <-lifecycle.written; status != OK || lifecycle.early.Load() {
		t.Fatalf("ReplyWritten = %v, early=%t", status, lifecycle.early.Load())
	}
}

func TestTrackedReplyLifecycleFinalizesPayloadAtWriterBoundary(t *testing.T) {
	var writeReturned atomic.Bool
	base := &testReplyWriteLifecycle{tracked: true, writeReturned: &writeReturned, written: make(chan Status, 1)}
	lifecycle := &testVariableReplyLifecycle{testReplyWriteLifecycle: base, prepared: make(chan struct{})}
	input := make([]byte, unsafe.Sizeof(InHeader{}))
	header := (*InHeader)(unsafe.Pointer(&input[0]))
	header.Unique, header.NodeId, header.Opcode = 91, 7, _OP_CREATE
	req := &request{inputBuf: input, outHeaderBuf: make([]byte, sizeOfOutHeader), outPayload: make([]byte, 0, 16), variableReply: true, status: OK}
	server := &Server{replyWriteLifecycle: lifecycle}
	status := runReplyWriteLifecycle(lifecycle, header.Unique, func() Status {
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

func TestUntrackedReplySkipsPhysicalLifecycle(t *testing.T) {
	lifecycle := &testReplyWriteLifecycle{writeReturned: &atomic.Bool{}, written: make(chan Status, 1)}
	if status := runReplyWriteLifecycle(lifecycle, 9, func() Status { return OK }); status != OK {
		t.Fatalf("write status = %v", status)
	}
	select {
	case status := <-lifecycle.written:
		t.Fatalf("untracked reply produced ReplyWritten(%v)", status)
	default:
	}
}

func TestBlockedNotificationAllowsTrackedReply(t *testing.T) {
	fd, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	lifecycle := &testReplyWriteLifecycle{tracked: true, written: make(chan Status, 1)}
	server := &Server{mountFd: fd, opts: &MountOptions{}, replyWriteLifecycle: lifecycle}
	server.protocolServer.opts = server.opts
	notifyEntered := make(chan struct{})
	releaseNotify := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseNotify) }) }
	defer release()
	server.protocolServer.writev = func(iov [][]byte) (int, syscall.Errno) {
		return server.writevWith(iov, func(_ int, vectors [][]byte) (int, error) {
			close(notifyEntered)
			<-releaseNotify
			return vectorsSize(vectors), nil
		})
	}
	notifyDone := make(chan Status, 1)
	go func() { notifyDone <- server.InodeNotify(7, 0, 0) }()
	<-notifyEntered

	input := make([]byte, unsafe.Sizeof(InHeader{}))
	(*InHeader)(unsafe.Pointer(&input[0])).Unique = 41
	req := &request{inputBuf: input, outHeaderBuf: make([]byte, sizeOfOutHeader), status: OK}
	replyDone := make(chan Status, 1)
	go func() { replyDone <- server.writeReply(req) }()
	select {
	case status := <-replyDone:
		if status != OK {
			t.Fatalf("reply status = %v", status)
		}
	case <-time.After(time.Second):
		release()
		<-notifyDone
		t.Fatal("tracked reply waited behind a synchronous notification")
	}
	if status := <-lifecycle.written; status != OK {
		t.Fatalf("ReplyWritten status = %v", status)
	}
	release()
	if status := <-notifyDone; status != OK {
		t.Fatalf("notification status = %v", status)
	}
}

func TestFailedTrackedReplyFinalizesAfterDescriptorUnlock(t *testing.T) {
	fd, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	server := &Server{mountFd: fd, opts: &MountOptions{}}
	server.protocolServer.opts = server.opts
	lockReleased := atomic.Bool{}
	lifecycle := &testReplyWriteLifecycle{tracked: true, written: make(chan Status, 1), afterWrite: func() {
		if server.fdMu.TryLock() {
			lockReleased.Store(true)
			server.fdMu.Unlock()
		}
	}}
	server.replyWriteLifecycle = lifecycle
	input := make([]byte, unsafe.Sizeof(InHeader{}))
	(*InHeader)(unsafe.Pointer(&input[0])).Unique = 42
	req := &request{inputBuf: input, outHeaderBuf: make([]byte, sizeOfOutHeader), status: OK}
	status := server.writeReply(req)
	if status != Status(syscall.EBADF) {
		t.Fatalf("write status = %v, want EBADF", status)
	}
	if written := <-lifecycle.written; written != status || !lockReleased.Load() {
		t.Fatalf("ReplyWritten = %v, descriptor lock released=%t", written, lockReleased.Load())
	}
}

func TestCloseWaitsForNotificationAndRejectsLateWrites(t *testing.T) {
	fd, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{mountFd: fd, opts: &MountOptions{}}
	server.protocolServer.opts = server.opts
	notifyEntered := make(chan struct{})
	releaseNotify := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseNotify) }) }
	defer release()
	server.protocolServer.writev = func(iov [][]byte) (int, syscall.Errno) {
		return server.writevWith(iov, func(_ int, vectors [][]byte) (int, error) {
			close(notifyEntered)
			<-releaseNotify
			return vectorsSize(vectors), nil
		})
	}
	notifyDone := make(chan Status, 1)
	go func() { notifyDone <- server.InodeNotify(9, 0, 0) }()
	<-notifyEntered
	closeDone := make(chan struct{})
	go func() {
		server.closeMountFd()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		release()
		t.Fatal("closed mount descriptor during an in-flight notification")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if status := <-notifyDone; status != OK {
		t.Fatalf("notification status = %v", status)
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("descriptor close did not finish after notification returned")
	}
	server.protocolServer.writev = server.writev
	if status := server.InodeNotify(9, 0, 0); status != ENODEV {
		t.Fatalf("late notification status = %v, want ENODEV", status)
	}
}

func vectorsSize(vectors [][]byte) int {
	total := 0
	for _, vector := range vectors {
		total += len(vector)
	}
	return total
}
