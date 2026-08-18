// Copyright 2026 Steer Labs. All rights reserved.
// Use of this source code is governed by the BSD-style license in LICENSE.

package fuse

import (
	"io"
	"os"
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

type testVariableReplyLifecycle struct {
	*testReplyWriteLifecycle
	prepared chan struct{}
}

type lookupLifecycleFileSystem struct {
	RawFileSystem
	status Status
	nodeID uint64
}

func (f *lookupLifecycleFileSystem) Lookup(_ <-chan struct{}, _ *InHeader, _ string, out *EntryOut) Status {
	*out = EntryOut{}
	out.NodeId = f.nodeID
	return f.status
}

type lookupReplyLifecycle struct {
	ordered     bool
	marked      bool
	payloadSize int
	markerCalls atomic.Int32
	written     chan Status
}

func (l *lookupReplyLifecycle) PrepareReplyPayload(_ uint64, _ uint64, _ uint32, _ []byte, payload []byte, _ int) (int, Status) {
	if l.payloadSize < 0 || l.payloadSize > len(payload) {
		return 0, EIO
	}
	clear(payload[:l.payloadSize])
	return l.payloadSize, OK
}

func (l *lookupReplyLifecycle) ReplyWriteOrdered(uint64) bool { return l.ordered }

func (l *lookupReplyLifecycle) ReplyPublishMarked(uint64, uint64, uint32) bool {
	l.markerCalls.Add(1)
	return l.marked
}

func (l *lookupReplyLifecycle) ReplyWritten(_ uint64, status Status) {
	l.written <- status
}

func (l *testVariableReplyLifecycle) PrepareReplyPayload(_ uint64, _ uint64, _ uint32, _ []byte, payload []byte, priorSize int) (int, Status) {
	if priorSize != 0 || len(payload) < 5 {
		return 0, EIO
	}
	copy(payload, "trail")
	close(l.prepared)
	return 5, OK
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

func TestLookupCallbackStatusControlsPhysicalPublicationLifecycle(t *testing.T) {
	for _, test := range []struct {
		name           string
		callback       Status
		local          bool
		ordered        bool
		marked         bool
		payloadSize    int
		wantMarker     int32
		wantDataSize   int
		wantWireStatus int32
	}{
		{name: "local structured negative", callback: OK, local: true, wantMarker: 1, wantDataSize: int(unsafe.Sizeof(EntryOut{}))},
		{name: "shared structured negative", callback: OK, ordered: true, marked: true, payloadSize: PFSCacheStampSize, wantMarker: 1, wantDataSize: int(unsafe.Sizeof(EntryOut{}))},
		{name: "errno negative", callback: ENOENT, wantDataSize: 0, wantWireStatus: -int32(ENOENT)},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := make([]byte, unsafe.Sizeof(InHeader{}))
			header := (*InHeader)(unsafe.Pointer(&input[0]))
			header.Unique, header.NodeId, header.Opcode = 52, FUSE_ROOT_ID, _OP_LOOKUP
			req := &request{
				inputBuf: input, inPayload: []byte("missing\x00"),
				outHeaderBuf:  make([]byte, sizeOfOutHeader),
				outDataBuf:    make([]byte, unsafe.Sizeof(EntryOut{})),
				outPayload:    make([]byte, 0, PFSCacheStampSize),
				variableReply: true, status: OK,
			}
			protocol := &protocolServer{fileSystem: &lookupLifecycleFileSystem{
				RawFileSystem: NewDefaultRawFileSystem(), status: test.callback,
			}}
			doLookup(protocol, req)
			if req.status != test.callback {
				t.Fatalf("callback status = %v, want %v", req.status, test.callback)
			}

			lifecycle := &lookupReplyLifecycle{
				ordered: test.ordered, marked: test.marked, payloadSize: test.payloadSize,
				written: make(chan Status, 1),
			}
			server := &Server{replyWriteLifecycle: lifecycle}
			status := runReplyWriteLifecycle(lifecycle, header.Unique, &server.writeMu, func() Status {
				return server.prepareReplyForWrite(req)
			})
			if !status.Ok() {
				t.Fatalf("physical lifecycle = %v", status)
			}
			if calls := lifecycle.markerCalls.Load(); calls != test.wantMarker {
				t.Fatalf("marker calls = %d, want %d", calls, test.wantMarker)
			}
			if got := len(req.outDataBuf); got != test.wantDataSize {
				t.Fatalf("structured data bytes = %d, want %d", got, test.wantDataSize)
			}
			if got := req.outHeader().Status; got != test.wantWireStatus {
				t.Fatalf("wire status = %d, want %d", got, test.wantWireStatus)
			}
			wantUnique := header.Unique
			if test.marked {
				wantUnique |= PFS_UNIQUE_PUBLISH
			}
			if got := req.outHeader().Unique; got != wantUnique {
				t.Fatalf("wire unique = %#x, want %#x", got, wantUnique)
			}
			if test.ordered {
				if got := <-lifecycle.written; !got.Ok() {
					t.Fatalf("ReplyWritten = %v", got)
				}
			} else {
				select {
				case got := <-lifecycle.written:
					t.Fatalf("unordered reply produced ReplyWritten(%v)", got)
				default:
				}
			}
		})
	}
}

func TestVariableReplyWithoutPortableFSLifecycleUsesUpstreamWriterPath(t *testing.T) {
	for _, test := range []struct {
		name           string
		status         Status
		nodeID         uint64
		wantDataSize   int
		wantWireStatus int32
	}{
		{name: "success", status: OK, nodeID: 17, wantDataSize: int(unsafe.Sizeof(EntryOut{}))},
		{name: "errno", status: ENOENT, wantWireStatus: -int32(ENOENT)},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := make([]byte, unsafe.Sizeof(InHeader{}))
			header := (*InHeader)(unsafe.Pointer(&input[0]))
			header.Unique, header.NodeId, header.Opcode = 61, FUSE_ROOT_ID, _OP_LOOKUP
			req := &request{
				inputBuf: input, inPayload: []byte("plain\x00"),
				outHeaderBuf:  make([]byte, sizeOfOutHeader),
				outDataBuf:    make([]byte, unsafe.Sizeof(EntryOut{})),
				outPayload:    make([]byte, 0, PFSCacheStampSize),
				variableReply: true, status: OK,
			}
			protocol := &protocolServer{fileSystem: &lookupLifecycleFileSystem{
				RawFileSystem: NewDefaultRawFileSystem(), status: test.status, nodeID: test.nodeID,
			}}
			doLookup(protocol, req)

			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			server := &Server{mountFd: int(writer.Fd())}
			if status := server.writeReply(req); status != OK {
				t.Fatalf("write reply = %v, want OK", status)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			wire, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if got, want := len(wire), int(sizeOfOutHeader)+test.wantDataSize; got != want {
				t.Fatalf("wire bytes = %d, want %d", got, want)
			}
			out := (*OutHeader)(unsafe.Pointer(&wire[0]))
			if got := out.Status; got != test.wantWireStatus {
				t.Fatalf("wire status = %d, want %d", got, test.wantWireStatus)
			}
			if got := out.Unique; got != header.Unique {
				t.Fatalf("wire unique = %#x, want %#x", got, header.Unique)
			}
		})
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

func TestOrderedReplyLifecycleFinalizesVariablePayloadAtWriterBoundary(t *testing.T) {
	var writeReturned atomic.Bool
	base := &testReplyWriteLifecycle{
		ordered:       true,
		writeReturned: &writeReturned,
		written:       make(chan Status, 1),
	}
	lifecycle := &testVariableReplyLifecycle{
		testReplyWriteLifecycle: base,
		prepared:                make(chan struct{}),
	}
	input := make([]byte, unsafe.Sizeof(InHeader{}))
	header := (*InHeader)(unsafe.Pointer(&input[0]))
	header.Unique, header.NodeId, header.Opcode = 91, 7, _OP_CREATE
	req := &request{
		inputBuf:      input,
		outHeaderBuf:  make([]byte, sizeOfOutHeader),
		outPayload:    make([]byte, 0, 16),
		variableReply: true,
		status:        OK,
	}
	server := &Server{replyWriteLifecycle: lifecycle}
	var writeMu sync.Mutex
	status := runReplyWriteLifecycle(lifecycle, header.Unique, &writeMu, func() Status {
		if status := server.prepareReplyForWrite(req); !status.Ok() {
			return status
		}
		select {
		case <-lifecycle.prepared:
		default:
			return EIO
		}
		if got := string(req.outPayload); got != "trail" {
			return EIO
		}
		writeReturned.Store(true)
		return OK
	})
	if status != OK {
		t.Fatalf("write status = %v, want OK", status)
	}
	if observed := <-lifecycle.written; observed != OK {
		t.Fatalf("observed status = %v, want OK", observed)
	}
	if lifecycle.early.Load() {
		t.Fatal("ReplyWritten ran before the finalized payload write returned")
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
