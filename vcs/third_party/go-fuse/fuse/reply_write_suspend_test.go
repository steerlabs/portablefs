//go:build linux

package fuse

import (
	"encoding/binary"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"
)

// This models a suspend-inclusive native permission sample, rather than a
// stronger atomic sample/write primitive that Linux does not provide. The real
// writeReply -> prepareReplyForWrite -> Server.write path performs the write.
type suspendReplyLifecycle struct {
	now                                    *atomic.Int64
	beforeSample, afterSample, insideWrite func()
	written                                Status
}

func (*suspendReplyLifecycle) ReplyWriteTracked(uint64) bool { return true }
func (l *suspendReplyLifecycle) PrepareReplyPayload(_ uint64, _ uint64, _ uint32, _ []byte, _ []byte, n int) (int, Status, Status) {
	if l.beforeSample != nil {
		l.beforeSample()
	}
	sampled := l.now.Load()
	if l.afterSample != nil {
		l.afterSample()
	}
	if sampled >= 10 {
		return 0, EIO, OK
	}
	return n, OK, OK
}
func (l *suspendReplyLifecycle) ReplyWritten(_ uint64, s Status) { l.written = s }

type suspendReadResult struct{ inside func() }

func (*suspendReadResult) Size() int { return 1 }
func (*suspendReadResult) Done()     {}
func (r *suspendReadResult) Bytes([]byte) ([]byte, Status) {
	if r.inside != nil {
		r.inside()
	}
	return []byte{'x'}, OK
}

func TestTrackedReplyLifecycleNativeSuspendPublicationCuts(t *testing.T) {
	for _, cut := range []string{"before-final-sample", "inside-sample-before-return", "after-return", "after-prepare", "before-physical-write", "inside-physical-write"} {
		t.Run(cut, func(t *testing.T) {
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			var now atomic.Int64
			now.Store(1)
			freeze := func() { now.Store(31) } // independent authority expiry=10, peer=10.25
			lifecycle := &suspendReplyLifecycle{now: &now}
			if cut == "before-final-sample" {
				lifecycle.beforeSample = freeze
			} else if cut == "inside-sample-before-return" || cut == "after-return" {
				lifecycle.afterSample = freeze
			}
			input := make([]byte, unsafe.Sizeof(InHeader{}))
			header := (*InHeader)(unsafe.Pointer(&input[0]))
			header.Unique = 42
			header.NodeId = 1
			header.Opcode = _OP_READ
			req := &request{inputBuf: input, outHeaderBuf: make([]byte, sizeOfOutHeader), outPayload: make([]byte, 1), status: OK}
			if cut == "inside-physical-write" {
				req.readResult = &suspendReadResult{inside: freeze}
			}
			server := &Server{mountFd: int(write.Fd()), opts: &MountOptions{}, replyWriteLifecycle: lifecycle}
			attempt := func() Status { return server.writeReply(req) }
			if cut == "after-prepare" || cut == "before-physical-write" {
				attempt = func() Status {
					return runReplyWriteLifecycle(lifecycle, header.Unique, func() Status {
						if status := server.prepareReplyForWrite(req); status != OK {
							return status
						}
						freeze()
						return server.write(req)
					})
				}
			}
			if status := attempt(); status != OK || lifecycle.written != OK {
				t.Fatal("physical reply failed", status, lifecycle.written)
			}
			bytes := make([]byte, 256)
			n, err := syscall.Read(int(read.Fd()), bytes)
			if err != nil || n < 16 {
				t.Fatal(n, err)
			}
			errno := int32(binary.LittleEndian.Uint32(bytes[4:8]))
			if cut == "before-final-sample" && errno != -int32(syscall.EIO) {
				t.Fatal("post-resume native sample admitted", errno)
			}
			if cut != "before-final-sample" && errno != 0 {
				t.Fatal("lost native in-flight residual control", errno)
			}
			// A different request performs a different final sample. No cached decision
			// from the preceding physical reply authorizes it after resume.
			lifecycle.beforeSample = nil
			lifecycle.afterSample = nil
			header.Unique = 44
			req.readResult = nil
			req.outPayload = make([]byte, 1)
			req.status = OK
			if status := server.writeReply(req); status != OK {
				t.Fatal(status)
			}
			n, err = syscall.Read(int(read.Fd()), bytes)
			if err != nil || n < 16 || int32(binary.LittleEndian.Uint32(bytes[4:8])) != -int32(syscall.EIO) {
				t.Fatal("different request revived permission", n, err)
			}
			t.Logf("request=42 anchor=0 sample=1 cut=%s expiry=10 peer=10.25 completion=31; request=44 sample=31 denied", cut)
		})
	}
}
