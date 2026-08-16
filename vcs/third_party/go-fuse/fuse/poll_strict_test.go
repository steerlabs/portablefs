// Copyright 2026 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"unsafe"
)

type recordingPollLookupFS struct {
	RawFileSystem
	called bool
	name   string
}

func (fs *recordingPollLookupFS) Lookup(_ <-chan struct{}, _ *InHeader, name string, _ *EntryOut) Status {
	fs.called = true
	fs.name = name
	return ENOENT
}

func pollLookupWire(unique uint64) (header, body []byte) {
	in := InHeader{
		Length: uint32(unsafe.Sizeof(InHeader{})) + uint32(len(pollHackName)) + 1,
		Opcode: _OP_LOOKUP,
		Unique: unique,
		NodeId: FUSE_ROOT_ID,
	}
	header = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&in)), unsafe.Sizeof(in))...)
	body = append([]byte(pollHackName), 0)
	return header, body
}

func TestStrictPollHackLookupReachesRawFileSystem(t *testing.T) {
	fs := &recordingPollLookupFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{ExtraCapabilities: CAP_PFS_STRICT_COHERENCE})
	header, body := pollLookupWire(2)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(EntryOut{}))}

	n, status := ps.HandleRequest([][]byte{header, body}, out)
	if status != OK {
		t.Fatalf("HandleRequest status = %v, want OK", status)
	}
	if !fs.called || fs.name != pollHackName {
		t.Fatalf("strict lookup bypassed RawFileSystem: called=%t name=%q", fs.called, fs.name)
	}
	if n != int(sizeOfOutHeader) {
		t.Fatalf("strict negative lookup wrote %d bytes, want header-only %d", n, sizeOfOutHeader)
	}
	if got := int32(binary.LittleEndian.Uint32(out[0][4:8])); got != -int32(ENOENT) {
		t.Fatalf("strict lookup status = %d, want %d", got, -int32(ENOENT))
	}
}

func TestLegacyPollHackLookupRemainsSynthetic(t *testing.T) {
	fs := &recordingPollLookupFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{})
	header, body := pollLookupWire(2)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(EntryOut{}))}

	n, status := ps.HandleRequest([][]byte{header, body}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(EntryOut{})) {
		t.Fatalf("legacy poll lookup = (%d, %v)", n, status)
	}
	if fs.called {
		t.Fatal("legacy poll lookup unexpectedly reached RawFileSystem")
	}
	if got := binary.LittleEndian.Uint64(out[1][0:8]); got != pollHackInode {
		t.Fatalf("legacy synthetic nodeid = %#x, want %#x", got, uint64(pollHackInode))
	}
}

func TestStrictWaitMountSkipsSyntheticPollProbe(t *testing.T) {
	ready := make(chan error, 1)
	ready <- nil
	server := &Server{
		protocolServer: protocolServer{opts: &MountOptions{ExtraCapabilities: CAP_PFS_STRICT_COHERENCE}},
		mountPoint:     filepath.Join(t.TempDir(), "not-a-mount"),
		ready:          ready,
	}

	if err := server.WaitMount(); err != nil {
		t.Fatalf("strict WaitMount invoked synthetic poll probe: %v", err)
	}
}
