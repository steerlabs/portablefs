//go:build linux

package fuse

import "testing"

type spliceEligibleTestResult struct{}

func (spliceEligibleTestResult) Bytes(buf []byte) ([]byte, Status) { return buf[:0], OK }
func (spliceEligibleTestResult) Size() int                         { return 0 }
func (spliceEligibleTestResult) Done()                             {}
func (spliceEligibleTestResult) Stateful() (uintptr, int)          { return 1, 0 }

func TestReadResultSpliceEligibilityIsDescriptorBased(t *testing.T) {
	if readResultCanSplice(ReadResultData([]byte("resident"))) {
		t.Fatal("an in-memory read result has no descriptor-backed splice path")
	}
	if !readResultCanSplice(spliceEligibleTestResult{}) {
		t.Fatal("a descriptor-backed result was denied the zero-copy splice path")
	}

	server := new(Server)
	request := new(request)
	if err := server.trySplice(request, ReadResultData([]byte("resident"))); err != errRecoverSplice {
		t.Fatalf("in-memory trySplice error = %v, want the direct byte-path sentinel", err)
	}
}
