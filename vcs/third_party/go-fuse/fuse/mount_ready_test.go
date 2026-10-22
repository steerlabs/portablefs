package fuse

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMountReadyBootstrapDoesNotServe(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "unserved-mount")
	server := &Server{ready: make(chan error, 1), mountPoint: missing}
	close(server.ready)
	if err := server.WaitMountReady(); err != nil {
		t.Fatal(err)
	}
	// The ordinary probe still accesses its path; closed-start readiness must
	// complete without that serving operation or an invented filesystem answer.
	if err := server.WaitMount(); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("ordinary mount lost its path probe: %v", err)
	}
	failure := errors.New("mount helper failed")
	failed := &Server{ready: make(chan error, 1)}
	failed.ready <- failure
	close(failed.ready)
	if err := failed.WaitMountReady(); !errors.Is(err, failure) {
		t.Fatal("bootstrap hid helper failure", err)
	}
}
