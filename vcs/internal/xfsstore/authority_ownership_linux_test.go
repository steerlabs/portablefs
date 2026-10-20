//go:build linux

package xfsstore

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAuthorityRootOwnershipRefusesConcurrentTakeover(t *testing.T) {
	path := filepath.Clean(t.TempDir())
	first, err := open(path, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := open(path, false, 0, nil); err == nil {
		_ = second.Close()
		t.Fatal("held root admitted a second authority")
	} else if !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("second authority=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := open(path, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
}
