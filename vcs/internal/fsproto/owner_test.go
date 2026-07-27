package fsproto

import (
	"encoding/gob"
	"net"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// TestStreamReleasesOwnerOnDisconnect: a mount's subscribe stream is its liveness signal;
// when it drops, the authority must release that owner's checkouts so a crashed mount
// can't block others forever.
func TestStreamReleasesOwnerOnDisconnect(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	deleg := delegation.New()
	if granted, _ := deleg.Checkout("p", "X"); !granted {
		t.Fatal("checkout p as X should grant")
	}
	srv := NewServer(fs, fs, deleg)

	c1, c2 := net.Pipe()
	_ = c2.Close() // the mount end is gone: stream's reader sees EOF and returns
	srv.stream(c1, gob.NewEncoder(c1), &connSession{}, "X")
	_ = c1.Close()

	if o, _ := deleg.HeldBy("p"); o != "" {
		t.Fatalf("subscribe-stream disconnect must release owner X's checkout; still held by %q", o)
	}
}
