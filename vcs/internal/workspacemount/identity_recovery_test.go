package workspacemount

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Losing guest.json while volume records survive silently mints a new guest
// UUID: the key and epoch are kept but the renewal scope changes.
func TestGuestRecordLossRefusesRetainedVolumeScope(t *testing.T) {
	s, _ := store(t)
	dir := s.directory
	s.Close()
	if err := os.Remove(filepath.Join(dir, "guest.json")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		again, err := Open(dir)
		if again != nil {
			again.Close()
		}
		if !errors.Is(err, ErrIdentityUnavailable) {
			t.Fatalf("guest loss must durably refuse: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "guest.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("minted replacement guest UUID", err)
		}
	}
}

func TestOpenSweepsCrashIdentityTransactions(t *testing.T) {
	s, _ := store(t)
	// Simulate a crash after CreateTemp+write: deferred Remove never runs.
	f, _ := os.CreateTemp(s.directory, ".identity-")
	f.WriteString("{}")
	f.Close()
	s.Close()
	again, err := Open(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	m, _ := filepath.Glob(filepath.Join(s.directory, ".identity-*"))
	if len(m) != 0 {
		t.Fatalf("Open left %d private-key crash transactions", len(m))
	}
}
