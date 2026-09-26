//go:build linux

package soak

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSoakReproAsyncCloseBreakDeadlock is a candidate reduction extracted from
// the seed-730021 chaos hang. A closes a freshly written delegated inode in the
// background; its aliases are then linked, truncated and renamed through both
// mounts. Resolving the last alias on B requests a break while A's async close
// owns the identity transition lock and waits for a durability watermark. In
// the failure, neither side can advance and unlink(2) remains in the kernel.
//
// The process boundary captures the wait graph if this mounted request stalls.
func TestSoakReproAsyncCloseBreakDeadlock(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	f := newFixture(t)
	if err := os.Mkdir(filepath.Join(f.a, "repro"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Repeat the five-syscall identity cycle. This candidate passed in the
	// recorded runs; the seeded interleaving is retained in a separate test.
	for iteration := 0; iteration < 256; iteration++ {
		dir := fmt.Sprintf("repro/d-%03d", iteration)
		if err := os.Mkdir(filepath.Join(f.a, dir), 0o700); err != nil {
			t.Fatalf("iteration %d mkdir: %v", iteration, err)
		}
		file := filepath.Join(dir, "file")
		alias := filepath.Join(dir, "alias")
		renamed := filepath.Join(dir, "renamed")
		payload := []byte(fmt.Sprintf("iteration=%d delegated payload", iteration))
		if err := os.WriteFile(filepath.Join(f.a, file), payload, 0o600); err != nil {
			t.Fatalf("iteration %d write/async close: %v", iteration, err)
		}
		if err := os.Link(filepath.Join(f.b, file), filepath.Join(f.b, alias)); err != nil {
			t.Fatalf("iteration %d cross-mount link: %v", iteration, err)
		}
		if err := os.Truncate(filepath.Join(f.a, alias), int64(len(payload)/2)); err != nil {
			t.Fatalf("iteration %d alias truncate: %v", iteration, err)
		}
		if err := os.Rename(filepath.Join(f.b, file), filepath.Join(f.b, renamed)); err != nil {
			t.Fatalf("iteration %d cross-mount rename: %v", iteration, err)
		}

		started := time.Now()
		if err := os.Remove(filepath.Join(f.a, alias)); err != nil {
			t.Fatalf("iteration %d alias unlink: %v", iteration, err)
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("iteration %d alias unlink took %s; async close/break exceeded its five-second budget", iteration, elapsed)
		}
	}
}
