package histworker

import (
	"context"
	"fmt"
	"testing"
)

// The retention loop turns the database's bounded release crank and stays
// healthy on databases without the retention surface.
func TestRetentionPassDrivesBoundedRelease(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	// Capability missing (pre-028 database): idle, never an error.
	busy, err := r.worker.retentionPass(ctx)
	if err != nil || busy {
		t.Fatalf("capability-missing pass: busy=%v err=%v", busy, err)
	}

	var askedLimit int
	r.repo.mu.Lock()
	r.repo.retentionRelease = func(limit int) (int64, error) {
		askedLimit = limit
		return 2, nil
	}
	r.repo.mu.Unlock()
	busy, err = r.worker.retentionPass(ctx)
	if err != nil || !busy {
		t.Fatalf("releasing pass: busy=%v err=%v", busy, err)
	}
	if askedLimit != retentionBatch {
		t.Fatalf("pass asked for %d releases, want the %d batch constant", askedLimit, retentionBatch)
	}

	r.repo.mu.Lock()
	r.repo.retentionRelease = func(int) (int64, error) { return 0, fmt.Errorf("db down") }
	r.repo.mu.Unlock()
	if _, err := r.worker.retentionPass(ctx); err == nil {
		t.Fatal("a real database error was swallowed")
	}
}
