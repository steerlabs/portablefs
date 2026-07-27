package authority

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

// TestSingleAuthorityEnforced verifies the core multi-client safety property: a
// volume can be held by exactly one VCS at a time. A second Acquire on a volume
// already held must fail (the backend's exclusive lease), and once the first
// authority is released a new one can be acquired (failover).
//
// Gated: set VOLUME_API_URL (+ VOLUME_API_TOKEN).
func TestSingleAuthorityEnforced(t *testing.T) {
	url := os.Getenv("VOLUME_API_URL")
	if url == "" {
		t.Skip("set VOLUME_API_URL (+ VOLUME_API_TOKEN) to run")
	}
	cli := backend.NewClient(url, os.Getenv("VOLUME_API_TOKEN"))
	ctx := context.Background()

	volID, err := cli.CreateVolume(ctx, "vcs_authority_"+time.Now().Format("20060102150405"), "main")
	if err != nil {
		t.Fatalf("create volume: %v", err)
	}

	a1, err := Acquire(ctx, cli, volID, "main", "vcs-1", 0)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// A second VCS must not be able to acquire the same volume.
	a2, err := Acquire(ctx, cli, volID, "main", "vcs-2", 0)
	if err == nil {
		_ = a2.Release(ctx)
		_ = a1.Release(ctx)
		t.Fatal("second acquire succeeded; single-authority not enforced")
	}
	t.Logf("second acquire correctly rejected: %v", err)

	// After the first releases, a new authority can take over.
	if err := a1.Release(ctx); err != nil {
		t.Fatalf("release first: %v", err)
	}
	a3, err := Acquire(ctx, cli, volID, "main", "vcs-3", 0)
	if err != nil {
		t.Fatalf("acquire after release (failover): %v", err)
	}
	_ = a3.Release(ctx)
}
