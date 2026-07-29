package histworker

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
)

// threeDomainRig wires a worker over three fs failure domains, the third
// behind a fault wrapper that refuses every Put until healed.
func threeDomainRig(t *testing.T) (*rig, *quotaFailStore) {
	t.Helper()
	const domC = "dom-c"
	repo := newFakeRepo([]string{domA, domB, domC})
	roots := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	var raw []*histstore.FSStore
	for i, domain := range []string{domA, domB, domC} {
		fs, err := histstore.NewFSStore(histstore.FSConfig{Domain: domain, RootDir: roots[i]})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fs.Close() })
		raw = append(raw, fs)
	}
	dark := &quotaFailStore{Store: raw[2], admitPuts: 0, succeeded: map[string]int{}}
	stores, err := NewDomainStores(raw[0], raw[1], dark)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DSN:                 "postgres://test@localhost/test",
		WorkerID:            "test-worker",
		ExpectedPolicyEpoch: 1,
		Stores: []StoreConfig{
			{FailureDomain: domA, Kind: "fs", RootDir: roots[0]},
			{FailureDomain: domB, Kind: "fs", RootDir: roots[1]},
			{FailureDomain: domC, Kind: "fs", RootDir: roots[2]},
		},
		MaterializeConcurrency: 1,
		UploadConcurrency:      4,
		ScrubBatch:             64,
		ScrubConcurrency:       4,
		RepairBatch:            16,
		RepairConcurrency:      4,
		LeaseTTL:               60 * time.Second,
		HeartbeatInterval:      15 * time.Second,
		PollInterval:           100 * time.Millisecond,
		SweepMinAge:            time.Hour,
		FreshenAge:             24 * time.Hour,
		ShutdownGrace:          time.Second,
		MaxCacheBytes:          8 << 20,
		MaxPendingUploadBytes:  8 << 20,
		MaxLegacyBlobBytes:     8 << 20,
	}
	worker, err := New(cfg, repo, stores, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{repo: repo, stores: stores, fsA: raw[0], fsB: raw[1], worker: worker}, dark
}

// W-of-N readiness: with three policy domains and one completely dark, a
// cut still publishes on the 2-copy write quorum — every closure object
// verified in two independent domains — and the missing third-domain
// copies heal asynchronously through the ordinary repair loop once the
// domain returns.
func TestCutPublishesOnWriteQuorumWithOneDomainDown(t *testing.T) {
	r, dark := threeDomainRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-q", "hcut_quorum")
	r.repo.addCut(cut)

	if n := r.repo.mustRunCuts(t, ctx, r.worker); n != 1 {
		t.Fatalf("claimed %d cuts", n)
	}
	if cut.state != "ready" || cut.opSettled != "succeeded" {
		t.Fatalf("cut state %s / op %s (err %s)", cut.state, cut.opSettled, cut.lastError)
	}
	closure := mergedClosures(cut)
	for digest := range closure {
		located, err := r.repo.LocateObject(ctx, "tenant-q", "pft2", digest)
		if err != nil || located == nil {
			t.Fatalf("locate %s: %+v %v", digest, located, err)
		}
		if located.State != "live" || len(located.Copies) != 2 {
			t.Fatalf("object %s below quorum: %+v", digest, located)
		}
		for _, c := range located.Copies {
			if c.FailureDomain == "dom-c" {
				t.Fatalf("object %s carries a receipt for the dark domain", digest)
			}
		}
	}
	// Upload receipts landed in batched transactions, never one-per-copy.
	r.repo.mu.Lock()
	batch, single := r.repo.callsReceiptBatch, r.repo.callsReceipt
	r.repo.mu.Unlock()
	if batch == 0 || single != 0 {
		t.Fatalf("receipts recorded in %d batches and %d singles; want batched only", batch, single)
	}

	// The healed domain converges to full coverage through repair alone.
	dark.heal()
	for i := 0; i < 64; i++ {
		if r.worker.runRepairOnce(ctx) == 0 {
			break
		}
	}
	for digest := range closure {
		located, err := r.repo.LocateObject(ctx, "tenant-q", "pft2", digest)
		if err != nil || located == nil || len(located.Copies) != 3 {
			t.Fatalf("object %s not repaired to full coverage: %+v %v", digest, located, err)
		}
	}
}
