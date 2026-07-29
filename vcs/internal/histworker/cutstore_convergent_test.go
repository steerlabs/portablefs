package histworker

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
)

// quotaFailStore admits a bounded number of successful Puts, then fails
// every further Put until healed — the shape of a store outage that kills
// an attempt partway through its upload set. Successful puts are counted
// per key so a test can prove no object was ever uploaded twice.
type quotaFailStore struct {
	histstore.Store

	mu        sync.Mutex
	admitPuts int // -1 = unlimited
	succeeded map[string]int
}

func (q *quotaFailStore) Put(ctx context.Context, key string, size int64, digestHex string, body io.Reader) error {
	q.mu.Lock()
	if q.admitPuts == 0 {
		q.mu.Unlock()
		return fmt.Errorf("histstore: %s: HTTP 503 SlowDown (simulated outage)", q.Domain())
	}
	if q.admitPuts > 0 {
		q.admitPuts--
	}
	q.mu.Unlock()
	if err := q.Store.Put(ctx, key, size, digestHex, body); err != nil {
		return err
	}
	q.mu.Lock()
	q.succeeded[key]++
	q.mu.Unlock()
	return nil
}

func (q *quotaFailStore) heal() {
	q.mu.Lock()
	q.admitPuts = -1
	q.mu.Unlock()
}

func (q *quotaFailStore) putStats() (total, maxPerKey int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, n := range q.succeeded {
		total += n
		if n > maxPerKey {
			maxPerKey = n
		}
	}
	return total, maxPerKey
}

// A retried cut attempt must upload ONLY the objects the first attempt
// never receipted: the batch locate consults the previous attempt's fenced
// copy receipts at the bound incarnation and skips everything fresh. This
// is the fix for the 25-minute incident class, where every retry re-walked
// the full upload set against the same throttled store.
func TestFlushSkipsReceiptedUploadsOnRetry(t *testing.T) {
	const domain = "dom-conv"
	ctx := context.Background()
	inner, err := histstore.NewFSStore(histstore.FSConfig{Domain: domain, RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	fault := &quotaFailStore{Store: inner, admitPuts: 3, succeeded: map[string]int{}}
	stores, err := NewDomainStores(fault)
	if err != nil {
		t.Fatal(err)
	}
	repo := newFakeRepo([]string{domain})
	repo.addCut(buildManagedCut(t, "tenant-conv", "cut-conv"))
	cfg := Config{
		UploadConcurrency:     1, // deterministic: exactly the first 3 jobs land
		MaxPendingUploadBytes: 1 << 20,
		MaxCacheBytes:         1 << 20,
		FreshenAge:            24 * time.Hour,
	}

	claims, err := repo.ClaimCuts(ctx, "test-worker", 1, 60_000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %v (%d claims)", err, len(claims))
	}
	first := newCutStore(ctx, repo, stores, claims[0], cfg)
	seedObjects(t, first, 8)
	if err := first.Flush(); err == nil {
		t.Fatal("outage mid-upload reported a successful flush")
	}
	if got := first.ObjectsUploaded.Load(); got != 3 {
		t.Fatalf("first attempt receipted %d objects, want 3", got)
	}
	if err := repo.RetryCut(ctx, "cut-conv", claims[0].ClaimEpoch, map[string]any{"kind": "transient"}, 0); err != nil {
		t.Fatal(err)
	}

	fault.heal()
	claims, err = repo.ClaimCuts(ctx, "test-worker", 1, 60_000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("reclaim: %v (%d claims)", err, len(claims))
	}
	second := newCutStore(ctx, repo, stores, claims[0], cfg)
	seedObjects(t, second, 8)
	if err := second.Flush(); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if got := second.ObjectsSkipped.Load(); got != 3 {
		t.Fatalf("retry skipped %d receipted objects, want 3", got)
	}
	if got := second.ObjectsUploaded.Load(); got != 5 {
		t.Fatalf("retry uploaded %d objects, want 5", got)
	}
	total, maxPerKey := fault.putStats()
	if total != 8 || maxPerKey != 1 {
		t.Fatalf("store admitted %d puts (max %d per key); every object must upload exactly once", total, maxPerKey)
	}
	// Skipped objects still count as receipted for publication: they must
	// be in the uploaded set so the closure proof does not re-verify them.
	for digest := range second.uploaded {
		if _, ok := second.UploadedIncarnation(digest); !ok {
			t.Fatalf("uploaded set lost %s", digest)
		}
	}
	if len(second.uploaded) != 8 {
		t.Fatalf("uploaded set holds %d objects, want 8", len(second.uploaded))
	}
}
