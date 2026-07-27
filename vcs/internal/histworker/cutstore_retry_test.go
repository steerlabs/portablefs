package histworker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

// throttlingS3 is a minimal S3-compatible endpoint that answers the first N
// requests with 503 SlowDown — the production failure mode of the history
// buckets, where one throttled PUT used to fail an entire fold attempt.
type throttlingS3 struct {
	mu       sync.Mutex
	objects  map[string][]byte
	failures int // remaining 503s (negative = every request)
	requests int
}

func (t *throttlingS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	t.requests++
	fail := t.failures != 0
	if fail && t.failures > 0 {
		t.failures--
	}
	t.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "<Error><Code>SlowDown</Code></Error>")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		t.mu.Lock()
		t.objects[key] = body
		t.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		t.mu.Lock()
		data, ok := t.objects[key]
		t.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(data)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (t *throttlingS3) stored() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.objects)
}

// newThrottlingRig wires ONE claimed cut whose single required domain is an
// S3 store pointed at a throttling endpoint.
func newThrottlingRig(t *testing.T, failures int) (*cutStore, *throttlingS3) {
	t.Helper()
	const domain = "dom-s3"
	fake := &throttlingS3{objects: map[string][]byte{}, failures: failures}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain: domain, Endpoint: server.URL, Region: "auto",
		Bucket: "portablefs-history", Prefix: "pfh-b", PathStyle: true,
		AccessKeyID: "AKTEST", SecretAccessKey: "secretsecret",
		OperationTimeout: 5 * time.Second,
		Retry: histstore.RetryPolicy{
			MaxAttempts: 6, Base: time.Millisecond, Cap: 4 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	stores, err := NewDomainStores(store)
	if err != nil {
		t.Fatal(err)
	}
	repo := newFakeRepo([]string{domain})
	repo.addCut(buildManagedCut(t, "tenant-throttle", "cut-throttle"))
	claims, err := repo.ClaimCuts(context.Background(), "test-worker", 1, 60_000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %v (%d claims)", err, len(claims))
	}
	cfg := Config{
		UploadConcurrency:     4,
		MaxPendingUploadBytes: 1 << 20,
		MaxCacheBytes:         1 << 20,
	}
	return newCutStore(context.Background(), repo, stores, claims[0], cfg), fake
}

func seedObjects(t *testing.T, store *cutStore, n int) {
	t.Helper()
	for i := range n {
		data := []byte(strings.Repeat("fold-object-", 8) + strconv.Itoa(i))
		if err := store.Seed(pft2.RefOf(data), data); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

// A throttling burst no longer costs the whole attempt: the fold's uploads
// absorb the 503s, every object lands and is read-back-verified, and the
// cut-level retry is never reached (the 16x amplification loop that dead
// lettered an 871k-record cut).
func TestCutStoreFlushAbsorbsThrottling(t *testing.T) {
	store, fake := newThrottlingRig(t, 5)
	seedObjects(t, store, 8)
	if err := store.Flush(); err != nil {
		t.Fatalf("flush under throttling: %v", err)
	}
	if got := store.ObjectsUploaded.Load(); got != 8 {
		t.Fatalf("uploaded %d objects, want 8", got)
	}
	if got := fake.stored(); got != 8 {
		t.Fatalf("endpoint holds %d objects, want 8", got)
	}
	if got := store.StoreRetries.Load(); got != 5 {
		t.Fatalf("counted %d absorbed store retries, want 5", got)
	}
}

// Throttling that outlasts the bounded budget still fails the attempt — the
// cut-level retry remains the outer loop — and the absorbed retries are
// counted so an operator can see WHY the attempt failed.
func TestCutStoreFlushSurfacesPersistentThrottling(t *testing.T) {
	store, _ := newThrottlingRig(t, -1)
	seedObjects(t, store, 3)
	err := store.Flush()
	if err == nil {
		t.Fatal("persistent throttling reported a successful flush")
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("error lost its shape: %v", err)
	}
	if got := store.StoreRetries.Load(); got == 0 {
		t.Fatal("absorbed retries were not counted")
	}
}

// The counter is fed by the stores themselves; a backend with no transient
// failure mode (the local filesystem) simply reports nothing.
func TestCutStoreRetryCounterIgnoresNonReportingStores(t *testing.T) {
	rig := newRig(t)
	repo := rig.repo
	repo.addCut(buildManagedCut(t, "tenant-fs", "cut-fs"))
	claims, err := repo.ClaimCuts(context.Background(), "test-worker", 1, 60_000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %v (%d claims)", err, len(claims))
	}
	store := newCutStore(context.Background(), repo, rig.stores, claims[0], Config{
		UploadConcurrency:     2,
		MaxPendingUploadBytes: 1 << 20,
		MaxCacheBytes:         1 << 20,
	})
	seedObjects(t, store, 2)
	if err := store.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := store.StoreRetries.Load(); got != 0 {
		t.Fatalf("filesystem stores reported %d retries, want 0", got)
	}
}
