package histstore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
)

// fakeS3 is a real HTTP S3-compatible endpoint (httptest, real sockets, real
// transport) with scripted transient failures. It does not verify SigV4 —
// s3_test.go's in-process double already proves the signing path; this one
// exists to prove what the store does when a bucket answers 503 SlowDown.
type fakeS3 struct {
	mu       sync.Mutex
	requests []string
	objects  map[string][]byte

	// failures is how many more requests get the scripted failure
	// (negative = every request).
	failures int
	// status is the scripted failure response (0 with hangup = drop the
	// connection instead of answering).
	status int
	// hangup closes the connection without a response (transient network
	// failure) instead of returning status.
	hangup bool
	// onRequest runs before each response, under no lock.
	onRequest func(n int)
}

func newFakeS3(t *testing.T) (*fakeS3, *httptest.Server) {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}}
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	return f, server
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	n := len(f.requests)
	fail := f.failures != 0
	if fail && f.failures > 0 {
		f.failures--
	}
	status, hangup, hook := f.status, f.hangup, f.onRequest
	f.mu.Unlock()

	if hook != nil {
		hook(n)
	}
	if fail {
		if hangup {
			// Drop the connection mid-request: the client sees a reset or an
			// EOF, the cleanly transient network failure.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		io.WriteString(w, "<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>")
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
		f.mu.Lock()
		f.objects[key] = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		f.mu.Lock()
		data, ok := f.objects[key]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(data)
		}
	case http.MethodDelete:
		f.mu.Lock()
		delete(f.objects, key)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, req := range f.requests {
		if strings.HasPrefix(req, method+" ") {
			n++
		}
	}
	return n
}

func (f *fakeS3) object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects["history/"+key]
	return data, ok
}

// newRetryStore builds a store against the fake endpoint with a fast bounded
// policy (real timings would make the suite sleep for seconds).
func newRetryStore(t *testing.T, server *httptest.Server, policy histstore.RetryPolicy) *histstore.S3Store {
	t.Helper()
	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain: "s3-retry", Endpoint: server.URL, Region: "auto",
		Bucket: "history", PathStyle: true,
		AccessKeyID: "AKTEST", SecretAccessKey: "secretsecret",
		OperationTimeout: 5 * time.Second,
		Retry:            policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func fastPolicy(attempts int) histstore.RetryPolicy {
	return histstore.RetryPolicy{
		MaxAttempts: attempts,
		Base:        time.Millisecond,
		Cap:         4 * time.Millisecond,
	}
}

// A burst of SlowDown responses is absorbed: the operation succeeds, having
// issued exactly one request per failure plus the successful one, and the
// bytes that land are the bytes the caller passed (the body is rewound, not
// re-derived, so the fold stays byte-identical).
func TestS3PutRidesOutSlowDownBurst(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = 3, http.StatusServiceUnavailable
	store := newRetryStore(t, server, fastPolicy(6))

	data := bytes.Repeat([]byte("throttled-bytes"), 512)
	key := "pfh-b/t/acme/pft2/sha256/aa/" + hexDigest(data) + "/i1"
	if err := store.Put(context.Background(), key, int64(len(data)), hexDigest(data), bytes.NewReader(data)); err != nil {
		t.Fatalf("put through 3 SlowDowns: %v", err)
	}
	if got := fake.count("PUT"); got != 4 {
		t.Fatalf("PUT requests = %d, want 4 (3 throttled + 1 success)", got)
	}
	stored, ok := fake.object(key)
	if !ok || !bytes.Equal(stored, data) {
		t.Fatalf("stored object mismatch (present=%v, %d bytes, want %d)", ok, len(stored), len(data))
	}
	if stats := store.RetryStats(); stats.Retries != 3 || stats.Exhausted != 0 {
		t.Fatalf("retry stats = %+v, want {Retries:3 Exhausted:0}", stats)
	}
	// Read-after-write on the same store proves the readback path too.
	if _, err := histstore.ReadVerified(context.Background(), store, key, int64(len(data)), hexDigest(data)); err != nil {
		t.Fatalf("readback: %v", err)
	}
}

// Throttling that never lets up is BOUNDED: the store spends its budget and
// then surfaces the failure exactly as it did before retries existed, so the
// cut-level retry stays the outer loop.
func TestS3PutSurfacesAfterRetryBudget(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = -1, http.StatusServiceUnavailable
	store := newRetryStore(t, server, fastPolicy(4))

	data := []byte("permanently throttled")
	start := time.Now()
	err := store.Put(context.Background(), "pfx/perm/object", int64(len(data)), hexDigest(data), bytes.NewReader(data))
	if err == nil {
		t.Fatal("permanent SlowDown reported success")
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("error lost its shape: %v", err)
	}
	if errors.Is(err, histstore.ErrNotFound) {
		t.Fatalf("throttling must not read as absence: %v", err)
	}
	if got := fake.count("PUT"); got != 4 {
		t.Fatalf("PUT requests = %d, want exactly the 4-attempt bound", got)
	}
	if stats := store.RetryStats(); stats.Retries != 3 || stats.Exhausted != 1 {
		t.Fatalf("retry stats = %+v, want {Retries:3 Exhausted:1}", stats)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("bounded retries took %v", elapsed)
	}
}

// A fenced claim cancels the materialization context; a store sitting in a
// backoff must abort immediately instead of sleeping out the delay and
// issuing another request against a bucket it no longer owns the claim for.
func TestS3RetryAbortsPromptlyOnCancel(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = -1, http.StatusServiceUnavailable
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.onRequest = func(n int) {
		if n == 1 {
			cancel() // the fence lands while the store is about to back off
		}
	}
	// A long, unjittered backoff: the test would take 30s if the sleep were
	// not context-aware.
	store := newRetryStore(t, server, histstore.RetryPolicy{
		MaxAttempts: 6, Base: 30 * time.Second, Cap: 30 * time.Second, NoJitter: true,
	})

	data := []byte("fenced mid-backoff")
	start := time.Now()
	err := store.Put(ctx, "pfx/fenced/object", int64(len(data)), hexDigest(data), bytes.NewReader(data))
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel mid-backoff surfaced %v, want context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancel took %v to interrupt the backoff", elapsed)
	}
	if got := fake.count("PUT"); got != 1 {
		t.Fatalf("PUT requests after cancel = %d, want 1", got)
	}
	if stats := store.RetryStats(); stats.Retries != 0 {
		t.Fatalf("a canceled backoff must not count as an absorbed retry: %+v", stats)
	}
}

// The read path rides out throttling the same way: 429 on GET and HEAD.
func TestS3ReadPathRidesOutThrottling(t *testing.T) {
	fake, server := newFakeS3(t)
	store := newRetryStore(t, server, fastPolicy(6))
	ctx := context.Background()

	data := []byte("read path bytes")
	key := "pfx/read/object"
	if err := store.Put(ctx, key, int64(len(data)), hexDigest(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.failures, fake.status = 2, http.StatusTooManyRequests
	fake.mu.Unlock()
	got, err := histstore.ReadVerified(ctx, store, key, int64(len(data)), hexDigest(data))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get through 429s: %v", err)
	}
	if n := fake.count("GET"); n != 3 {
		t.Fatalf("GET requests = %d, want 3", n)
	}

	fake.mu.Lock()
	fake.failures, fake.status = 2, http.StatusTooManyRequests
	fake.mu.Unlock()
	size, err := store.Head(ctx, key)
	if err != nil || size != int64(len(data)) {
		t.Fatalf("head through 429s: %d %v", size, err)
	}
	if n := fake.count("HEAD"); n != 3 {
		t.Fatalf("HEAD requests = %d, want 3", n)
	}
}

// Deterministic failures are NOT retried: a rejected signature, a malformed
// request, or a proven absence answers identically every time, so retrying
// only delays the truth.
func TestS3PermanentStatusesAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"forbidden", http.StatusForbidden},
		{"bad request", http.StatusBadRequest},
		{"not found", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, server := newFakeS3(t)
			fake.failures, fake.status = -1, tc.status
			store := newRetryStore(t, server, fastPolicy(6))
			data := []byte("x")
			if err := store.Put(context.Background(), "pfx/permanent/object",
				int64(len(data)), hexDigest(data), bytes.NewReader(data)); err == nil {
				t.Fatal("permanent status reported success")
			}
			if got := fake.count("PUT"); got != 1 {
				t.Fatalf("PUT requests = %d, want 1 (no retry)", got)
			}
			if stats := store.RetryStats(); stats.Retries != 0 || stats.Exhausted != 0 {
				t.Fatalf("retry stats = %+v, want zero", stats)
			}
		})
	}
}

// A body that cannot be rewound is never re-sent: the transport may already
// have consumed it, so a second attempt could write truncated bytes. Such an
// operation keeps its pre-retry single-shot behaviour.
func TestS3NonRewindableBodyIsNotRetried(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = -1, http.StatusServiceUnavailable
	store := newRetryStore(t, server, fastPolicy(6))

	data := []byte("streamed, not seekable")
	// readerOnly hides bytes.Reader's Seeker (what a piped copy looks like).
	body := struct{ io.Reader }{bytes.NewReader(data)}
	if err := store.Put(context.Background(), "pfx/stream/object",
		int64(len(data)), hexDigest(data), body); err == nil {
		t.Fatal("throttled stream reported success")
	}
	if got := fake.count("PUT"); got != 1 {
		t.Fatalf("PUT requests = %d, want 1 (a consumed stream is never re-sent)", got)
	}
}

// A dropped connection is transient in exactly the way a SlowDown is.
func TestS3RetriesDroppedConnection(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.hangup = 2, true
	store := newRetryStore(t, server, fastPolicy(6))

	data := []byte("connection dropped twice")
	key := "pfx/dropped/object"
	if err := store.Put(context.Background(), key, int64(len(data)), hexDigest(data), bytes.NewReader(data)); err != nil {
		t.Fatalf("put through 2 dropped connections: %v", err)
	}
	if got := fake.count("PUT"); got != 3 {
		t.Fatalf("PUT requests = %d, want 3", got)
	}
	stored, ok := fake.object(key)
	if !ok || !bytes.Equal(stored, data) {
		t.Fatalf("stored object mismatch after reconnects (present=%v)", ok)
	}
}

// MaxAttempts=1 is the explicit opt-out and restores exactly the old
// behaviour: one request, one error.
func TestS3RetryDisabled(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = -1, http.StatusServiceUnavailable
	store := newRetryStore(t, server, histstore.RetryPolicy{MaxAttempts: 1})

	data := []byte("no retries")
	if err := store.Put(context.Background(), "pfx/once/object",
		int64(len(data)), hexDigest(data), bytes.NewReader(data)); err == nil {
		t.Fatal("disabled retry reported success")
	}
	if got := fake.count("PUT"); got != 1 {
		t.Fatalf("PUT requests = %d, want 1", got)
	}
	if stats := store.RetryStats(); stats.Retries != 0 || stats.Exhausted != 0 {
		t.Fatalf("retry stats = %+v, want zero when retrying is off", stats)
	}
}

// The observer hook sees every absorbed failure (what a caller with a logger
// or a metrics registry wires to).
func TestS3RetryObserverSeesEveryAbsorbedFailure(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = 2, http.StatusServiceUnavailable

	var mu sync.Mutex
	var events []histstore.RetryEvent
	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain: "s3-retry", Endpoint: server.URL, Region: "auto",
		Bucket: "history", PathStyle: true,
		AccessKeyID: "AKTEST", SecretAccessKey: "secretsecret",
		OperationTimeout: 5 * time.Second,
		Retry:            fastPolicy(6),
		OnRetry: func(ev histstore.RetryEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("observed")
	if err := store.Put(context.Background(), "pfx/observed/object",
		int64(len(data)), hexDigest(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("observed %d retries, want 2", len(events))
	}
	for i, ev := range events {
		if ev.Status != http.StatusServiceUnavailable || ev.Op != http.MethodPut ||
			ev.Domain != "s3-retry" || ev.Attempt != i+1 {
			t.Fatalf("event[%d] = %+v", i, ev)
		}
		if ev.Key != "pfx/observed/object" {
			t.Fatalf("event[%d] key = %q", i, ev.Key)
		}
	}
}

// Backoff grows and is capped: with jitter disabled the delays are exactly
// Base, 2*Base, ... clamped at Cap, so a long throttling burst cannot make
// one operation sleep unboundedly.
func TestS3BackoffGrowsAndCaps(t *testing.T) {
	fake, server := newFakeS3(t)
	fake.failures, fake.status = -1, http.StatusServiceUnavailable
	var mu sync.Mutex
	var delays []time.Duration
	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain: "s3-retry", Endpoint: server.URL, Region: "auto",
		Bucket: "history", PathStyle: true,
		AccessKeyID: "AKTEST", SecretAccessKey: "secretsecret",
		OperationTimeout: 5 * time.Second,
		Retry: histstore.RetryPolicy{
			MaxAttempts: 5, Base: 2 * time.Millisecond, Cap: 6 * time.Millisecond, NoJitter: true,
		},
		OnRetry: func(ev histstore.RetryEvent) {
			mu.Lock()
			delays = append(delays, ev.Delay)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("backoff")
	if err := store.Put(context.Background(), "pfx/backoff/object",
		int64(len(data)), hexDigest(data), bytes.NewReader(data)); err == nil {
		t.Fatal("permanent SlowDown reported success")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []time.Duration{2 * time.Millisecond, 4 * time.Millisecond, 6 * time.Millisecond, 6 * time.Millisecond}
	if len(delays) != len(want) {
		t.Fatalf("delays = %v, want %v", delays, want)
	}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("delay[%d] = %v, want %v (full sequence %v)", i, delays[i], want[i], delays)
		}
	}
}
