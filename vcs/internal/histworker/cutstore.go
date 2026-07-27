package histworker

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/historycut"
	"github.com/steerlabs/portablefs/vcs/internal/histstore"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

// Read-after-write patience for S3-compatible stores: a freshly PUT object
// may answer 404 from an immediately following GET (propagation lag, seen
// in production between write and readback on the same bucket). ONLY that
// typed absence is retried, with bounded exponential backoff
// (200/400/800/1600/3200ms, ~6.2s worst case); every other failure — size
// lie, digest mismatch, transport error — stays attempt-fatal immediately.
const (
	readbackNotFoundRetries = 5
	readbackInitialBackoff  = 200 * time.Millisecond
)

// throttleBackoff sleeps a full-jittered backoff or returns early with the
// context's error.
func throttleBackoff(ctx context.Context, backoff time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(backoff/2 + rand.N(backoff/2+1)):
		return nil
	}
}

// cutStore is the historycut.Store of one claimed materialization: reducer
// output is uploaded AS PRODUCED (claim-fenced intent → streamed write to
// every required domain's exact per-incarnation key → read-after-write
// verify → fenced copy receipt) under a bounded pending budget, and reads
// resolve through a disposable bounded LRU, falling back to DB-located
// exact recorded keys with full re-verification. Nothing here is durable
// local truth: the process can die at any instant and a rerun reproduces
// the same objects at the same keys.
type cutStore struct {
	ctx     context.Context
	repo    Repository
	stores  *DomainStores
	claim   CutClaim
	domains []string // required failure domains (validated configured)

	uploadConcurrency int
	maxPendingBytes   int64

	mu           sync.Mutex
	pending      map[pft2.Ref][]byte
	pendingOrder []pft2.Ref
	pendingBytes int64

	cache      map[pft2.Ref]*list.Element
	cacheList  *list.List // front = most recent
	cacheBytes int64
	cacheMax   int64

	// uploaded maps "sha256:<hex>" -> bound incarnation for every object
	// this run intended+uploaded+receipted in all required domains.
	uploaded map[string]int64

	needs map[string]int64

	// progress counters (read by the heartbeat goroutine).
	ObjectsUploaded atomic.Int64
	BytesUploaded   atomic.Int64
	ObjectsFetched  atomic.Int64
	// StoreRetries counts the transient store failures (503 SlowDown, 429,
	// reset connections) the required domains absorbed with backoff while
	// this run's uploads were in flight. It is the operator's signal that a
	// history bucket is throttling the fold: nonzero means the attempt was
	// SAVED from the old failure mode, where one 503 failed the whole
	// attempt and the retry restarted the fold and re-hammered the store.
	// The stores count per process, so when several cuts materialize at
	// once the attribution to one cut is approximate; the signal is not.
	StoreRetries atomic.Int64

	// phase names the attempt's current stage ("materializing", then
	// "publishing") for heartbeat progress and outcome events.
	phase atomic.Value

	// peakMemory tracks pending+cache high water (bounded-memory tests).
	peakMemory int64
}

type cacheEntry struct {
	ref  pft2.Ref
	data []byte
}

func newCutStore(ctx context.Context, repo Repository, stores *DomainStores, claim CutClaim, cfg Config) *cutStore {
	s := &cutStore{
		ctx:               ctx,
		repo:              repo,
		stores:            stores,
		claim:             claim,
		domains:           claim.ReplicationPolicy.RequiredFailureDomains,
		uploadConcurrency: cfg.UploadConcurrency,
		maxPendingBytes:   cfg.MaxPendingUploadBytes,
		pending:           map[pft2.Ref][]byte{},
		cache:             map[pft2.Ref]*list.Element{},
		cacheList:         list.New(),
		cacheMax:          cfg.MaxCacheBytes,
		uploaded:          map[string]int64{},
		needs:             map[string]int64{},
	}
	s.phase.Store("materializing")
	return s
}

// SetPhase / Phase publish the attempt stage to the heartbeat goroutine
// and outcome events.
func (s *cutStore) SetPhase(phase string) { s.phase.Store(phase) }

func (s *cutStore) Phase() string {
	phase, _ := s.phase.Load().(string)
	return phase
}

func digestOfRef(ref pft2.Ref) string { return "sha256:" + ref.Hex() }

// Seed implements historycut.Store: stage one produced object for upload.
func (s *cutStore) Seed(ref pft2.Ref, data []byte) error {
	if pft2.RefOf(data) != ref {
		return fmt.Errorf("histworker: staged object does not match its reference")
	}
	s.mu.Lock()
	_, inPending := s.pending[ref]
	_, inCache := s.cache[ref]
	_, isUploaded := s.uploaded[digestOfRef(ref)]
	if inPending || inCache || isUploaded {
		s.mu.Unlock()
		return nil
	}
	s.pending[ref] = append([]byte(nil), data...)
	s.pendingOrder = append(s.pendingOrder, ref)
	s.pendingBytes += int64(len(data))
	s.notePeakLocked()
	needFlush := s.pendingBytes >= s.maxPendingBytes || len(s.pendingOrder) >= 512
	s.mu.Unlock()
	if needFlush {
		return s.Flush()
	}
	return nil
}

// PutNode implements pft2.NodeSink.
func (s *cutStore) PutNode(ref pft2.Ref, encoded []byte) error { return s.Seed(ref, encoded) }

// PutPack implements pft2.PackSink.
func (s *cutStore) PutPack(ref pft2.Ref, data []byte) error { return s.Seed(ref, data) }

// NeedDigest / Needs implement the reducer's diagnostic surface; the worker
// fetches directly, so needs only accumulate on hard fetch failures.
func (s *cutStore) NeedDigest(digest string, size int64) {
	s.mu.Lock()
	s.needs[digest] = size
	s.mu.Unlock()
}

func (s *cutStore) Needs() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.needs))
	for k, v := range s.needs {
		out[k] = v
	}
	return out
}

// Flush uploads every pending object: one bounded intent batch (binding
// incarnations BEFORE the first PUT), then per object × required domain a
// streamed write to the exact key, an independent read-after-write
// verification, and a fenced copy receipt. Only a fully receipted object
// leaves pending (into the disposable cache).
func (s *cutStore) Flush() error {
	for {
		s.mu.Lock()
		if len(s.pendingOrder) == 0 {
			s.mu.Unlock()
			return nil
		}
		batchRefs := s.pendingOrder
		if len(batchRefs) > 512 {
			batchRefs = batchRefs[:512]
		}
		batch := make([]pft2.Ref, len(batchRefs))
		copy(batch, batchRefs)
		s.mu.Unlock()

		intents := make([]ObjectIntent, len(batch))
		for i, ref := range batch {
			intents[i] = ObjectIntent{Digest: digestOfRef(ref), Size: int64(ref.Size)}
		}
		bindings, err := s.repo.IntendObjects(s.ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, intents)
		if err != nil {
			return err
		}

		type job struct {
			ref         pft2.Ref
			incarnation int64
		}
		jobs := make([]job, 0, len(batch))
		for _, ref := range batch {
			incarnation, ok := bindings[digestOfRef(ref)]
			if !ok {
				return fmt.Errorf("histworker: intent response is missing %s", digestOfRef(ref))
			}
			jobs = append(jobs, job{ref: ref, incarnation: incarnation})
		}

		// Per-job error slots keep the reported failure deterministic: the
		// first failed job in intent order wins, regardless of goroutine
		// scheduling.
		retriesBefore := s.storeRetryTotal()
		sem := make(chan struct{}, s.uploadConcurrency)
		uploadErrs := make([]error, len(jobs))
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			go func(i int, j job) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				s.mu.Lock()
				data := s.pending[j.ref]
				s.mu.Unlock()
				if data == nil {
					return // uploaded by an earlier overlapping flush
				}
				uploadErrs[i] = s.uploadOne(j.ref, j.incarnation, data)
			}(i, j)
		}
		wg.Wait()
		if absorbed := s.storeRetryTotal() - retriesBefore; absorbed > 0 {
			s.StoreRetries.Add(absorbed)
		}
		for _, err := range uploadErrs {
			if err != nil {
				return err
			}
		}

		s.mu.Lock()
		remaining := s.pendingOrder[:0]
		inBatch := map[pft2.Ref]bool{}
		for _, j := range jobs {
			inBatch[j.ref] = true
			s.uploaded[digestOfRef(j.ref)] = j.incarnation
		}
		for _, ref := range s.pendingOrder {
			if !inBatch[ref] {
				remaining = append(remaining, ref)
				continue
			}
			data := s.pending[ref]
			delete(s.pending, ref)
			s.pendingBytes -= int64(len(data))
			s.cacheInsertLocked(ref, data)
		}
		s.pendingOrder = append([]pft2.Ref(nil), remaining...)
		s.mu.Unlock()
	}
}

// storeRetryTotal sums the transient failures every required domain's store
// has absorbed with backoff so far in this process. Backends with no
// transient failure mode (the local filesystem) do not report and count 0;
// histstore owns the retrying, this layer only counts it, because histstore
// has no logger or metrics registry of its own.
func (s *cutStore) storeRetryTotal() int64 {
	var total int64
	for _, domain := range s.domains {
		store, ok := s.stores.Get(domain)
		if !ok {
			continue
		}
		if reporter, ok := store.(histstore.RetryReporter); ok {
			total += reporter.RetryStats().Retries
		}
	}
	return total
}

// uploadOne writes one object to every required domain and records fenced
// receipts after read-after-write proof. Same-incarnation bytes only: the
// exact key embeds the intent-bound incarnation.
func (s *cutStore) uploadOne(ref pft2.Ref, incarnation int64, data []byte) error {
	id := histstore.ObjectID{
		Tenant: s.claim.TenantID, Kind: "pft2",
		DigestHex: ref.Hex(), Incarnation: incarnation,
	}
	for _, domain := range s.domains {
		store, ok := s.stores.Get(domain)
		if !ok {
			return fmt.Errorf("%w: required failure domain %q has no store", ErrPolicyMismatch, domain)
		}
		key, err := store.ExactKey(id)
		if err != nil {
			return err
		}
		if err := store.Put(s.ctx, key, int64(ref.Size), ref.Hex(), bytes.NewReader(data)); err != nil {
			return fmt.Errorf("histworker: upload %s to %s: %w", digestOfRef(ref), domain, err)
		}
		// Independent read-after-write proof from the same exact key.
		if err := readbackVerified(s.ctx, store, key, int64(ref.Size), ref.Hex()); err != nil {
			return fmt.Errorf("histworker: readback %s from %s: %w", digestOfRef(ref), domain, err)
		}
		if err := s.repo.RecordCopyReceipt(s.ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch,
			digestOfRef(ref), incarnation, domain, key, int64(ref.Size)); err != nil {
			return err
		}
	}
	s.ObjectsUploaded.Add(1)
	s.BytesUploaded.Add(int64(len(data)))
	return nil
}

// readbackVerified is ReadVerified with propagation patience: it retries
// ONLY histstore.ErrNotFound (the just-written key not yet visible to
// readers) within the bounded backoff schedule above, so seconds of
// eventual consistency stop costing whole attempt restarts. Any other
// error, and absence that outlives the schedule, fail immediately.
// (Throttling is absorbed inside the store itself — see
// histstore.RetryPolicy — never here, so the two layers cannot multiply.)
func readbackVerified(ctx context.Context, store histstore.Store, key string, size int64, digestHex string) error {
	backoff := readbackInitialBackoff
	for attempt := 0; ; attempt++ {
		_, err := histstore.ReadVerified(ctx, store, key, size, digestHex)
		if err == nil || !errors.Is(err, histstore.ErrNotFound) || attempt >= readbackNotFoundRetries {
			return err
		}
		if waitErr := throttleBackoff(ctx, backoff); waitErr != nil {
			return waitErr
		}
		backoff *= 2
	}
}

// Fetch implements pft2.Fetcher: pending, then cache, then the database's
// recorded exact keys with re-verification. All local copies are
// disposable; the recorded keys are the only address of truth.
func (s *cutStore) Fetch(ctx context.Context, ref pft2.Ref) ([]byte, error) {
	s.mu.Lock()
	if data, ok := s.pending[ref]; ok {
		s.mu.Unlock()
		return data, nil
	}
	if elem, ok := s.cache[ref]; ok {
		s.cacheList.MoveToFront(elem)
		data := elem.Value.(*cacheEntry).data
		s.mu.Unlock()
		return data, nil
	}
	s.mu.Unlock()

	data, err := s.fetchRecorded(ctx, ref)
	if err != nil {
		s.NeedDigest(digestOfRef(ref), int64(ref.Size))
		return nil, err
	}
	s.mu.Lock()
	s.cacheInsertLocked(ref, data)
	s.mu.Unlock()
	s.ObjectsFetched.Add(1)
	return data, nil
}

// fetchRecorded resolves one object through pfh.object_locate and verifies
// bytes from the first healthy recorded copy.
func (s *cutStore) fetchRecorded(ctx context.Context, ref pft2.Ref) ([]byte, error) {
	digest := digestOfRef(ref)
	loc, err := s.repo.LocateObject(ctx, s.claim.TenantID, "pft2", digest)
	if err != nil {
		return nil, err
	}
	if loc == nil {
		return nil, fmt.Errorf("histworker: object %s has no recorded location", digest)
	}
	if loc.Size != int64(ref.Size) {
		return nil, fmt.Errorf("%w: object %s recorded size %d, reference says %d",
			historycut.ErrCorrupt, digest, loc.Size, ref.Size)
	}
	var lastErr error
	for _, copyRec := range loc.Copies {
		store, ok := s.stores.Get(copyRec.FailureDomain)
		if !ok {
			continue
		}
		data, err := histstore.ReadVerified(ctx, store, copyRec.StorageKey, int64(ref.Size), ref.Hex())
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no copy is reachable from configured domains")
	}
	return nil, fmt.Errorf("histworker: object %s: %w", digest, lastErr)
}

// UploadedIncarnation reports the bound incarnation of an object this run
// uploaded (ok=false when the object was reused from the base).
func (s *cutStore) UploadedIncarnation(digest string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incarnation, ok := s.uploaded[digest]
	return incarnation, ok
}

// CachedBytes returns bytes for a digest when locally available (upload
// avoidance during closure proof); the second result reports availability.
func (s *cutStore) CachedBytes(ref pft2.Ref) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if data, ok := s.pending[ref]; ok {
		return data, true
	}
	if elem, ok := s.cache[ref]; ok {
		return elem.Value.(*cacheEntry).data, true
	}
	return nil, false
}

// PeakMemoryBytes reports the pending+cache high water mark.
func (s *cutStore) PeakMemoryBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peakMemory
}

func (s *cutStore) cacheInsertLocked(ref pft2.Ref, data []byte) {
	if elem, ok := s.cache[ref]; ok {
		s.cacheList.MoveToFront(elem)
		return
	}
	s.cache[ref] = s.cacheList.PushFront(&cacheEntry{ref: ref, data: data})
	s.cacheBytes += int64(len(data))
	for s.cacheBytes > s.cacheMax && s.cacheList.Len() > 1 {
		oldest := s.cacheList.Back()
		entry := oldest.Value.(*cacheEntry)
		s.cacheList.Remove(oldest)
		delete(s.cache, entry.ref)
		s.cacheBytes -= int64(len(entry.data))
	}
	s.notePeakLocked()
}

func (s *cutStore) notePeakLocked() {
	if total := s.pendingBytes + s.cacheBytes; total > s.peakMemory {
		s.peakMemory = total
	}
}
