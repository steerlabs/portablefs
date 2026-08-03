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
	// freshFloor is the receipt-freshness cutoff (claim DB time minus the
	// freshen age): a copy verified at or after it needs no re-upload and
	// no re-verification — the same rule proveOne applies at publish.
	freshFloor int64

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
	// ObjectsSkipped counts objects a previous attempt already uploaded and
	// receipted (fresh, at the bound incarnation, in every required
	// domain): the convergent-retry path skips their uploads entirely, so
	// a retried cut only pays for what is actually missing.
	ObjectsSkipped atomic.Int64
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
		freshFloor:        claim.DbTimeMs - cfg.FreshenAge.Milliseconds(),
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
		digests := make([]string, len(batch))
		for i, ref := range batch {
			digests[i] = digestOfRef(ref)
			intents[i] = ObjectIntent{Digest: digests[i], Size: int64(ref.Size)}
		}
		bindings, err := s.repo.IntendObjects(s.ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, intents)
		if err != nil {
			return err
		}
		// Convergent retries: a previous attempt's verified receipts at the
		// SAME bound incarnation are exactly as good as ours — locate the
		// whole batch once and upload only to domains without a fresh copy.
		located, err := s.repo.LocateObjects(s.ctx, s.claim.TenantID, "pft2", digests)
		if err != nil {
			return err
		}

		type job struct {
			ref         pft2.Ref
			incarnation int64
			missing     []string // required domains without a fresh receipt
		}
		jobs := make([]job, 0, len(batch))
		for _, ref := range batch {
			digest := digestOfRef(ref)
			incarnation, ok := bindings[digest]
			if !ok {
				return fmt.Errorf("histworker: intent response is missing %s", digest)
			}
			jobs = append(jobs, job{
				ref:         ref,
				incarnation: incarnation,
				missing:     s.missingDomains(located[digest], incarnation),
			})
		}

		// Per-job error slots keep the reported failure deterministic: the
		// first failed job in intent order wins, regardless of goroutine
		// scheduling. Receipts collect per job and land in batched
		// transactions after the wave — including proven copies of jobs
		// whose quorum failed, so the next attempt converges on them.
		quorum := writeQuorum(len(s.domains))
		retriesBefore := s.storeRetryTotal()
		sem := make(chan struct{}, s.uploadConcurrency)
		uploadErrs := make([]error, len(jobs))
		jobReceipts := make([][]CopyReceipt, len(jobs))
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
				if len(s.domains)-len(j.missing) >= quorum {
					s.ObjectsSkipped.Add(1)
					return // quorum already receipted by a previous attempt
				}
				jobReceipts[i], uploadErrs[i] = s.uploadObject(j.ref, j.incarnation, data, j.missing, quorum)
			}(i, j)
		}
		wg.Wait()
		if absorbed := s.storeRetryTotal() - retriesBefore; absorbed > 0 {
			s.StoreRetries.Add(absorbed)
		}
		var receipts []CopyReceipt
		for _, proven := range jobReceipts {
			receipts = append(receipts, proven...)
		}
		if err := s.recordReceipts(receipts); err != nil {
			return err
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

// missingDomains reports the required failure domains without a fresh
// verified receipt at the bound incarnation — the domains an upload must
// still cover. A location at a different incarnation grants nothing (its
// keys embed the superseded incarnation).
func (s *cutStore) missingDomains(loc *ObjectLocation, incarnation int64) []string {
	fresh := map[string]bool{}
	if loc != nil && loc.Incarnation == incarnation {
		for _, c := range loc.Copies {
			if c.LastVerified >= s.freshFloor {
				fresh[c.FailureDomain] = true
			}
		}
	}
	missing := make([]string, 0, len(s.domains))
	for _, domain := range s.domains {
		if !fresh[domain] {
			missing = append(missing, domain)
		}
	}
	return missing
}

// writeQuorum is the readiness quorum over the policy's N required
// domains: two independently verified copies whenever the policy names at
// least two, one for explicit single-domain deployments. A constant of
// the design (mirrored by pfh.write_quorum), never a knob.
func writeQuorum(n int) int {
	if n < 2 {
		return n
	}
	return 2
}

// uploadObject writes one object to every still-missing required domain IN
// PARALLEL, each write independently read-after-write verified from its
// exact per-incarnation key. It returns the proven copies as receipt facts
// for the batched receipt transaction; the object succeeds once fresh plus
// newly proven copies reach the write quorum — domains a passing quorum
// left unwritten heal through the ordinary repair loop.
func (s *cutStore) uploadObject(ref pft2.Ref, incarnation int64, data []byte, missing []string, quorum int) ([]CopyReceipt, error) {
	id := histstore.ObjectID{
		Tenant: s.claim.TenantID, Kind: "pft2",
		DigestHex: ref.Hex(), Incarnation: incarnation,
	}
	proven := make([]*CopyReceipt, len(missing))
	domainErrs := make([]error, len(missing))
	var wg sync.WaitGroup
	for i, domain := range missing {
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			store, ok := s.stores.Get(domain)
			if !ok {
				domainErrs[i] = fmt.Errorf("%w: required failure domain %q has no store", ErrPolicyMismatch, domain)
				return
			}
			key, err := store.ExactKey(id)
			if err != nil {
				domainErrs[i] = err
				return
			}
			if err := store.Put(s.ctx, key, int64(ref.Size), ref.Hex(), bytes.NewReader(data)); err != nil {
				domainErrs[i] = fmt.Errorf("histworker: upload %s to %s: %w", digestOfRef(ref), domain, err)
				return
			}
			// Independent read-after-write proof from the same exact key.
			if err := readbackVerified(s.ctx, store, key, int64(ref.Size), ref.Hex()); err != nil {
				domainErrs[i] = fmt.Errorf("histworker: readback %s from %s: %w", digestOfRef(ref), domain, err)
				return
			}
			proven[i] = &CopyReceipt{
				Digest: digestOfRef(ref), Incarnation: incarnation,
				FailureDomain: domain, StorageKey: key, Size: int64(ref.Size),
			}
		}(i, domain)
	}
	wg.Wait()
	receipts := make([]CopyReceipt, 0, len(missing))
	for _, r := range proven {
		if r != nil {
			receipts = append(receipts, *r)
		}
	}
	fresh := len(s.domains) - len(missing)
	if fresh+len(receipts) < quorum {
		for _, err := range domainErrs {
			if err != nil {
				return receipts, err
			}
		}
		return receipts, fmt.Errorf("histworker: %s proved %d of the %d-copy write quorum",
			digestOfRef(ref), fresh+len(receipts), quorum)
	}
	s.ObjectsUploaded.Add(1)
	s.BytesUploaded.Add(int64(len(data)))
	return receipts, nil
}

// recordReceipts lands proven copies in bounded batched transactions.
func (s *cutStore) recordReceipts(receipts []CopyReceipt) error {
	for start := 0; start < len(receipts); start += 4096 {
		end := min(start+4096, len(receipts))
		if err := s.repo.RecordCopyReceipts(s.ctx, s.claim.Facts.CutID,
			s.claim.ClaimEpoch, receipts[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// readbackVerified is the read-after-write proof with propagation patience:
// it retries ONLY histstore.ErrNotFound (the just-written key not yet visible
// to readers) within the bounded backoff schedule above, so seconds of
// eventual consistency stop costing whole attempt restarts. Any other error,
// and absence that outlives the schedule, fail immediately. (Throttling is
// absorbed inside the store itself — see histstore.RetryPolicy — never here,
// so the two layers cannot multiply.)
//
// It STREAMS the proof (VerifyStream) rather than materializing the object:
// the caller wants a yes/no, and the bytes were already in hand when the
// upload started. Buffering a whole object per in-flight readback made the
// upload wave's memory O(UploadConcurrency x domains x object size) — up to
// 4 MiB apiece — which is precisely what pinned the concurrency ceiling that
// bounds a cut's upload throughput.
func readbackVerified(ctx context.Context, store histstore.Store, key string, size int64, digestHex string) error {
	backoff := readbackInitialBackoff
	for attempt := 0; ; attempt++ {
		err := histstore.VerifyStream(ctx, store, key, size, digestHex)
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
// bytes from the first healthy recorded copy in this worker's configured
// locality order. The database orders copies by verification freshness for
// serving diagnostics, not network proximity; following that order made a
// west-coast worker read most objects cross-country whenever IAD happened
// to carry the newest receipt. Replication policy still requires every
// named domain for writes. Read locality is deterministic store declaration
// order and an unhealthy preferred copy fails this attempt: there is no
// failure-induced route to another domain.
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
	copyRec, store, ok := s.preferredReadableCopy(loc.Copies)
	if !ok {
		return nil, fmt.Errorf("histworker: object %s: no recorded copy is reachable from configured domains", digest)
	}
	data, err := histstore.ReadVerified(ctx, store, copyRec.StorageKey, int64(ref.Size), ref.Hex())
	if err != nil {
		return nil, fmt.Errorf("histworker: object %s from preferred domain %s: %w",
			digest, copyRec.FailureDomain, err)
	}
	return data, nil
}

// preferredReadableCopy binds one read to the first configured domain with a
// recorded copy. A read error is attempt-fatal; choosing a different copy
// after failure would be an implicit availability fallback and would make
// latency and failure behavior depend on the error.
func (s *cutStore) preferredReadableCopy(copies []CopyRecord) (CopyRecord, histstore.Store, bool) {
	byDomain := make(map[string]CopyRecord, len(copies))
	for _, copyRec := range copies {
		byDomain[copyRec.FailureDomain] = copyRec
	}
	for _, domain := range s.stores.Domains() {
		copyRec, ok := byDomain[domain]
		if !ok {
			continue
		}
		store, configured := s.stores.Get(domain)
		if configured {
			return copyRec, store, true
		}
	}
	return CopyRecord{}, nil, false
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
