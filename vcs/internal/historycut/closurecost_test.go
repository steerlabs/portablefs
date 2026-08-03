package historycut

// Cut THROUGHPUT, not just cut correctness.
//
// A cut only relieves the writer if it lands before the writer refills the
// bound that triggered it. The live gate measured the opposite: a cut that
// captured 954 B of backlog still took 169 s because it walked 7,668 tree
// objects, and a cut that captured 1,073,069,387 B took 963 s. That is
// ~1.06 MiB/s of cut throughput against a 7 MiB/s single-threaded writer —
// the writer wins by 7x, and no trigger threshold can rescue a cut that
// cannot finish.
//
// The measurements below isolate WHY. A cut's object work has exactly three
// shapes, and only the last two cost round trips:
//
//	produced-and-reachable   the objects THIS run wrote  — free: their
//	                         outgoing edges were decoded at production time
//	reused-and-reachable     base objects the closure still covers — one
//	                         database locate + one verified store read each
//	base reads during fold   the paths the fold actually touches
//
// The old walk paid a round trip for EVERY object in the first two classes,
// strictly one at a time, at the very end of the cut — by which time the
// worker's bounded object LRU had long evicted the run's own output. These
// tests state the throughput target, measure the round trips the closure
// phase actually issues, and fail when the implied throughput cannot outrun
// the writer.

import (
	"container/list"
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const (
	// closureRoundTripMs is the measured cost of resolving ONE object during
	// a cut's closure phase against the live history plane: one
	// pfh.object_locate plus one verified read of the recorded exact key.
	// Derived from the gate itself — cut #1 spent 169 s walking 7,668 objects
	// and captured 954 B, i.e. 22.0 ms per object with no other work to hide
	// behind.
	closureRoundTripMs = 22

	// sustainedWriteBytesPerSec is the single-threaded writer a cut has to
	// outrun (7 MiB/s at the same gate).
	sustainedWriteBytesPerSec = 7 << 20

	// coordinatedDirtyBoundBytes is the backlog a cut is triggered at when
	// PORTABLEFS_HISTORY_COORDINATE_DIRTY_BOUND clamps the trigger to 25% of
	// a 4 GiB journal quota against a 2048 MiB dirty-RSS bound.
	coordinatedDirtyBoundBytes = 1024 << 20

	// cutThroughputMargin is how much faster than the writer a cut must be
	// for resident dirty bytes to saw-tooth instead of climb. At 1x the cut
	// merely ties the writer and residency never falls.
	cutThroughputMargin = 2

	// closurePhaseBudgetFraction is the share of one cut's whole time budget
	// the CLOSURE phase may consume. The fold, the uploads and the
	// publication all have to fit in the remainder, so the phase that
	// produces no objects at all gets a tenth.
	closurePhaseBudgetFraction = 10
)

// cutTimeBudgetSeconds is the wall time a cut triggered at the coordinated
// bound has before the writer refills it, with margin.
func cutTimeBudgetSeconds() float64 {
	return float64(coordinatedDirtyBoundBytes) /
		float64(sustainedWriteBytesPerSec*cutThroughputMargin)
}

// ─── an instrumented stand-in for the worker's bounded cutStore ──────────────

// costStore mirrors the history worker's cutStore closely enough to price a
// cut: reducer output is written straight through to a durable "remote"
// (the replicated object stores plus their registry rows) and is retained
// locally only in a bounded LRU, so anything the fold produced early is gone
// by the time the closure phase runs. Every LRU miss is one modeled round
// trip. Latency is optional: the counters alone price the phase, and the
// concurrency proof turns it on.
type costStore struct {
	mu     sync.Mutex
	remote map[pft2.Ref][]byte

	cache      map[pft2.Ref]*list.Element
	cacheList  *list.List
	cacheBytes int64
	cacheMax   int64

	// mine marks the objects THIS run produced, so a re-read of the run's
	// own output is distinguishable from a genuine base read.
	mine map[pft2.Ref]bool

	fetchLatency time.Duration

	produced       int
	producedBytes  int64
	roundTrips     int
	ownOutputReads int
	inFlight       int
	maxInFlight    int

	needs map[string]int64
}

func newCostStore(cacheMax int64) *costStore {
	return &costStore{
		remote:    map[pft2.Ref][]byte{},
		cache:     map[pft2.Ref]*list.Element{},
		cacheList: list.New(),
		cacheMax:  cacheMax,
		mine:      map[pft2.Ref]bool{},
		needs:     map[string]int64{},
	}
}

type costEntry struct {
	ref  pft2.Ref
	data []byte
}

func (s *costStore) insertLocked(ref pft2.Ref, data []byte) {
	if _, ok := s.cache[ref]; ok {
		return
	}
	s.cache[ref] = s.cacheList.PushFront(&costEntry{ref: ref, data: data})
	s.cacheBytes += int64(len(data))
	for s.cacheBytes > s.cacheMax && s.cacheList.Len() > 1 {
		oldest := s.cacheList.Back()
		entry := oldest.Value.(*costEntry)
		s.cacheList.Remove(oldest)
		delete(s.cache, entry.ref)
		s.cacheBytes -= int64(len(entry.data))
	}
}

func (s *costStore) Seed(ref pft2.Ref, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.mine[ref] {
		s.mine[ref] = true
		s.produced++
		s.producedBytes += int64(len(data))
	}
	if _, ok := s.remote[ref]; !ok {
		s.remote[ref] = append([]byte(nil), data...)
	}
	s.insertLocked(ref, s.remote[ref])
	return nil
}

func (s *costStore) PutNode(ref pft2.Ref, encoded []byte) error { return s.Seed(ref, encoded) }
func (s *costStore) PutPack(ref pft2.Ref, data []byte) error    { return s.Seed(ref, data) }

func (s *costStore) Fetch(_ context.Context, ref pft2.Ref) ([]byte, error) {
	s.mu.Lock()
	if elem, ok := s.cache[ref]; ok {
		s.cacheList.MoveToFront(elem)
		data := elem.Value.(*costEntry).data
		s.mu.Unlock()
		return data, nil
	}
	data, ok := s.remote[ref]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: object sha256:%s", ErrNeedBlobs, ref.Hex())
	}
	s.roundTrips++
	if s.mine[ref] {
		s.ownOutputReads++
	}
	s.inFlight++
	if s.inFlight > s.maxInFlight {
		s.maxInFlight = s.inFlight
	}
	latency := s.fetchLatency
	s.mu.Unlock()

	if latency > 0 {
		time.Sleep(latency)
	}

	s.mu.Lock()
	s.inFlight--
	s.insertLocked(ref, data)
	s.mu.Unlock()
	return data, nil
}

func (s *costStore) NeedDigest(digest string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.needs[digest] = size
}

func (s *costStore) Needs() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.needs))
	for k, v := range s.needs {
		out[k] = v
	}
	return out
}

// adopt makes every object another run produced readable here WITHOUT
// claiming it as this run's output — exactly the relationship a chained cut
// has to its base cut's published objects.
func (s *costStore) adopt(other *costStore) {
	other.mu.Lock()
	defer other.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, data := range other.remote {
		s.remote[ref] = data
	}
}

func (s *costStore) stats() (roundTrips, ownOutputReads, produced, maxInFlight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roundTrips, s.ownOutputReads, s.produced, s.maxInFlight
}

// ─── representative folds ────────────────────────────────────────────────────

// backlogRecords writes fileCount distinct files of bytesPerFile bytes in
// chunk-sized appends. Content is salted per prefix so two folds never
// silently deduplicate into each other.
func backlogRecords(prefix string, fileCount, bytesPerFile, chunk int, firstLocal uint64) []wal.Record {
	records := make([]wal.Record, 0, fileCount*(1+bytesPerFile/chunk))
	salt := byte(len(prefix) * 131)
	for f := 0; f < fileCount; f++ {
		path := prefix + strconv.Itoa(f)
		records = append(records, wal.Record{
			Op: wal.OpCreate, Path: path, Mode: 0o644,
			Ino: nsIno(7, firstLocal+uint64(f)), TsMs: int64(1000 + f),
		})
		for off := 0; off < bytesPerFile; off += chunk {
			data := make([]byte, chunk)
			for i := range data {
				data[i] = byte(i) ^ byte(f*7) ^ byte(off/chunk) ^ salt
			}
			records = append(records, wal.Record{
				Op: wal.OpWrite, Path: path, Offset: int64(off),
				Data: data, TsMs: int64(2000 + f),
			})
		}
	}
	return records
}

// costFold is one materialized cut plus the store it wrote into.
type costFold struct {
	facts  CutFacts
	result *Result
	store  *costStore
	cutSeq uint64
	digest string
}

// materializeFold runs one cut from the zero origin over an optional adopted
// base and returns everything a chained fold needs.
func materializeFold(
	t *testing.T, store *costStore, base *costFold, records []wal.Record,
	deltaClosures bool, edgeBytes int64,
) *costFold {
	t.Helper()
	ctx := context.Background()

	var chain [32]byte
	baseSeq := uint64(0)
	baseDigest := zeroChainDigest
	if base != nil {
		parsed, err := parseHex32(base.digest, "base digest")
		if err != nil {
			t.Fatal(err)
		}
		chain, baseSeq, baseDigest = parsed, base.cutSeq, base.digest
	}
	payloads := encodeEntries(t, baseSeq, records...)
	page, cutDigest := buildJournal(t, chain, baseSeq, payloads)

	facts := managedFacts(baseDigest, cutDigest, baseSeq, baseSeq+uint64(len(page)))
	if base != nil {
		in := base.result
		facts.BaseCommit = &BaseCommitFacts{
			CommitID: "cmt_base", CommitKind: "pft2", BaseMode: "adopted",
			RootDigest: in.Root.Hex(), RootSize: strconv.FormatUint(in.Root.Size, 10),
			MaxInoSeen:       strconv.FormatUint(in.RootMaxInoSeen, 10),
			AnchorID:         "anc_base",
			RecoveryRoot:     in.RecoveryRoot.Hex(),
			RecoveryRootSize: strconv.FormatUint(in.RecoveryRoot.Size, 10),
			InodeNamespace:   "7",
			NextLocal:        strconv.FormatUint(in.NextLocal, 10),
			AnchorMaxIno:     strconv.FormatUint(in.MaxInoSeen, 10),
		}
	}
	m := &Materializer{
		Facts:               facts,
		Journal:             &fakeJournal{records: page},
		Spool:               store,
		DeltaClosures:       deltaClosures,
		MaxClosureEdgeBytes: edgeBytes,
	}
	result, err := m.Run(ctx)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	return &costFold{
		facts: facts, result: result, store: store,
		cutSeq: baseSeq + uint64(len(page)), digest: cutDigest,
	}
}

// modeledClosureSeconds prices a closure phase: serial round trips pay full
// latency, concurrent ones amortize across the walk's fetch bound.
func modeledClosureSeconds(roundTrips int, concurrent bool) float64 {
	seconds := float64(roundTrips) * closureRoundTripMs / 1000
	if concurrent {
		seconds /= closureFetchConcurrency
	}
	return seconds
}

// ─── the throughput gate ─────────────────────────────────────────────────────

// TestCutClosurePhaseKeepsUpWithASustainedWriter is the failing-first
// throughput gate. A cut triggered at the coordinated dirty bound has
// cutTimeBudgetSeconds() before the writer refills it; the closure phase —
// which produces nothing — gets a tenth of that. Before the produced-edge
// cache the phase re-read this run's ENTIRE output one blocking round trip
// at a time and blew the budget by more than an order of magnitude.
func TestCutClosurePhaseKeepsUpWithASustainedWriter(t *testing.T) {
	const (
		baseFiles    = 24
		deltaFiles   = 192
		bytesPerFile = 1 << 20
		chunkBytes   = 256 << 10
		// The fold is scaled down but the RATIO that drives the cost is not.
		// Production folds up to the 1024 MiB coordinated bound while the
		// worker retains 128 MiB locally (MaxCacheBytes) — 8 bytes produced
		// per byte retained. The fixture folds 192 MiB against 24 MiB for the
		// same 8:1, so the eviction the closure phase actually meets is
		// reproduced at a size a unit test can run.
		workerCacheBytes = 24 << 20
	)
	deltaBytes := int64(deltaFiles) * bytesPerFile
	budget := cutTimeBudgetSeconds() / closurePhaseBudgetFraction
	// Normalize to the bound a cut is actually triggered at, so the target is
	// stated once and holds at any fold size.
	scale := float64(coordinatedDirtyBoundBytes) / float64(deltaBytes)

	// price runs the same chained fold twice: once with the produced-edge
	// cache disabled — which is exactly the walk this code shipped with, one
	// blocking resolution per object — and once as production runs it.
	price := func(edgeBytes int64) (ownOutputReads, roundTrips, produced, closureObjects int) {
		baseStore := newCostStore(workerCacheBytes)
		base := materializeFold(t, baseStore, nil,
			backlogRecords("base-f", baseFiles, bytesPerFile, chunkBytes, 2), false, edgeBytes)

		deltaStore := newCostStore(workerCacheBytes)
		deltaStore.adopt(baseStore)
		chained := materializeFold(t, deltaStore, base,
			backlogRecords("delta-f", deltaFiles, bytesPerFile, chunkBytes, 100_000), true, edgeBytes)

		roundTrips, ownOutputReads, produced, _ = deltaStore.stats()
		closureObjects = len(chained.result.UserClosure) + len(chained.result.RecoveryClosure)
		return ownOutputReads, roundTrips, produced, closureObjects
	}

	baselineOwn, baselineTrips, produced, closureObjects := price(-1)
	baselineSeconds := modeledClosureSeconds(int(float64(baselineOwn)*scale), false)
	t.Logf("delta fold: %d MiB, %d objects produced, %d-object closure",
		deltaBytes>>20, produced, closureObjects)
	t.Logf("BASELINE (edge cache disabled): %d round trips, %d re-reads of this run's own output "+
		"— %.0f at the %d MiB bound = %.0f s modeled, %.2f MiB/s cut throughput",
		baselineTrips, baselineOwn, float64(baselineOwn)*scale, coordinatedDirtyBoundBytes>>20,
		baselineSeconds, float64(coordinatedDirtyBoundBytes>>20)/baselineSeconds)

	// The baseline has to be a real cost or this test is measuring nothing.
	if baselineOwn == 0 {
		t.Fatal("fixture retains the fold's own output locally; it cannot price the closure phase")
	}
	if baselineSeconds <= budget {
		t.Fatalf("fixture is not representative: the un-cached walk already fits the %.1f s budget", budget)
	}

	ownOutputReads, roundTrips, _, _ := price(0)
	modeledSeconds := modeledClosureSeconds(int(float64(ownOutputReads)*scale), false)
	t.Logf("PRODUCTION: %d round trips, %d re-reads of own output = %.1f s modeled "+
		"(budget %.1f s of the %.1f s cut budget); the baseline spent %.0f s here",
		roundTrips, ownOutputReads, modeledSeconds, budget, cutTimeBudgetSeconds(),
		baselineSeconds)

	// The hard requirement: the closure phase must never pay a round trip for
	// an object this very run produced. Its edges were decoded when the bytes
	// were written; re-reading them proves nothing and costs everything.
	if ownOutputReads != 0 {
		t.Fatalf("closure phase re-read %d of its own %d produced objects: "+
			"%.1f s modeled at the %d MiB bound against a %.1f s budget — "+
			"cut throughput %.2f MiB/s cannot outrun a %d MiB/s writer",
			ownOutputReads, produced, modeledSeconds, coordinatedDirtyBoundBytes>>20, budget,
			float64(coordinatedDirtyBoundBytes>>20)/modeledSeconds,
			sustainedWriteBytesPerSec>>20)
	}
	if modeledSeconds > budget {
		t.Fatalf("closure phase costs %.1f s at the coordinated bound, budget %.1f s", modeledSeconds, budget)
	}
}

// TestClosureWalkOverAReusedTreeIsConcurrent covers the other half: the
// exact-closure refresh (the deterministic ~1-in-16 slice) and every
// fork/conversion base walk objects this run did NOT produce, so their edges
// cannot be cached and the bytes must genuinely be read. Those reads have to
// overlap. Serially they cost objectCount x round trip no matter how little
// the cut captured — the exact signature of the 954 B / 169 s cut.
func TestClosureWalkOverAReusedTreeIsConcurrent(t *testing.T) {
	const (
		baseFiles    = 48
		bytesPerFile = 1 << 20
		chunkBytes   = 256 << 10
	)
	baseStore := newCostStore(128 << 20)
	base := materializeFold(t, baseStore, nil,
		backlogRecords("base-f", baseFiles, bytesPerFile, chunkBytes, 2), false, 0)

	// A tiny chained fold that publishes an EXACT closure: almost every
	// object it registers is inherited, and every one of those is a read.
	tiny := newCostStore(8 << 20)
	tiny.adopt(baseStore)
	tiny.fetchLatency = 2 * time.Millisecond
	started := time.Now()
	chained := materializeFold(t, tiny, base,
		backlogRecords("tail-f", 1, 4<<10, 4<<10, 900_000), false, 0)
	elapsed := time.Since(started)

	roundTrips, ownOutputReads, _, maxInFlight := tiny.stats()
	closureObjects := len(chained.result.UserClosure) + len(chained.result.RecoveryClosure)
	t.Logf("exact-closure tail cut: %d-object closure, %d round trips (%d own output), "+
		"max %d in flight, %v at %v per read",
		closureObjects, roundTrips, ownOutputReads, maxInFlight, elapsed, tiny.fetchLatency)

	if ownOutputReads != 0 {
		t.Fatalf("exact-closure walk re-read %d of its own objects", ownOutputReads)
	}
	if closureObjects < 100 {
		t.Fatalf("fixture is not representative: %d-object closure", closureObjects)
	}
	// Serial resolution is the defect. Anything above 1 in flight proves the
	// waves overlap; the bound itself is what turns 169 s into seconds.
	if maxInFlight < 2 {
		t.Fatalf("closure walk resolved %d inherited objects strictly one at a time: "+
			"%.1f s modeled per 1,000 objects, so a %d-object tree costs %.0f s "+
			"however little the cut captured",
			roundTrips, modeledClosureSeconds(1000, false),
			closureObjects, modeledClosureSeconds(closureObjects, false))
	}
	serial := modeledClosureSeconds(roundTrips, false)
	concurrent := modeledClosureSeconds(roundTrips, true)
	t.Logf("modeled: %.1f s serial vs %.1f s at %d-way — %.0fx",
		serial, concurrent, closureFetchConcurrency, serial/concurrent)
}

// TestClosureIsIdenticalWithAndWithoutTheEdgeCache is the identity guard.
// Cut identity is frozen (PF009) and adoption proofs bind the published
// roots and closures byte-exactly, so the produced-edge cache is only
// admissible if it changes nothing at all. Disabling it forces every edge
// back through a fetch — the pre-existing behaviour — and both runs must
// agree on every published fact.
func TestClosureIsIdenticalWithAndWithoutTheEdgeCache(t *testing.T) {
	const (
		baseFiles    = 12
		deltaFiles   = 24
		bytesPerFile = 1 << 20
		chunkBytes   = 256 << 10
	)
	baseRecords := backlogRecords("base-f", baseFiles, bytesPerFile, chunkBytes, 2)
	deltaRecords := backlogRecords("delta-f", deltaFiles, bytesPerFile, chunkBytes, 100_000)

	run := func(edgeBytes int64, delta bool) *Result {
		baseStore := newCostStore(4 << 30)
		base := materializeFold(t, baseStore, nil, baseRecords, false, edgeBytes)
		deltaStore := newCostStore(4 << 30)
		deltaStore.adopt(baseStore)
		return materializeFold(t, deltaStore, base, deltaRecords, delta, edgeBytes).result
	}

	for _, mode := range []struct {
		name  string
		delta bool
	}{{"delta closures", true}, {"exact closure", false}} {
		cached := run(0, mode.delta)   // produced-edge cache on (production)
		fetched := run(-1, mode.delta) // cache disabled: every edge from a fetch

		if cached.Root != fetched.Root || cached.RecoveryRoot != fetched.RecoveryRoot {
			t.Fatalf("%s: roots diverge: %s/%s vs %s/%s", mode.name,
				cached.Root.Hex(), cached.RecoveryRoot.Hex(),
				fetched.Root.Hex(), fetched.RecoveryRoot.Hex())
		}
		if cached.DeltaClosures != fetched.DeltaClosures {
			t.Fatalf("%s: delta-closure reporting diverges", mode.name)
		}
		for _, arm := range []struct {
			what           string
			a, b           []string
			aBytes, bBytes uint64
			aCount, bCount uint64
		}{
			{"user", cached.UserClosure, fetched.UserClosure,
				cached.UserObjectBytes, fetched.UserObjectBytes,
				cached.UserObjectCount, fetched.UserObjectCount},
			{"recovery", cached.RecoveryClosure, fetched.RecoveryClosure,
				cached.RecoveryObjectBytes, fetched.RecoveryObjectBytes,
				cached.RecoveryObjectCount, fetched.RecoveryObjectCount},
		} {
			if len(arm.a) != len(arm.b) || arm.aBytes != arm.bBytes || arm.aCount != arm.bCount {
				t.Fatalf("%s: %s closure accounting diverges: %d objects/%d bytes vs %d/%d",
					mode.name, arm.what, arm.aCount, arm.aBytes, arm.bCount, arm.bBytes)
			}
			for i := range arm.a {
				if arm.a[i] != arm.b[i] {
					t.Fatalf("%s: %s closure diverges at %d: %s vs %s",
						mode.name, arm.what, i, arm.a[i], arm.b[i])
				}
			}
		}
		if cached.NextLocal != fetched.NextLocal || cached.MaxInoSeen != fetched.MaxInoSeen ||
			cached.RootMaxInoSeen != fetched.RootMaxInoSeen {
			t.Fatalf("%s: allocator watermarks diverge", mode.name)
		}
	}
}

// TestProducedEdgeCacheFallsBackWhenItsBudgetIsExhausted proves the bound is
// a bound: a budget too small to hold the fold's adjacency degrades to
// fetching, and the published closure is unchanged.
func TestProducedEdgeCacheFallsBackWhenItsBudgetIsExhausted(t *testing.T) {
	records := backlogRecords("f", 24, 1<<20, 256<<10, 2)

	// A cache too small to retain the fold's own output, which is exactly the
	// worker's situation: without the edge cache the closure walk has to read
	// its own objects back.
	full := newCostStore(8 << 20)
	generous := materializeFold(t, full, nil, records, false, 0)

	tight := newCostStore(8 << 20)
	// Room for a handful of entries, not the thousands the fold produces.
	squeezed := materializeFold(t, tight, nil, records, false, 4*edgeEntryBytes)

	if generous.result.Root != squeezed.result.Root {
		t.Fatal("a squeezed edge budget changed the published root")
	}
	if len(generous.result.UserClosure) != len(squeezed.result.UserClosure) {
		t.Fatalf("closure sizes diverge: %d vs %d",
			len(generous.result.UserClosure), len(squeezed.result.UserClosure))
	}
	for i := range generous.result.UserClosure {
		if generous.result.UserClosure[i] != squeezed.result.UserClosure[i] {
			t.Fatalf("closure diverges at %d", i)
		}
	}
	generousTrips, _, _, _ := full.stats()
	squeezedTrips, _, _, _ := tight.stats()
	t.Logf("round trips: %d with the edge cache, %d with it squeezed to %d entries",
		generousTrips, squeezedTrips, 4)
	if squeezedTrips <= generousTrips {
		t.Fatal("the squeezed budget did not actually force the fetching fallback")
	}
}
