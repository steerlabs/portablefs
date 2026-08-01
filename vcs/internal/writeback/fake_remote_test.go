package writeback

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// fakeAuthority models the authority for engine unit tests: adaptive grants,
// a durable per-stream watermark + digest with the server-side density and
// digest checks, and an applied tree the tests verify byte-exactness against.
type fakeAuthority struct {
	mu sync.Mutex

	nextEpoch int
	grants    map[string]fakeGrant // scope -> grant
	streams   map[string]*fakeStream
	// lanesSupported mirrors fsproto's FeatureWritebackLanes. Default true;
	// the legacy-boundary tests clear it to hold a stream in the legacy era.
	lanesSupported bool
	// heldDataBatches counts data batches refused on their namespace
	// dependency. In steady state it must stay zero — see
	// TestNamespaceDependencyNeverHoldsADataBatchInSteadyState.
	heldDataBatches int

	files    map[string][]byte
	dirs     map[string]bool
	symlinks map[string]string
	modes    map[string]uint32

	denyAll bool
	// acquireErr simulates a definite pre-grant transport failure. It is
	// distinct from a policy denial and must never select another lane.
	acquireErr error
	// omitChildren makes grants ship no snapshot (the duplicate-replay
	// shape); the client then seeds via readdir under the held grant.
	omitChildren bool
	flushErr     error
	flushStat    int32
	// throughShortfall simulates a protocol-violating authority: flushes
	// apply and succeed, but the reported watermark is lowered by this much.
	throughShortfall uint64
	// throughExcess simulates a success reply that claims records this request
	// never supplied.
	throughExcess uint64
	// flushGate, when set, blocks each flush until the gate closes or the
	// caller's context ends; flushEntered signals entry (buffered).
	flushGate    chan struct{}
	flushEntered chan struct{}
	// flushRateBps models an uplink of a finite throughput: each flush is
	// delayed in proportion to the bulk bytes it carries before it applies.
	// Unlike flushGate (a blackhole), this authority DOES make durable
	// progress — just slowly — which is the shape the credit gate must turn
	// into a paced completion rather than an error.
	flushRateBps int64
	// flushFixedCost models everything ONE batch costs besides moving its
	// bytes: the round trip, the authority's apply turn, its durability
	// commit, and the reply. It is charged per flush regardless of size, which
	// is exactly why batch size is the amortization knob — the measured
	// production shape was 1.52s for an 8 MiB batch of which only ~0.70s was
	// transfer.
	flushFixedCost time.Duration
	// discardContent keeps only sizes for applied writes (RSS-bounding tests
	// stream gigabytes; the fake must not hold them on the heap).
	discardContent bool
	sizes          map[string]int64

	acquires int
	releases int
	flushes  int
	rebinds  int
}

type fakeGrant struct {
	epoch    string
	wbID     string
	recovery bool
}

// fakeStream mirrors the authority's per-lane ledger: each lane keeps its own
// dense watermark and chain digest, and the data lane's namespace dependency is
// enforced against the namespace lane's watermark.
type fakeStream struct {
	lanes [streamLaneCount]laneMark
}

func newFakeStream() *fakeStream {
	st := &fakeStream{}
	for i := range st.lanes {
		st.lanes[i].digest = digestZero()
	}
	return st
}

// newFakeStreamAt seeds a stream at a LEGACY-lane position: the shape every
// pre-round-7 WAL's authority state has, and the one the legacy-recovery
// fixtures assert against.
func newFakeStreamAt(through uint64, digest [32]byte) *fakeStream {
	st := newFakeStream()
	st.lanes[StreamLaneLegacy] = laneMark{through: through, digest: digest}
	return st
}

// total is the number of records the stream has made durable across every
// lane. Each lane is dense from 1, so the sum of the watermarks IS the count —
// the lane-aware replacement for reading the single stream watermark.
func (s *fakeStream) total() uint64 {
	var n uint64
	for _, l := range s.lanes {
		n += l.through
	}
	return n
}

func newFakeAuthority() *fakeAuthority {
	return &fakeAuthority{
		grants: map[string]fakeGrant{}, streams: map[string]*fakeStream{},
		files: map[string][]byte{}, dirs: map[string]bool{"": true},
		symlinks: map[string]string{}, modes: map[string]uint32{},
		lanesSupported: true,
	}
}

// SupportsLanes mirrors fsproto's FeatureWritebackLanes bit. Tests that need the
// pre-upgrade posture clear it before the engine opens.
func (a *fakeAuthority) SupportsLanes() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lanesSupported
}

// holdLanesForTest parks every lane worker's dispatch schedule, the lane-aware
// form of pushing the single flusher's nextAttempt out.
func (f *flusher) holdLanesForTest(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for lane := range f.lanes {
		f.lanes[lane].nextAttempt = time.Now().Add(d)
	}
}

// backdateProgressForTest ages every lane's progress clock so the watchdog's
// verdict is available without waiting a real window.
func (f *flusher) backdateProgressForTest(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for lane := range f.lanes {
		f.lanes[lane].lastProgress = time.Now().Add(-d)
	}
}

// laneStateForTest reports one lane's unshipped depth and applied watermark.
func (f *flusher) laneStateForTest(lane StreamLane) (pending int, applied uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lanes[lane].pending), f.lanes[lane].applied
}

// laneDependencyBlockedForTest exposes the dispatchability predicate so a test
// can assert its fixture actually reached the hold rather than merely running
// fast enough to miss it.
func (f *flusher) laneDependencyBlockedForTest(lane StreamLane) (blocked bool, needed uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.laneDependencyBlockedLocked(lane)
}

// degradedForTest reads the STREAM-WIDE sticky verdict. It is separate from the
// per-lane stall verdict on purpose: the promotion of a lane-local condition
// into this flag is itself the thing some tests are about.
func (f *flusher) degradedForTest() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.degraded
}

func (a *fakeAuthority) DelegationAcquire(_ context.Context, scope, writebackID string) (AcquireReply, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acquires++
	if a.acquireErr != nil {
		return AcquireReply{}, a.acquireErr
	}
	if a.denyAll {
		return AcquireReply{}, nil
	}
	for held := range a.grants {
		if held == scope || strings.HasPrefix(held, scope+"/") || strings.HasPrefix(scope, held+"/") {
			return AcquireReply{}, nil
		}
	}
	a.nextEpoch++
	epoch := fmt.Sprintf("%d", a.nextEpoch)
	a.grants[scope] = fakeGrant{epoch: epoch, wbID: writebackID}
	if _, ok := a.streams[writebackID]; !ok {
		a.streams[writebackID] = newFakeStream()
	}
	if !a.dirs[scope] {
		// Only an existing directory is delegable (matches the authority
		// policy: absent and file scopes decline to write-through).
		delete(a.grants, scope)
		return AcquireReply{}, nil
	}
	reply := AcquireReply{Granted: true, Epoch: epoch}
	reply.Exists = true
	reply.Self = Entry{Name: baseName(scope), Kind: "directory", Mode: 0o755, Nlink: 2}
	if !a.omitChildren {
		reply.HasChildren = true
		reply.Children = a.childrenLocked(scope)
	}
	return reply, nil
}

func (a *fakeAuthority) childrenLocked(dir string) []Entry {
	var out []Entry
	member := func(p string) (string, bool) {
		if dir == "" {
			if !strings.Contains(p, "/") && p != "" {
				return p, true
			}
			return "", false
		}
		if strings.HasPrefix(p, dir+"/") && !strings.Contains(p[len(dir)+1:], "/") {
			return p[len(dir)+1:], true
		}
		return "", false
	}
	for p, content := range a.files {
		if name, ok := member(p); ok {
			out = append(out, Entry{Name: name, Kind: "file", Mode: a.modes[p], Size: int64(len(content)), Nlink: 1})
		}
	}
	for p := range a.dirs {
		if name, ok := member(p); ok {
			out = append(out, Entry{Name: name, Kind: "directory", Mode: 0o755, Nlink: 2})
		}
	}
	for p, target := range a.symlinks {
		if name, ok := member(p); ok {
			out = append(out, Entry{Name: name, Kind: "symlink", Mode: 0o777, Size: int64(len(target)), Nlink: 1, Target: target})
		}
	}
	return out
}

func (a *fakeAuthority) ReleaseDelegation(_ context.Context, scope, epoch string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releases++
	g, ok := a.grants[scope]
	if !ok || g.epoch != epoch {
		return fmt.Errorf("fake: release of %q@%s that is not the live grant", scope, epoch)
	}
	delete(a.grants, scope)
	return nil
}

func (a *fakeAuthority) Flush(ctx context.Context, req FlushRequest) (FlushReply, error) {
	a.mu.Lock()
	gate, entered, rate := a.flushGate, a.flushEntered, a.flushRateBps
	fixed := a.flushFixedCost
	a.mu.Unlock()
	if rate > 0 || fixed > 0 {
		var bulk int64
		for _, rec := range req.Records {
			bulk += int64(len(rec.Data))
		}
		delay := fixed
		if rate > 0 {
			delay += time.Duration(float64(bulk) / float64(rate) * float64(time.Second))
		}
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return FlushReply{}, ctx.Err()
			}
		}
	}
	if gate != nil {
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return FlushReply{}, ctx.Err()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flushes++
	if a.flushErr != nil {
		return FlushReply{}, a.flushErr
	}
	if a.flushStat != 0 {
		return FlushReply{Status: a.flushStat}, nil
	}
	if len(req.Records) == 0 || len(req.ScopeRuns) == 0 ||
		req.ScopeRuns[len(req.ScopeRuns)-1].Through != req.Records[len(req.Records)-1].Seq {
		return FlushReply{Status: 22}, nil
	}
	runIndex := 0
	for _, rec := range req.Records {
		for runIndex < len(req.ScopeRuns) && rec.Seq > req.ScopeRuns[runIndex].Through {
			runIndex++
		}
		if runIndex == len(req.ScopeRuns) {
			return FlushReply{Status: 22}, nil
		}
		run := req.ScopeRuns[runIndex]
		g, ok := a.grants[run.Scope]
		if !ok || g.epoch != run.Epoch {
			return FlushReply{Status: 116}, nil // ESTALE
		}
	}
	st := a.streams[req.WritebackID]
	if st == nil {
		st = newFakeStream()
		a.streams[req.WritebackID] = st
	}
	if req.Lane >= streamLaneCount {
		return FlushReply{Status: 22}, nil
	}
	if req.Lane != StreamLaneData && req.NSRequired != 0 {
		return FlushReply{Status: 22}, nil
	}
	// The cross-lane dependency: a data batch is HELD (typed retryable, nothing
	// staged) until the namespace lane covers the watermark it names.
	if req.NSRequired > st.lanes[StreamLaneNamespace].through {
		a.heldDataBatches++
		return FlushReply{Status: 11}, nil // EAGAIN
	}
	lane := &st.lanes[req.Lane]
	if len(req.Records) > 0 && req.Records[0].Seq == lane.through+1 && req.PrevDigest != lane.digest {
		return FlushReply{Status: 22}, nil // digest divergence fences
	}
	digest := lane.digest
	next := lane.through
	applied := false
	for _, rec := range req.Records {
		if rec.Seq <= lane.through {
			continue // retry catch-up: already durably covered
		}
		if rec.Seq != next+1 {
			return FlushReply{Status: 22}, nil // EINVAL: not dense
		}
		payload := canonicalPayload(rec)
		digest = digestNext(digest, rec.Seq, payload)
		a.applyLocked(rec)
		next = rec.Seq
		applied = true
	}
	if applied {
		if digest != req.EndDigest {
			return FlushReply{Status: 22}, nil // digest divergence fences
		}
		lane.through = next
		lane.digest = digest
	}
	reported := lane.through
	if a.throughShortfall > 0 {
		// Saturating, so the under-report fires at ANY batch size. It used to
		// be conditional on `reported > shortfall`, which silently stopped
		// firing once lanes split a two-record batch into two one-record ones —
		// turning a protocol-integrity test into a no-op rather than a failure.
		reported -= min(a.throughShortfall, reported)
	}
	reported += a.throughExcess
	return FlushReply{Through: reported}, nil
}

// canonicalPayload is the digest domain: the PFR1 bytes with the stream
// sequence zeroed (both sides compute it identically).
func canonicalPayload(rec wal.Record) []byte {
	rec.Seq = 0
	b, err := wal.EncodePFR1(&rec)
	if err != nil {
		panic(err)
	}
	return b
}

func (a *fakeAuthority) applyLocked(rec wal.Record) {
	switch rec.Op {
	case wal.OpCreate:
		if _, ok := a.files[rec.Path]; !ok {
			a.files[rec.Path] = nil
		}
		a.modes[rec.Path] = rec.Mode
	case wal.OpMkdir:
		a.dirs[rec.Path] = true
	case wal.OpSymlink:
		a.symlinks[rec.Path] = rec.Target
	case wal.OpWrite:
		if a.discardContent {
			if a.sizes == nil {
				a.sizes = map[string]int64{}
			}
			a.sizes[rec.Path] = max(a.sizes[rec.Path], rec.Offset+int64(len(rec.Data)))
			return
		}
		content := a.files[rec.Path]
		end := rec.Offset + int64(len(rec.Data))
		if int64(len(content)) < end {
			grown := make([]byte, end)
			copy(grown, content)
			content = grown
		}
		copy(content[rec.Offset:end], rec.Data)
		a.files[rec.Path] = content
	case wal.OpTruncate:
		content := a.files[rec.Path]
		if int64(len(content)) > rec.Size {
			content = content[:rec.Size]
		} else {
			grown := make([]byte, rec.Size)
			copy(grown, content)
			content = grown
		}
		a.files[rec.Path] = content
	case wal.OpRemove:
		delete(a.files, rec.Path)
		delete(a.dirs, rec.Path)
		delete(a.symlinks, rec.Path)
	case wal.OpRename:
		moveKey(a.files, rec.Path, rec.NewPath)
		moveKeyStr(a.symlinks, rec.Path, rec.NewPath)
		if a.dirs[rec.Path] {
			delete(a.dirs, rec.Path)
			a.dirs[rec.NewPath] = true
			prefix := rec.Path + "/"
			for p := range a.files {
				if strings.HasPrefix(p, prefix) {
					moveKey(a.files, p, rec.NewPath+"/"+p[len(prefix):])
				}
			}
			for p := range a.dirs {
				if strings.HasPrefix(p, prefix) {
					delete(a.dirs, p)
					a.dirs[rec.NewPath+"/"+p[len(prefix):]] = true
				}
			}
		}
	case wal.OpChmod:
		a.modes[rec.Path] = rec.Mode
	}
}

func moveKey(m map[string][]byte, from, to string) {
	if v, ok := m[from]; ok {
		delete(m, from)
		m[to] = v
	}
}

func moveKeyStr(m map[string]string, from, to string) {
	if v, ok := m[from]; ok {
		delete(m, from)
		m[to] = v
	}
}

func (a *fakeAuthority) FlushResolved(ctx context.Context, req FlushRequest) (FlushReply, error) {
	return a.Flush(ctx, req)
}

func (a *fakeAuthority) StreamState(_ context.Context, writebackID string) (StreamState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.streams[writebackID]
	if st == nil {
		return StreamState{}, nil
	}
	return StreamState{
		Exists:  true,
		Through: st.lanes[StreamLaneLegacy].through, Digest: st.lanes[StreamLaneLegacy].digest,
		NSThrough: st.lanes[StreamLaneNamespace].through, NSDigest: st.lanes[StreamLaneNamespace].digest,
		DataThrough: st.lanes[StreamLaneData].through, DataDigest: st.lanes[StreamLaneData].digest,
	}, nil
}

func (a *fakeAuthority) Rebind(_ context.Context, writebackID string, scopes []RebindScope, mark StreamState) (RebindReply, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rebinds++
	var conflicts []ConflictDetail
	for _, sc := range scopes {
		g, ok := a.grants[sc.Scope]
		switch {
		case !ok:
			conflicts = append(conflicts, ConflictDetail{Scope: sc.Scope, Epoch: sc.Epoch, Kind: "SCOPE_MISSING"})
		case g.epoch != sc.Epoch || g.wbID != writebackID:
			conflicts = append(conflicts, ConflictDetail{Scope: sc.Scope, Epoch: sc.Epoch, Kind: "HOLDER_CHANGED"})
		}
	}
	if st := a.streams[writebackID]; st != nil {
		for lane := range st.lanes {
			l := StreamLane(lane)
			if st.lanes[lane].through != mark.LaneThrough(l) || st.lanes[lane].digest != mark.LaneDigest(l) {
				conflicts = append(conflicts, ConflictDetail{Kind: "DIGEST_MISMATCH"})
				break
			}
		}
	}
	return RebindReply{Conflicts: conflicts}, nil
}

func (a *fakeAuthority) Discard(_ context.Context, writebackID string, scopes []RebindScope) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(scopes) == 0 {
		// Stream sweep: every grant bound to writebackID.
		for scope, g := range a.grants {
			if g.wbID == writebackID {
				delete(a.grants, scope)
			}
		}
		return nil
	}
	for _, sc := range scopes {
		if g, ok := a.grants[sc.Scope]; ok && g.wbID == writebackID {
			delete(a.grants, sc.Scope)
		}
	}
	return nil
}

func (a *fakeAuthority) fileContent(p string) ([]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.files[p]
	return append([]byte(nil), c...), ok
}

func (a *fakeAuthority) grantCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.grants)
}

func (a *fakeAuthority) calls() (acquires, flushes, releases int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acquires, a.flushes, a.releases
}

// baseReader serves clean ranges from the fake authority AT THE BASE PATH
// the engine reports (which trails local renames until they apply).
func (a *fakeAuthority) baseReader(string) BaseReader {
	return func(basePath string, off int64, dst []byte) (int, error) {
		content, _ := a.fileContent(basePath)
		if off >= int64(len(content)) {
			return 0, nil
		}
		return copy(dst, content[off:]), nil
	}
}

func (a *fakeAuthority) equalFile(p string, want []byte) error {
	got, ok := a.fileContent(p)
	if !ok {
		return fmt.Errorf("%s absent on authority", p)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s content mismatch: got %d bytes, want %d", p, len(got), len(want))
	}
	return nil
}
