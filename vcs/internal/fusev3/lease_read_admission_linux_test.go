//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func attrRecall(identity []byte, grantEpoch, revokeEpoch uint64) *authoritypb.LeaseRecall {
	return &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, GrantEpoch: grantEpoch, RevokeEpoch: revokeEpoch,
	}
}

// TestSuccessorGrantLosingToAnEarlierPeerRecallIsNotInstalled covers the lane
// race the successor grant introduced: CONTROL and the mutation reply are
// independent, so a peer's REVOKE for a coordinate can reach this mount before
// the reply carrying a successor grant over the same coordinate does. Installing
// that grant would hand the frontend authority over state a recall is in the
// middle of taking away.
func TestSuccessorGrantLosingToAnEarlierPeerRecallIsNotInstalled(t *testing.T) {
	fixture := newStrictFixture(t)
	registry := fixture.mount.leases
	identity := testIdentity(90)
	key := leaseKey{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, identity: publicationIdentity(identity),
	}
	now := time.Now()
	if accepted := registry.install(mustValidateLeaseGrant(t, attrGrant(identity, 4, 8), now), now); len(accepted) != 1 {
		t.Fatalf("initial attribute grant was refused: %+v", accepted)
	}
	if remaining := registry.remaining(key, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, now); remaining <= 0 {
		t.Fatal("the coordinate was not held before the recall")
	}

	recalls := []*authoritypb.LeaseRecall{attrRecall(identity, 4, 5)}
	if _, err := registry.beginRecalls(context.Background(), 12, recalls); err != nil {
		t.Fatalf("deliver the peer REVOKE: %v", err)
	}
	accepted := registry.install(mustValidateLeaseGrant(t, attrGrant(identity, 6, 12), now), now)
	if len(accepted) != 0 {
		t.Fatalf("successor grant installed under a pending recall: %+v", accepted)
	}
	if remaining := registry.remaining(key, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, now); remaining > 0 {
		t.Fatalf("a follow-up stat would be served locally for %v instead of missing to the authority", remaining)
	}

	if _, err := registry.completeRecalls(recalls); err != nil {
		t.Fatalf("complete the peer recall: %v", err)
	}
	registry.finishRecalls(recalls)

	// The recall is over, but its issued-generation floor is not: a grant minted
	// before the recall's sequence is still stale and must not install.
	if accepted := registry.install(mustValidateLeaseGrant(t, attrGrant(identity, 7, 11), now), now); len(accepted) != 0 {
		t.Fatalf("grant below the recall floor installed: %+v", accepted)
	}
	if remaining := registry.remaining(key, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, now); remaining > 0 {
		t.Fatalf("a stale-generation grant became a local stat answer for %v", remaining)
	}
	if accepted := registry.install(mustValidateLeaseGrant(t, attrGrant(identity, 8, 12), now), now); len(accepted) != 1 {
		t.Fatalf("grant at the recall floor was refused: %+v", accepted)
	}
	if remaining := registry.remaining(key, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, now); remaining <= 0 {
		t.Fatal("the coordinate did not become cacheable again after the recall completed")
	}
}

func mustValidateLeaseGrant(t *testing.T, grant *authoritypb.LeaseGrant, now time.Time) []validatedLeaseGrant {
	t.Helper()
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{grant}, now)
	if err != nil {
		t.Fatal(err)
	}
	return grants
}

// TestBlockingReadNeverFailsWhileAPeerRewritesTheFile is the regression the
// lease protocol's read admission exists for. A blocking read(2) has no
// retryable errno: EAGAIN reaches the caller verbatim, where a Go runtime
// registers the descriptor with its poller and never wakes. Every coherence
// state a peer's write puts this mount into -- the authority coordinate closed
// from recall reservation to discharge, this mount repairing that coordinate,
// and the recall catching a read already in flight -- used to refuse a read
// with exactly that errno.
//
// The second phase then pins the ordering the wait has to preserve: a read
// issued after the writer's own call returned may not answer with the state
// that write replaced.
func TestBlockingReadNeverFailsWhileAPeerRewritesTheFile(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	const size = 128 * 1024
	before := bytes.Repeat([]byte{'a'}, size)
	after := bytes.Repeat([]byte{'b'}, size)
	writerPath := f.join(0, "raced")
	readerPath := f.join(1, "raced")
	mustWrite(t, writerPath, before, 0o600)

	reader, err := os.Open(readerPath)
	if err != nil {
		t.Fatalf("open the racing reader: %v", err)
	}
	defer reader.Close()

	var readFailure atomic.Pointer[error]
	var reads atomic.Int64
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 6 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			buf := make([]byte, size)
			for {
				select {
				case <-stop:
					return
				default:
				}
				// syscall.Pread, not os.File.ReadAt: the point is to observe the
				// raw errno the kernel returns, without any runtime retry.
				if _, err := syscall.Pread(int(reader.Fd()), buf, 0); err != nil {
					failure := fmt.Errorf("blocking pread during a peer write: %w", err)
					readFailure.CompareAndSwap(nil, &failure)
					return
				}
				reads.Add(1)
				// Paced, not saturating. What opens the window this test is
				// about is a read landing inside a recall, not raw throughput.
				time.Sleep(50 * time.Microsecond)
			}
		}()
	}
	stopped := false
	stopReaders := func() {
		if !stopped {
			stopped = true
			close(stop)
			readers.Wait()
		}
	}
	t.Cleanup(stopReaders)

	payloads := [2][]byte{after, before}
	for round := range 64 {
		if err := os.WriteFile(writerPath, payloads[round%2], 0o600); err != nil {
			t.Fatalf("round %d: peer write: %v (mount 0 revocation: %v; mount 1 revocation: %v)",
				round, err, f.mounts[0].fatalError(), f.mounts[1].fatalError())
		}
		if failure := readFailure.Load(); failure != nil {
			t.Fatalf("round %d: %v", round, *failure)
		}
	}
	stopReaders()
	if failure := readFailure.Load(); failure != nil {
		t.Fatal(*failure)
	}
	// A run whose readers never overlapped the writes would pass vacuously.
	if completed := reads.Load(); completed < 500 {
		t.Fatalf("only %d reads raced 64 peer rewrites; the window this test exists for was not entered", completed)
	}

	// A descriptor of its own, because the ordering below is about what one
	// read observes and not about what the first phase left in the page cache.
	orderedWriter := f.join(0, "ordered")
	mustWrite(t, orderedWriter, before, 0o600)
	ordered, err := os.Open(f.join(1, "ordered"))
	if err != nil {
		t.Fatalf("open the ordered reader: %v", err)
	}
	defer ordered.Close()
	for round := range 8 {
		want := payloads[round%2]
		mustWrite(t, orderedWriter, want, 0o600)
		got := make([]byte, size)
		n, err := syscall.Pread(int(ordered.Fd()), got, 0)
		if err != nil {
			t.Fatalf("round %d: read issued after the peer write returned: %v", round, err)
		}
		if n != size || !bytes.Equal(got[:n], want) {
			t.Fatalf("round %d: read issued after the peer write returned %d bytes of %s, want %d of %q",
				round, n, summarize(got[:n]), size, string(want[0]))
		}
	}
	for index := range 2 {
		if cause := f.mounts[index].fatalError(); cause != nil {
			t.Fatalf("mount %d revoked during the race: %v", index, cause)
		}
	}
}

// TestSaturatedBulkLaneDoesNotStallASourcePurge covers the lane inversion at
// the exact admission boundary. A whole-file purge waits for the buffered reads
// already admitted for that inode, and the source mutation that drives that
// purge is itself holding one of the mount's bounded bulk slots. If a read
// registers its data publication before taking a slot, a saturated lane makes
// the purge wait on a read which is waiting on the lane the purge occupies.
//
// This is deliberately a transport-admission test, not a live-kernel load
// test. Continuously reading the target through FUSE also continuously takes
// its folio locks; stock invalidate_inode_pages2 can be starved by those locks,
// which is the separate, explicitly unbounded residual in
// docs/portable-coherence.md §7.3b. Driving that unrelated scheduler race made
// the former integration test take anywhere from 19 to 49 seconds and
// occasionally revoke a correct mount at its authority horizon. Filling the
// actual lane and observing the publication registry proves the intended
// ordering directly and deterministically.
func TestSaturatedBulkLaneDoesNotStallASourcePurge(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(91, authoritypb.Attr_REGULAR, 91)
	fixture.rpc.item = item
	fixture.rpc.byName = map[string]*authoritypb.Item{"saturated": item}
	fixture.rpc.fileData = []byte("data")
	entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "saturated")
	opened := fixture.openForData(t, entry.NodeId)

	for range cap(fixture.mount.bulk) {
		fixture.mount.bulk <- struct{}{}
	}
	t.Cleanup(func() {
		for len(fixture.mount.bulk) != 0 {
			<-fixture.mount.bulk
		}
	})

	type readOutcome struct {
		result fuse.ReadResult
		status fuse.Status
	}
	unique := fixture.unique.Add(2)
	readDone := make(chan readOutcome, 1)
	go func() {
		result, status := fixture.raw.Read(nil, &fuse.ReadIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 4,
		}, make([]byte, 4))
		readDone <- readOutcome{result: result, status: status}
	}()

	waitFor(t, "the lane-blocked read to reserve its reply lifecycle", func() bool {
		fixture.raw.mu.Lock()
		defer fixture.raw.mu.Unlock()
		return fixture.raw.replyPublications[unique] != nil
	})
	coordinate := publicationCoordinate{kind: publicationItemData, item: publicationIdentity(item.GetStableIdentity())}
	fixture.raw.mu.Lock()
	publication := fixture.raw.replyPublications[unique]
	for _, admitted := range publication.admittedData {
		if admitted == coordinate {
			fixture.raw.mu.Unlock()
			t.Fatal("a read waiting for bulk-lane capacity registered a data publication")
		}
	}
	fixture.raw.mu.Unlock()
	if err := fixture.raw.drainDataPublications(coordinate); err != nil {
		t.Fatalf("a source purge waited on a read which had not entered the bulk lane: %v", err)
	}

	<-fixture.mount.bulk
	select {
	case outcome := <-readDone:
		if !outcome.status.Ok() || outcome.result == nil || outcome.result.Size() != 4 {
			t.Fatalf("admitted READ = (%v, %v), want four bytes", outcome.result, outcome.status)
		}
		completeTestReply(t, fixture.raw, unique, fuse.OK)
	case <-time.After(2 * time.Second):
		t.Fatal("read did not enter the lane after capacity was released")
	}
}

// summarize renders a byte run as the distinct values it contains, which is
// what distinguishes a stale page from a stale size in a failure message.
func summarize(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}
	runs := make([]string, 0, 4)
	start := 0
	for index := 1; index <= len(data); index++ {
		if index == len(data) || data[index] != data[start] {
			runs = append(runs, fmt.Sprintf("%d*%#02x", index-start, data[start]))
			if len(runs) == 4 {
				return fmt.Sprintf("%v...", runs)
			}
			start = index
		}
	}
	return fmt.Sprintf("%v", runs)
}

// TestRepeatedOpenForReadRacingAPeerWriteKeepsBothMountsServing covers the
// barrier cycle that only a fresh open can enter. The frontend registers an
// open-for-read's page-cache publication and a recall's whole-file purge waits
// for that publication's physical reply, so an open admitted on the metadata
// lane -- which parks for the entire barrier -- would be a reply the purge waits
// on that is itself waiting on the purge's own transaction. That cycle is broken
// only by the repair budget, which revokes the peer mount.
//
// Unlike the other race tests here, every reader opens the file inside the write
// loop rather than holding a descriptor across it. The openers are bounded per
// round and joined before the next one: what has to land inside a recall is an
// open, not a sustained read stream. A sustained stream on one inode measures
// something else entirely -- how long stock's whole-file invalidation can be
// starved of the folio locks it needs, which docs/portable-coherence.md §7.3b
// records as an unbounded kernel-side residual.
func TestRepeatedOpenForReadRacingAPeerWriteKeepsBothMountsServing(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	const size = 96 * 1024
	before := bytes.Repeat([]byte{'a'}, size)
	after := bytes.Repeat([]byte{'b'}, size)
	writerPath := f.join(0, "opened")
	readerPath := f.join(1, "opened")
	mustWrite(t, writerPath, before, 0o600)

	var failure atomic.Pointer[error]
	var opens atomic.Int64
	openOnce := func() {
		file, err := os.Open(readerPath)
		if err != nil {
			recorded := fmt.Errorf("open(O_RDONLY) during a peer write: %w", err)
			failure.CompareAndSwap(nil, &recorded)
			return
		}
		defer file.Close()
		if _, err := syscall.Pread(int(file.Fd()), make([]byte, size), 0); err != nil {
			recorded := fmt.Errorf("read on a descriptor opened during a peer write: %w", err)
			failure.CompareAndSwap(nil, &recorded)
			return
		}
		// Content is deliberately not asserted here. A read concurrent with a
		// multi-chunk rewrite may legitimately observe an intermediate size, and
		// §3.3's disclosed mixed-state residual covers the rest. What this test
		// is about is that the open and the read complete at all, and that
		// neither mount is torn down by the barrier they raced.
		opens.Add(1)
	}

	payloads := [2][]byte{after, before}
	// The cycle this test exists for does not only end in a revoked mount. With
	// the open admitted on the metadata lane but the frontend no longer refusing
	// a read outright, the open still parks for the whole barrier and the purge
	// still waits on it -- and the pair is broken by a request timeout rather
	// than by a fence, so every assertion below passes and the suite only gets
	// slower. Measured: 0.12s for these 96 rounds when the lanes are right,
	// 240.65s when they are not, about a quarter of the rounds eating a full
	// request timeout. A wall-clock bound is what makes that state fail.
	//
	// The bound is on the whole loop rather than per round, because one round
	// stalling on a loaded machine is ordinary and the defect is systemic. At
	// 20s it sits two orders of magnitude above the healthy total and an order
	// of magnitude below the degraded one, so neither CI load nor a slow
	// filesystem reaches it.
	const raceBound = 20 * time.Second
	raceStart := time.Now()
	for round := range 96 {
		// One opener, two opens, joined before the next round. That is enough
		// for an open to land inside a recall, which is this test's subject,
		// and few enough that the invalidation discharging that recall always
		// finds the folio locks it needs -- see the note above.
		var racing sync.WaitGroup
		racing.Add(1)
		go func() {
			defer racing.Done()
			for range 2 {
				openOnce()
			}
		}()
		err := os.WriteFile(writerPath, payloads[round%2], 0o600)
		racing.Wait()
		if err != nil {
			t.Fatalf("round %d: peer write: %v (%s)", round, err, f.sessionDiagnostics())
		}
		if recorded := failure.Load(); recorded != nil {
			t.Fatalf("round %d: %v", round, *recorded)
		}
	}
	if raced := time.Since(raceStart); raced > raceBound {
		t.Fatalf("96 rewrites raced by repeated opens took %s, past the %s bound: opens are parking for a whole barrier and being released by a timeout rather than by the data lane (%s)",
			raced, raceBound, f.sessionDiagnostics())
	}
	if completed := opens.Load(); completed < 150 {
		t.Fatalf("only %d opens raced 96 peer rewrites; the window this test exists for was not entered", completed)
	}
	// Quiescent, the ordering is exact: an open issued after the last write
	// returned observes what that write left.
	want := payloads[95%2]
	quiesced, err := os.Open(readerPath)
	if err != nil {
		t.Fatalf("open after the race: %v", err)
	}
	defer quiesced.Close()
	got := make([]byte, size)
	n, err := syscall.Pread(int(quiesced.Fd()), got, 0)
	if err != nil {
		t.Fatalf("read after the race: %v", err)
	}
	if n != size || !bytes.Equal(got[:n], want) {
		t.Fatalf("open after the race read %d bytes of %s, want %d of %q", n, summarize(got[:n]), size, string(want[0]))
	}
	for index := range 2 {
		if cause := f.mounts[index].fatalError(); cause != nil {
			t.Fatalf("mount %d revoked during the open race: %v", index, cause)
		}
	}
}
