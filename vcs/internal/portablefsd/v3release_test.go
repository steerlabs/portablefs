package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// recordingV3ReleaseSend is a release transport whose work batches can be
// held open, so a test controls exactly which tokens arrive while one is in
// flight.
type recordingV3ReleaseSend struct {
	mu      sync.Mutex
	batches []v3SentReleaseBatch
	entered chan int
	release chan struct{}
	hold    bool
	fail    error
}

type v3SentReleaseBatch struct {
	closes, reclaims []string
}

func newRecordingV3ReleaseSend(hold bool) *recordingV3ReleaseSend {
	return &recordingV3ReleaseSend{entered: make(chan int, 64), release: make(chan struct{}, 64), hold: hold}
}

func v3TokenNames(tokens [][]byte) []string {
	names := make([]string, len(tokens))
	for index, token := range tokens {
		names[index] = string(token)
	}
	return names
}

func (s *recordingV3ReleaseSend) send(closes, reclaims [][]byte) error {
	s.mu.Lock()
	s.batches = append(s.batches, v3SentReleaseBatch{closes: v3TokenNames(closes), reclaims: v3TokenNames(reclaims)})
	index, hold, fail := len(s.batches), s.hold, s.fail
	s.mu.Unlock()
	s.entered <- index
	if hold {
		<-s.release
	}
	return fail
}

func (s *recordingV3ReleaseSend) sent() []v3SentReleaseBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]v3SentReleaseBatch(nil), s.batches...)
}

func v3ReleaseTokens(names ...string) [][]byte {
	tokens := make([][]byte, len(names))
	for index, name := range names {
		tokens[index] = []byte(name)
	}
	return tokens
}

func waitV3ReleaseForming(t *testing.T, r *v3ReleaseOwner, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		forming := 0
		if r.forming != nil {
			forming = r.forming.tokens()
		}
		r.mu.Unlock()
		if forming == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("forming batch holds %d tokens, want %d", forming, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitV3ReleasesIdle waits until every accepted release has settled without
// closing admission, so a test can keep using the data plane afterwards.
func waitV3ReleasesIdle(t *testing.T, d *v3DataPlane) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := d.releases
		r.mu.Lock()
		idle := !r.running && (r.forming == nil || r.forming.tokens()+r.forming.reserved == 0)
		r.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted releases did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

func submitV3Async(r *v3ReleaseOwner, closes, reclaims [][]byte) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.submit(closes, reclaims) }()
	return done
}

func requireV3ReleaseResult(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) && !(err == nil && want == nil) {
			t.Fatalf("release = %v, want %v", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("release producer did not return")
	}
}

// saturateV3Releases puts one live capability in flight behind a blocked
// Reclaim and fills the forming batch, so every later producer is pre-enqueue.
func saturateV3Releases(t *testing.T, d *v3DataPlane, client *fakeV3DataClient) {
	t.Helper()
	r := d.releases
	if err := r.submit(nil, [][]byte{client.issueItem(900, authoritypb.Attr_REGULAR, 0x90).GetToken()}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		inFlight := r.running && r.forming == nil
		r.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first release batch did not go in flight")
		}
		time.Sleep(time.Millisecond)
	}
	for index := range r.limit {
		if err := r.submit(nil, [][]byte{client.issueItem(uint64(901+index), authoritypb.Attr_REGULAR, 0x91).GetToken()}); err != nil {
			t.Fatal(err)
		}
	}
	waitV3ReleaseForming(t, r, r.limit)
}

func requireV3ReleaseBlocked(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("producer returned %v while the forming batch was full", err)
	case <-time.After(20 * time.Millisecond):
	}
}

// Producers return at acceptance: the worker carries the in-flight batch and
// every later token joins one forming batch, so a burst costs one round trip
// per batch and no producer waits for its own settlement.
func TestV3ReleaseOwnerProducersReturnAtAcceptanceAndCoalesce(t *testing.T) {
	transport := newRecordingV3ReleaseSend(true)
	r := newV3ReleaseOwner(v3ReleaseBatchTokens, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	<-transport.entered
	for _, name := range []string{"b", "c", "d"} {
		requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens(name)), nil)
	}
	requireV3ReleaseResult(t, submitV3Async(r, v3ReleaseTokens("h1", "h2"), nil), nil)
	waitV3ReleaseForming(t, r, 5)
	transport.release <- struct{}{}
	<-transport.entered
	transport.release <- struct{}{}
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := transport.sent()
	if len(sent) != 2 || !slices.Equal(sent[0].reclaims, []string{"a"}) {
		t.Fatalf("batches = %+v, want [a] then one coalesced batch", sent)
	}
	reclaims := slices.Clone(sent[1].reclaims)
	slices.Sort(reclaims)
	if !slices.Equal(reclaims, []string{"b", "c", "d"}) || !slices.Equal(sent[1].closes, []string{"h1", "h2"}) {
		t.Fatalf("coalesced batch = %+v, want closes [h1 h2] and every reclaim submitted while in flight", sent[1])
	}
}

// One in-flight batch plus one forming batch of B tokens each: the next
// producer waits for room, and every token is sent exactly once within B.
func TestV3ReleaseOwnerBoundsBatchesWithBackpressure(t *testing.T) {
	transport := newRecordingV3ReleaseSend(true)
	r := newV3ReleaseOwner(2, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	<-transport.entered
	requireV3ReleaseResult(t, submitV3Async(r, v3ReleaseTokens("b"), nil), nil)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("c")), nil)
	waitV3ReleaseForming(t, r, 2)
	blocked := submitV3Async(r, nil, v3ReleaseTokens("d"))
	requireV3ReleaseBlocked(t, blocked)
	reserved := make(chan error, 1)
	go func() {
		reservation, err := r.reserve(context.Background(), 1)
		if err == nil {
			reservation.commit(v3ReleaseTokens("e"), nil)
		}
		reserved <- err
	}()
	requireV3ReleaseBlocked(t, reserved)
	// How the unblocked producers group is scheduling-dependent; only the
	// bound and exactly-once delivery are asserted.
	transport.mu.Lock()
	transport.hold = false
	transport.mu.Unlock()
	transport.release <- struct{}{}
	requireV3ReleaseResult(t, blocked, nil)
	requireV3ReleaseResult(t, reserved, nil)
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, batch := range transport.sent() {
		if size := len(batch.closes) + len(batch.reclaims); size == 0 || size > 2 {
			t.Fatalf("batch %+v exceeds the bound", batch)
		}
		all = append(all, batch.closes...)
		all = append(all, batch.reclaims...)
	}
	slices.Sort(all)
	if !slices.Equal(all, []string{"a", "b", "c", "d", "e"}) {
		t.Fatalf("tokens sent = %v, want each exactly once", all)
	}
}

func TestV3ReleaseOwnerSplitsLargeSubmissionsWithinTheBound(t *testing.T) {
	transport := newRecordingV3ReleaseSend(false)
	r := newV3ReleaseOwner(2, transport.send)
	if err := r.submit(v3ReleaseTokens("h1", "h2", "h3"), v3ReleaseTokens("a", "b")); err != nil {
		t.Fatal(err)
	}
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var closes, reclaims []string
	for _, batch := range transport.sent() {
		if size := len(batch.closes) + len(batch.reclaims); size == 0 || size > 2 {
			t.Fatalf("batch %+v exceeds the bound", batch)
		}
		closes = append(closes, batch.closes...)
		reclaims = append(reclaims, batch.reclaims...)
	}
	if !slices.Equal(closes, []string{"h1", "h2", "h3"}) || !slices.Equal(reclaims, []string{"a", "b"}) {
		t.Fatalf("closes=%v reclaims=%v, want each exactly once in order", closes, reclaims)
	}
}

// The worker never takes a batch with an outstanding reservation, so a
// producer that reserved before detaching always lands in the batch it was
// granted.
func TestV3ReleaseOwnerWaitsForReservationsBeforeSending(t *testing.T) {
	transport := newRecordingV3ReleaseSend(false)
	r := newV3ReleaseOwner(4, transport.send)
	reservation, err := r.reserve(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	select {
	case <-transport.entered:
		t.Fatal("worker sent a batch with an outstanding reservation")
	case <-time.After(20 * time.Millisecond):
	}
	reservation.commit(v3ReleaseTokens("h"), nil)
	<-transport.entered
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent := transport.sent(); len(sent) != 1 || !slices.Equal(sent[0].closes, []string{"h"}) || !slices.Equal(sent[0].reclaims, []string{"a"}) {
		t.Fatalf("batches = %+v, want one batch carrying the reserved close", sent)
	}
}

func TestV3ReleaseOwnerFailureIsStickyAndNeverRetriedItemByItem(t *testing.T) {
	failure := errors.New("authority rejected the batch")
	transport := newRecordingV3ReleaseSend(true)
	transport.fail = failure
	r := newV3ReleaseOwner(v3ReleaseBatchTokens, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, v3ReleaseTokens("h"), v3ReleaseTokens("a")), nil)
	<-transport.entered
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("b")), nil)
	waitV3ReleaseForming(t, r, 1)
	transport.release <- struct{}{}
	if err := r.drain(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("drain after failure = %v, want the sticky failure", err)
	}
	// The batch formed behind the failed one is never sent, and later
	// producers are refused instead of claiming success.
	if err := r.submit(nil, v3ReleaseTokens("c")); !errors.Is(err, failure) {
		t.Fatalf("submit after failure = %v, want the sticky failure", err)
	}
	if _, err := r.reserve(context.Background(), 1); !errors.Is(err, failure) {
		t.Fatalf("reserve after failure = %v, want the sticky failure", err)
	}
	if sent := transport.sent(); len(sent) != 1 {
		t.Fatalf("batches after failure = %+v, want only the failed one", sent)
	}
}

// A failure wakes producers parked on a full forming batch rather than leaving
// them waiting for capacity that will never come.
func TestV3ReleaseOwnerFailureWakesWaitingProducers(t *testing.T) {
	failure := errors.New("release failed")
	transport := newRecordingV3ReleaseSend(true)
	transport.fail = failure
	r := newV3ReleaseOwner(1, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	<-transport.entered
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("b")), nil)
	waiting := submitV3Async(r, nil, v3ReleaseTokens("c"))
	requireV3ReleaseBlocked(t, waiting)
	transport.release <- struct{}{}
	requireV3ReleaseResult(t, waiting, failure)
}

// Drain settles accepted work on the original session, then hands every later
// token to the detach explicitly: later producers return without a round trip
// and reservations report the closed owner.
func TestV3ReleaseOwnerDrainSettlesAcceptedWorkAndTransfersLaterTokens(t *testing.T) {
	transport := newRecordingV3ReleaseSend(true)
	r := newV3ReleaseOwner(v3ReleaseBatchTokens, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	<-transport.entered
	requireV3ReleaseResult(t, submitV3Async(r, v3ReleaseTokens("h"), nil), nil)
	waitV3ReleaseForming(t, r, 1)
	drained := make(chan error, 1)
	go func() { drained <- r.drain(context.Background()) }()
	requireV3ReleaseBlocked(t, drained)
	transport.release <- struct{}{}
	<-transport.entered
	transport.release <- struct{}{}
	requireV3ReleaseResult(t, drained, nil)
	if err := r.submit(nil, v3ReleaseTokens("late")); err != nil {
		t.Fatalf("submit after drain = %v, want acceptance by the detach", err)
	}
	if _, err := r.reserve(context.Background(), 1); !errors.Is(err, errV3ReleaseClosed) {
		t.Fatalf("reserve after drain = %v, want the closed owner", err)
	}
	if sent := transport.sent(); len(sent) != 2 {
		t.Fatalf("batches = %+v, want only the two accepted before drain", sent)
	}
}

// A drain that cannot settle before its bound reports that, rather than
// letting the detach claim the accepted work was released.
func TestV3ReleaseOwnerDrainNeverClaimsUnfinishedWork(t *testing.T) {
	transport := newRecordingV3ReleaseSend(true)
	r := newV3ReleaseOwner(v3ReleaseBatchTokens, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	<-transport.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.drain(ctx); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unfinished drain = %v, want its deadline", err)
	}
	transport.release <- struct{}{}
}

// A terminal data plane leaves forming tokens to session cleanup; the batch
// already in flight still settles, and producers return.
func TestV3ReleaseOwnerAbandonLeavesFormingTokensToTheSession(t *testing.T) {
	transport := newRecordingV3ReleaseSend(true)
	r := newV3ReleaseOwner(1, transport.send)
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("a")), nil)
	<-transport.entered
	requireV3ReleaseResult(t, submitV3Async(r, nil, v3ReleaseTokens("b")), nil)
	waiting := submitV3Async(r, nil, v3ReleaseTokens("c"))
	requireV3ReleaseBlocked(t, waiting)
	r.abandon()
	requireV3ReleaseResult(t, waiting, nil)
	transport.release <- struct{}{}
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent := transport.sent(); len(sent) != 1 {
		t.Fatalf("batches = %+v, want only the batch in flight before the terminal transition", sent)
	}
}

func TestV3ReleaseLimitFollowsBAndTheNegotiatedFrame(t *testing.T) {
	for _, test := range []struct {
		maxWrite uint32
		want     int
	}{
		{maxWrite: 1 << 20, want: v3ReleaseBatchTokens},
		{maxWrite: v3ReleaseBatchTokens * v3CloseTokenWireBytes, want: v3ReleaseBatchTokens},
		{maxWrite: 1000, want: 1000 / v3CloseTokenWireBytes},
		{maxWrite: v3CloseTokenWireBytes, want: 1},
		{maxWrite: 1, want: 1},
	} {
		client := newFakeV3DataClient()
		client.maxWrite = test.maxWrite
		d := testV3DataPlane(t, client)
		if d.releases.limit != test.want {
			t.Fatalf("maxWrite %d: release bound = %d, want %d", test.maxWrite, d.releases.limit, test.want)
		}
	}
	if v3ReleaseBatchTokens != 128 || v3ReleaseBatchTokens > authorityrpc.MaxReclaimBatch {
		t.Fatalf("B = %d, want 128 and within the Reclaim bound", v3ReleaseBatchTokens)
	}
}

func TestV3DataPlaneRefusesASessionWithoutBatchedClose(t *testing.T) {
	client := &noBatchedCloseV3Client{newFakeV3DataClient()}
	_, err := newV3DataPlane(context.Background(), v3DataPlaneConfig{Client: client, VolumeID: "volume", VolumeName: "Volume", ItemGeneration: 9, CachePolicy: v3CachePolicyFSKit})
	if err == nil {
		t.Fatal("data plane started without batched-close-v1")
	}
}

type noBatchedCloseV3Client struct{ *fakeV3DataClient }

func (noBatchedCloseV3Client) SupportsBatchedClose() bool { return false }

func openV3TestHandles(t *testing.T, d *v3DataPlane, file pfslocal.Item, count int) []uint64 {
	t.Helper()
	handles := make([]uint64, count)
	for index := range handles {
		reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeRead})
		if errno != 0 {
			t.Fatalf("open %d errno=%d", index, errno)
		}
		handles[index] = reply.(*pfslocal.OpenReply).Handle
	}
	return handles
}

// Many concurrent closes retire locally, coalesce into CloseBatch requests of
// at most B handles, and release every authority handle exactly once.
func TestV3ManyOpenHandlesCloseThroughBoundedCloseBatches(t *testing.T) {
	client := newFakeV3DataClient()
	client.limit = 16
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	handles := openV3TestHandles(t, d, file.Item, 300)
	var wg sync.WaitGroup
	for _, handle := range handles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: handle})
			if errno != 0 || !reply.(*pfslocal.CloseReply).Retired {
				t.Errorf("close %d = (%#v,%d)", handle, reply, errno)
			}
		}()
	}
	wg.Wait()
	waitV3ReleasesIdle(t, d)
	seen := map[string]bool{}
	for _, batch := range client.closedBatches() {
		if len(batch) == 0 || len(batch) > v3ReleaseBatchTokens {
			t.Fatalf("CloseBatch of %d handles exceeds B", len(batch))
		}
		for _, handle := range batch {
			if seen[string(handle)] {
				t.Fatalf("handle %x closed twice", handle)
			}
			seen[string(handle)] = true
		}
	}
	if len(seen) != len(handles) || client.liveTokens() != 2 || d.terminalError() != nil {
		t.Fatalf("closed=%d live=%d terminal=%v, want every handle released once", len(seen), client.liveTokens(), d.terminalError())
	}
}

// A duplicate Close of a retired handle is a local answer; the handle's
// release is accepted exactly once.
func TestV3DuplicateCloseReleasesTheHandleOnce(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	handle := openV3TestHandles(t, d, file.Item, 1)[0]
	for range 2 {
		reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: handle})
		if errno != 0 || !reply.(*pfslocal.CloseReply).Retired {
			t.Fatalf("close = (%#v,%d)", reply, errno)
		}
	}
	waitV3ReleasesIdle(t, d)
	if batches := client.closedBatches(); len(batches) != 1 || len(batches[0]) != 1 {
		t.Fatalf("CloseBatch requests = %x, want one release of the handle", batches)
	}
}

// A call that resolved the handle pointer before a competing Close won must
// revalidate under its lock and refuse, instead of using a released token.
func TestV3StaleHandlePointerRacingCloseIsRefusedUnderItsLock(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	id := openV3TestHandles(t, d, file.Item, 1)[0]
	stale, errno := d.handle(id, nil)
	if errno != 0 {
		t.Fatalf("handle errno=%d", errno)
	}
	stale.mu.RLock()
	closed := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: id})
		closed <- errno
	}()
	select {
	case errno := <-closed:
		t.Fatalf("close returned %d while an admitted call held the handle", errno)
	case <-time.After(20 * time.Millisecond):
	}
	stale.mu.RUnlock()
	if errno := <-closed; errno != 0 {
		t.Fatalf("close errno=%d", errno)
	}
	waitV3ReleasesIdle(t, d)
	before := len(client.mutationRequests())
	for _, request := range []any{
		&pfslocal.ReadRequest{Handle: id, Length: 1},
		&pfslocal.WriteRequest{Handle: id, Data: []byte("x")},
		&pfslocal.FsyncRequest{Handle: id},
		&pfslocal.GetAttrRequest{Item: file.Item, Handle: id},
	} {
		if _, errno := dispatchV3Test(d, context.Background(), 0, request); errno != darwinEBADF {
			t.Fatalf("%T on a closed handle errno=%d, want EBADF", request, errno)
		}
	}
	if after := len(client.mutationRequests()); after != before {
		t.Fatalf("closed handle reached the authority %d times", after-before)
	}
}

// Serial kernel reclamation replies at local speed: each Reclaim returns once
// the owner accepted its capability, while the authority round trip that
// carries it is still in flight.
func TestV3SerialReclaimRepliesBeforeItsAuthorityRoundTrip(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	names := map[string]*authoritypb.Item{}
	for index := range 6 {
		names[fmt.Sprintf("file-%d", index)] = authorityTestItem(uint64(10+index), authoritypb.Attr_REGULAR, 0, byte(0x60+index))
	}
	client.mutation = lookupByName(client, names)
	items := make([]pfslocal.Item, 6)
	for index := range items {
		items[index] = lookupTestAttr(t, d, root, fmt.Sprintf("file-%d", index)).Item
	}
	release := blockV3Reclaims(client)
	for _, item := range items {
		done := make(chan int32, 1)
		go func() {
			_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: item})
			done <- errno
		}()
		select {
		case errno := <-done:
			if errno != 0 {
				t.Fatalf("reclaim errno=%d", errno)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("reclaim waited for its authority round trip")
		}
	}
	release()
	waitV3ReleasesIdle(t, d)
	if client.liveTokens() != 1 || len(client.reclaimBatches()) > 2 {
		t.Fatalf("live=%d reclaim batches=%d, want every capability retired in at most two batches", client.liveTokens(), len(client.reclaimBatches()))
	}
}

// Cancellation after acceptance does not cancel the release.
func TestV3CloseCancellationAfterTransferStillReleases(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	id := openV3TestHandles(t, d, file.Item, 1)[0]
	ctx, cancel := context.WithCancel(context.Background())
	if _, errno := dispatchV3Test(d, ctx, 0, &pfslocal.CloseRequest{Handle: id}); errno != 0 {
		t.Fatalf("close errno=%d", errno)
	}
	cancel()
	waitV3ReleasesIdle(t, d)
	if batches := client.closedBatches(); len(batches) != 1 || client.liveTokens() != 2 {
		t.Fatalf("CloseBatch requests=%d live=%d, want the accepted close sent", len(batches), client.liveTokens())
	}
}

// Every failed CloseBatch entry, a short result list, or a failed Reclaim is a
// sticky terminal release failure with no per-entry retry.
func TestV3ReleaseBatchFailuresAreTerminal(t *testing.T) {
	for _, test := range []struct {
		name string
		// reclaim selects which request the mutation corrupts.
		reclaim bool
		mutate  func(*authoritypb.Response)
	}{
		{name: "first-entry-errno", mutate: func(r *authoritypb.Response) {
			r.GetCloseBatch().Results[0] = &authoritypb.CloseBatchResult{Retired: true, Errno: errnos.EIO}
		}},
		{name: "last-entry-not-retired", mutate: func(r *authoritypb.Response) {
			results := r.GetCloseBatch().Results
			results[len(results)-1] = &authoritypb.CloseBatchResult{}
		}},
		{name: "failure-class", mutate: func(r *authoritypb.Response) {
			r.GetCloseBatch().Results[0].Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
		}},
		{name: "short-results", mutate: func(r *authoritypb.Response) {
			r.GetCloseBatch().Results = r.GetCloseBatch().Results[1:]
		}},
		{name: "envelope-errno", mutate: func(r *authoritypb.Response) {
			r.Errno, r.Body = errnos.EINVAL, nil
		}},
		{name: "reclaim-errno", reclaim: true, mutate: func(r *authoritypb.Response) {
			r.Errno = errnos.ESTALE
		}},
		// Whole-outcome shapes generic classification would admit.
		{name: "closebatch-top-level-failure-class", mutate: func(r *authoritypb.Response) {
			r.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL
		}},
		{name: "reclaim-failure-class", reclaim: true, mutate: func(r *authoritypb.Response) {
			r.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL
		}},
		{name: "reclaim-with-closebatch-body", reclaim: true, mutate: func(r *authoritypb.Response) {
			r.Body = &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			root := d.resolveReply().Root
			file := lookupTestAttr(t, d, root, "file")
			other := lookupTestAttr(t, d, root, "other")
			handles := openV3TestHandles(t, d, file.Item, 3)
			hold := make(chan struct{})
			var mu sync.Mutex
			sends, failedAt := 0, 0
			waitV3ReleasesIdle(t, d)
			client.mu.Lock()
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				<-hold
				var response *authoritypb.Response
				switch request.GetBody().(type) {
				case *authoritypb.Request_CloseBatch:
					response = client.closeBatch(identity, request)
				case *authoritypb.Request_Reclaim:
					response = client.reclaim(identity, request)
				default:
					return nil, errors.New("unexpected request")
				}
				mu.Lock()
				defer mu.Unlock()
				sends++
				if failedAt == 0 && test.reclaim == (request.GetReclaim() != nil) {
					failedAt = sends
					test.mutate(response)
				}
				return response, nil
			}
			client.mu.Unlock()
			for _, handle := range handles {
				if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: handle}); errno != 0 {
					t.Fatalf("close errno=%d", errno)
				}
			}
			if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: other.Item}); errno != 0 {
				t.Fatalf("reclaim errno=%d", errno)
			}
			close(hold)
			deadline := time.Now().Add(2 * time.Second)
			for d.terminalError() == nil {
				if time.Now().After(deadline) {
					t.Fatal("a failed release left the data plane serving")
				}
				time.Sleep(time.Millisecond)
			}
			if err := d.releases.drain(context.Background()); err == nil {
				t.Fatal("drain after a failed release claimed success")
			}
			definite := test.name == "first-entry-errno" || test.name == "envelope-errno" || test.name == "reclaim-errno"
			select {
			case <-client.SessionDone():
				if definite {
					t.Fatal("definite refusal closed the usable authority transport")
				}
			default:
				if !definite {
					t.Fatal("malformed release retained authority transport")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if failedAt == 0 || sends != failedAt {
				t.Fatalf("release requests = %d with the failure at %d, want nothing sent after it", sends, failedAt)
			}
		})
	}
}

// The serial frontend reader settles an abandonment synchronously and keeps
// going even while release capacity is saturated; the abandoned resources are
// pre-enqueue debt until the owner accepts them.
func TestV3SaturatedReleasesNeverBlockTheSerialReader(t *testing.T) {
	client := newFakeV3DataClient()
	client.maxWrite = v3CloseTokenWireBytes // B = 1
	d := testV3DataPlane(t, client)
	release := blockV3Reclaims(client)
	saturateV3Releases(t, d, client)
	c := &frontendConn{}
	open := provisionalTestOpen(t, d, client)
	if !c.registerProvisionalResource(7, open) {
		t.Fatal("provisional open was not registered")
	}
	settled := make(chan bool, 1)
	go func() { settled <- c.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{TargetRequestID: 7}) }()
	select {
	case ok := <-settled:
		if !ok {
			t.Fatal("abandonment disposition was refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the serial reader blocked on release capacity")
	}
	if debt := d.outstandingCleanup(); debt != 1 {
		t.Fatalf("pre-enqueue debt = %d, want the abandoned open still counted", debt)
	}
	release()
	waitV3CleanupDebt(t, d, 0)
	waitV3ReleasesIdle(t, d)
	if client.liveTokens() != 1 {
		t.Fatalf("live capabilities = %d, want only the root", client.liveTokens())
	}
}

// After exact kernel absence the drain explicitly transfers later releases to
// the detach; abandoned cleanup that arrives afterwards settles its debt
// without a round trip.
func TestV3DrainTransfersLateAbandonmentToTheDetach(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	collector := &v3ReplyResourceCollector{d: d}
	collectTestItem(t, d, collector, client.issueItem(3, authoritypb.Attr_REGULAR, 0x43))
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.releases.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(client.mutationRequests())
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	if debt, after := d.outstandingCleanup(), len(client.mutationRequests()); debt != 0 || after != before || d.terminalError() != nil {
		t.Fatalf("late abandonment debt=%d requests=%d terminal=%v, want settled by the detach", debt, after-before, d.terminalError())
	}
}

// A handle token released through the owner never reaches the authority twice
// even when an abandonment and a Close race for it.
func TestV3AbandonmentAndCloseRaceReleaseOnce(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	record := d.itemsByID[file.Item.ItemID]
	handle, err := d.installHandle(client.issueHandle(), record.item, false)
	if err != nil {
		t.Fatal(err)
	}
	collector := &v3ReplyResourceCollector{d: d}
	collectV3ReplyHandle(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), handle)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: handle.id})
		closed <- errno
	}()
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	if errno := <-closed; errno != 0 {
		t.Fatalf("close errno=%d", errno)
	}
	waitV3ReleasesIdle(t, d)
	total := 0
	for _, batch := range client.closedBatches() {
		for _, token := range batch {
			if bytes.Equal(token, handle.token) {
				total++
			}
		}
	}
	if total != 1 || d.terminalError() != nil {
		t.Fatalf("handle released %d times terminal=%v, want once", total, d.terminalError())
	}
}

// The pointer-to-lock window itself: a call resolves the handle, pauses before
// taking its shared lock, a Close wins and retires the handle, and the call
// must then refuse under its lock instead of using the released token.
func TestV3HandleRevalidatesAfterAPausedPointerResolution(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	id := openV3TestHandles(t, d, file.Item, 1)[0]
	resolved, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	d.testBeforeHandleLock = func(*v3HandleRecord) {
		once.Do(func() {
			close(resolved)
			<-resume
		})
	}
	readsBefore := func() int {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.readCalls
	}()
	read := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReadRequest{Handle: id, Length: 1})
		read <- errno
	}()
	<-resolved
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: id}); errno != 0 {
		t.Fatalf("close errno=%d", errno)
	}
	close(resume)
	if errno := <-read; errno != darwinEBADF {
		t.Fatalf("read that lost the race to Close errno=%d, want EBADF", errno)
	}
	client.mu.Lock()
	reads := client.readCalls
	client.mu.Unlock()
	if reads != readsBefore {
		t.Fatalf("a read of a closed handle reached the authority %d time(s)", reads-readsBefore)
	}
}

// A late release outcome belongs to the original DATA request, but after exact
// absence it must not overwrite Detach or poison its working CONTROL path.
func TestV3ReleaseTransferRetainsInflightOwnerWithoutOverwritingDetach(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	entered, settle := make(chan struct{}), make(chan struct{})
	client.mutation = func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error) {
		close(entered)
		<-settle
		return nil, errors.New("DATA transport closed by successful Detach")
	}
	if err := d.releases.submit(v3ReleaseTokens("h"), nil); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := d.transferReleases(); err == nil {
		t.Fatal("in-flight release was reported as settled")
	}
	_ = d.stopServing(errV3AttachDetached)
	close(settle)
	if err := d.releases.drain(context.Background()); err == nil {
		t.Fatal("unconfirmed release was reported as successful")
	}
	if !errors.Is(d.terminalError(), errV3AttachDetached) {
		t.Fatalf("detach verdict replaced: %v", d.terminalError())
	}
	select {
	case <-client.SessionDone():
		t.Fatal("late DATA error closed the retained transport")
	default:
	}
}
