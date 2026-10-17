package portablefsd

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// recordingV3ReclaimSend is a reclaimer transport whose batches can be held
// open, so a test controls exactly which tokens arrive while one is in flight.
type recordingV3ReclaimSend struct {
	mu      sync.Mutex
	batches [][]string
	entered chan int
	release chan struct{}
	hold    bool
	fail    error
}

func newRecordingV3ReclaimSend(hold bool) *recordingV3ReclaimSend {
	return &recordingV3ReclaimSend{entered: make(chan int, 64), release: make(chan struct{}, 64), hold: hold}
}

func (s *recordingV3ReclaimSend) send(tokens [][]byte) error {
	names := make([]string, len(tokens))
	for index, token := range tokens {
		names[index] = string(token)
	}
	s.mu.Lock()
	s.batches = append(s.batches, names)
	index, hold, fail := len(s.batches), s.hold, s.fail
	s.mu.Unlock()
	s.entered <- index
	if hold {
		<-s.release
	}
	return fail
}

func (s *recordingV3ReclaimSend) sent() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.batches...)
}

func v3ReclaimTokens(names ...string) [][]byte {
	tokens := make([][]byte, len(names))
	for index, name := range names {
		tokens[index] = []byte(name)
	}
	return tokens
}

func waitV3ReclaimerForming(t *testing.T, r *v3Reclaimer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		forming := 0
		if r.forming != nil {
			forming = len(r.forming.tokens)
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

func retireV3Async(r *v3Reclaimer, names ...string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.retire(v3ReclaimTokens(names...)...) }()
	return done
}

func requireV3RetireResult(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) && !(err == nil && want == nil) {
			t.Fatalf("retire = %v, want %v", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retire did not settle")
	}
}

func TestV3ReclaimerCoalescesSubmittersBehindTheInFlightBatch(t *testing.T) {
	transport := newRecordingV3ReclaimSend(true)
	r := newV3Reclaimer(authorityrpc.MaxReclaimBatch, transport.send)
	first := retireV3Async(r, "a")
	<-transport.entered
	later := []<-chan error{retireV3Async(r, "b"), retireV3Async(r, "c"), retireV3Async(r, "d")}
	waitV3ReclaimerForming(t, r, 3)
	select {
	case err := <-first:
		t.Fatalf("submitter returned before its batch settled: %v", err)
	default:
	}
	transport.release <- struct{}{}
	requireV3RetireResult(t, first, nil)
	<-transport.entered
	transport.release <- struct{}{}
	for _, done := range later {
		requireV3RetireResult(t, done, nil)
	}
	sent := transport.sent()
	if len(sent) != 2 || !slices.Equal(sent[0], []string{"a"}) {
		t.Fatalf("batches = %v, want [a] then one coalesced batch", sent)
	}
	coalesced := slices.Clone(sent[1])
	slices.Sort(coalesced)
	if !slices.Equal(coalesced, []string{"b", "c", "d"}) {
		t.Fatalf("second batch = %v, want every token submitted while the first was in flight", sent[1])
	}
}

func TestV3ReclaimerSerialSubmittersEachComplete(t *testing.T) {
	transport := newRecordingV3ReclaimSend(false)
	r := newV3Reclaimer(authorityrpc.MaxReclaimBatch, transport.send)
	for _, name := range []string{"a", "b", "c"} {
		if err := r.retire([]byte(name)); err != nil {
			t.Fatalf("retire %s = %v", name, err)
		}
	}
	if sent := transport.sent(); !slices.EqualFunc(sent, [][]string{{"a"}, {"b"}, {"c"}}, slices.Equal[[]string]) {
		t.Fatalf("serial batches = %v, want one immediate batch per submitter", sent)
	}
	r.mu.Lock()
	idle := !r.running && r.forming == nil
	r.mu.Unlock()
	if !idle {
		t.Fatal("reclaimer did not return to idle between serial submitters")
	}
}

func TestV3ReclaimerBoundsBatchesWithBackpressure(t *testing.T) {
	transport := newRecordingV3ReclaimSend(true)
	r := newV3Reclaimer(2, transport.send)
	first := retireV3Async(r, "a")
	<-transport.entered
	b, c := retireV3Async(r, "b"), retireV3Async(r, "c")
	waitV3ReclaimerForming(t, r, 2)
	// The forming batch is full: the next submitter waits for room instead of
	// growing an unbounded queue.
	d := retireV3Async(r, "d")
	time.Sleep(20 * time.Millisecond)
	waitV3ReclaimerForming(t, r, 2)
	for range 3 {
		transport.release <- struct{}{}
	}
	for _, done := range []<-chan error{first, b, c, d} {
		requireV3RetireResult(t, done, nil)
	}
	sent := transport.sent()
	if len(sent) != 3 || len(sent[0]) != 1 || len(sent[1]) != 2 || len(sent[2]) != 1 {
		t.Fatalf("bounded batches = %v, want sizes 1, 2, 1", sent)
	}
	var all []string
	for _, batch := range sent {
		all = append(all, batch...)
	}
	slices.Sort(all)
	if !slices.Equal(all, []string{"a", "b", "c", "d"}) {
		t.Fatalf("tokens sent = %v, want each exactly once", all)
	}
}

func TestV3ReclaimerMultiTokenSubmissionRespectsTheBound(t *testing.T) {
	transport := newRecordingV3ReclaimSend(false)
	r := newV3Reclaimer(2, transport.send)
	if err := r.retire(v3ReclaimTokens("a", "b", "c", "d", "e")...); err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, batch := range transport.sent() {
		if len(batch) == 0 || len(batch) > 2 {
			t.Fatalf("batch %v exceeds the bound", batch)
		}
		all = append(all, batch...)
	}
	slices.Sort(all)
	if !slices.Equal(all, []string{"a", "b", "c", "d", "e"}) {
		t.Fatalf("tokens sent = %v, want each exactly once", all)
	}
}

func TestV3ReclaimerFailureIsTerminal(t *testing.T) {
	failure := errors.New("authority rejected the batch")
	transport := newRecordingV3ReclaimSend(true)
	transport.fail = failure
	r := newV3Reclaimer(authorityrpc.MaxReclaimBatch, transport.send)
	first := retireV3Async(r, "a")
	<-transport.entered
	queued := retireV3Async(r, "b")
	waitV3ReclaimerForming(t, r, 1)
	transport.release <- struct{}{}
	requireV3RetireResult(t, first, failure)
	// The batch formed behind the failed one is never sent: no failed batch can
	// be recovered item by item.
	requireV3RetireResult(t, queued, failure)
	if err := r.retire([]byte("c")); !errors.Is(err, failure) {
		t.Fatalf("retire after failure = %v, want the sticky failure", err)
	}
	if sent := transport.sent(); len(sent) != 1 {
		t.Fatalf("batches after failure = %v, want only the failed one", sent)
	}
}

func TestV3ReclaimerDrainSettlesSubmittedBatchesAndReleasesLaterTokens(t *testing.T) {
	transport := newRecordingV3ReclaimSend(true)
	r := newV3Reclaimer(authorityrpc.MaxReclaimBatch, transport.send)
	first := retireV3Async(r, "a")
	<-transport.entered
	queued := retireV3Async(r, "b")
	waitV3ReclaimerForming(t, r, 1)
	drained := make(chan struct{})
	go func() {
		r.drain()
		close(drained)
	}()
	select {
	case <-drained:
		t.Fatal("drain returned while a submitted batch was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	transport.release <- struct{}{}
	<-transport.entered
	transport.release <- struct{}{}
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not return after submitted batches settled")
	}
	requireV3RetireResult(t, first, nil)
	requireV3RetireResult(t, queued, nil)
	// The detach that follows the drain releases every capability, so a later
	// retirement is complete without a round trip.
	if err := r.retire([]byte("c")); err != nil {
		t.Fatalf("retire after drain = %v", err)
	}
	if sent := transport.sent(); len(sent) != 2 {
		t.Fatalf("batches = %v, want the two submitted before drain", sent)
	}
}

func TestV3ReclaimBatchBoundFollowsTheNegotiatedFrame(t *testing.T) {
	for _, test := range []struct {
		maxWrite uint32
		want     int
	}{
		{maxWrite: 1 << 20, want: authorityrpc.MaxReclaimBatch},
		{maxWrite: 4096, want: 4096 / v3ReclaimTokenWireBytes},
		{maxWrite: v3ReclaimTokenWireBytes, want: 1},
		{maxWrite: 1, want: 1},
	} {
		client := newFakeV3DataClient()
		client.maxWrite = test.maxWrite
		d := testV3DataPlane(t, client)
		if d.reclaimer.maxBatch != test.want {
			t.Fatalf("maxWrite %d: batch bound = %d, want %d", test.maxWrite, d.reclaimer.maxBatch, test.want)
		}
	}
}
