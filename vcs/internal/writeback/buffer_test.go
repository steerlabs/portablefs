package writeback

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type flusherFunc func(context.Context, Identity, Entry) (uint64, error)

func (f flusherFunc) Flush(ctx context.Context, id Identity, entry Entry) (uint64, error) {
	return f(ctx, id, entry)
}

type flushCall struct {
	id    Identity
	entry Entry
}

type recordingFlusher struct {
	mu    sync.Mutex
	next  uint64
	calls []flushCall
}

func (f *recordingFlusher) Flush(_ context.Context, id Identity, entry Entry) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copyEntry := entry
	copyEntry.Data = bytes.Clone(entry.Data)
	f.calls = append(f.calls, flushCall{id: id, entry: copyEntry})
	f.next += 10
	return f.next, nil
}

func (f *recordingFlusher) snapshot() []flushCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func testIdentity(v byte) Identity {
	var id Identity
	id[0] = v
	return id
}

func newTestBuffer(t *testing.T, flusher Flusher, options ...Options) *Buffer {
	t.Helper()
	opts := Options{MaxBytes: 8 << 20, MaxEntries: 256, FlushInterval: -1}
	if len(options) != 0 {
		opts = options[0]
	}
	b, err := New(flusher, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(b.Stop)
	return b
}

func TestBufferValidationAndStop(t *testing.T) {
	noop := flusherFunc(func(context.Context, Identity, Entry) (uint64, error) { return 1, nil })
	for _, tt := range []struct {
		name string
		opts Options
		nil  bool
	}{
		{name: "nil flusher", nil: true},
		{name: "negative bytes", opts: Options{MaxBytes: -1}},
		{name: "negative entries", opts: Options{MaxEntries: -1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flusher := Flusher(noop)
			if tt.nil {
				flusher = nil
			}
			if _, err := New(flusher, tt.opts); !errors.Is(err, ErrInvalid) {
				t.Fatalf("New error = %v, want ErrInvalid", err)
			}
		})
	}

	b := newTestBuffer(t, noop)
	id := testIdentity(1)
	invalid := []struct {
		name string
		do   func() error
	}{
		{name: "negative write offset", do: func() error { _, err := b.Write(context.Background(), id, -1, []byte("x")); return err }},
		{name: "empty write", do: func() error { _, err := b.Write(context.Background(), id, 0, nil); return err }},
		{name: "write overflow", do: func() error {
			_, err := b.Write(context.Background(), id, int64(^uint64(0)>>1), []byte("xx"))
			return err
		}},
		{name: "write exceeds cap", do: func() error { _, err := b.Write(context.Background(), id, 0, make([]byte, (8<<20)+1)); return err }},
		{name: "negative truncate", do: func() error { _, err := b.Truncate(context.Background(), id, -1); return err }},
		{name: "negative setattr size", do: func() error {
			_, err := b.SetAttr(context.Background(), id, Attributes{HasSize: true, Size: -1})
			return err
		}},
		{name: "atime value and now", do: func() error {
			_, err := b.SetAttr(context.Background(), id, Attributes{HasATime: true, ATimeNow: true})
			return err
		}},
		{name: "mtime value and now", do: func() error {
			_, err := b.SetAttr(context.Background(), id, Attributes{HasMTime: true, MTimeNow: true})
			return err
		}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.do(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}

	b.Stop()
	if _, err := b.Write(context.Background(), id, 0, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Stop = %v, want ErrClosed", err)
	}
}

func TestSetAttrResolvesNowOnceAtAdmission(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(2)
	before := time.Now().UnixNano()
	cut, err := b.SetAttr(context.Background(), id, Attributes{ATimeNow: true, MTimeNow: true})
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UnixNano()
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	calls := recorder.snapshot()
	if len(calls) != 1 {
		t.Fatalf("flush calls = %d, want 1", len(calls))
	}
	a := calls[0].entry.Attributes
	if !a.HasATime || !a.HasMTime || a.ATimeNow || a.MTimeNow {
		t.Fatalf("resolved attributes = %+v", a)
	}
	if a.ATimeNS != a.MTimeNS || a.ATimeNS < before || a.ATimeNS > after {
		t.Fatalf("resolved timestamps = (%d, %d), admission range [%d, %d]", a.ATimeNS, a.MTimeNS, before, after)
	}
}

func TestInitialLossSequenceIsPreservedAndAdvanced(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{}, Options{InitialLossSequence: 41, MaxBytes: 1024, MaxEntries: 8, FlushInterval: -1})
	if got := b.Snapshot(); got.LossSequence != 41 || got.Sequence != 0 {
		t.Fatalf("initial cut = %+v, want sequence 0 and loss 41", got)
	}
	if got := b.Stats().LossSequence; got != 41 {
		t.Fatalf("initial Stats loss = %d, want 41", got)
	}
	report := b.Drop(testIdentity(40), "epoch replacement")
	if report.LossSequence != 42 || b.LossSequence() != 42 {
		t.Fatalf("loss after Drop = report %d buffer %d, want 42", report.LossSequence, b.LossSequence())
	}
}

func TestWriteCopiesCallerDataAtAdmission(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(39)
	data := []byte("original")
	cut, err := b.Write(context.Background(), id, 0, data)
	if err != nil {
		t.Fatal(err)
	}
	copy(data, "mutated!")
	assertRead(t, b, id, 0, len(data), make([]byte, len(data)), []byte("original"))
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	if calls := recorder.snapshot(); len(calls) != 1 || string(calls[0].entry.Data) != "original" {
		t.Fatalf("transport data = %+v, want original", calls)
	}
}

func TestBufferStateTransitionsAndPartialOverlayRetirement(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(3)
	ctx := context.Background()

	first, err := b.Write(ctx, id, 0, []byte("ABCDEFGH"))
	if err != nil {
		t.Fatal(err)
	}
	assertStats(t, b, Stats{Bytes: 8, Entries: 1, Accepted: 1})
	if seq, err := b.FlushIdentity(ctx, id, first); err != nil || seq != 10 {
		t.Fatalf("first flush = (%d, %v), want (10, nil)", seq, err)
	}
	assertStats(t, b, Stats{Bytes: 8, Entries: 1, Applied: 1})

	second, err := b.Write(ctx, id, 2, []byte("xy"))
	if err != nil {
		t.Fatal(err)
	}
	if seq, err := b.FlushIdentity(ctx, id, second); err != nil || seq != 20 {
		t.Fatalf("second flush = (%d, %v), want (20, nil)", seq, err)
	}
	assertRead(t, b, id, 0, 8, []byte("........"), []byte("ABxyEFGH"))

	b.VisibleSequence(9)
	assertStats(t, b, Stats{Bytes: 10, Entries: 2, Applied: 2})
	b.VisibleSequence(10)
	assertStats(t, b, Stats{Bytes: 10, Entries: 2, Applied: 1, Visible: 1})
	b.DurableSequence(10)
	assertStats(t, b, Stats{Bytes: 2, Entries: 1, Applied: 1})
	// The old extent is now in the Authority image. The newer dirty extent must
	// remain indexed after the old record and its owned AVL nodes retire.
	assertRead(t, b, id, 0, 8, []byte("ABCDEFGH"), []byte("ABxyEFGH"))

	b.VisibleSequence(20)
	assertStats(t, b, Stats{Bytes: 2, Entries: 1, Visible: 1})
	b.DurableSequence(20)
	assertStats(t, b, Stats{})
	assertRead(t, b, id, 0, 8, []byte("ABxyEFGH"), []byte("ABxyEFGH"))
}

func TestDurableNotificationMayRaceAheadOfFlushReply(t *testing.T) {
	var b *Buffer
	flusher := flusherFunc(func(_ context.Context, _ Identity, _ Entry) (uint64, error) {
		b.DurableSequence(42)
		return 42, nil
	})
	b = newTestBuffer(t, flusher)
	id := testIdentity(4)
	cut, err := b.Write(context.Background(), id, 0, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	assertStats(t, b, Stats{})
}

func TestPartialDurabilityRetiresOldWriteAndTruncateButKeepsLaterWrite(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(41)
	ctx := context.Background()

	first := mustWrite(t, b, id, 0, "ABCDEFGH")
	if _, err := b.FlushIdentity(ctx, id, first); err != nil {
		t.Fatal(err)
	}
	truncate, err := b.Truncate(ctx, id, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.FlushIdentity(ctx, id, truncate); err != nil {
		t.Fatal(err)
	}
	later := mustWrite(t, b, id, 5, "Z")
	if _, err := b.FlushIdentity(ctx, id, later); err != nil {
		t.Fatal(err)
	}
	want := []byte{'A', 'B', 'C', 0, 0, 'Z'}
	assertRead(t, b, id, 0, 20, []byte("abcdefgh"), want)

	b.DurableSequence(10)
	assertStats(t, b, Stats{Bytes: 1, Entries: 2, Applied: 2})
	assertRead(t, b, id, 0, 20, []byte("ABCDEFGH"), want)
	b.DurableSequence(20)
	assertStats(t, b, Stats{Bytes: 1, Entries: 1, Applied: 1})
	assertRead(t, b, id, 0, 20, []byte("ABC"), want)
	if got := b.Size(id, 3); got != 6 {
		t.Fatalf("size after truncate retirement with later write = %d, want 6", got)
	}
	b.DurableSequence(30)
	assertStats(t, b, Stats{})
}

func TestCumulativeNotificationsNeverRegress(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(42)
	first := mustWrite(t, b, id, 0, "a")
	if _, err := b.FlushIdentity(context.Background(), id, first); err != nil {
		t.Fatal(err)
	}
	second := mustWrite(t, b, id, 2, "b")
	if _, err := b.FlushIdentity(context.Background(), id, second); err != nil {
		t.Fatal(err)
	}
	b.VisibleSequence(20)
	b.VisibleSequence(5)
	assertStats(t, b, Stats{Bytes: 2, Entries: 2, Visible: 2})
	b.DurableSequence(10)
	b.DurableSequence(3)
	assertStats(t, b, Stats{Bytes: 1, Entries: 1, Visible: 1})
	b.DurableSequence(20)
	assertStats(t, b, Stats{})
}

func TestFlushCoalescingAndOrderingBarriers(t *testing.T) {
	tests := []struct {
		name string
		ops  func(*testing.T, *Buffer, Identity) Cut
		want []Entry
	}{
		{
			name: "forward adjacent",
			ops: func(t *testing.T, b *Buffer, id Identity) Cut {
				mustWrite(t, b, id, 0, "abc")
				return mustWrite(t, b, id, 3, "def")
			},
			want: []Entry{{First: 1, Last: 2, Generation: 1, Kind: Write, Offset: 0, Data: []byte("abcdef")}},
		},
		{
			name: "reverse adjacent",
			ops: func(t *testing.T, b *Buffer, id Identity) Cut {
				mustWrite(t, b, id, 3, "def")
				return mustWrite(t, b, id, 0, "abc")
			},
			want: []Entry{{First: 1, Last: 2, Generation: 1, Kind: Write, Offset: 0, Data: []byte("abcdef")}},
		},
		{
			name: "last overlapping write wins",
			ops: func(t *testing.T, b *Buffer, id Identity) Cut {
				mustWrite(t, b, id, 0, "abcdef")
				return mustWrite(t, b, id, 2, "XYZ")
			},
			want: []Entry{{First: 1, Last: 2, Generation: 1, Kind: Write, Offset: 0, Data: []byte("abXYZf")}},
		},
		{
			name: "gap stops coalescing",
			ops: func(t *testing.T, b *Buffer, id Identity) Cut {
				mustWrite(t, b, id, 0, "a")
				return mustWrite(t, b, id, 2, "c")
			},
			want: []Entry{
				{First: 1, Last: 1, Generation: 1, Kind: Write, Offset: 0, Data: []byte("a")},
				{First: 2, Last: 2, Generation: 1, Kind: Write, Offset: 2, Data: []byte("c")},
			},
		},
		{
			name: "metadata is an ordering barrier",
			ops: func(t *testing.T, b *Buffer, id Identity) Cut {
				mustWrite(t, b, id, 0, "a")
				if _, err := b.SetAttr(context.Background(), id, Attributes{HasMode: true, Mode: 0o640}); err != nil {
					t.Fatal(err)
				}
				return mustWrite(t, b, id, 1, "b")
			},
			want: []Entry{
				{First: 1, Last: 1, Generation: 1, Kind: Write, Offset: 0, Data: []byte("a")},
				{First: 2, Last: 2, Generation: 1, Kind: SetAttr, Attributes: Attributes{HasMode: true, Mode: 0o640}},
				{First: 3, Last: 3, Generation: 1, Kind: Write, Offset: 1, Data: []byte("b")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := &recordingFlusher{}
			b := newTestBuffer(t, recorder)
			id := testIdentity(5)
			cut := tt.ops(t, b, id)
			if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
				t.Fatal(err)
			}
			calls := recorder.snapshot()
			if len(calls) != len(tt.want) {
				t.Fatalf("flush calls = %d, want %d: %+v", len(calls), len(tt.want), calls)
			}
			for i := range tt.want {
				got := calls[i].entry
				want := tt.want[i]
				want.Token = got.Token
				if !entriesEqual(got, want) {
					t.Fatalf("call %d = %+v data %q, want %+v data %q", i, got, got.Data, want, want.Data)
				}
			}
		})
	}
}

func TestFlushHonorsCut(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(6)
	cut := mustWrite(t, b, id, 0, "a")
	later := mustWrite(t, b, id, 1, "b")
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	calls := recorder.snapshot()
	if len(calls) != 1 || calls[0].entry.First != 1 || calls[0].entry.Last != 1 || string(calls[0].entry.Data) != "a" {
		t.Fatalf("first cut flushed %+v", calls)
	}
	if _, err := b.FlushIdentity(context.Background(), id, later); err != nil {
		t.Fatal(err)
	}
	calls = recorder.snapshot()
	if len(calls) != 2 || calls[1].entry.First != 2 || string(calls[1].entry.Data) != "b" {
		t.Fatalf("later cut flushed %+v", calls)
	}
}

func TestPendingRetryIsNotPulledIntoOlderCut(t *testing.T) {
	id := testIdentity(61)
	var mu sync.Mutex
	var calls []Entry
	failSecond := true
	flusher := flusherFunc(func(_ context.Context, _ Identity, entry Entry) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		copyEntry := entry
		copyEntry.Data = bytes.Clone(entry.Data)
		calls = append(calls, copyEntry)
		if entry.First == 2 && failSecond {
			failSecond = false
			return 0, errors.New("retry later")
		}
		return entry.First * 10, nil
	})
	b := newTestBuffer(t, flusher)
	oldCut := mustWrite(t, b, id, 0, "a")
	if _, err := b.FlushIdentity(context.Background(), id, oldCut); err != nil {
		t.Fatal(err)
	}
	newCut := mustWrite(t, b, id, 2, "c")
	if _, err := b.FlushIdentity(context.Background(), id, newCut); err == nil {
		t.Fatal("newer flush unexpectedly succeeded")
	}
	if _, err := b.FlushIdentity(context.Background(), id, oldCut); err != nil {
		t.Fatalf("older cut retried a newer pending batch: %v", err)
	}
	mu.Lock()
	if len(calls) != 2 {
		t.Fatalf("older cut made %d total transport calls, want 2", len(calls))
	}
	mu.Unlock()
	if _, err := b.FlushIdentity(context.Background(), id, newCut); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 || calls[1].Token != calls[2].Token {
		t.Fatalf("newer pending retry calls = %+v", calls)
	}
}

func TestFlushCoalescingRandomizedAgainstNaiveBytes(t *testing.T) {
	for seed := int64(0); seed < 32; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			recorder := &recordingFlusher{}
			b := newTestBuffer(t, recorder, Options{MaxBytes: 1 << 20, MaxEntries: 128, FlushInterval: -1})
			id := testIdentity(byte(seed + 62))
			want := make([]byte, 256)
			var cut Cut
			for i := 0; i < 100; i++ {
				off := rng.Intn(240)
				data := make([]byte, 1+rng.Intn(16))
				rng.Read(data)
				var err error
				cut, err = b.Write(context.Background(), id, int64(off), data)
				if err != nil {
					t.Fatal(err)
				}
				copy(want[off:], data)
			}
			if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			var previousLast uint64
			for _, call := range recorder.snapshot() {
				e := call.entry
				if e.First <= previousLast || e.Last < e.First {
					t.Fatalf("transport order [%d,%d] after %d", e.First, e.Last, previousLast)
				}
				previousLast = e.Last
				copy(got[e.Offset:], e.Data)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("coalesced transport image differs from admission-order image")
			}
		})
	}
}

func TestFlushChunksAndRetriesWithStableToken(t *testing.T) {
	id := testIdentity(7)
	payload := make([]byte, 2*MaxPayload+17)
	for i := range payload {
		payload[i] = byte(i)
	}
	var mu sync.Mutex
	var calls []Entry
	failed := false
	flusher := flusherFunc(func(_ context.Context, _ Identity, entry Entry) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		copyEntry := entry
		copyEntry.Data = bytes.Clone(entry.Data)
		calls = append(calls, copyEntry)
		if entry.Offset == MaxPayload && !failed {
			failed = true
			return 0, errors.New("ambiguous transport failure")
		}
		return uint64(10 + entry.Offset/MaxPayload), nil
	})
	b := newTestBuffer(t, flusher, Options{MaxBytes: int64(len(payload)) + 1, MaxEntries: 8, FlushInterval: -1})
	cut, err := b.Write(context.Background(), id, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.FlushIdentity(context.Background(), id, cut); err == nil || !bytes.Contains([]byte(err.Error()), []byte("ambiguous transport failure")) {
		t.Fatalf("first FlushIdentity error = %v", err)
	}
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatalf("retry FlushIdentity: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 4 {
		t.Fatalf("calls = %d, want first chunk, failed second, retried second, third", len(calls))
	}
	if calls[1].Token != calls[2].Token || calls[1].Offset != calls[2].Offset || !bytes.Equal(calls[1].Data, calls[2].Data) {
		t.Fatalf("retry changed operation: first %+v, retry %+v", calls[1], calls[2])
	}
	if calls[0].Token == calls[1].Token || calls[2].Token == calls[3].Token {
		t.Fatalf("distinct chunks reused tokens: %d %d %d", calls[0].Token, calls[2].Token, calls[3].Token)
	}
	joined := append(bytes.Clone(calls[0].Data), calls[2].Data...)
	joined = append(joined, calls[3].Data...)
	if !bytes.Equal(joined, payload) {
		t.Fatal("chunked payload did not reconstruct the admitted write")
	}
}

func TestFlushRejectsInvalidAuthoritySequencesAndRetries(t *testing.T) {
	for _, returned := range []uint64{0, 9} {
		t.Run(fmt.Sprintf("sequence_%d", returned), func(t *testing.T) {
			var mu sync.Mutex
			var calls []Entry
			responses := []uint64{10, returned, 11}
			flusher := flusherFunc(func(_ context.Context, _ Identity, entry Entry) (uint64, error) {
				mu.Lock()
				defer mu.Unlock()
				copyEntry := entry
				copyEntry.Data = bytes.Clone(entry.Data)
				calls = append(calls, copyEntry)
				response := responses[0]
				responses = responses[1:]
				return response, nil
			})
			b := newTestBuffer(t, flusher)
			id := testIdentity(72)
			first := mustWrite(t, b, id, 0, "a")
			if _, err := b.FlushIdentity(context.Background(), id, first); err != nil {
				t.Fatal(err)
			}
			second := mustWrite(t, b, id, 2, "b")
			if _, err := b.FlushIdentity(context.Background(), id, second); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid applied sequence error = %v, want ErrInvalid", err)
			}
			if _, err := b.FlushIdentity(context.Background(), id, second); err != nil {
				t.Fatalf("retry after invalid response: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(calls) != 3 || calls[1].Token != calls[2].Token || !entriesEqual(calls[1], calls[2]) {
				t.Fatalf("invalid-response retry calls = %+v", calls)
			}
		})
	}
}

func TestAdmissionBlocksAtCapsUntilDurableRetirement(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts Options
		fill func(*testing.T, *Buffer, Identity)
	}{
		{
			name: "entry cap",
			opts: Options{MaxBytes: 1024, MaxEntries: 2, FlushInterval: -1},
			fill: func(t *testing.T, b *Buffer, id Identity) {
				mustWrite(t, b, id, 0, "a")
				mustWrite(t, b, id, 1, "b")
			},
		},
		{
			name: "byte cap",
			opts: Options{MaxBytes: 2, MaxEntries: 10, FlushInterval: -1},
			fill: func(t *testing.T, b *Buffer, id Identity) { mustWrite(t, b, id, 0, "ab") },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			flusher := flusherFunc(func(ctx context.Context, _ Identity, _ Entry) (uint64, error) {
				started <- struct{}{}
				select {
				case <-release:
					return 10, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			})
			b := newTestBuffer(t, flusher, tt.opts)
			id := testIdentity(8)
			tt.fill(t, b, id)
			await(t, started, "cap-triggered flush")

			result := make(chan error, 1)
			go func() {
				_, err := b.Write(context.Background(), id, 10, []byte("z"))
				result <- err
			}()
			assertBlocked(t, result, "admission at cap")
			close(release)
			// Application alone does not release retained dirty capacity.
			assertBlocked(t, result, "admission before durability")
			b.DurableSequence(10)
			if err := await(t, result, "admission after durability"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdmissionCancellationAtCap(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	flusher := flusherFunc(func(ctx context.Context, _ Identity, _ Entry) (uint64, error) {
		started <- struct{}{}
		select {
		case <-release:
			return 1, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher, Options{MaxBytes: 1, MaxEntries: 4, FlushInterval: -1})
	id := testIdentity(9)
	mustWrite(t, b, id, 0, "a")
	await(t, started, "cap-triggered flush")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := b.Write(ctx, id, 1, []byte("b")); result <- err }()
	assertBlocked(t, result, "admission before cancellation")
	cancel()
	if err := await(t, result, "canceled admission"); !errors.Is(err, context.Canceled) {
		t.Fatalf("admission error = %v, want context.Canceled", err)
	}
	close(release)
}

func TestFullByteCapBlocksMetadataAdmissions(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	flusher := flusherFunc(func(ctx context.Context, _ Identity, _ Entry) (uint64, error) {
		started <- struct{}{}
		select {
		case <-release:
			return 12, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher, Options{MaxBytes: 1, MaxEntries: 8, FlushInterval: -1})
	id := testIdentity(70)
	mustWrite(t, b, id, 0, "x")
	await(t, started, "cap-triggered data flush")
	truncated := make(chan error, 1)
	attributed := make(chan error, 1)
	go func() { _, err := b.Truncate(context.Background(), id, 0); truncated <- err }()
	go func() {
		_, err := b.SetAttr(context.Background(), id, Attributes{HasMode: true, Mode: 0o600})
		attributed <- err
	}()
	assertBlocked(t, truncated, "truncate at full byte cap")
	assertBlocked(t, attributed, "setattr at full byte cap")
	close(release)
	assertBlocked(t, truncated, "truncate before durable retirement")
	assertBlocked(t, attributed, "setattr before durable retirement")
	b.DurableSequence(12)
	if err := await(t, truncated, "truncate after capacity release"); err != nil {
		t.Fatal(err)
	}
	if err := await(t, attributed, "setattr after capacity release"); err != nil {
		t.Fatal(err)
	}
}

func TestCapKickSkippedByExplicitFlushIsRetried(t *testing.T) {
	entered := make(chan Entry, 2)
	release := make(chan struct{}, 2)
	var seq atomic.Uint64
	flusher := flusherFunc(func(ctx context.Context, _ Identity, entry Entry) (uint64, error) {
		entered <- entry
		select {
		case <-release:
			return seq.Add(1), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher, Options{MaxBytes: 1024, MaxEntries: 2, FlushInterval: -1})
	id := testIdentity(71)
	firstCut := mustWrite(t, b, id, 0, "a")
	firstDone := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(context.Background(), id, firstCut); firstDone <- err }()
	await(t, entered, "explicit first flush")
	mustWrite(t, b, id, 2, "c") // Reaching the cap kicks the scheduler.
	deadline := time.Now().Add(3 * time.Second)
	for len(b.kick) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(b.kick) != 0 {
		t.Fatal("scheduler did not consume the cap kick")
	}
	release <- struct{}{}
	if err := await(t, firstDone, "explicit first flush"); err != nil {
		t.Fatal(err)
	}
	second := await(t, entered, "scheduler retry after skipped cap kick")
	if second.First != 2 {
		t.Fatalf("scheduler flushed sequence %d, want 2", second.First)
	}
	release <- struct{}{}
}

func TestRetirementFencesGenerationAndAdmissions(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(10)
	other := testIdentity(11)
	oldCut := mustWrite(t, b, id, 0, "old")
	retirement, err := b.BeginRetire(context.Background(), &id)
	if err != nil {
		t.Fatal(err)
	}
	if retirement.Cut() != oldCut {
		t.Fatalf("retirement cut = %+v, want %+v", retirement.Cut(), oldCut)
	}
	if err := retirement.Resume(); !errors.Is(err, ErrPending) {
		t.Fatalf("Resume before application = %v, want ErrPending", err)
	}

	blocked := make(chan error, 1)
	go func() { _, err := b.Write(context.Background(), id, 3, []byte("new")); blocked <- err }()
	assertBlocked(t, blocked, "same-identity admission during retirement")
	if _, err := b.Write(context.Background(), other, 0, []byte("independent")); err != nil {
		t.Fatalf("independent admission during identity retirement: %v", err)
	}
	if _, err := b.FlushIdentity(context.Background(), id, retirement.Cut()); err != nil {
		t.Fatal(err)
	}
	if err := retirement.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := retirement.Resume(); err != nil {
		t.Fatalf("second Resume: %v", err)
	}
	if err := await(t, blocked, "admission in successor generation"); err != nil {
		t.Fatal(err)
	}
	if got := b.Generation(id); got != 2 {
		t.Fatalf("Generation = %d, want 2", got)
	}
	if _, err := b.FlushIdentity(context.Background(), id, b.Snapshot()); err != nil {
		t.Fatal(err)
	}
	calls := recorder.snapshot()
	var generations []uint64
	for _, call := range calls {
		if call.id == id {
			generations = append(generations, call.entry.Generation)
		}
	}
	if !slices.Equal(generations, []uint64{1, 2}) {
		t.Fatalf("flushed generations = %v, want [1 2]", generations)
	}
}

func TestMountRetirementBlocksNewIdentitiesAndCompetingRetirements(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(12)
	mustWrite(t, b, id, 0, "x")
	r, err := b.BeginRetire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	newID := testIdentity(13)
	blockedWrite := make(chan error, 1)
	go func() { _, err := b.Write(context.Background(), newID, 0, []byte("new")); blockedWrite <- err }()
	assertBlocked(t, blockedWrite, "new identity during mount retirement")

	ctx, cancel := context.WithCancel(context.Background())
	blockedRetire := make(chan error, 1)
	go func() { _, err := b.BeginRetire(ctx, &id); blockedRetire <- err }()
	assertBlocked(t, blockedRetire, "competing retirement")
	cancel()
	if err := await(t, blockedRetire, "canceled retirement"); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginRetire error = %v, want context.Canceled", err)
	}

	if _, err := b.FlushAll(context.Background(), r.Cut()); err != nil {
		t.Fatal(err)
	}
	if err := r.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, blockedWrite, "write after mount resume"); err != nil {
		t.Fatal(err)
	}
}

func TestDropDuringFlushInvalidatesBatchAndOverlay(t *testing.T) {
	started := make(chan Entry, 1)
	release := make(chan struct{})
	flusher := flusherFunc(func(ctx context.Context, _ Identity, entry Entry) (uint64, error) {
		started <- entry
		select {
		case <-release:
			return 50, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher)
	id := testIdentity(14)
	cut := mustWrite(t, b, id, 1, "dirty")
	result := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(context.Background(), id, cut); result <- err }()
	await(t, started, "in-flight flush")
	report := b.Drop(id, "stale generation")
	if report.Identity != id || report.Reason != "stale generation" || report.Bytes != 5 || report.Entries != 1 || report.LossSequence != 1 {
		t.Fatalf("Drop report = %+v", report)
	}
	close(release)
	if err := await(t, result, "dropped flush"); !errors.Is(err, ErrLost) {
		t.Fatalf("FlushIdentity error = %v, want ErrLost", err)
	}
	assertStats(t, b, Stats{LossSequence: 1})
	assertRead(t, b, id, 0, 7, []byte("clean!!"), []byte("clean!!"))
	if !b.Lost(id) || b.IdentityLoss(id) != 1 {
		t.Fatalf("loss state = (%v, %d), want (true, 1)", b.Lost(id), b.IdentityLoss(id))
	}
	if !b.ClearLost(id) || b.ClearLost(id) {
		t.Fatal("ClearLost must report the sticky identity error exactly once")
	}
	if b.IdentityLoss(id) != 1 {
		t.Fatal("ClearLost erased per-handle loss observation")
	}
	if got := b.Generation(id); got != 2 {
		t.Fatalf("generation after drop = %d, want 2", got)
	}
	// Late cumulative notifications for the dropped operation must be harmless.
	b.VisibleSequence(50)
	b.DurableSequence(50)
}

func TestFlushCancellationRetainsStableRetry(t *testing.T) {
	var mu sync.Mutex
	var calls []Entry
	flusher := flusherFunc(func(ctx context.Context, _ Identity, entry Entry) (uint64, error) {
		mu.Lock()
		copyEntry := entry
		copyEntry.Data = bytes.Clone(entry.Data)
		calls = append(calls, copyEntry)
		attempt := len(calls)
		mu.Unlock()
		if attempt == 1 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return 9, nil
	})
	b := newTestBuffer(t, flusher)
	id := testIdentity(15)
	cut := mustWrite(t, b, id, 0, "retry")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.FlushIdentity(ctx, id, cut); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled flush = %v, want context.Canceled", err)
	}
	// The pre-canceled call never entered the transport, so use a cancellation
	// that occurs while the transport owns the entry.
	entered := make(chan struct{})
	var once sync.Once
	blocking := flusherFunc(func(ctx context.Context, _ Identity, entry Entry) (uint64, error) {
		once.Do(func() { close(entered) })
		mu.Lock()
		copyEntry := entry
		copyEntry.Data = bytes.Clone(entry.Data)
		calls = append(calls, copyEntry)
		mu.Unlock()
		<-ctx.Done()
		return 0, ctx.Err()
	})
	b.mu.Lock()
	b.flusher = blocking
	b.mu.Unlock()
	ctx, cancel = context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(ctx, id, cut); result <- err }()
	await(t, entered, "transport entry")
	cancel()
	if err := await(t, result, "canceled transport"); !errors.Is(err, context.Canceled) {
		t.Fatalf("flush error = %v, want context.Canceled", err)
	}
	b.mu.Lock()
	b.flusher = flusherFunc(func(_ context.Context, _ Identity, entry Entry) (uint64, error) {
		mu.Lock()
		copyEntry := entry
		copyEntry.Data = bytes.Clone(entry.Data)
		calls = append(calls, copyEntry)
		mu.Unlock()
		return 9, nil
	})
	b.mu.Unlock()
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[0].Token != calls[1].Token || !entriesEqual(calls[0], calls[1]) {
		t.Fatalf("retry calls = %+v", calls)
	}
}

func TestFlushAllRunsDifferentIdentitiesConcurrently(t *testing.T) {
	entered := make(chan Identity, 2)
	release := make(chan struct{})
	flusher := flusherFunc(func(ctx context.Context, id Identity, _ Entry) (uint64, error) {
		entered <- id
		select {
		case <-release:
			return uint64(id[0]), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher)
	a, z := testIdentity(16), testIdentity(17)
	mustWrite(t, b, a, 0, "a")
	cut := mustWrite(t, b, z, 0, "z")
	result := make(chan error, 1)
	go func() { _, err := b.FlushAll(context.Background(), cut); result <- err }()
	got := map[Identity]bool{await(t, entered, "first identity"): true, await(t, entered, "second identity"): true}
	if !got[a] || !got[z] {
		t.Fatalf("concurrent identities = %v", got)
	}
	close(release)
	if err := await(t, result, "FlushAll"); err != nil {
		t.Fatal(err)
	}
}

func TestFlushIdentitySerializesSameIdentity(t *testing.T) {
	entered := make(chan Entry, 2)
	releases := make(chan struct{}, 2)
	var seq atomic.Uint64
	flusher := flusherFunc(func(ctx context.Context, _ Identity, entry Entry) (uint64, error) {
		entered <- entry
		select {
		case <-releases:
			return seq.Add(1), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher)
	id := testIdentity(18)
	first := mustWrite(t, b, id, 0, "a")
	one := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(context.Background(), id, first); one <- err }()
	await(t, entered, "first flush")
	second := mustWrite(t, b, id, 1, "b")
	two := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(context.Background(), id, second); two <- err }()
	assertBlocked(t, entered, "second transport call for same identity")
	releases <- struct{}{}
	if err := await(t, one, "first FlushIdentity"); err != nil {
		t.Fatal(err)
	}
	entry := await(t, entered, "second transport call")
	if entry.First != 2 {
		t.Fatalf("second entry starts at %d, want 2", entry.First)
	}
	releases <- struct{}{}
	if err := await(t, two, "second FlushIdentity"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteSyncWaitsForDurability(t *testing.T) {
	flushed := make(chan uint64, 1)
	flusher := flusherFunc(func(_ context.Context, _ Identity, entry Entry) (uint64, error) {
		flushed <- entry.Token
		return 70, nil
	})
	b := newTestBuffer(t, flusher)
	id := testIdentity(19)
	result := make(chan error, 1)
	go func() { _, err := b.WriteSync(context.Background(), id, 0, []byte("sync")); result <- err }()
	await(t, flushed, "synchronous flush")
	assertBlocked(t, result, "WriteSync before durability")
	b.VisibleSequence(70)
	assertBlocked(t, result, "WriteSync after visibility only")
	b.DurableSequence(70)
	if err := await(t, result, "WriteSync after durability"); err != nil {
		t.Fatal(err)
	}
}

func TestFsyncWaitsForItsIdentityCutOnly(t *testing.T) {
	flushed := make(chan Identity, 2)
	flusher := flusherFunc(func(_ context.Context, id Identity, _ Entry) (uint64, error) {
		flushed <- id
		if id[0] == 73 {
			return 40, nil
		}
		return 50, nil
	})
	b := newTestBuffer(t, flusher)
	target, other := testIdentity(73), testIdentity(74)
	mustWrite(t, b, target, 0, "target")
	mustWrite(t, b, other, 0, "other")
	result := make(chan error, 1)
	go func() { result <- b.Fsync(context.Background(), target) }()
	if id := await(t, flushed, "fsync flush"); id != target {
		t.Fatalf("Fsync flushed %x, want %x", id, target)
	}
	assertBlocked(t, result, "Fsync before durability")
	b.DurableSequence(40)
	if err := await(t, result, "Fsync target durability"); err != nil {
		t.Fatal(err)
	}
	stats := b.Stats()
	if stats.Entries != 1 || stats.Accepted != 1 {
		t.Fatalf("unrelated identity state = %+v, want one accepted entry", stats)
	}
}

func TestBarrierUsesCallTimeCutAndReportsObservedLoss(t *testing.T) {
	entered := make(chan Identity, 1)
	release := make(chan struct{})
	flusher := flusherFunc(func(ctx context.Context, id Identity, _ Entry) (uint64, error) {
		entered <- id
		select {
		case <-release:
			return 80, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher)
	before := testIdentity(20)
	after := testIdentity(21)
	mustWrite(t, b, before, 0, "before")
	type barrierResult struct {
		lost bool
		err  error
	}
	result := make(chan barrierResult, 1)
	go func() { lost, err := b.Barrier(context.Background(), 0); result <- barrierResult{lost, err} }()
	if id := await(t, entered, "barrier flush"); id != before {
		t.Fatalf("barrier flushed identity %x, want %x", id, before)
	}
	mustWrite(t, b, after, 0, "after")
	close(release)
	b.DurableSequence(80)
	got := await(t, result, "barrier")
	if got.lost || got.err != nil {
		t.Fatalf("Barrier = (%v, %v), want (false, nil)", got.lost, got.err)
	}
	stats := b.Stats()
	if stats.Entries != 1 || stats.Accepted != 1 {
		t.Fatalf("post-cut entry stats = %+v", stats)
	}

	b.Drop(after, "test loss")
	lost, err := b.Barrier(context.Background(), 0)
	if !lost || err != nil {
		t.Fatalf("Barrier observing prior loss = (%v, %v), want (true, nil)", lost, err)
	}
}

func TestTimerFlushesAcceptedEntries(t *testing.T) {
	called := make(chan Entry, 1)
	flusher := flusherFunc(func(_ context.Context, _ Identity, entry Entry) (uint64, error) {
		called <- entry
		return 1, nil
	})
	b := newTestBuffer(t, flusher, Options{MaxBytes: 1024, MaxEntries: 16, FlushInterval: 5 * time.Millisecond})
	mustWrite(t, b, testIdentity(22), 0, "timer")
	entry := await(t, called, "timer flush")
	if string(entry.Data) != "timer" {
		t.Fatalf("timer flushed %q", entry.Data)
	}
}

func TestReadOverlayTruncateAndAttributes(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{})
	id := testIdentity(23)
	ctx := context.Background()
	mustWrite(t, b, id, 2, "XY")
	if _, err := b.Truncate(ctx, id, 6); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, b, id, 5, "Z")
	assertRead(t, b, id, 0, 20, []byte("abcdefghij"), []byte("abXYeZ"))
	if got := b.Size(id, 100); got != 6 {
		t.Fatalf("Size = %d, want exact 6", got)
	}
	if _, err := b.SetAttr(ctx, id, Attributes{HasMode: true, Mode: 0o600, HasUID: true, UID: 7, HasMTime: true, MTimeNS: 99}); err != nil {
		t.Fatal(err)
	}
	got := b.OverlayAttributes(id, Attributes{HasMode: true, Mode: 0o644, HasGID: true, GID: 8, HasSize: true, Size: 100})
	want := Attributes{HasMode: true, Mode: 0o600, HasUID: true, UID: 7, HasGID: true, GID: 8, HasSize: true, Size: 6, HasMTime: true, MTimeNS: 99}
	if !got.HasCTime || got.CTimeNS <= 0 {
		t.Fatal("missing implicit ctime", got)
	}
	got.CTimeNS, got.HasCTime = 0, false
	if got != want {
		t.Fatalf("OverlayAttributes = %+v, want %+v", got, want)
	}

	if got, err := b.Read(ctx, id, 6, 1, bytesFetch([]byte("ignored"))); err != nil || len(got) != 0 {
		t.Fatalf("read at exact EOF = (%q, %v)", got, err)
	}
}

func TestReadSnapshotSurvivesConcurrentDurableRetirement(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(75)
	cut := mustWrite(t, b, id, 0, "dirty")
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	fetchEntered := make(chan struct{})
	fetchRelease := make(chan struct{})
	result := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := b.Read(context.Background(), id, 0, 5, func(context.Context, int64, int) ([]byte, error) {
			close(fetchEntered)
			<-fetchRelease
			return []byte("clean"), nil
		})
		result <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	await(t, fetchEntered, "blocked fetch after overlay snapshot")
	b.DurableSequence(10)
	assertStats(t, b, Stats{})
	close(fetchRelease)
	got := await(t, result, "read after concurrent retirement")
	if got.err != nil || string(got.data) != "dirty" {
		t.Fatalf("Read = (%q, %v), want dirty overlay snapshot", got.data, got.err)
	}
}

func TestReadValidationAndFetchErrors(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{})
	id := testIdentity(24)
	boom := errors.New("fetch failed")
	for _, tt := range []struct {
		name  string
		off   int64
		len   int
		fetch Fetch
		want  error
	}{
		{name: "negative offset", off: -1, len: 1, fetch: bytesFetch(nil), want: ErrInvalid},
		{name: "negative length", len: -1, fetch: bytesFetch(nil), want: ErrInvalid},
		{name: "nil fetch", len: 1, want: ErrInvalid},
		{name: "fetch error", len: 1, fetch: func(context.Context, int64, int) ([]byte, error) { return nil, boom }, want: boom},
		{name: "excess bytes", len: 1, fetch: func(context.Context, int64, int) ([]byte, error) { return []byte("xx"), nil }, want: ErrInvalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.Read(context.Background(), id, tt.off, tt.len, tt.fetch)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Read error = %v, want %v", err, tt.want)
			}
		})
	}
	got, err := b.Read(context.Background(), id, 0, 4, func(context.Context, int64, int) ([]byte, error) { return []byte("ab"), io.EOF })
	if err != nil || string(got) != "ab" {
		t.Fatalf("short EOF read = (%q, %v)", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Read(ctx, id, 0, 1, bytesFetch(nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Read = %v", err)
	}
}

func TestForgetOnlyReleasesIdleCleanIdentity(t *testing.T) {
	recorder := &recordingFlusher{}
	b := newTestBuffer(t, recorder)
	id := testIdentity(25)
	if !b.Forget(id) {
		t.Fatal("Forget absent identity = false")
	}
	if got := b.Generation(id); got != 1 {
		t.Fatalf("initial generation = %d", got)
	}
	cut := mustWrite(t, b, id, 0, "x")
	if b.Forget(id) {
		t.Fatal("Forget accepted identity = true")
	}
	if _, err := b.FlushIdentity(context.Background(), id, cut); err != nil {
		t.Fatal(err)
	}
	b.DurableSequence(10)
	if !b.Forget(id) {
		t.Fatal("Forget clean identity = false")
	}
	if got := b.Generation(id); got != 1 {
		t.Fatalf("forgotten identity generation = %d, want fresh 1", got)
	}
	b.Drop(id, "lost")
	if b.Forget(id) {
		t.Fatal("Forget lost identity = true")
	}
	b.ClearLost(id)
	if !b.Forget(id) {
		t.Fatal("Forget after loss observed = false")
	}
}

func FuzzBufferOverlayAgainstNaiveFile(f *testing.F) {
	f.Add([]byte{0, 2, 3, 'x', 0, 8, 2, 'q', 1, 5, 0, 0, 4, 2, 'z'})
	f.Add([]byte{1, 0, 0, 0, 0, 3, 4, 'a', 2, 9, 0, 0})
	f.Fuzz(func(t *testing.T, operations []byte) {
		const maxOps = 64
		base := []byte("0123456789abcdefghijklmnopqrstuv")
		model := bytes.Clone(base)
		recorder := &recordingFlusher{}
		b, err := New(recorder, Options{MaxBytes: 4096, MaxEntries: maxOps + 1, FlushInterval: -1})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Stop()
		id := testIdentity(26)
		for op, i := 0, 0; op < maxOps && i+3 < len(operations); op, i = op+1, i+4 {
			switch operations[i] % 3 {
			case 0:
				off := int(operations[i+1] % 48)
				length := 1 + int(operations[i+2]%8)
				data := make([]byte, length)
				for j := range data {
					data[j] = operations[i+3] + byte(j)
				}
				if _, err := b.Write(context.Background(), id, int64(off), data); err != nil {
					t.Fatal(err)
				}
				if end := off + length; end > len(model) {
					model = append(model, make([]byte, end-len(model))...)
				}
				copy(model[off:], data)
			case 1:
				size := int(operations[i+1] % 56)
				if operations[i+2]&1 == 0 {
					if _, err := b.Truncate(context.Background(), id, int64(size)); err != nil {
						t.Fatal(err)
					}
				} else if _, err := b.SetAttr(context.Background(), id, Attributes{HasSize: true, Size: int64(size)}); err != nil {
					t.Fatal(err)
				}
				if size < len(model) {
					model = model[:size]
				} else {
					model = append(model, make([]byte, size-len(model))...)
				}
			case 2:
				off := int(operations[i+1] % 56)
				length := int(operations[i+2] % 16)
				got, err := b.Read(context.Background(), id, int64(off), length, bytesFetch(base))
				if err != nil {
					t.Fatal(err)
				}
				want := modelSlice(model, off, length)
				if !bytes.Equal(got, want) {
					t.Fatalf("operation %d Read(%d, %d) = %v, want %v; operations %v", op, off, length, got, want, operations)
				}
			}
		}
		if got := b.Size(id, int64(len(base))); got != int64(len(model)) {
			t.Fatalf("Size = %d, want %d", got, len(model))
		}
		got, err := b.Read(context.Background(), id, 0, 64, bytesFetch(base))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, model) {
			t.Fatalf("whole file = %v, want %v; operations %v", got, model, operations)
		}
		if _, err := b.FlushAll(context.Background(), b.Snapshot()); err != nil {
			t.Fatal(err)
		}
		authority := bytes.Clone(base)
		for _, call := range recorder.snapshot() {
			e := call.entry
			switch e.Kind {
			case Write:
				end := int(e.Offset) + len(e.Data)
				if end > len(authority) {
					authority = append(authority, make([]byte, end-len(authority))...)
				}
				copy(authority[e.Offset:], e.Data)
			case Truncate, SetAttr:
				if !e.Attributes.HasSize {
					continue
				}
				size := int(e.Attributes.Size)
				if size < len(authority) {
					authority = authority[:size]
				} else {
					authority = append(authority, make([]byte, size-len(authority))...)
				}
			default:
				t.Fatalf("unknown transport kind %d", e.Kind)
			}
		}
		if !bytes.Equal(authority, model) {
			t.Fatalf("coalesced transport image = %v, want %v; operations %v; calls %+v", authority, model, operations, recorder.snapshot())
		}
	})
}

func mustWrite(t *testing.T, b *Buffer, id Identity, off int64, data string) Cut {
	t.Helper()
	cut, err := b.Write(context.Background(), id, off, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return cut
}

func assertStats(t *testing.T, b *Buffer, want Stats) {
	t.Helper()
	if got := b.Stats(); got != want {
		t.Fatalf("Stats = %+v, want %+v", got, want)
	}
}

func assertRead(t *testing.T, b *Buffer, id Identity, off int64, length int, base, want []byte) {
	t.Helper()
	got, err := b.Read(context.Background(), id, off, length, bytesFetch(base))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Read(%d, %d) = %q, want %q", off, length, got, want)
	}
}

func bytesFetch(data []byte) Fetch {
	return func(_ context.Context, off int64, length int) ([]byte, error) {
		if off >= int64(len(data)) {
			return nil, io.EOF
		}
		end := min(len(data), int(off)+length)
		return data[off:end], nil
	}
}

func entriesEqual(a, b Entry) bool {
	return a.Token == b.Token && a.First == b.First && a.Last == b.Last && a.Generation == b.Generation &&
		a.Kind == b.Kind && a.Offset == b.Offset && a.Attributes == b.Attributes && bytes.Equal(a.Data, b.Data)
}

func modelSlice(model []byte, off, length int) []byte {
	if off >= len(model) {
		return []byte{}
	}
	return bytes.Clone(model[off:min(len(model), off+length)])
}

func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func assertBlocked[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case value := <-ch:
		t.Fatalf("%s completed early with %v", what, value)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestImplicitTimestampOverlayPreservesOrderUntilDurability(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{})
	id := testIdentity(81)
	base := Attributes{HasMTime: true, MTimeNS: 1, HasCTime: true, CTimeNS: 2}
	var cut Cut
	var err error
	steps := []struct {
		name     string
		admit    func() (Cut, error)
		explicit int64
	}{
		{"write", func() (Cut, error) { return b.Write(t.Context(), id, 0, []byte("a")) }, 0},
		{"explicit mtime after write", func() (Cut, error) { return b.SetAttr(t.Context(), id, Attributes{HasMTime: true, MTimeNS: 99}) }, 99},
		{"size and explicit mtime", func() (Cut, error) {
			return b.SetAttr(t.Context(), id, Attributes{HasSize: true, Size: 3, HasMTime: true, MTimeNS: 77})
		}, 77},
		{"write after explicit mtime", func() (Cut, error) { return b.Write(t.Context(), id, 1, []byte("b")) }, 0},
		{"truncate", func() (Cut, error) { return b.Truncate(t.Context(), id, 2) }, 0},
	}
	for _, step := range steps {
		before := time.Now().UnixNano()
		cut, err = step.admit()
		after := time.Now().UnixNano()
		if err != nil {
			t.Fatal(step.name, err)
		}
		got := b.OverlayAttributes(id, base)
		if !got.HasCTime || got.CTimeNS < before || got.CTimeNS > after {
			t.Fatalf("%s ctime outside admission: %+v", step.name, got)
		}
		if step.explicit != 0 {
			if got.MTimeNS != step.explicit {
				t.Fatalf("%s explicit mtime lost: %+v", step.name, got)
			}
		} else if got.MTimeNS != got.CTimeNS {
			t.Fatalf("%s implicit timestamps differ: %+v", step.name, got)
		}
	}
	want := b.OverlayAttributes(id, base)
	sequence, err := b.FlushIdentity(t.Context(), id, cut)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.OverlayAttributes(id, base); got != want {
		t.Fatalf("application retired implicit attributes: got %+v want %+v", got, want)
	}
	b.DurableSequence(sequence)
	if got := b.OverlayAttributes(id, base); got.MTimeNS != base.MTimeNS || got.CTimeNS != base.CTimeNS {
		t.Fatalf("durable overlay did not retire: %+v", got)
	}
}

func TestWriteOptionsFenceCoalescingAndPreservePrivilegeOrder(t *testing.T) {
	ctx := context.Background()
	f := &recordingFlusher{}
	b := newTestBuffer(t, f)
	id := testIdentity(81)
	first := WriteOptions{Flags: 6, LockOwner: 11, KillPrivileges: true}
	second := WriteOptions{Flags: 6, LockOwner: 12, KillPrivileges: true}
	for i, opts := range []WriteOptions{first, first, second, {}} {
		if _, err := b.WriteWithOptions(ctx, id, int64(i), []byte("x"), opts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.FlushIdentity(ctx, id, b.Snapshot()); err != nil {
		t.Fatal(err)
	}
	calls := f.snapshot()
	if len(calls) != 3 || len(calls[0].entry.Data) != 2 || calls[0].entry.WriteOptions != first || calls[1].entry.WriteOptions != second || calls[2].entry.WriteOptions != (WriteOptions{}) {
		t.Fatalf("write metadata coalescing: %+v", calls)
	}
	for _, tc := range []struct{ mode, want uint32 }{{0o6755, 0o755}, {0o6744, 0o2744}} {
		base := Attributes{Mode: tc.mode, HasMode: true}
		if got := b.OverlayAttributes(id, base).Mode; got != tc.want {
			t.Fatalf("killpriv %o: got %o want %o", tc.mode, got, tc.want)
		}
	}
	if _, err := b.SetAttr(ctx, id, Attributes{Mode: 0o6755, HasMode: true}); err != nil {
		t.Fatal(err)
	}
	if got := b.OverlayAttributes(id, Attributes{Mode: 0o755, HasMode: true}).Mode; got != 0o6755 {
		t.Fatalf("later chmod lost: %o", got)
	}
	if _, err := b.WriteWithOptions(ctx, id, 4, []byte("x"), first); err != nil {
		t.Fatal(err)
	}
	if got := b.OverlayAttributes(id, Attributes{Mode: 0o755, HasMode: true}).Mode; got != 0o755 {
		t.Fatalf("write after chmod kept privileges: %o", got)
	}
}

func TestBackgroundFlushBoundsFanoutAndExplicitFlushBypassesQueue(t *testing.T) {
	entered := make(chan Identity, 128)
	release := make(chan struct{})
	var sequence atomic.Uint64
	explicit := testIdentity(200)
	flusher := flusherFunc(func(ctx context.Context, id Identity, _ Entry) (uint64, error) {
		if id == explicit {
			return sequence.Add(1), nil
		}
		select {
		case entered <- id:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		select {
		case <-release:
			return sequence.Add(1), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	b := newTestBuffer(t, flusher)
	for i := 0; i < 96; i++ {
		mustWrite(t, b, testIdentity(byte(i)), 0, "x")
	}
	b.trigger()
	await(t, entered, "background worker")
	assertBlocked(t, entered, "background fanout beyond worker bound")
	cut := mustWrite(t, b, explicit, 0, "priority")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := b.FlushIdentity(ctx, explicit, cut); err != nil {
		t.Fatalf("explicit flush waited behind background queue: %v", err)
	}
	// A coalesced kick during the active batch must preserve new work.
	later := testIdentity(201)
	mustWrite(t, b, later, 0, "later")
	b.trigger()
	close(release)
	seen := false
	for range 96 {
		if id := await(t, entered, "remaining background work"); id == later {
			seen = true
		}
	}
	if !seen {
		t.Fatal("kick during active batch lost later admission")
	}
}

func TestStopCancelsBlockedBackgroundBatch(t *testing.T) {
	entered := make(chan struct{}, 128)
	b := newTestBuffer(t, flusherFunc(func(ctx context.Context, _ Identity, _ Entry) (uint64, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}))
	for i := 0; i < 96; i++ {
		mustWrite(t, b, testIdentity(byte(i)), 0, "x")
	}
	b.trigger()
	await(t, entered, "blocked worker")
	done := make(chan struct{})
	go func() { b.Stop(); close(done) }()
	await(t, done, "stop of blocked worker batch")
	if got := b.Stats().Entries; got != 96 {
		t.Fatalf("Stop discarded retained entries: %d", got)
	}
}
