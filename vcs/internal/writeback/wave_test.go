package writeback

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"testing"
)

type waveTestFlusher struct {
	width, payload int
	call           func([]Entry) ([]uint64, error)
}

func (*waveTestFlusher) Flush(context.Context, Identity, Entry) (uint64, error) {
	panic("batch flusher reached serial path")
}
func (f *waveTestFlusher) FlushBatchSize() (int, int) { return f.width, f.payload }
func (f *waveTestFlusher) FlushBatch(_ context.Context, _ Identity, entries []Entry) ([]uint64, error) {
	return f.call(entries)
}
func entryPieces(e Entry) [][]byte {
	if e.Segments != nil {
		return e.Segments
	}
	return [][]byte{e.Data}
}

func TestFlushWaveBorrowsRecordsAndPreservesOverlapAndCut(t *testing.T) {
	f := &waveTestFlusher{width: 4, payload: 8}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	id := testIdentity(1)
	mustWrite(t, b, id, 0, "abcdefghijklmnopq")
	mustWrite(t, b, id, 17, "rstuv")
	cut := mustWrite(t, b, id, 4, "UVWXYZ")
	_, err := b.SetAttr(t.Context(), id, Attributes{HasMode: true, Mode: 0600})
	if err != nil {
		t.Fatal(err)
	}
	var borrowed [][]byte
	b.mu.Lock()
	for r := b.files[id].head; r != nil; r = r.next {
		if r.kind == Write {
			borrowed = append(borrowed, r.data)
		}
	}
	b.mu.Unlock()
	image := make([]byte, 22)
	var token, sequence uint64
	calls := 0
	f.call = func(entries []Entry) ([]uint64, error) {
		calls++
		if len(entries) == 0 || len(entries) > 4 {
			t.Fatalf("unbounded wave: %d", len(entries))
		}
		result := make([]uint64, len(entries))
		for i, e := range entries {
			if e.Kind != Write || e.Last > cut.Sequence || e.Token <= token {
				t.Fatal("wave crossed acceptance/cut/metadata boundary")
			}
			token = e.Token
			n := 0
			for _, piece := range entryPieces(e) {
				aliases := false
				for _, record := range borrowed {
					for at := range record {
						if &piece[0] == &record[at] && len(piece) <= len(record)-at {
							aliases = true
						}
					}
				}
				if !aliases {
					t.Fatal("wave copied retained payload")
				}
				copy(image[int(e.Offset)+n:], piece)
				n += len(piece)
			}
			if n > 8 || n == 0 {
				t.Fatalf("negotiated payload violated: %d", n)
			}
			sequence++
			result[i] = sequence
		}
		return result, nil
	}
	if _, err := b.FlushIdentity(t.Context(), id, cut); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(image) != "abcdUVWXYZklmnopqrstuv" {
		t.Fatalf("calls=%d data=%q", calls, image)
	}
	if stats := b.Stats(); stats.Accepted != 1 || stats.Applied != 3 {
		t.Fatalf("partial cut lost metadata or records: %+v", stats)
	}
	f.call = func(entries []Entry) ([]uint64, error) {
		if len(entries) != 1 || entries[0].Kind != SetAttr {
			t.Fatal("metadata not isolated")
		}
		sequence++
		return []uint64{sequence}, nil
	}
	if _, err := b.FlushIdentity(t.Context(), id, b.Snapshot()); err != nil {
		t.Fatal(err)
	}
}

func TestFlushWaveRetryKeepsTokensAndPartiallyConsumedRecord(t *testing.T) {
	f := &waveTestFlusher{width: 4, payload: 8}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	id := testIdentity(2)
	cut := mustWrite(t, b, id, 0, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	failure := errors.New("retryable wave refusal")
	var first []Entry
	completed := map[uint64]uint64{}
	var sequence uint64
	calls := 0
	f.call = func(entries []Entry) ([]uint64, error) {
		calls++
		if calls == 1 {
			first = append([]Entry(nil), entries...)
		}
		if calls == 2 {
			if len(entries) != len(first) {
				t.Fatal("retry changed wave")
			}
			for i, e := range entries {
				if e.Token != first[i].Token || e.Offset != first[i].Offset || &e.Data[0] != &first[i].Data[0] {
					t.Fatal("retry changed token or borrowed bytes")
				}
			}
		}
		results := make([]uint64, len(entries))
		for i, e := range entries {
			if calls == 1 && i == 2 {
				return nil, failure
			}
			seq := completed[e.Token]
			if seq == 0 {
				sequence++
				seq = sequence
				completed[e.Token] = seq
			}
			results[i] = seq
		}
		return results, nil
	}
	if _, err := b.FlushIdentity(t.Context(), id, cut); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if stats := b.Stats(); stats.Accepted != 1 || stats.Applied != 0 {
		t.Fatalf("partial wave retired a record: %+v", stats)
	}
	if _, err := b.FlushIdentity(t.Context(), id, cut); err != nil {
		t.Fatal(err)
	}
	if len(completed) != 9 || calls != 4 {
		t.Fatalf("unique chunks=%d calls=%d", len(completed), calls)
	}
	if stats := b.Stats(); stats.Applied != 1 || stats.Accepted != 0 {
		t.Fatalf("completed record was not applied: %+v", stats)
	}
}

func TestFlushWaveDropDoesNotMutateBorrowedEntries(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := &waveTestFlusher{width: 4, payload: 4}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	id := testIdentity(3)
	cut := mustWrite(t, b, id, 0, "abcdefghijklmnop")
	f.call = func(entries []Entry) ([]uint64, error) {
		close(entered)
		<-release
		if len(entries) != 4 || string(entries[0].Data) != "abcd" || string(entries[3].Data) != "mnop" {
			t.Error("Drop rewrote in-flight immutable wave")
		}
		return []uint64{1, 2, 3, 4}, nil
	}
	done := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(t.Context(), id, cut); done <- err }()
	<-entered
	b.Drop(id, "test concurrent fence")
	close(release)
	if err := <-done; !errors.Is(err, ErrLost) {
		t.Fatalf("late completion after loss: %v", err)
	}
	if stats := b.Stats(); stats.Entries != 0 || stats.LossSequence != 1 {
		t.Fatalf("late wave revived dropped records: %+v", stats)
	}
}

func TestFlushWaveRejectsSequenceBelowPriorWave(t *testing.T) {
	f := &waveTestFlusher{width: 2, payload: 4}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	id := testIdentity(4)
	cut := mustWrite(t, b, id, 0, "abcd")
	f.call = func([]Entry) ([]uint64, error) { return []uint64{10}, nil }
	if _, err := b.FlushIdentity(t.Context(), id, cut); err != nil {
		t.Fatal(err)
	}
	cut = mustWrite(t, b, id, 4, "efghijkl")
	f.call = func([]Entry) ([]uint64, error) { return []uint64{9, 11}, nil }
	if _, err := b.FlushIdentity(t.Context(), id, cut); !errors.Is(err, ErrInvalid) {
		t.Fatalf("regressed first sequence accepted: %v", err)
	}
	if s := b.Stats(); s.Applied != 1 || s.Accepted != 1 {
		t.Fatalf("invalid wave retired records: %+v", s)
	}
}

func TestFlushWaveCompletesPrefixBeforePartialRecord(t *testing.T) {
	f := &waveTestFlusher{width: 1, payload: 4}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	id := testIdentity(5)
	small := mustWrite(t, b, id, 0, "ab")
	cut := mustWrite(t, b, id, 2, "cdefgh")
	calls := 0
	var remainder *byte
	f.call = func(entries []Entry) ([]uint64, error) {
		calls++
		e := entries[0]
		if calls == 1 {
			if len(e.Segments) != 2 || e.AppliedThrough != small.Sequence || e.Last != cut.Sequence {
				t.Fatalf("complete prefix not distinguished: %+v", e)
			}
			b.mu.Lock()
			remainder = &b.files[id].head.next.data[2]
			b.mu.Unlock()
		} else {
			if s := b.Stats(); s.Applied != 1 || s.Accepted != 1 {
				t.Fatalf("partial record applied early: %+v", s)
			}
			if e.Offset != 4 || string(e.Data) != "efgh" || &e.Data[0] != remainder || e.AppliedThrough != cut.Sequence {
				t.Fatalf("cursor restarted or copied: %+v", e)
			}
		}
		return []uint64{uint64(calls)}, nil
	}
	if _, err := b.FlushIdentity(t.Context(), id, cut); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("waves=%d", calls)
	}
}

func TestFlushWaveAdmissionOrderModel(t *testing.T) {
	rng := rand.New(rand.NewSource(192))
	for trial := 0; trial < 100; trial++ {
		f := &waveTestFlusher{width: 1 + rng.Intn(4), payload: 1 + rng.Intn(16)}
		b := newTestBuffer(t, f, Options{FlushInterval: -1})
		id := testIdentity(6)
		want, got := make([]byte, 256), make([]byte, 256)
		for n := 0; n < 40; n++ {
			off, size := rng.Intn(192), 1+rng.Intn(64)
			data := make([]byte, size)
			rng.Read(data)
			mustWrite(t, b, id, int64(off), string(data))
			copy(want[off:], data)
		}
		var seq uint64
		f.call = func(entries []Entry) ([]uint64, error) {
			result := make([]uint64, len(entries))
			for i, e := range entries {
				off := int(e.Offset)
				for _, p := range entryPieces(e) {
					copy(got[off:], p)
					off += len(p)
				}
				seq++
				result[i] = seq
			}
			return result, nil
		}
		if _, err := b.FlushIdentity(t.Context(), id, b.Snapshot()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("trial %d width %d payload %d reordered writes", trial, f.width, f.payload)
		}
	}
}

func TestFileDurabilityCannotRetireAnotherIdentityOrLaterCut(t *testing.T) {
	f := &waveTestFlusher{width: 4, payload: 8}
	var seq uint64
	f.call = func(e []Entry) ([]uint64, error) {
		r := make([]uint64, len(e))
		for i := range r {
			seq++
			r[i] = seq
		}
		return r, nil
	}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	one, two := testIdentity(7), testIdentity(8)
	mustWrite(t, b, two, 0, "earlier")
	cut := mustWrite(t, b, one, 0, "first")
	if err := b.DurableIdentity(one, cut); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted record treated as durable: %v", err)
	}
	if _, err := b.FlushAll(t.Context(), cut); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, b, one, 5, "later")
	if err := b.DurableIdentity(one, cut); err != nil {
		t.Fatal(err)
	}
	if s := b.Stats(); s.Entries != 2 || s.Accepted != 1 || s.Applied != 1 {
		t.Fatalf("file sync crossed identity/cut: %+v", s)
	}
	b.mu.Lock()
	if b.durable != 0 || b.visible != 0 {
		t.Error("file sync invented a volume prefix")
	}
	b.mu.Unlock()
	b.Drop(one, "fence")
	if err := b.DurableIdentity(one, cut); !errors.Is(err, ErrLost) {
		t.Fatalf("file sync erased intervening loss: %v", err)
	}
}
