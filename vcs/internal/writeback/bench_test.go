package writeback

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

const (
	benchmarkFileSize = 64 << 20
	benchmarkPageSize = 4 << 10
)

var benchmarkBytes []byte

type benchmarkFlusher struct {
	buffer atomic.Pointer[Buffer]
	seq    atomic.Uint64
}

func (f *benchmarkFlusher) Flush(_ context.Context, _ Identity, _ Entry) (uint64, error) {
	seq := f.seq.Add(1)
	f.buffer.Load().DurableSequence(seq)
	return seq, nil
}

type idleBenchmarkFlusher struct{}

func (idleBenchmarkFlusher) Flush(context.Context, Identity, Entry) (uint64, error) {
	panic("unexpected flush in admission benchmark")
}

func newAdmissionBenchmarkBuffer(b *testing.B, payloadSize, admissions int) (*Buffer, Identity) {
	b.Helper()
	buffer, err := New(idleBenchmarkFlusher{}, Options{
		MaxBytes:      int64(payloadSize * (admissions + 1)),
		MaxEntries:    admissions + 1,
		FlushInterval: -1,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(buffer.Stop)
	id := Identity{1}
	if _, err := buffer.Write(context.Background(), id, 0, make([]byte, payloadSize)); err != nil {
		b.Fatal(err)
	}
	buffer.Drop(id, "benchmark warmup")
	return buffer, id
}

func benchmarkAdmission(b *testing.B, payloadSize, admissions int, offsets []int64) {
	payload := make([]byte, payloadSize)
	buffer, id := newAdmissionBenchmarkBuffer(b, payloadSize, admissions)
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(int64(payloadSize))
	b.ResetTimer()
	for completed := 0; completed < b.N; {
		n := min(admissions, b.N-completed)
		for i := 0; i < n; i++ {
			off := int64(completed+i) * int64(payloadSize)
			if offsets != nil {
				off = offsets[i%len(offsets)]
			}
			if _, err := buffer.Write(ctx, id, off, payload); err != nil {
				b.Fatal(err)
			}
		}
		completed += n
		if completed < b.N {
			b.StopTimer()
			buffer.Drop(id, "benchmark arena recycle")
			b.StartTimer()
		}
	}
	b.StopTimer()
	buffer.Drop(id, "benchmark cleanup")
}

func BenchmarkWriteSequential4KiB(b *testing.B) {
	benchmarkAdmission(b, benchmarkPageSize, 2_048, nil)
}

func BenchmarkWriteSequential1MiB(b *testing.B) {
	benchmarkAdmission(b, MaxPayload, 32, nil)
}

func BenchmarkWriteRandom4KiB64MiB(b *testing.B) {
	const admissions = 8_192
	offsets := make([]int64, admissions)
	state := uint64(0x9e3779b97f4a7c15)
	for i := range offsets {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		offsets[i] = int64(state%uint64(benchmarkFileSize/benchmarkPageSize)) * benchmarkPageSize
	}
	benchmarkAdmission(b, benchmarkPageSize, admissions, offsets)
}

func BenchmarkReadOverlay1000DirtyRanges(b *testing.B) {
	const (
		dirtyRanges = 1_000
		readSize    = 1 << 20
	)
	buffer, err := New(idleBenchmarkFlusher{}, Options{
		MaxBytes:      dirtyRanges*benchmarkPageSize + 1,
		MaxEntries:    dirtyRanges + 1,
		FlushInterval: -1,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(buffer.Stop)
	id := Identity{2}
	dirty := make([]byte, benchmarkPageSize)
	for i := range dirty {
		dirty[i] = byte(i)
	}
	const spacing = benchmarkFileSize / dirtyRanges
	for i := 0; i < dirtyRanges; i++ {
		off := int64(i*spacing) &^ int64(benchmarkPageSize-1)
		if _, err := buffer.Write(context.Background(), id, off, dirty); err != nil {
			b.Fatal(err)
		}
	}
	base := make([]byte, benchmarkFileSize)
	for i := range base {
		base[i] = byte(i)
	}
	fetch := func(_ context.Context, off int64, length int) ([]byte, error) {
		return base[off : off+int64(length)], nil
	}
	const positions = 1_024
	offsets := make([]int64, positions)
	state := uint64(0xd1b54a32d192ed03)
	for i := range offsets {
		state = state*6364136223846793005 + 1
		offsets[i] = int64(state % uint64(benchmarkFileSize-readSize))
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(readSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := buffer.Read(ctx, id, offsets[i%len(offsets)], readSize, fetch)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = out
	}
}

func BenchmarkCapAdmissionUnderContention(b *testing.B) {
	const capEntries = 64
	flusher := new(benchmarkFlusher)
	buffer, err := New(flusher, Options{
		MaxBytes:      capEntries * benchmarkPageSize,
		MaxEntries:    capEntries,
		FlushInterval: -1,
	})
	if err != nil {
		b.Fatal(err)
	}
	flusher.buffer.Store(buffer)
	b.Cleanup(buffer.Stop)
	payload := make([]byte, benchmarkPageSize)
	ctx := context.Background()
	var next atomic.Uint64
	b.ReportAllocs()
	b.SetBytes(benchmarkPageSize)
	b.SetParallelism(2)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := next.Add(1) - 1
			id := Identity{byte(n % 8)}
			off := int64(n/8) * benchmarkPageSize
			if _, err := buffer.Write(ctx, id, off, payload); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	cut := buffer.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := buffer.FlushAll(ctx, cut); err != nil {
		b.Fatal(err)
	}
	if stats := buffer.Stats(); stats.Entries != 0 {
		b.Fatalf("flush left %d entries", stats.Entries)
	}
}
