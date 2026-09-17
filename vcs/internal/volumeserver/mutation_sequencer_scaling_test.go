package volumeserver

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkMutationSequencerContendedQueue(b *testing.B) {
	for _, count := range []int{64, 256, 1024, 4096} {
		b.Run(fmt.Sprintf("waiters-%d", count), func(b *testing.B) {
			deps := testInodeDependencies(1)
			b.ReportAllocs()
			b.ReportMetric(float64(count), "waiters/op")
			for b.Loop() {
				s := newMutationSequencer()
				owner, _ := s.acquire(context.Background(), deps)
				ws := make([]*mutationSequencerWaiter, count)
				for i := range ws {
					ws[i] = s.enqueue(deps)
				}
				owner.release()
				for _, w := range ws {
					<-w.ready
					w.release()
				}
			}
		})
	}
}

// A pending mutation may reserve many disjoint keys while one common key is
// busy. Rebuilding a map of all older claims on every transition made memory
// work quadratic even though the live queue remained bounded.
func TestMutationSequencerQueueMemoryIsLinear(t *testing.T) {
	const count = 256
	dependencies := make([]MutationDependencies, count)
	for i := range dependencies {
		dependencies[i] = newMutationDependencies(inodeKey([16]byte{1}), inodeKey([16]byte{2, byte(i), byte(i >> 8)}))
	}
	result := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			s := newMutationSequencer()
			owner, _ := s.acquire(context.Background(), testInodeDependencies(1))
			waiters := make([]*mutationSequencerWaiter, count)
			for i := range waiters {
				waiters[i] = s.enqueue(dependencies[i])
			}
			owner.release()
			for _, w := range waiters {
				<-w.ready
				w.release()
			}
		}
	})
	const budget = count * 2048
	if got := result.AllocedBytesPerOp(); got > budget {
		t.Fatalf("queue bookkeeping allocated %d bytes for %d waiters, bound %d", got, count, budget)
	}
	t.Logf("queue bookkeeping: %d bytes for %d waiters", result.AllocedBytesPerOp(), count)
}

func TestMutationSequencerCancellationExposesDisjointFront(t *testing.T) {
	s := newMutationSequencer()
	owner, _ := s.acquire(t.Context(), testInodeDependencies(2))
	first := s.enqueue(testInodeDependencies(1, 2))
	second := s.enqueue(testInodeDependencies(1))
	first.abandon()
	select {
	case <-second.ready:
	default:
		t.Fatal("cancelled multi-key claimant stranded an unowned key")
	}
	second.release()
	owner.release()
	if s.queued() != 0 || len(s.held) != 0 || len(s.claims) != 0 {
		t.Fatal("completed queue retained ownership")
	}
}

func TestMutationSequencerMultiKeyFrontsRemainFIFO(t *testing.T) {
	s := newMutationSequencer()
	owner, _ := s.acquire(t.Context(), testInodeDependencies(1, 2))
	first := s.enqueue(testInodeDependencies(1, 2))
	a := s.enqueue(testInodeDependencies(1))
	b := s.enqueue(testInodeDependencies(2))
	owner.release()
	select {
	case <-first.ready:
	default:
		t.Fatal("oldest complete footprint did not enter")
	}
	for _, w := range []*mutationSequencerWaiter{a, b} {
		select {
		case <-w.ready:
			t.Fatal("younger key front bypassed multi-key owner")
		default:
		}
	}
	first.release()
	for _, w := range []*mutationSequencerWaiter{a, b} {
		select {
		case <-w.ready:
			w.release()
		default:
			t.Fatal("disjoint front did not enter after shared owner")
		}
	}
}
