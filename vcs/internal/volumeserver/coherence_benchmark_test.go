package volumeserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	coherenceBenchmarkBudget      = 100_000
	coherenceBenchmarkDelegations = 100_000
)

type coherenceBenchmarkClock struct {
	now time.Time
}

func (c coherenceBenchmarkClock) Now() time.Time { return c.now }
func (coherenceBenchmarkClock) NewTimer(d time.Duration) CoherenceTimer {
	return coherenceWallTimer{time.NewTimer(d)}
}

func coherenceBenchmarkIdentity(value uint64) [16]byte {
	var identity [16]byte
	binary.LittleEndian.PutUint64(identity[:8], value)
	return identity
}

func coherenceBenchmarkSession(value uint64) SessionID {
	var session SessionID
	binary.LittleEndian.PutUint64(session[:8], value)
	return session
}

func newCoherenceBenchmarkCoordinator(maxLogEntries int) *CoherenceCoordinator {
	return NewCoherenceCoordinator(CoherenceConfig{
		Clock:         coherenceBenchmarkClock{now: time.Unix(1, 0)},
		MaxLogEntries: maxLogEntries,
	})
}

func BenchmarkCoherenceAppendDeliverAck(b *testing.B) {
	for _, batchSize := range []int{1, 64, 1024} {
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			coordinator := newCoherenceBenchmarkCoordinator(batchSize)
			snapshot, err := coordinator.Subscribe(coherenceBenchmarkSession(1))
			if err != nil {
				b.Fatal(err)
			}
			entries := make([]ChangeEntry, batchSize)
			for i := range entries {
				entries[i] = ChangeEntry{
					Kind:          DataChanged,
					Identity:      coherenceBenchmarkIdentity(uint64(i + 1)),
					VolumeVersion: 1,
				}
			}
			dst := make([]StreamEvent, 0, batchSize)
			cursor := snapshot.Position

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				position := coordinator.OnCommit(entries)
				delivered, err := coordinator.Poll(context.Background(), snapshot.Token, cursor, dst[:0], batchSize)
				if err != nil {
					b.Fatal(err)
				}
				if len(delivered) != batchSize {
					b.Fatalf("delivered %d events, want %d", len(delivered), batchSize)
				}
				if err := coordinator.Ack(snapshot.Token, position); err != nil {
					b.Fatal(err)
				}
				cursor = position
			}
			b.StopTimer()

			entriesProcessed := float64(b.N) * float64(batchSize)
			throughput := entriesProcessed / b.Elapsed().Seconds()
			b.ReportMetric(float64(batchSize), "entries/op")
			b.ReportMetric(throughput, "entries/s")
			b.ReportMetric(coherenceBenchmarkBudget, "budget_entries/s")
			b.ReportMetric(throughput/coherenceBenchmarkBudget*100, "%budget")
		})
	}
}

func BenchmarkCoherenceAckSubscriberScaling(b *testing.B) {
	for _, subscriberCount := range []int{1, 64, 1024} {
		b.Run(fmt.Sprintf("subscribers_%d", subscriberCount), func(b *testing.B) {
			coordinator := newCoherenceBenchmarkCoordinator(1)
			tokens := make([]SubscriptionToken, subscriberCount)
			for i := range tokens {
				snapshot, err := coordinator.Subscribe(coherenceBenchmarkSession(uint64(i + 1)))
				if err != nil {
					b.Fatal(err)
				}
				tokens[i] = snapshot.Token
			}
			entry := []ChangeEntry{{
				Kind:          DataChanged,
				Identity:      coherenceBenchmarkIdentity(1),
				VolumeVersion: 1,
			}}
			dst := make([]StreamEvent, 0, 1)
			var cursor uint64

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				position := coordinator.OnCommit(entry)
				for _, token := range tokens {
					delivered, err := coordinator.Poll(context.Background(), token, cursor, dst[:0], 1)
					if err != nil {
						b.Fatal(err)
					}
					if len(delivered) != 1 {
						b.Fatalf("delivered %d events, want 1", len(delivered))
					}
					if err := coordinator.Ack(token, position); err != nil {
						b.Fatal(err)
					}
				}
				cursor = position
			}
			b.StopTimer()

			acks := float64(b.N) * float64(subscriberCount)
			b.ReportMetric(acks/b.Elapsed().Seconds(), "acks/s")
			b.ReportMetric(float64(subscriberCount), "subscribers")
		})
	}
}

var (
	coherenceDelegationBenchmarkOnce        sync.Once
	coherenceDelegationBenchmarkCoordinator *CoherenceCoordinator
	coherenceDelegationBenchmarkErr         error
	coherenceDelegationBenchmarkSink        uint64
)

func coherenceDelegationFixture() (*CoherenceCoordinator, error) {
	coherenceDelegationBenchmarkOnce.Do(func() {
		const deliveryBatch = 512

		coordinator := newCoherenceBenchmarkCoordinator(2 * deliveryBatch)
		snapshot, err := coordinator.Subscribe(coherenceBenchmarkSession(1))
		if err != nil {
			coherenceDelegationBenchmarkErr = err
			return
		}
		cursor := snapshot.Position
		dst := make([]StreamEvent, 0, deliveryBatch)
		pending := 0
		drain := func() error {
			delivered, err := coordinator.Poll(context.Background(), snapshot.Token, cursor, dst[:0], pending)
			if err != nil {
				return err
			}
			if len(delivered) != pending {
				return fmt.Errorf("delivered %d delegation grants, want %d", len(delivered), pending)
			}
			cursor = delivered[len(delivered)-1].Position
			if err := coordinator.Ack(snapshot.Token, cursor); err != nil {
				return err
			}
			pending = 0
			return nil
		}

		for i := uint64(1); i <= coherenceBenchmarkDelegations; i++ {
			reservation, err := coordinator.ReserveNew(snapshot.Token, coherenceBenchmarkIdentity(i))
			if err != nil {
				coherenceDelegationBenchmarkErr = fmt.Errorf("reserve delegation %d: %w", i, err)
				return
			}
			if _, err := reservation.Grant(context.Background()); err != nil {
				coherenceDelegationBenchmarkErr = fmt.Errorf("grant delegation %d: %w", i, err)
				return
			}
			pending++
			if pending == deliveryBatch {
				if err := drain(); err != nil {
					coherenceDelegationBenchmarkErr = fmt.Errorf("ack delegation grants through %d: %w", i, err)
					return
				}
			}
		}
		if pending != 0 {
			if err := drain(); err != nil {
				coherenceDelegationBenchmarkErr = fmt.Errorf("ack final delegation grants: %w", err)
				return
			}
		}
		coherenceDelegationBenchmarkCoordinator = coordinator
	})
	return coherenceDelegationBenchmarkCoordinator, coherenceDelegationBenchmarkErr
}

func BenchmarkCoherenceDelegationLookup100K(b *testing.B) {
	coordinator, err := coherenceDelegationFixture()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	next := uint64(1)
	var sink uint64
	for i := 0; i < b.N; i++ {
		grant, ok := coordinator.LookupDelegation(coherenceBenchmarkIdentity(next))
		if !ok {
			b.Fatalf("delegation %d was not active", next)
		}
		sink ^= grant.ID
		next++
		if next > coherenceBenchmarkDelegations {
			next = 1
		}
	}
	b.StopTimer()
	coherenceDelegationBenchmarkSink = sink
	b.ReportMetric(float64(coherenceBenchmarkDelegations), "active_delegations")
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "lookups/s")
}
