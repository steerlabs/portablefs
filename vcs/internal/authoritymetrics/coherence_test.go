package authoritymetrics

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestCoherenceMetricFamiliesUseOneSnapshot(t *testing.T) {
	for _, tc := range []struct {
		family string
		series int
	}{
		{"portablefs_authority_delegations", 4},
		{"portablefs_authority_delegation_recalls_total", 2},
		{"portablefs_authority_delegation_breaks_total", 2},
	} {
		t.Run(tc.family, func(t *testing.T) {
			m, err := New("volume")
			if err != nil {
				t.Fatal(err)
			}
			var calls uint64
			m.BindCoherence(func() volumeserver.CoherenceStats {
				// Mark every field with its owner's snapshot number. Distinct
				// numbers in one family reveal a resample during exposition.
				calls++
				return volumeserver.CoherenceStats{
					DelegationsReserved: calls, DelegationsActive: calls,
					DelegationsRecalling: calls, DelegationsRetiring: calls,
					RecallCompleted: calls, RecallLost: calls,
					BreakCompleted: calls, BreakLost: calls,
				}
			})
			for range 2 {
				var output bytes.Buffer
				if err := m.Registry().WritePrometheus(&output); err != nil {
					t.Fatal(err)
				}
				var snapshot uint64
				var series int
				for _, line := range strings.Split(output.String(), "\n") {
					if !strings.HasPrefix(line, tc.family+"{") {
						continue
					}
					fields := strings.Fields(line)
					value, err := strconv.ParseUint(fields[1], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					if series == 0 {
						snapshot = value
					} else if value != snapshot {
						t.Fatalf("family combines snapshots %d and %d", snapshot, value)
					}
					series++
				}
				if series != tc.series {
					t.Fatalf("family has %d series, want %d", series, tc.series)
				}
			}
		})
	}
}

func TestCoherenceMetricsSampleOwnedState(t *testing.T) {
	m, err := New("volume")
	if err != nil {
		t.Fatal(err)
	}
	var active atomic.Uint64
	active.Store(7)
	m.BindCoherence(func() volumeserver.CoherenceStats {
		return volumeserver.CoherenceStats{DelegationsActive: active.Load(), DelegationsReserved: 2, DelegationsRetiring: 1, RecallCompleted: 9, RecallLost: 1, BreakCompleted: 8, BreakLost: 2}
	})
	for _, current := range []uint64{7, 0} {
		active.Store(current)
		var output bytes.Buffer
		if err := m.Registry().WritePrometheus(&output); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			`portablefs_authority_delegation_recalls_total{volume="volume",outcome="completed"} 9`,
			`portablefs_authority_delegation_recalls_total{volume="volume",outcome="lost"} 1`,
			`portablefs_authority_delegation_breaks_total{volume="volume",outcome="lost"} 2`,
			`portablefs_authority_delegations{volume="volume",state="retiring"} 1`,
		} {
			if !strings.Contains(output.String(), want+"\n") {
				t.Errorf("missing %s", want)
			}
		}
		want := "7"
		if current == 0 {
			want = "0"
		}
		if !strings.Contains(output.String(), `portablefs_authority_delegations{volume="volume",state="active"} `+want+"\n") {
			t.Fatal("scrape retained stale snapshot")
		}
	}
}

func TestCoherenceBindingAndScrapingAreConcurrent(t *testing.T) {
	m, err := New("volume")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			m.BindCoherence(func() volumeserver.CoherenceStats { return volumeserver.CoherenceStats{} })
		}
	})
	for range 20 {
		var output bytes.Buffer
		if err := m.Registry().WritePrometheus(&output); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
