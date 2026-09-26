package authoritymetrics

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

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
