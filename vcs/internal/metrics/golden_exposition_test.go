package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGoldenExposition pins the EXACT Prometheus text this exporter produces
// for a representative child registry. The same golden file is consumed by
// the authority-manager's TypeScript aggregator tests
// (apps/authority-manager/src/child-metrics.test.ts), making the Go exporter
// and the TS parser a checked cross-language contract: if the render format
// changes, this test and the aggregator fixtures fail together.
func TestGoldenExposition(t *testing.T) {
	r := NewRegistry()
	r.Counter("vcs_fsproto_ops").Add(1234)
	r.Counter("vcs_mutations").Add(567)
	r.Counter("vcs_cache_ram_hits").Add(89)
	r.Gauge("vcs_ready").Set(1)
	r.Gauge("vcs_fsproto_conns").Set(3)
	r.Gauge("writeback_pending_bytes").Set(4096)
	// The dirty-RSS pair (vcs/internal/workfs dirtyrss.go): resident
	// uncommitted dirty-block bytes plus the configured admission bound.
	r.Gauge("vcs_dirty_block_bytes").Set(8388608)
	r.Gauge("vcs_dirty_block_bytes_max").Set(2147483648)

	h := r.Histogram("vcs_fsproto_op_latency")
	// Deterministic observations: 30µs, 30µs, 700µs, 2ms.
	h.Observe(30 * time.Microsecond)
	h.Observe(30 * time.Microsecond)
	h.Observe(700 * time.Microsecond)
	h.Observe(2 * time.Millisecond)

	got := r.Prometheus()

	goldenPath := filepath.Join("testdata", "golden_exposition.txt")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		if os.IsNotExist(err) && os.Getenv("UPDATE_GOLDEN") == "1" {
			if mkErr := os.MkdirAll("testdata", 0o755); mkErr != nil {
				t.Fatalf("mkdir testdata: %v", mkErr)
			}
			if writeErr := os.WriteFile(goldenPath, []byte(got), 0o644); writeErr != nil {
				t.Fatalf("write golden: %v", writeErr)
			}
			t.Logf("wrote golden exposition (%d bytes)", len(got))
			return
		}
		t.Fatalf("read golden: %v (set UPDATE_GOLDEN=1 to create)", err)
	}
	if got != string(want) {
		t.Fatalf("Prometheus render drifted from the cross-language golden.\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
}
