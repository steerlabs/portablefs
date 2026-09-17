//go:build linux

package soak

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Reduction of the package soak's stalled peer heartbeat: repeat close/reopen
// on B while A creates independent files, without npm, Git, links, or renames.
func TestSoakReproRewriteReadLoop(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	f := newFixture(t)
	mustMkdir(t, filepath.Join(f.a, "writer"))
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if err := os.WriteFile(filepath.Join(f.a, "writer", fmt.Sprintf("%06d", i)), []byte("independent writer"), 0600); err != nil {
				done <- err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		if err := f.bounded(t, "join independent creator", 5*time.Second, func() error { return <-done }); err != nil {
			t.Error(err)
		}
	}()
	f.measure(t, "rewrite-close-stat-read-30", func() error {
		path := filepath.Join(f.b, "heartbeat")
		latencies := make([]time.Duration, 0, 30)
		for i := 0; i < 30; i++ {
			data := []byte(fmt.Sprint(i))
			t.Logf("REWRITE iteration=%d", i)
			started := time.Now()
			if err := f.bounded(t, fmt.Sprintf("rewrite iteration=%d", i), 15*time.Second, func() error {
				if err := os.WriteFile(path, data, 0600); err != nil {
					return err
				}
				if _, err := os.Stat(path); err != nil {
					return err
				}
				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if string(got) != string(data) {
					return fmt.Errorf("iteration %d read %q want %q", i, got, data)
				}
				return nil
			}); err != nil {
				return err
			}
			latencies = append(latencies, time.Since(started))
		}
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		t.Logf("SOAK_LATENCY rewrite iterations=30 p50=%s p95=%s max=%s", latencies[15], latencies[28], latencies[29])
		f.barrier(t)
		return nil
	})
}
