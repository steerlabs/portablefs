package main

import (
	"bytes"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestBulkEmitsPhaseSplitLine pins the machine-readable contract that
// bench/prod-flush-rate.sh consumes: fsops reports the write(2) acknowledgement
// phase and the fsync barrier that follows it as SEPARATE timings, so no
// harness has to re-derive an "ack rate" from process exit (which folds the
// barrier into the write phase and calls a durable rate an ack rate).
func TestBulkEmitsPhaseSplitLine(t *testing.T) {
	work, cleanup, err := provisionWorkDir(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	out := captureStdout(t, func() { runBulk(work, 1, 1<<16) })

	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "fsops-bulk ") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no 'fsops-bulk' phase line in output:\n%s", out)
	}
	fields := map[string]float64{}
	for _, kv := range strings.Fields(line)[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed field %q in %q", kv, line)
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			t.Fatalf("field %s is not a number: %v", k, err)
		}
		fields[k] = f
	}
	for _, k := range []string{"mib", "write_acked_s", "fsync_barrier_s", "durable_total_s", "write_acked_mbps", "durable_total_mbps"} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("phase line is missing %s: %q", k, line)
		}
	}
	if fields["mib"] != 1 {
		t.Fatalf("mib = %v, want 1", fields["mib"])
	}
	// The barrier is timed separately, and the durable total is exactly the
	// two phases summed — never the write phase relabelled.
	// (each field is printed to 6 decimals, so allow the rounding slack)
	if sum := fields["write_acked_s"] + fields["fsync_barrier_s"]; math.Abs(sum-fields["durable_total_s"]) > 1e-5 {
		t.Fatalf("durable_total_s %v != write_acked_s + fsync_barrier_s %v", fields["durable_total_s"], sum)
	}
	if fields["write_acked_s"] <= 0 || fields["durable_total_s"] < fields["write_acked_s"] {
		t.Fatalf("implausible phase timings: %q", line)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}
