package fsproto

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// TestOpNamesCoverEverySequentialOp guards the per-op counter map against new
// ops silently landing in vcs_fsproto_op_other: every op in the sequential
// block (plus the out-of-band version probe) must have a stable name.
func TestOpNamesCoverEverySequentialOp(t *testing.T) {
	for op := OpGetattr; op <= OpUnmarkOpenInodes; op++ {
		if _, ok := opNames[op]; !ok {
			t.Errorf("op %d has no counter name; add it to opNames", op)
		}
	}
	if _, ok := opNames[OpProtocolVersion]; !ok {
		t.Error("OpProtocolVersion has no counter name")
	}
}

func counterValue(name string) int64 {
	snap := metrics.Default.Snapshot()
	counters, _ := snap["counters"].(map[string]int64)
	return counters[name]
}

// TestCountOpAttributesKnownAndUnknownOps: countOp bumps the op's own counter,
// and an op outside the map lands in vcs_fsproto_op_other.
func TestCountOpAttributesKnownAndUnknownOps(t *testing.T) {
	mkdirBefore := counterValue("vcs_fsproto_op_mkdir")
	otherBefore := counterValue("vcs_fsproto_op_other")
	countOp(OpMkdir)
	countOp(Op(199)) // not a defined op
	if got := counterValue("vcs_fsproto_op_mkdir") - mkdirBefore; got != 1 {
		t.Fatalf("mkdir counter delta = %d, want 1", got)
	}
	if got := counterValue("vcs_fsproto_op_other") - otherBefore; got != 1 {
		t.Fatalf("other counter delta = %d, want 1", got)
	}
}

// TestServeCountsPerOp proves the wiring: ops served over a real connection land
// in their per-op counters (the benchmark harness reads these to attribute a
// workload's round-trips).
func TestServeCountsPerOp(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewServer(fs, fs, delegation.New()).Serve(ctx, ln) }()
	cli, err := Dial(ln.Addr().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	mkdirBefore := counterValue("vcs_fsproto_op_mkdir")
	getattrBefore := counterValue("vcs_fsproto_op_getattr")
	readdirBefore := counterValue("vcs_fsproto_op_readdir")

	if _, st, err := cli.Mkdir("d", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Getattr("d"); err != nil || st != OK {
		t.Fatalf("getattr: st=%d err=%v", st, err)
	}
	if _, _, st, err := cli.Readdir(""); err != nil || st != OK {
		t.Fatalf("readdir: st=%d err=%v", st, err)
	}

	for _, c := range []struct {
		name   string
		before int64
	}{
		{"vcs_fsproto_op_mkdir", mkdirBefore},
		{"vcs_fsproto_op_getattr", getattrBefore},
		{"vcs_fsproto_op_readdir", readdirBefore},
	} {
		if got := counterValue(c.name) - c.before; got != 1 {
			t.Fatalf("%s delta = %d, want 1", c.name, got)
		}
	}
}
