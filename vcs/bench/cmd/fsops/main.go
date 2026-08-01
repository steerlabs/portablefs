// Command fsops is a per-operation latency microbenchmark for a mounted
// PortableFS workspace (or any POSIX directory, for a local-disk baseline).
//
// It times each individual syscall rather than a whole workload, so the
// resulting distribution can be compared directly against the measured network
// RTT to the authority: an op whose p50 is ~1 RTT is one round trip, ~2 RTT is
// two, and an op well under one RTT was served without touching the wire.
//
//	go run ./bench/cmd/fsops -dir /tmp/bench-m1/probe -n 200
//	go run ./bench/cmd/fsops -dir /tmp/local -n 200            # local baseline
//	go run ./bench/cmd/fsops -dir /tmp/bench-m1/enum -enum 1000,10000
//	go run ./bench/cmd/fsops -dir /tmp/bench-m1/bulk -bulk 512 -bulkchunk 1048576
//
// -dir names a WORKSPACE, not the directory the benchmark writes into. The
// workspace is created if absent and is never removed; every phase runs inside
// a freshly created, uniquely named fsops-<pid>-<rand> child of it, and only
// that child is deleted on exit (-keep leaves even that in place). The tool
// therefore never removes a directory it did not create, so pointing -dir at a
// workspace that already holds data is safe.
//
// Every phase is independent and reported separately; -json emits machine
// readable records for the roadmap tables. The -bulk phase additionally emits
// one stable `fsops-bulk key=value ...` line that separates the write(2)
// acknowledgement rate from the fsync barrier that follows it.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sample struct {
	Op   string    `json:"op"`
	N    int       `json:"n"`
	Min  float64   `json:"min_ms"`
	P50  float64   `json:"p50_ms"`
	P90  float64   `json:"p90_ms"`
	P99  float64   `json:"p99_ms"`
	Max  float64   `json:"max_ms"`
	Mean float64   `json:"mean_ms"`
	Raw  []float64 `json:"-"`
}

type recorder struct {
	order []string
	byOp  map[string][]float64
}

func newRecorder() *recorder { return &recorder{byOp: map[string][]float64{}} }

func (r *recorder) add(op string, d time.Duration) {
	if _, ok := r.byOp[op]; !ok {
		r.order = append(r.order, op)
	}
	r.byOp[op] = append(r.byOp[op], float64(d.Microseconds())/1000)
}

func (r *recorder) results() []sample {
	out := make([]sample, 0, len(r.order))
	for _, op := range r.order {
		v := append([]float64(nil), r.byOp[op]...)
		if len(v) == 0 {
			continue
		}
		sort.Float64s(v)
		var sum float64
		for _, x := range v {
			sum += x
		}
		out = append(out, sample{
			Op: op, N: len(v), Min: v[0],
			P50: pct(v, 50), P90: pct(v, 90), P99: pct(v, 99),
			Max: v[len(v)-1], Mean: sum / float64(len(v)),
		})
	}
	return out
}

func pct(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	i := (p*len(sorted))/100 - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// provisionWorkDir creates the directory every phase operates in: a freshly
// created, uniquely named child of the caller's workspace.
//
// The workspace itself is only ever created, never removed — it is the user's
// directory and may already hold anything. The returned cleanup removes the
// child and nothing else, so the tool can only ever delete a directory it
// created and uniquely owns.
func provisionWorkDir(parent string, keep bool) (string, func(), error) {
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", nil, err
	}
	// MkdirTemp creates exclusively: the returned path did not exist a moment
	// ago and belongs to this process alone.
	work, err := os.MkdirTemp(parent, fmt.Sprintf("fsops-%d-", os.Getpid()))
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		if !keep {
			_ = os.RemoveAll(work)
		}
	}
	return work, cleanup, nil
}

func main() {
	dir := flag.String("dir", "", "workspace to benchmark in (created if absent, never removed); every phase runs in a freshly created fsops-* child of it")
	n := flag.Int("n", 100, "iterations per op phase")
	size := flag.Int("size", 4096, "bytes written per small-file write")
	enum := flag.String("enum", "", "comma-separated dir sizes to enumerate, e.g. 1000,10000")
	scale := flag.String("scale", "", "comma-separated dir sizes; measures per-op cost as a function of directory size, e.g. 10,50,200,800")
	bulk := flag.Int("bulk", 0, "if >0, write this many MiB into one file and report MB/s")
	bulkChunk := flag.Int("bulkchunk", 1<<20, "write(2) chunk size for the bulk phase")
	fsyncEvery := flag.Bool("fsync", false, "fsync each small file after write (durability barrier cost)")
	asJSON := flag.Bool("json", false, "emit JSON")
	keep := flag.Bool("keep", false, "leave this run's fsops-* work directory in place instead of removing it")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "fsops: -dir required")
		os.Exit(2)
	}
	work, cleanup, err := provisionWorkDir(*dir, *keep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	fmt.Fprintf(os.Stderr, "# fsops work dir %s\n", work)

	rec := newRecorder()
	switch {
	case *scale != "":
		runScale(rec, work, *scale)
	case *enum != "":
		runEnum(rec, work, *enum)
	case *bulk > 0:
		runBulk(work, *bulk, *bulkChunk)
		return
	default:
		runOps(rec, work, *n, *size, *fsyncEvery)
	}

	res := rec.results()
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return
	}
	fmt.Printf("%-22s %6s %8s %8s %8s %8s %8s %8s\n", "op", "n", "min", "p50", "p90", "p99", "max", "mean")
	for _, s := range res {
		fmt.Printf("%-22s %6d %8.3f %8.3f %8.3f %8.3f %8.3f %8.3f\n",
			s.Op, s.N, s.Min, s.P50, s.P90, s.P99, s.Max, s.Mean)
	}
}

// runOps walks the primitive VFS operations one at a time. Each phase runs to
// completion before the next starts, so a phase's distribution is not polluted
// by another phase's background flush traffic.
func runOps(rec *recorder, dir string, n, size int, doFsync bool) {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	paths := make([]string, n)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("f%05d", i))
	}

	// create (O_CREAT|O_EXCL) — the namespace mutation, isolated from the write.
	handles := make([]*os.File, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		f, err := os.OpenFile(paths[i], os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
		rec.add("create", time.Since(t0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "create %s: %v\n", paths[i], err)
			return
		}
		handles[i] = f
	}

	// write(2) of one small payload into the already-open handle.
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_, err := handles[i].Write(payload)
		rec.add("write", time.Since(t0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
		}
		if doFsync {
			t1 := time.Now()
			_ = handles[i].Sync()
			rec.add("fsync", time.Since(t1))
		}
	}

	// close(2) — on a write-back mount this is where a deferred flush can land.
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_ = handles[i].Close()
		rec.add("close", time.Since(t0))
	}

	// getattr on a path just touched (warm attribute cache if one exists).
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_, err := os.Stat(paths[i])
		rec.add("stat-warm", time.Since(t0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "stat: %v\n", err)
		}
	}

	// lookup of a name that does not exist — the negative-dentry path, which
	// no attribute cache can serve on first ask.
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_, _ = os.Stat(filepath.Join(dir, fmt.Sprintf("missing%05d", i)))
		rec.add("lookup-enoent", time.Since(t0))
	}

	// open+read of an existing small file (cold-ish: different file each time).
	buf := make([]byte, size)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		f, err := os.Open(paths[i])
		if err == nil {
			_, _ = f.Read(buf)
			_ = f.Close()
		}
		rec.add("open-read-close", time.Since(t0))
	}

	// rename within the same directory.
	for i := 0; i < n; i++ {
		np := paths[i] + ".r"
		t0 := time.Now()
		err := os.Rename(paths[i], np)
		rec.add("rename", time.Since(t0))
		if err == nil {
			paths[i] = np
		}
	}

	// readdir of the whole directory, repeated — first call is cold.
	for i := 0; i < min(n, 20); i++ {
		t0 := time.Now()
		f, err := os.Open(dir)
		if err == nil {
			_, _ = f.ReadDir(-1)
			_ = f.Close()
		}
		if i == 0 {
			rec.add("readdir-cold", time.Since(t0))
		} else {
			rec.add("readdir-warm", time.Since(t0))
		}
	}

	// mkdir / rmdir.
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("d%05d", i))
		t0 := time.Now()
		_ = os.Mkdir(p, 0o755)
		rec.add("mkdir", time.Since(t0))
	}
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("d%05d", i))
		t0 := time.Now()
		_ = os.Remove(p)
		rec.add("rmdir", time.Since(t0))
	}

	// unlink.
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_ = os.Remove(paths[i])
		rec.add("unlink", time.Since(t0))
	}
}

// runScale answers one question: is the cost of a single namespace operation a
// function of how many entries the parent directory already holds?
//
// For each N it builds a fresh directory of N files and then measures a FIXED,
// small number of probes (so the probe count never varies with N). If p50 grows
// linearly in N, the operation is doing O(N) work per call — which makes any
// bulk operation over the directory O(N^2).
func runScale(rec *recorder, dir, spec string) {
	const probes = 12
	fmt.Printf("%-8s %-16s %8s %8s %8s %10s\n", "N", "op", "p50", "p90", "max", "us/entry")
	for _, part := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n <= 0 {
			continue
		}
		sub := filepath.Join(dir, fmt.Sprintf("s%06d", n))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			continue
		}
		names := make([]string, n)
		for i := range names {
			names[i] = filepath.Join(sub, fmt.Sprintf("p%07d", i))
		}
		for _, p := range names {
			f, err := os.Create(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "populate: %v\n", err)
				break
			}
			_ = f.Close()
		}

		local := newRecorder()
		// Probe from the middle of the directory so no probe is advantaged by
		// being the first or last entry in any ordering the server may use.
		mid := n / 2
		for i := 0; i < probes && mid+i < n; i++ {
			t0 := time.Now()
			_, _ = os.Stat(names[mid+i])
			local.add("stat", time.Since(t0))
		}
		for i := 0; i < probes; i++ {
			t0 := time.Now()
			f, err := os.Open(sub)
			if err == nil {
				_, _ = f.ReadDir(-1)
				_ = f.Close()
			}
			local.add("readdir", time.Since(t0))
		}
		for i := 0; i < probes && mid+i < n; i++ {
			t0 := time.Now()
			_ = os.Rename(names[mid+i], names[mid+i]+".r")
			local.add("rename", time.Since(t0))
			names[mid+i] += ".r"
		}
		for i := 0; i < probes && mid+i < n; i++ {
			t0 := time.Now()
			_ = os.Remove(names[mid+i])
			local.add("unlink", time.Since(t0))
		}
		for _, s := range local.results() {
			fmt.Printf("%-8d %-16s %8.3f %8.3f %8.3f %10.2f\n",
				n, s.Op, s.P50, s.P90, s.Max, s.P50*1000/float64(n))
			rec.add(fmt.Sprintf("N%d-%s", n, s.Op), time.Duration(s.P50*float64(time.Millisecond)))
		}
		_ = os.RemoveAll(sub)
	}
}

// runEnum measures readdir of directories of increasing size, cold (first read
// after population) and warm (immediately repeated).
func runEnum(rec *recorder, dir, spec string) {
	for _, part := range strings.Split(spec, ",") {
		count, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || count <= 0 {
			continue
		}
		sub := filepath.Join(dir, fmt.Sprintf("n%d", count))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", sub, err)
			continue
		}
		t0 := time.Now()
		for i := 0; i < count; i++ {
			f, err := os.Create(filepath.Join(sub, fmt.Sprintf("e%06d", i)))
			if err != nil {
				fmt.Fprintf(os.Stderr, "populate: %v\n", err)
				break
			}
			_ = f.Close()
		}
		fmt.Fprintf(os.Stderr, "# populated %d entries in %s in %.2fs (%.0f creates/s)\n",
			count, sub, time.Since(t0).Seconds(), float64(count)/time.Since(t0).Seconds())

		label := fmt.Sprintf("readdir-%d", count)
		for i := 0; i < 6; i++ {
			t1 := time.Now()
			f, err := os.Open(sub)
			var got int
			if err == nil {
				ents, _ := f.ReadDir(-1)
				got = len(ents)
				_ = f.Close()
			}
			d := time.Since(t1)
			if i == 0 {
				rec.add(label+"-cold", d)
				fmt.Fprintf(os.Stderr, "# %s cold: %d entries in %.1fms\n", label, got, float64(d.Microseconds())/1000)
			} else {
				rec.add(label+"-warm", d)
			}
		}
		// stat every entry — the "ls -l" shape, which is where an enumeration
		// that returns names but not attributes turns into N extra lookups.
		f, err := os.Open(sub)
		if err != nil {
			continue
		}
		ents, _ := f.ReadDir(-1)
		_ = f.Close()
		t2 := time.Now()
		for _, e := range ents {
			_, _ = os.Stat(filepath.Join(sub, e.Name()))
		}
		d := time.Since(t2)
		fmt.Fprintf(os.Stderr, "# %s stat-all: %d stats in %.1fms (%.1fus/stat)\n",
			label, len(ents), float64(d.Microseconds())/1000, float64(d.Microseconds())/float64(max(len(ents), 1)))
	}
}

// runBulk measures sustained single-file write throughput — the shape the
// write-back flusher has to keep up with.
//
// The payload is re-randomized for every chunk. A repeated buffer would be
// trivially deduplicated or compressed somewhere in the stack and the measured
// rate would describe the dedup table, not the upload path.
func runBulk(dir string, mb, chunk int) {
	p := filepath.Join(dir, "bulk.bin")
	buf := make([]byte, chunk)
	rng := uint64(0x9E3779B97F4A7C15)
	fill := func() {
		for i := 0; i+8 <= len(buf); i += 8 {
			rng ^= rng << 13
			rng ^= rng >> 7
			rng ^= rng << 17
			binary.LittleEndian.PutUint64(buf[i:], rng)
		}
	}
	fill()
	f, err := os.Create(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}
	total := int64(mb) << 20
	var written int64
	t0 := time.Now()
	lastReport := t0
	var lastWritten int64
	for written < total {
		fill()
		nw, err := f.Write(buf)
		written += int64(nw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			break
		}
		if time.Since(lastReport) >= time.Second {
			d := time.Since(lastReport).Seconds()
			fmt.Printf("  t=%5.1fs written=%6.1fMiB inst=%7.2fMB/s avg=%7.2fMB/s\n",
				time.Since(t0).Seconds(), float64(written)/(1<<20),
				float64(written-lastWritten)/(1<<20)/d,
				float64(written)/(1<<20)/time.Since(t0).Seconds())
			lastReport = time.Now()
			lastWritten = written
		}
	}
	acked := time.Since(t0)
	mib := float64(written) / (1 << 20)
	fmt.Printf("write-acked   %.1fMiB in %.2fs = %.2f MB/s (write(2) return only; no barrier)\n", mib, acked.Seconds(), mib/acked.Seconds())

	t1 := time.Now()
	if err := f.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "fsync: %v\n", err)
	}
	sync := time.Since(t1)
	_ = f.Close()
	fmt.Printf("fsync-barrier %.2fs (drains the unshipped tail to the authority, then the authority barrier RPC)\n", sync.Seconds())
	end := acked + sync
	fmt.Printf("durable-total %.1fMiB in %.2fs = %.2f MB/s effective upload\n", mib, end.Seconds(), mib/end.Seconds())

	// One stable machine-readable line so a harness consumes THESE numbers
	// instead of re-deriving a rate from process exit — which would fold the
	// fsync barrier into the write phase and report a durable rate as an ack
	// rate.
	fmt.Printf("fsops-bulk mib=%.4f write_acked_s=%.6f fsync_barrier_s=%.6f durable_total_s=%.6f write_acked_mbps=%.4f durable_total_mbps=%.4f\n",
		mib, acked.Seconds(), sync.Seconds(), end.Seconds(), mib/acked.Seconds(), mib/end.Seconds())
}
