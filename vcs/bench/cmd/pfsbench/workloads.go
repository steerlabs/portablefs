package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"os/exec"
	"sort"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
)

// benchSeed makes every size distribution and path layout deterministic.
const benchSeed = 42

// profile scales the workloads. "full" is the headline profile; "quick" keeps
// CI under a couple of minutes.
type profile struct {
	Name        string `json:"name"`
	W1Files     int    `json:"w1Files"`
	W1Dirs      int    `json:"w1Dirs"`
	W2Files     int    `json:"w2Files"`
	W2Dirs      int    `json:"w2Dirs"`
	W2ProbeMiss int    `json:"w2ProbeMiss"` // distinct missing paths probed
	W2ProbeIter int    `json:"w2ProbeIter"` // rounds over the missing set
	W3Appends   int    `json:"w3Appends"`
	W3ChunkB    int    `json:"w3ChunkB"`
	W5MiB       int    `json:"w5MiB"`
}

var profiles = map[string]profile{
	"full":  {Name: "full", W1Files: 10_000, W1Dirs: 500, W2Files: 5_000, W2Dirs: 100, W2ProbeMiss: 2_000, W2ProbeIter: 3, W3Appends: 1_000, W3ChunkB: 256, W5MiB: 256},
	"quick": {Name: "quick", W1Files: 2_000, W1Dirs: 100, W2Files: 1_000, W2Dirs: 50, W2ProbeMiss: 500, W2ProbeIter: 3, W3Appends: 200, W3ChunkB: 256, W5MiB: 64},
}

// phaseResult is one measured phase of a workload: N runs, p50 wall time,
// logical ops, and (core transport) authority round-trip counts.
type phaseResult struct {
	Workload  string           `json:"workload"`
	Phase     string           `json:"phase"`
	RunsSec   []float64        `json:"runsSec"`
	P50Sec    float64          `json:"p50Sec"`
	Ops       int64            `json:"ops"`
	OpsPerSec float64          `json:"opsPerSec"`
	RPCs      int64            `json:"rpcs,omitempty"`      // client->authority round-trips during the p50 run
	ServerOps map[string]int64 `json:"serverOps,omitempty"` // per-op server counters during the p50 run
	Note      string           `json:"note,omitempty"`
}

// runner executes phases against one benchFS and records results.
type runner struct {
	fs        benchFS
	transport string
	n         int
	results   []phaseResult
}

// timePhase runs fn n times (with optional per-run setup), keeps per-run wall
// times, and snapshots RPC + server-op counters around the run whose wall time
// lands at the p50 — attributing round-trips to a representative run.
func (r *runner) timePhase(workload, phase string, ops int64, note string, setup func(run int) error, fn func(run int) error) error {
	type sample struct {
		sec    float64
		rpcs   int64
		server map[string]int64
	}
	samples := make([]sample, 0, r.n)
	for i := 0; i < r.n; i++ {
		if setup != nil {
			setupStart := time.Now()
			if err := setup(i); err != nil {
				return fmt.Errorf("%s/%s setup run %d: %w", workload, phase, i, err)
			}
			if el := time.Since(setupStart); el > 2*time.Second {
				log.Printf("  %s/%s setup %d: %.1fs", workload, phase, i, el.Seconds())
			}
		}
		rpc0 := r.fs.RPCCount()
		srv0 := serverOpSnapshot()
		start := time.Now()
		if err := fn(i); err != nil {
			return fmt.Errorf("%s/%s run %d: %w", workload, phase, i, err)
		}
		el := time.Since(start).Seconds()
		samples = append(samples, sample{sec: el, rpcs: r.fs.RPCCount() - rpc0, server: diffServerOps(srv0, serverOpSnapshot())})
		log.Printf("  %s/%s run %d/%d: %.3fs", workload, phase, i+1, r.n, el)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].sec < samples[j].sec })
	med := samples[len(samples)/2]
	runs := make([]float64, len(samples))
	for i, s := range samples {
		runs[i] = s.sec
	}
	pr := phaseResult{
		Workload: workload, Phase: phase, RunsSec: runs, P50Sec: med.sec,
		Ops: ops, Note: note,
	}
	if med.sec > 0 {
		pr.OpsPerSec = float64(ops) / med.sec
	}
	if r.transport != "local" {
		pr.RPCs = med.rpcs
		pr.ServerOps = med.server
	}
	r.results = append(r.results, pr)
	return nil
}

// serverOpSnapshot reads the in-process fsproto per-op counters (populated when
// the authority runs in this process: core transport, and fuse when pfsbench
// hosts the authority). Zero for out-of-process authorities.
func serverOpSnapshot() map[string]int64 {
	snap := metrics.Default.Snapshot()
	counters, _ := snap["counters"].(map[string]int64)
	out := map[string]int64{}
	for name, v := range counters {
		if len(name) > 15 && name[:15] == "vcs_fsproto_op_" {
			out[name[15:]] = v
		}
	}
	return out
}

func diffServerOps(before, after map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for name, v := range after {
		if d := v - before[name]; d != 0 {
			out[name] = d
		}
	}
	return out
}

// ---- deterministic content ----

var patternBuf = func() []byte {
	b := make([]byte, 1<<20)
	rnd := rand.New(rand.NewSource(benchSeed))
	for i := range b {
		b[i] = byte('a' + rnd.Intn(26))
	}
	// Plant the W4 grep needle at a fixed stride so scans have real matches.
	needle := []byte("PORTABLEFS_NEEDLE")
	for off := 4096; off+len(needle) < len(b); off += 64 * 1024 {
		copy(b[off:], needle)
	}
	return b
}()

func contentFor(size int) []byte { return patternBuf[:size] }

// ---- W1: metadata walk (git status proxy) ----

func w1Paths(p profile) (dirs []string, files map[string][]string) {
	dirs = make([]string, 0, p.W1Dirs)
	files = make(map[string][]string, p.W1Dirs)
	perDir := p.W1Files / p.W1Dirs
	for d := 0; d < p.W1Dirs; d++ {
		dir := fmt.Sprintf("w1/d%03d", d)
		dirs = append(dirs, dir)
		names := make([]string, 0, perDir)
		for f := 0; f < perDir; f++ {
			names = append(names, fmt.Sprintf("f%04d.txt", f))
		}
		files[dir] = names
	}
	return dirs, files
}

// setupW1 builds the tree once per transport (untimed). This is fsync-bound on
// the write-through transports (every create/write is a WAL-durable RPC), so it
// logs progress: quiet minutes here are physics, not a hang — the reason the
// harness once got killed as "hung".
func setupW1(fs benchFS, p profile) error {
	start := time.Now()
	log.Printf("  W1 setup: %d files / %d dirs (durable create+write per file)...", p.W1Files, p.W1Dirs)
	defer func() { log.Printf("  W1 setup done in %.1fs", time.Since(start).Seconds()) }()
	rnd := rand.New(rand.NewSource(benchSeed))
	if err := fs.Mkdir("w1"); err != nil {
		return err
	}
	dirs, files := w1Paths(p)
	for _, dir := range dirs {
		if err := fs.Mkdir(dir); err != nil {
			return err
		}
		for _, name := range files[dir] {
			size := 64 + rnd.Intn(960) // 64B..1KiB
			f, err := fs.Create(dir + "/" + name)
			if err != nil {
				return err
			}
			if err := f.WriteAt(contentFor(size), 0); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	return fs.SyncDurable()
}

// walkW1 is the measured walk: readdir every directory + lstat every entry —
// exactly the syscall shape of `git status` enumerating an unchanged tree.
func walkW1(fs benchFS, p profile) error {
	dirs, _ := w1Paths(p)
	for _, dir := range dirs {
		ents, err := fs.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if _, exists, err := fs.Lstat(dir + "/" + e.Name); err != nil || !exists {
				return fmt.Errorf("lstat %s/%s: exists=%v err=%v", dir, e.Name, exists, err)
			}
		}
	}
	return nil
}

func runW1(r *runner, p profile) error {
	if err := setupW1(r.fs, p); err != nil {
		return fmt.Errorf("W1 setup: %w", err)
	}
	walkOps := int64(p.W1Files + p.W1Dirs)
	if err := r.timePhase("W1", "walk_cold", walkOps, "fresh client caches per run",
		func(int) error { return r.fs.Fresh() },
		func(int) error { return walkW1(r.fs, p) },
	); err != nil {
		return err
	}
	if err := r.timePhase("W1", "walk_warm", walkOps, "immediately after a cold walk", nil,
		func(int) error { return walkW1(r.fs, p) },
	); err != nil {
		return err
	}
	// Real `git status` when the tree is an OS-visible directory and git exists.
	if root := r.fs.Root(); root != "" {
		if _, err := exec.LookPath("git"); err == nil {
			gitDir := root + "/w1"
			for _, args := range [][]string{
				{"init", "-q"}, {"add", "-A"},
				{"-c", "user.email=bench@pfs", "-c", "user.name=bench", "commit", "-qm", "seed"},
			} {
				cmd := exec.Command("git", args...)
				cmd.Dir = gitDir
				if out, err := cmd.CombinedOutput(); err != nil {
					return fmt.Errorf("git %v: %v: %s", args, err, out)
				}
			}
			if err := r.timePhase("W1", "git_status", int64(p.W1Files), "git status --porcelain", nil,
				func(int) error {
					cmd := exec.Command("git", "status", "--porcelain")
					cmd.Dir = gitDir
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("git status: %v: %s", err, out)
					}
					if bytes.Contains(out, []byte("fatal")) {
						return fmt.Errorf("git status: %s", out)
					}
					return nil
				},
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- W2: small-file storm (npm-ci proxy) + ENOENT probe storm ----

func runW2(r *runner, p profile) error {
	rnd := rand.New(rand.NewSource(benchSeed + 2))
	sizes := make([]int, p.W2Files)
	for i := range sizes {
		sizes[i] = 1024 + rnd.Intn(15*1024+1) // 1..16KiB
	}
	if err := r.fs.Mkdir("w2"); err != nil {
		return err
	}
	storm := func(run int) error {
		base := fmt.Sprintf("w2/run%d", run)
		if err := r.fs.Mkdir(base); err != nil {
			return err
		}
		for d := 0; d < p.W2Dirs; d++ {
			if err := r.fs.Mkdir(fmt.Sprintf("%s/pkg%03d", base, d)); err != nil {
				return err
			}
		}
		for i := 0; i < p.W2Files; i++ {
			path := fmt.Sprintf("%s/pkg%03d/mod%04d.js", base, i%p.W2Dirs, i)
			f, err := r.fs.Create(path)
			if err != nil {
				return err
			}
			if err := f.WriteAt(contentFor(sizes[i]), 0); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := r.timePhase("W2", "storm_visible", int64(p.W2Files), "create+write returned", nil, storm); err != nil {
		return err
	}
	// Time-to-durable: barrier alone, measured right after the last visible run.
	if err := r.timePhase("W2", "storm_durable", int64(p.W2Files), "durability barrier after storm",
		func(run int) error {
			return storm(run + r.n) // fresh namespace, un-flushed backlog to drain
		},
		func(int) error { return r.fs.SyncDurable() },
	); err != nil {
		return err
	}
	// npm probes many paths that do not exist (engines checks, optional deps).
	// The probed names are missing children of EXISTING directories — that is
	// npm's real shape (package.json probes inside node_modules dirs) and the
	// only shape a version-gated negative cache can serve (a negative needs a
	// parent directory version to be ordered against).
	probeDirs := p.W2Dirs
	for d := 0; d < probeDirs; d++ {
		if err := r.fs.Mkdir(fmt.Sprintf("w2/probe/pkg%03d", d)); err != nil {
			return err
		}
	}
	probe := func(int) error {
		for round := 0; round < p.W2ProbeIter; round++ {
			for i := 0; i < p.W2ProbeMiss; i++ {
				path := fmt.Sprintf("w2/probe/pkg%03d/nope%04d.json", i%probeDirs, i)
				if _, exists, err := r.fs.Lstat(path); err != nil {
					return err
				} else if exists {
					return fmt.Errorf("probe %s unexpectedly exists", path)
				}
			}
		}
		return nil
	}
	return r.timePhase("W2", "probe_miss", int64(p.W2ProbeMiss*p.W2ProbeIter), "lstat storm on missing names in existing dirs", nil, probe)
}

// ---- W3: appends to one log file ----

func runW3(r *runner, p profile) error {
	if err := r.fs.Mkdir("w3"); err != nil {
		return err
	}
	chunk := contentFor(p.W3ChunkB)
	return r.timePhase("W3", "append", int64(p.W3Appends), "sequential appends to one log", nil,
		func(run int) error {
			f, err := r.fs.Create(fmt.Sprintf("w3/run%d.log", run))
			if err != nil {
				return err
			}
			off := int64(0)
			for i := 0; i < p.W3Appends; i++ {
				if err := f.WriteAt(chunk, off); err != nil {
					_ = f.Close()
					return err
				}
				off += int64(len(chunk))
			}
			if err := f.Close(); err != nil {
				return err
			}
			return r.fs.SyncDurable()
		},
	)
}

// ---- W4: grep (walk + read all bytes of the W1 tree) ----

func runW4(r *runner, p profile) error {
	// W4 scans the W1 tree; build it if this invocation skipped W1.
	if _, exists, err := r.fs.Lstat("w1"); err != nil {
		return err
	} else if !exists {
		if err := setupW1(r.fs, p); err != nil {
			return fmt.Errorf("W4 setup (w1 tree): %w", err)
		}
	}
	needle := []byte("PORTABLEFS_NEEDLE")
	scan := func(int) error {
		dirs, files := w1Paths(p)
		buf := make([]byte, 1<<20)
		matches := 0
		for _, dir := range dirs {
			for _, name := range files[dir] {
				f, err := r.fs.Open(dir + "/" + name)
				if err != nil {
					return err
				}
				n, err := f.ReadAt(buf, 0)
				if err != nil {
					_ = f.Close()
					return err
				}
				if bytes.Contains(buf[:n], needle) {
					matches++
				}
				if err := f.Close(); err != nil {
					return err
				}
			}
		}
		_ = matches
		return nil
	}
	if err := r.timePhase("W4", "grep_cold", int64(p.W1Files), "fresh client caches per run",
		func(int) error { return r.fs.Fresh() }, scan,
	); err != nil {
		return err
	}
	return r.timePhase("W4", "grep_warm", int64(p.W1Files), "immediately after a cold scan", nil, scan)
}

// ---- W5: sequential large write + cold read ----

func runW5(r *runner, p profile) error {
	if err := r.fs.Mkdir("w5"); err != nil {
		return err
	}
	mib := contentFor(1 << 20)
	write := func(run int) error {
		f, err := r.fs.Create(fmt.Sprintf("w5/run%d.bin", run))
		if err != nil {
			return err
		}
		for i := 0; i < p.W5MiB; i++ {
			if err := f.WriteAt(mib, int64(i)<<20); err != nil {
				_ = f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
		return r.fs.SyncDurable()
	}
	if err := r.timePhase("W5", "write_seq", int64(p.W5MiB), "1MiB chunks + durability barrier", nil, write); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	return r.timePhase("W5", "read_seq_cold", int64(p.W5MiB), "fresh client caches; 1MiB chunks",
		func(int) error { return r.fs.Fresh() },
		func(run int) error {
			f, err := r.fs.Open(fmt.Sprintf("w5/run%d.bin", run%r.n))
			if err != nil {
				return err
			}
			defer f.Close()
			for i := 0; i < p.W5MiB; i++ {
				n, err := f.ReadAt(buf, int64(i)<<20)
				if err != nil {
					return err
				}
				if n != len(buf) {
					return fmt.Errorf("short read at MiB %d: %d", i, n)
				}
			}
			return nil
		},
	)
}
