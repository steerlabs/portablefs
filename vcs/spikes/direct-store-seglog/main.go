// Command seglog-writeamp measures the physical write amplification,
// durability latency, read latency, recovery time, index footprint, and
// steady-state cleaning cost of a segmented append-only mutation/value log
// with a rebuildable index over log offsets.
//
// It is a measurement spike, not a filesystem prototype. It does not serve
// fsproto, implement consensus, or change a production storage path. Its
// workloads, key encoding, and logical mutation sequence are copied from
// vcs/spikes/direct-store-writeamp so the numbers line up row by row.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type config struct {
	mode    string
	sizes   []int
	engines []string
	ops     int
	reps    int
	out     string
	work    string
	keep    bool
	seed    uint64
	pretty  bool

	liveCells    int
	warmupTurns  float64
	measureTurns float64
	utilizations []float64
	groupBytes   int
	batchSizes   []int
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fatal(err)
	}
	switch cfg.mode {
	case "table":
		err = runTable(cfg)
	case "steady":
		err = runSteady(cfg)
	case "micro":
		err = runMicro(cfg)
	default:
		err = fmt.Errorf("unknown mode %q", cfg.mode)
	}
	if err != nil {
		fatal(err)
	}
}

func parseFlags() (config, error) {
	var sizes, engines, utilizations, batches string
	var cfg config
	flag.StringVar(&cfg.mode, "mode", "table", "table, steady, or micro")
	flag.StringVar(&sizes, "sizes", "128,4096,65536,524288", "comma-separated baseline file counts")
	flag.StringVar(&engines, "engines", "seglog,pebble", "comma-separated engines")
	flag.IntVar(&cfg.ops, "ops", 32, "operations per non-mixed workload")
	flag.IntVar(&cfg.reps, "reps", 3, "repetitions per point")
	flag.StringVar(&cfg.out, "out", "results.csv", "raw CSV output")
	flag.StringVar(&cfg.work, "work", "", "working directory (default: temporary directory)")
	flag.BoolVar(&cfg.keep, "keep", false, "keep engine files")
	flag.Uint64Var(&cfg.seed, "seed", 0x50465432, "deterministic workload seed")
	flag.BoolVar(&cfg.pretty, "print", true, "print each measurement")
	flag.IntVar(&cfg.liveCells, "live-cells", 262144, "steady mode: live 4 KiB values (262144 = 1 GiB)")
	flag.Float64Var(&cfg.warmupTurns, "warmup-turns", 2, "steady mode: working-set turnovers before measuring")
	flag.Float64Var(&cfg.measureTurns, "measure-turns", 3, "steady mode: measured working-set turnovers")
	flag.StringVar(&utilizations, "utilizations", "0.7,0.8,0.9", "steady mode: live/total occupancy targets")
	flag.IntVar(&cfg.groupBytes, "group-bytes", 1<<20, "group commit byte threshold")
	flag.StringVar(&batches, "batch-sizes", "1,2,4,8,16,32,64,128,256", "micro mode: operations per durability barrier")
	flag.Parse()

	if cfg.ops <= 0 || cfg.reps <= 0 {
		return config{}, fmt.Errorf("ops and reps must be positive")
	}
	for _, raw := range strings.Split(sizes, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 2 {
			return config{}, fmt.Errorf("invalid size %q (each size must be at least 2)", raw)
		}
		cfg.sizes = append(cfg.sizes, n)
	}
	sort.Ints(cfg.sizes)
	for _, raw := range strings.Split(engines, ",") {
		name := strings.TrimSpace(raw)
		if name != "seglog" && name != "pebble" {
			return config{}, fmt.Errorf("invalid engine %q", name)
		}
		cfg.engines = append(cfg.engines, name)
	}
	for _, raw := range strings.Split(utilizations, ",") {
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || value <= 0 || value >= 1 {
			return config{}, fmt.Errorf("invalid utilization %q", raw)
		}
		cfg.utilizations = append(cfg.utilizations, value)
	}
	for _, raw := range strings.Split(batches, ",") {
		value, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || value <= 0 {
			return config{}, fmt.Errorf("invalid batch size %q", raw)
		}
		cfg.batchSizes = append(cfg.batchSizes, value)
	}
	return cfg, nil
}

func prepareWorkDir(cfg config) (string, func(), error) {
	if cfg.work != "" {
		if err := os.MkdirAll(cfg.work, 0o755); err != nil {
			return "", nil, err
		}
		return cfg.work, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "portablefs-seglog-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {}
	if !cfg.keep {
		cleanup = func() { os.RemoveAll(dir) }
	}
	return dir, cleanup, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func microseconds(d time.Duration) string {
	return strconv.FormatFloat(float64(d.Nanoseconds())/1000.0, 'f', 3, 64)
}
