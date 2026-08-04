package main

import (
	"encoding/csv"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/spikes/direct-store-seglog/seglog"
)

type microResult struct {
	Experiment   string
	Engine       string
	Parameter    string
	Samples      int
	LogicalBytes uint64
	KernelBytes  uint64
	Duration     time.Duration
	P50          time.Duration
	P95          time.Duration
	P99          time.Duration
	Max          time.Duration
	Extra        string
}

const microKeys = 262144 // 1 GiB of 4 KiB values

func runMicro(cfg config) error {
	workDir, cleanup, err := prepareWorkDir(cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err := diskBytesWritten(); err != nil {
		return fmt.Errorf("kernel disk accounting: %w", err)
	}

	var results []microResult
	floor, err := measureSyncFloor(workDir)
	if err != nil {
		return err
	}
	results = append(results, floor...)

	batch, err := measureBatchBenefit(cfg, workDir)
	if err != nil {
		return err
	}
	results = append(results, batch...)

	lifecycle, err := measureLifecycle(cfg, workDir)
	if err != nil {
		return err
	}
	results = append(results, lifecycle...)

	for _, r := range results {
		printMicro(r)
	}
	return writeMicroResults(cfg.out, results)
}

// measureSyncFloor establishes what the filesystem itself charges for one
// durable append. Nothing built on top of APFS can be cheaper than this, so it
// is the physical ceiling on any per-operation amplification gate.
func measureSyncFloor(workDir string) ([]microResult, error) {
	sizes := []int{0, 64, 512, 4096, 16384, 65536, 262144, 1 << 20}
	iterations := 128
	var results []microResult
	for _, size := range sizes {
		path := filepath.Join(workDir, fmt.Sprintf("floor-%d.log", size))
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		latencies := make([]time.Duration, 0, iterations)
		before, err := diskBytesWritten()
		if err != nil {
			return nil, err
		}
		started := time.Now()
		for i := 0; i < iterations; i++ {
			if size > 0 {
				if _, err := file.Write(payload); err != nil {
					return nil, err
				}
			}
			syncStarted := time.Now()
			if err := file.Sync(); err != nil {
				return nil, err
			}
			latencies = append(latencies, time.Since(syncStarted))
		}
		elapsed := time.Since(started)
		after, err := diskBytesWritten()
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		p50, p95, p99, max := latencyPercentiles(latencies)
		results = append(results, microResult{
			Experiment: "fsync-floor", Engine: "apfs", Parameter: strconv.Itoa(size),
			Samples: iterations, LogicalBytes: uint64(size * iterations), KernelBytes: after - before,
			Duration: elapsed, P50: p50, P95: p95, P99: p99, Max: max,
			Extra: "append bytes per durable barrier",
		})
	}
	return results, nil
}

// measureBatchBenefit varies how many logical operations share one durability
// barrier. It answers how much of the per-operation cost is the format and how
// much is the commit boundary.
func measureBatchBenefit(cfg config, workDir string) ([]microResult, error) {
	const operations = 8192
	var results []microResult
	for _, batch := range cfg.batchSizes {
		dir := filepath.Join(workDir, fmt.Sprintf("batch-%d", batch))
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
		store, err := seglog.Open(seglog.Options{
			Dir: dir, SegmentBytes: steadySegmentBytes, GroupInterval: time.Hour,
			GroupBytes: 1 << 30, PersistIndex: true, IndexOpener: openPebbleIndex,
		})
		if err != nil {
			return nil, err
		}
		rng := rand.New(rand.NewPCG(cfg.seed, uint64(batch)))
		before, err := diskBytesWritten()
		if err != nil {
			return nil, err
		}
		started := time.Now()
		for op := 0; op < operations; op++ {
			index := rng.IntN(operations)
			if err := store.Put(cellKey(2, uint64(index)*pft2.CellBytes), dataCell(op, uint64(index))); err != nil {
				return nil, err
			}
			if (op+1)%batch == 0 {
				if err := store.Barrier(); err != nil {
					return nil, err
				}
			}
		}
		if err := store.Barrier(); err != nil {
			return nil, err
		}
		elapsed := time.Since(started)
		after, err := diskBytesWritten()
		if err != nil {
			return nil, err
		}
		latencies := store.SyncLatencies()
		stats := store.Stats()
		if err := store.Close(); err != nil {
			return nil, err
		}
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
		p50, p95, p99, max := latencyPercentiles(latencies)
		results = append(results, microResult{
			Experiment: "batch-benefit", Engine: "seglog", Parameter: strconv.Itoa(batch),
			Samples: operations, LogicalBytes: uint64(operations) * pft2.CellBytes,
			KernelBytes: after - before, Duration: elapsed, P50: p50, P95: p95, P99: p99, Max: max,
			Extra: fmt.Sprintf("groups=%d appended=%d", stats.Groups, stats.AppendedBytes),
		})
	}
	return results, nil
}

// measureLifecycle covers read latency through the log-backed index, recovery
// time on both paths, and the in-memory index footprint.
func measureLifecycle(cfg config, workDir string) ([]microResult, error) {
	dir := filepath.Join(workDir, "lifecycle")
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	store, err := seglog.Open(seglog.Options{
		Dir: dir, SegmentBytes: steadySegmentBytes, GroupInterval: time.Millisecond,
		GroupBytes: cfg.groupBytes, PersistIndex: true, IndexOpener: openPebbleIndex,
	})
	if err != nil {
		return nil, err
	}
	for i := 0; i < microKeys; i++ {
		if err := store.Put(cellKey(2, uint64(i)*pft2.CellBytes), dataCell(i, uint64(i))); err != nil {
			return nil, err
		}
	}
	if err := store.Barrier(); err != nil {
		return nil, err
	}
	if err := store.Close(); err != nil {
		return nil, err
	}

	var results []microResult

	runtime.GC()
	var beforeMem runtime.MemStats
	runtime.ReadMemStats(&beforeMem)
	fullStarted := time.Now()
	full, err := seglog.Open(seglog.Options{
		Dir: dir, SegmentBytes: steadySegmentBytes, PersistIndex: true, IndexOpener: openPebbleIndex,
		FastRecovery: false,
	})
	if err != nil {
		return nil, err
	}
	fullElapsed := time.Since(fullStarted)
	runtime.GC()
	var afterMem runtime.MemStats
	runtime.ReadMemStats(&afterMem)
	report := full.Recovery()
	indexResident := int64(afterMem.HeapAlloc) - int64(beforeMem.HeapAlloc)
	results = append(results, microResult{
		Experiment: "recovery", Engine: "seglog", Parameter: "full-scan", Samples: report.Keys,
		Duration: fullElapsed, P50: report.Duration,
		Extra: fmt.Sprintf("scanned=%d segments=%d keys=%d", report.BytesScanned, report.Segments, report.Keys),
	})
	results = append(results, microResult{
		Experiment: "index-memory", Engine: "seglog", Parameter: "in-memory-map", Samples: report.Keys,
		Extra: fmt.Sprintf("heap_delta_bytes=%d bytes_per_key=%.1f", indexResident, float64(indexResident)/float64(max(report.Keys, 1))),
	})

	// Warm read latency through the index and into the log.
	rng := rand.New(rand.NewPCG(cfg.seed, 0x9e3779b97f4a7c15))
	const reads = 20000
	latencies := make([]time.Duration, 0, reads)
	readStarted := time.Now()
	for i := 0; i < reads; i++ {
		key := cellKey(2, uint64(rng.IntN(microKeys))*pft2.CellBytes)
		started := time.Now()
		value, found, err := full.Get(key)
		if err != nil {
			return nil, err
		}
		latencies = append(latencies, time.Since(started))
		if !found || len(value) != pft2.CellBytes {
			return nil, fmt.Errorf("read of %q returned found=%v len=%d", key, found, len(value))
		}
	}
	readElapsed := time.Since(readStarted)
	p50, p95, p99, maxLatency := latencyPercentiles(latencies)
	results = append(results, microResult{
		Experiment: "read-latency", Engine: "seglog", Parameter: "random-point-read",
		Samples: reads, Duration: readElapsed, P50: p50, P95: p95, P99: p99, Max: maxLatency,
		Extra: "page cache warm; index lookup plus one pread",
	})
	if err := full.Close(); err != nil {
		return nil, err
	}

	fastStarted := time.Now()
	fast, err := seglog.Open(seglog.Options{
		Dir: dir, SegmentBytes: steadySegmentBytes, PersistIndex: true, IndexOpener: openPebbleIndex,
		FastRecovery: true,
	})
	if err != nil {
		return nil, err
	}
	fastElapsed := time.Since(fastStarted)
	fastReport := fast.Recovery()
	if fastReport.Keys != report.Keys {
		return nil, fmt.Errorf("fast recovery produced %d keys, full scan produced %d", fastReport.Keys, report.Keys)
	}
	results = append(results, microResult{
		Experiment: "recovery", Engine: "seglog", Parameter: "index+tail", Samples: fastReport.Keys,
		Duration: fastElapsed, P50: fastReport.Duration,
		Extra: fmt.Sprintf("scanned=%d index_entries=%d keys=%d", fastReport.BytesScanned, fastReport.IndexEntries, fastReport.Keys),
	})
	if err := fast.Close(); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	return results, nil
}

func latencyPercentiles(samples []time.Duration) (p50, p95, p99, maximum time.Duration) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(fraction float64) time.Duration {
		return sorted[int(fraction*float64(len(sorted)-1))]
	}
	return pick(0.50), pick(0.95), pick(0.99), sorted[len(sorted)-1]
}

func printMicro(r microResult) {
	amp := "n/a"
	if r.LogicalBytes > 0 {
		amp = fmt.Sprintf("%.3fx", float64(r.KernelBytes)/float64(r.LogicalBytes))
	}
	fmt.Fprintf(os.Stderr, "%-14s %-8s %-18s n=%-8d disk=%-12d amp=%-9s p50=%-10s p99=%-10s %s\n",
		r.Experiment, r.Engine, r.Parameter, r.Samples, r.KernelBytes, amp,
		microseconds(r.P50), microseconds(r.P99), r.Extra)
}

func writeMicroResults(path string, results []microResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	header := []string{
		"experiment", "engine", "parameter", "samples", "logical_bytes", "kernel_disk_bytes",
		"kernel_amplification", "kernel_bytes_per_sample", "duration_ms",
		"p50_us", "p95_us", "p99_us", "max_us", "notes", "go_version", "os", "arch",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		amp, perSample := "", ""
		if r.LogicalBytes > 0 {
			amp = strconv.FormatFloat(float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
		}
		if r.Samples > 0 {
			perSample = strconv.FormatFloat(float64(r.KernelBytes)/float64(r.Samples), 'f', 3, 64)
		}
		record := []string{
			r.Experiment, r.Engine, r.Parameter, strconv.Itoa(r.Samples),
			strconv.FormatUint(r.LogicalBytes, 10), strconv.FormatUint(r.KernelBytes, 10),
			amp, perSample, strconv.FormatInt(r.Duration.Milliseconds(), 10),
			microseconds(r.P50), microseconds(r.P95), microseconds(r.P99), microseconds(r.Max),
			r.Extra, runtime.Version(), runtime.GOOS, runtime.GOARCH,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}
