package main

import (
	"encoding/csv"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/spikes/direct-store-seglog/seglog"
)

// steadySegmentBytes is small enough that a one-gibibyte live set spans tens
// of segments, so the cleaner has real choices instead of one candidate.
const steadySegmentBytes = 16 << 20

// measurementWindows splits the measured phase so convergence is visible
// rather than assumed.
const measurementWindows = 3

type steadyResult struct {
	Engine       string
	Utilization  float64
	LiveCells    int
	Phase        string
	Window       int
	Operations   int
	LogicalBytes uint64
	KernelBytes  uint64
	Appended     uint64
	CleanCopied  uint64
	CleanPasses  uint64
	Reclaimed    uint64
	IndexBytes   int64
	StoreBytes   int64
	LiveBytes    int64
	TotalBytes   int64
	CompactBytes uint64
	FlushBytes   uint64
	WALBytes     uint64
	AdmitWaitNs  uint64
	AdmitOverrun uint64
	Duration     time.Duration
}

func runSteady(cfg config) error {
	workDir, cleanup, err := prepareWorkDir(cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err := diskBytesWritten(); err != nil {
		return fmt.Errorf("kernel disk accounting: %w", err)
	}

	var results []steadyResult
	for _, name := range cfg.engines {
		utilizations := cfg.utilizations
		if name == "pebble" {
			// Utilization is a cleaner parameter. The control engine has no
			// cleaner, so it runs once.
			utilizations = cfg.utilizations[:1]
		}
		for _, utilization := range utilizations {
			points, err := measureSteadyPoint(cfg, workDir, name, utilization)
			if err != nil {
				return err
			}
			results = append(results, points...)
		}
	}
	return writeSteadyResults(cfg.out, results)
}

func measureSteadyPoint(cfg config, workDir, name string, utilization float64) ([]steadyResult, error) {
	dir := filepath.Join(workDir, fmt.Sprintf("steady-%s-%02d", name, int(utilization*100)))
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	store, err := openSteadyEngine(name, dir, utilization, cfg.groupBytes)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	fmt.Fprintf(os.Stderr, "steady %s u=%.2f: filling %d live cells (%d MiB)\n",
		name, utilization, cfg.liveCells, int64(cfg.liveCells)*pft2.CellBytes>>20)
	for i := 0; i < cfg.liveCells; i++ {
		if err := store.Put(cellKey(2, uint64(i)*pft2.CellBytes), dataCell(i, uint64(i))); err != nil {
			return nil, err
		}
	}
	if err := store.Barrier(); err != nil {
		return nil, err
	}

	rng := rand.New(rand.NewPCG(cfg.seed, cfg.seed^0x243f6a8885a308d3))
	// Both engines take a durability barrier on the same cadence, so the
	// comparison is between formats rather than between commit policies. For
	// the segmented log the group is already full at that point, so the
	// explicit barrier adds no extra fsync.
	barrierEvery := cfg.groupBytes / pft2.CellBytes
	if barrierEvery < 1 {
		barrierEvery = 1
	}
	progress := time.Now()
	overwrite := func(operations int) error {
		for op := 0; op < operations; op++ {
			if time.Since(progress) > 15*time.Second {
				progress = time.Now()
				if seg, ok := store.(*seglogEngine); ok {
					live, total, segments, reclaimed := seg.store.SpacePressure()
					st := seg.store.Stats()
					fmt.Fprintf(os.Stderr,
						"  ..op=%d live=%d total=%d occ=%.3f segments=%d reclaimed=%d retries=%d corrections=%d/%d wait=%dms over=%d\n",
						op, live, total, float64(live)/float64(total), segments, reclaimed,
						st.CleanRetries, st.LiveCorrections, st.LiveCorrectedBytes,
						st.AdmitWaitNanos/1e6, st.AdmitOverruns)
				} else {
					fmt.Fprintf(os.Stderr, "  ..op=%d\n", op)
				}
			}
			index := rng.IntN(cfg.liveCells)
			if err := store.Put(cellKey(2, uint64(index)*pft2.CellBytes), dataCell(op, uint64(index))); err != nil {
				return err
			}
			if (op+1)%barrierEvery == 0 {
				if err := store.Barrier(); err != nil {
					return err
				}
			}
		}
		return store.Barrier()
	}

	var results []steadyResult
	warmupOps := int(cfg.warmupTurns * float64(cfg.liveCells))
	fmt.Fprintf(os.Stderr, "steady %s u=%.2f: warmup %d overwrites\n", name, utilization, warmupOps)
	warm, err := measureWindow(store, name, utilization, cfg.liveCells, "warmup", 0, warmupOps, overwrite)
	if err != nil {
		return nil, err
	}
	results = append(results, warm)
	printSteady(warm)

	windowOps := int(cfg.measureTurns*float64(cfg.liveCells)) / measurementWindows
	for window := 1; window <= measurementWindows; window++ {
		point, err := measureWindow(store, name, utilization, cfg.liveCells, "steady", window, windowOps, overwrite)
		if err != nil {
			return nil, err
		}
		results = append(results, point)
		printSteady(point)
	}

	// Any cleaning or compaction debt still outstanding is charged here, so no
	// deferred work escapes the accounting.
	drain, err := measureWindow(store, name, utilization, cfg.liveCells, "drain", 0, 0, func(int) error {
		if seg, ok := store.(*seglogEngine); ok {
			for pass := 0; pass < 64; pass++ {
				if err := seg.store.Clean(); err != nil {
					return err
				}
				stats := seg.store.Stats()
				if stats.TotalBytes == 0 || float64(stats.LiveBytes) >= utilization*float64(stats.TotalBytes) {
					break
				}
			}
			return seg.store.FlushIndex()
		}
		if peb, ok := store.(*pebbleEngine); ok {
			return peb.db.Flush()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	results = append(results, drain)
	printSteady(drain)
	return results, nil
}

func openSteadyEngine(name, dir string, utilization float64, groupBytes int) (engine, error) {
	switch name {
	case "seglog":
		store, err := seglog.Open(seglog.Options{
			Dir:              dir,
			SegmentBytes:     steadySegmentBytes,
			GroupInterval:    time.Millisecond,
			GroupBytes:       groupBytes,
			PersistIndex:     true,
			IndexOpener:      openPebbleIndex,
			CleanUtilization: utilization,
			CleanInterval:    20 * time.Millisecond,
		})
		if err != nil {
			return nil, err
		}
		return &seglogEngine{store: store, dir: dir}, nil
	case "pebble":
		return openPebbleEngine(dir)
	default:
		return nil, fmt.Errorf("unknown engine %q", name)
	}
}

func measureWindow(
	store engine, name string, utilization float64, liveCells int,
	phase string, window, operations int, run func(int) error,
) (steadyResult, error) {
	var beforeStats seglog.Stats
	var beforeMetrics *pebble.Metrics
	if seg, ok := store.(*seglogEngine); ok {
		beforeStats = seg.store.Stats()
	}
	if peb, ok := store.(*pebbleEngine); ok {
		beforeMetrics = peb.db.Metrics()
	}
	before, err := diskBytesWritten()
	if err != nil {
		return steadyResult{}, err
	}
	started := time.Now()
	if err := run(operations); err != nil {
		return steadyResult{}, err
	}
	elapsed := time.Since(started)
	after, err := diskBytesWritten()
	if err != nil {
		return steadyResult{}, err
	}

	result := steadyResult{
		Engine: name, Utilization: utilization, LiveCells: liveCells, Phase: phase, Window: window,
		Operations: operations, LogicalBytes: uint64(operations) * pft2.CellBytes,
		KernelBytes: after - before, Duration: elapsed,
	}
	if seg, ok := store.(*seglogEngine); ok {
		stats := seg.store.Stats()
		result.Appended = stats.AppendedBytes - beforeStats.AppendedBytes
		result.CleanCopied = stats.CleanCopiedBytes - beforeStats.CleanCopiedBytes
		result.CleanPasses = stats.CleanPasses - beforeStats.CleanPasses
		result.Reclaimed = stats.ReclaimedBytes - beforeStats.ReclaimedBytes
		result.AdmitWaitNs = stats.AdmitWaitNanos - beforeStats.AdmitWaitNanos
		result.AdmitOverrun = stats.AdmitOverruns - beforeStats.AdmitOverruns
		result.LiveBytes = stats.LiveBytes
		result.TotalBytes = stats.TotalBytes
		indexBytes, err := directoryBytes(filepath.Join(seg.dir, "index"))
		if err != nil {
			return steadyResult{}, err
		}
		result.IndexBytes = indexBytes
	}
	if peb, ok := store.(*pebbleEngine); ok {
		metrics := peb.db.Metrics()
		result.CompactBytes = metrics.Total().TableBytesCompacted - beforeMetrics.Total().TableBytesCompacted
		result.FlushBytes = metrics.Total().TableBytesFlushed - beforeMetrics.Total().TableBytesFlushed
		result.WALBytes = metrics.WAL.BytesWritten - beforeMetrics.WAL.BytesWritten
		result.IndexBytes = -1
	}
	total, err := store.DiskBytes()
	if err != nil {
		return steadyResult{}, err
	}
	result.StoreBytes = total
	return result, nil
}

func printSteady(r steadyResult) {
	amp := "n/a"
	if r.LogicalBytes > 0 {
		amp = fmt.Sprintf("%.3fx", float64(r.KernelBytes)/float64(r.LogicalBytes))
	}
	occupancy := "n/a"
	if r.TotalBytes > 0 {
		occupancy = fmt.Sprintf("%.3f", float64(r.LiveBytes)/float64(r.TotalBytes))
	}
	var throughput float64
	if r.Duration > 0 {
		throughput = float64(r.LogicalBytes) / (1 << 20) / r.Duration.Seconds()
	}
	fmt.Fprintf(os.Stderr,
		"%-7s u=%.2f %-7s w=%d ops=%-9d disk=%-12d amp=%-9s clean=%-12d occ=%s store=%-11d %6.1f MiB/s wait=%dms over=%d\n",
		r.Engine, r.Utilization, r.Phase, r.Window, r.Operations, r.KernelBytes, amp, r.CleanCopied,
		occupancy, r.StoreBytes, throughput, r.AdmitWaitNs/1e6, r.AdmitOverrun)
}

func writeSteadyResults(path string, results []steadyResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	header := []string{
		"engine", "target_utilization", "live_cells", "phase", "window", "operations", "logical_bytes",
		"kernel_disk_bytes", "kernel_amplification", "three_way_kernel_amplification", "kernel_bytes_per_op",
		"foreground_appended_bytes", "clean_copied_bytes", "clean_passes", "reclaimed_bytes",
		"index_disk_bytes", "store_disk_bytes", "live_bytes", "total_log_bytes", "occupancy",
		"space_amplification", "pebble_compacted_bytes", "pebble_flush_bytes", "pebble_wal_bytes",
		"duration_ms", "logical_mib_per_s", "admit_wait_ms", "admit_overruns",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		amp, quorum, perOp, throughput := "", "", "", ""
		if r.LogicalBytes > 0 {
			amp = strconv.FormatFloat(float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
			quorum = strconv.FormatFloat(3*float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
		}
		if r.Operations > 0 {
			perOp = strconv.FormatFloat(float64(r.KernelBytes)/float64(r.Operations), 'f', 3, 64)
		}
		if r.Duration > 0 {
			throughput = strconv.FormatFloat(float64(r.LogicalBytes)/(1<<20)/r.Duration.Seconds(), 'f', 3, 64)
		}
		occupancy, spaceAmp := "", ""
		if r.TotalBytes > 0 {
			occupancy = strconv.FormatFloat(float64(r.LiveBytes)/float64(r.TotalBytes), 'f', 6, 64)
		}
		if r.LiveBytes > 0 {
			spaceAmp = strconv.FormatFloat(float64(r.StoreBytes)/float64(r.LiveBytes), 'f', 6, 64)
		}
		record := []string{
			r.Engine, strconv.FormatFloat(r.Utilization, 'f', 2, 64), strconv.Itoa(r.LiveCells), r.Phase,
			strconv.Itoa(r.Window), strconv.Itoa(r.Operations), strconv.FormatUint(r.LogicalBytes, 10),
			strconv.FormatUint(r.KernelBytes, 10), amp, quorum, perOp,
			strconv.FormatUint(r.Appended, 10), strconv.FormatUint(r.CleanCopied, 10),
			strconv.FormatUint(r.CleanPasses, 10), strconv.FormatUint(r.Reclaimed, 10),
			strconv.FormatInt(r.IndexBytes, 10), strconv.FormatInt(r.StoreBytes, 10),
			strconv.FormatInt(r.LiveBytes, 10), strconv.FormatInt(r.TotalBytes, 10), occupancy, spaceAmp,
			strconv.FormatUint(r.CompactBytes, 10), strconv.FormatUint(r.FlushBytes, 10),
			strconv.FormatUint(r.WALBytes, 10),
			strconv.FormatInt(r.Duration.Milliseconds(), 10), throughput,
			strconv.FormatUint(r.AdmitWaitNs/1e6, 10), strconv.FormatUint(r.AdmitOverrun, 10),
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
