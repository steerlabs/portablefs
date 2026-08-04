package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/steerlabs/portablefs/vcs/spikes/direct-store-seglog/seglog"
)

const (
	seglogVersion = "spike"
	pebbleVersion = "v2.1.6"
)

type tableResult struct {
	Engine         string
	EngineVersion  string
	TreeFiles      int
	Workload       string
	Rep            int
	Operations     int
	LogicalBytes   uint64
	FormatBytes    int64
	PathWriteBytes int64
	KernelBytes    uint64
	Duration       time.Duration
	Groups         uint64
	CleanBytes     uint64
	IndexBytes     int64
	StoreBytes     int64
	SyncP50        time.Duration
	SyncP99        time.Duration
	SyncMax        time.Duration
}

func runTable(cfg config) error {
	workDir, cleanup, err := prepareWorkDir(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	if _, err := diskBytesWritten(); err != nil {
		return fmt.Errorf("kernel disk accounting: %w", err)
	}

	var results []tableResult
	for _, size := range cfg.sizes {
		templates := map[string]string{}
		for _, name := range cfg.engines {
			fmt.Fprintf(os.Stderr, "building %s baseline for %d files\n", name, size)
			dir := filepath.Join(workDir, fmt.Sprintf("template-%s-%d", name, size))
			if err := buildTemplate(name, dir, size); err != nil {
				return fmt.Errorf("build %s baseline size %d: %w", name, size, err)
			}
			templates[name] = dir
		}
		for _, workload := range workloads {
			for rep := 1; rep <= cfg.reps; rep++ {
				seed := cfg.seed ^ uint64(size)<<17 ^ uint64(rep)<<41 ^ workloadSeed(workload)
				for _, name := range cfg.engines {
					result, err := measureTablePoint(workDir, templates[name], name, size, workload, cfg.ops, rep, seed)
					if err != nil {
						return err
					}
					results = append(results, result)
					if cfg.pretty {
						printTableResult(result)
					}
				}
			}
		}
		for _, dir := range templates {
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
		}
		runtime.GC()
	}
	return writeTableResults(cfg.out, results)
}

func buildTemplate(name, dir string, fileCount int) error {
	store, err := openEngine(name, dir, engineOptions{})
	if err != nil {
		return err
	}
	root := inodeValue{Kind: 2, Mode: 0o755}
	if err := store.Put(inodeKey(1), encodeInodeValue(root)); err != nil {
		return err
	}
	for i := 0; i < fileCount; i++ {
		ino := uint64(i + 2)
		size := sparseFileBytes
		if i == 0 {
			size = 0
		}
		if err := store.Put(inodeKey(ino), encodeInodeValue(inodeValue{Kind: 1, Mode: 0o644, Size: size})); err != nil {
			return err
		}
		if err := store.Put(dirKey(1, baseName(i)), encodeDirValue(ino, 1)); err != nil {
			return err
		}
	}
	if err := store.Barrier(); err != nil {
		return err
	}
	// Leave no deferred index work behind: the measured window must be charged
	// only for the mutations it performs, not for fixture construction.
	if err := store.Settle(); err != nil {
		return err
	}
	return store.Close()
}

type engineOptions struct {
	fastRecovery     bool
	cleanUtilization float64
	groupBytes       int
	groupInterval    time.Duration
}

func openEngine(name, dir string, opts engineOptions) (engine, error) {
	switch name {
	case "seglog":
		store, err := seglog.Open(seglog.Options{
			Dir:              dir,
			SegmentBytes:     64 << 20,
			GroupInterval:    orDuration(opts.groupInterval, time.Millisecond),
			GroupBytes:       orInt(opts.groupBytes, 1<<20),
			PersistIndex:     true,
			IndexOpener:      openPebbleIndex,
			FastRecovery:     opts.fastRecovery,
			CleanUtilization: opts.cleanUtilization,
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

func orDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func orInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func measureTablePoint(workDir, template, name string, fileCount int, workload string, ops, rep int, seed uint64) (tableResult, error) {
	dir := filepath.Join(workDir, fmt.Sprintf("run-%s-%d-%s-%d", name, fileCount, workload, rep))
	if err := os.RemoveAll(dir); err != nil {
		return tableResult{}, err
	}
	if err := copyTree(template, dir); err != nil {
		return tableResult{}, err
	}
	store, err := openEngine(name, dir, engineOptions{fastRecovery: true, cleanUtilization: 0.8})
	if err != nil {
		return tableResult{}, err
	}
	state := newMutationState(fileCount, seed)
	operations := measuredOperations(workload, ops)

	before, err := diskBytesWritten()
	if err != nil {
		return tableResult{}, err
	}
	started := time.Now()
	var logical uint64
	for op := 0; op < operations; op++ {
		written, err := applyMutation(store, state, operationKind(workload, op), op)
		if err != nil {
			return tableResult{}, fmt.Errorf("%s %s size %d op %d: %w", name, workload, fileCount, op, err)
		}
		if err := store.Barrier(); err != nil {
			return tableResult{}, err
		}
		logical += written
	}
	result := tableResult{
		Engine: name, TreeFiles: fileCount, Workload: workload, Rep: rep,
		Operations: operations, LogicalBytes: logical,
	}
	if seg, ok := store.(*seglogEngine); ok {
		stats := seg.store.Stats()
		result.FormatBytes = int64(stats.LogicalBytes)
		result.PathWriteBytes = int64(stats.AppendedBytes)
		result.Groups = stats.Groups
		result.CleanBytes = stats.CleanCopiedBytes
		result.SyncP50, result.SyncP99, result.SyncMax = percentiles(seg.store.SyncLatencies())
		result.EngineVersion = seglogVersion
	} else {
		result.FormatBytes = -1
		result.PathWriteBytes = -1
		result.EngineVersion = pebbleVersion
	}
	if err := store.Close(); err != nil {
		return tableResult{}, err
	}
	result.Duration = time.Since(started)
	after, err := diskBytesWritten()
	if err != nil {
		return tableResult{}, err
	}
	result.KernelBytes = after - before
	total, err := directoryBytes(dir)
	if err != nil {
		return tableResult{}, err
	}
	result.StoreBytes = total
	if name == "seglog" {
		indexBytes, err := directoryBytes(filepath.Join(dir, "index"))
		if err != nil {
			return tableResult{}, err
		}
		result.IndexBytes = indexBytes
	} else {
		result.IndexBytes = -1
	}
	if err := os.RemoveAll(dir); err != nil {
		return tableResult{}, err
	}
	return result, nil
}

func percentiles(samples []time.Duration) (p50, p99, max time.Duration) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(fraction float64) time.Duration {
		index := int(fraction * float64(len(sorted)-1))
		return sorted[index]
	}
	return pick(0.50), pick(0.99), sorted[len(sorted)-1]
}

func copyTree(source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFileSynced(path, target)
	})
}

func copyFileSynced(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func printTableResult(r tableResult) {
	amp := "n/a"
	if r.LogicalBytes > 0 {
		amp = fmt.Sprintf("%.2fx", float64(r.KernelBytes)/float64(r.LogicalBytes))
	}
	fmt.Fprintf(os.Stderr, "%-7s files=%-7d %-17s rep=%d disk=%-10d amp=%-9s groups=%d\n",
		r.Engine, r.TreeFiles, r.Workload, r.Rep, r.KernelBytes, amp, r.Groups)
}

func writeTableResults(path string, results []tableResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	header := []string{
		"engine", "engine_version", "tree_files", "pft2_inode_index_depth", "pft2_directory_depth", "workload", "rep",
		"operations", "logical_bytes", "format_bytes", "path_write_bytes", "kernel_disk_bytes", "duration_ms",
		"kernel_amplification", "three_way_kernel_amplification", "kernel_bytes_per_op", "go_version", "os", "arch",
		"groups", "clean_copied_bytes", "index_disk_bytes", "store_disk_bytes", "sync_p50_us", "sync_p99_us", "sync_max_us",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		amp, quorumAmp := "", ""
		if r.LogicalBytes > 0 {
			amp = strconv.FormatFloat(float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
			quorumAmp = strconv.FormatFloat(3*float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
		}
		record := []string{
			r.Engine, r.EngineVersion, strconv.Itoa(r.TreeFiles), "-1", "-1",
			r.Workload, strconv.Itoa(r.Rep), strconv.Itoa(r.Operations), strconv.FormatUint(r.LogicalBytes, 10),
			strconv.FormatInt(r.FormatBytes, 10), strconv.FormatInt(r.PathWriteBytes, 10), strconv.FormatUint(r.KernelBytes, 10),
			strconv.FormatInt(r.Duration.Milliseconds(), 10), amp, quorumAmp,
			strconv.FormatFloat(float64(r.KernelBytes)/float64(r.Operations), 'f', 3, 64), runtime.Version(), runtime.GOOS, runtime.GOARCH,
			strconv.FormatUint(r.Groups, 10), strconv.FormatUint(r.CleanBytes, 10),
			strconv.FormatInt(r.IndexBytes, 10), strconv.FormatInt(r.StoreBytes, 10),
			strconv.FormatInt(r.SyncP50.Microseconds(), 10), strconv.FormatInt(r.SyncP99.Microseconds(), 10),
			strconv.FormatInt(r.SyncMax.Microseconds(), 10),
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
