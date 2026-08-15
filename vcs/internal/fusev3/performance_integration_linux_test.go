//go:build linux

package fusev3

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const envPerformance = "PORTABLEFS_PERFORMANCE_TEST"

const (
	performanceOperations = 200
	performanceBulkBytes  = 64 << 20
	performanceBulkChunk  = 1 << 20
)

type performanceSample struct {
	Case       string         `json:"case"`
	Operation  string         `json:"operation"`
	N          int            `json:"n,omitempty"`
	P50US      float64        `json:"p50_us,omitempty"`
	P90US      float64        `json:"p90_us,omitempty"`
	P99US      float64        `json:"p99_us,omitempty"`
	MaxUS      float64        `json:"max_us,omitempty"`
	MeanUS     float64        `json:"mean_us,omitempty"`
	MiB        float64        `json:"mib,omitempty"`
	Seconds    float64        `json:"seconds,omitempty"`
	MiBPerSec  float64        `json:"mib_per_second,omitempty"`
	UserCPU    float64        `json:"user_cpu_seconds,omitempty"`
	SystemCPU  float64        `json:"system_cpu_seconds,omitempty"`
	Authority  map[string]int `json:"authority_requests,omitempty"`
	RatioBasis string         `json:"ratio_basis,omitempty"`
	OneDirect  float64        `json:"strict_one_over_direct,omitempty"`
	TwoDirect  float64        `json:"strict_two_over_direct,omitempty"`
	TwoOne     float64        `json:"strict_two_over_strict_one,omitempty"`
}

type performanceRun struct {
	label   string
	root    string
	peer    string
	counter *countingHandler
	results map[string]performanceSample
}

// TestStrictPerformanceAgainstDirectXFS is a measurement harness, not a timing
// gate. It runs one byte-identical workload against the authority's direct XFS
// ceiling, one strict mount, and two strict mounts where the second mount has
// deliberately acquired the exact negative-name/data grants affected by every
// mutation. The last case therefore measures the guarantee PortableFS actually
// sells: the mutating syscall does not return until the peer has repaired the
// overlapping state.
//
// Enable it explicitly so shared CI load never turns latency noise into a
// correctness failure:
//
//	PORTABLEFS_PERFORMANCE_TEST=1 go test -run TestStrictPerformanceAgainstDirectXFS
//
// Every result is one stable JSON object prefixed with PORTABLEFS_PERF. The
// payload and the peer's final bytes are hashed, so a fast but incorrect run is
// a test failure rather than a performance result.
func TestStrictPerformanceAgainstDirectXFS(t *testing.T) {
	if os.Getenv(envPerformance) != "1" {
		t.Skipf("set %s=1 to run the live direct-XFS/strict-mount performance matrix", envPerformance)
	}
	env := requireIntegrationEnvironment(t)

	all := make(map[string]map[string]performanceSample)
	t.Run("direct-xfs", func(t *testing.T) {
		root := filepath.Join(env.xfsRoot, integrationVolumeDirectory(t)+".direct")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("create direct-XFS benchmark root: %v", err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(root); err != nil {
				t.Errorf("remove direct-XFS benchmark root: %v", err)
			}
		})
		run := &performanceRun{label: "direct-xfs", root: root, results: make(map[string]performanceSample)}
		run.measure(t)
		all[run.label] = run.results
	})

	t.Run("strict-one-mount", func(t *testing.T) {
		fixture := newIntegrationFixture(t, integrationConfig{Mounts: 1})
		run := &performanceRun{
			label: "strict-one-mount", root: fixture.mountPath(0), counter: fixture.counter,
			results: make(map[string]performanceSample),
		}
		run.measure(t)
		all[run.label] = run.results
	})

	t.Run("strict-two-mount-overlap", func(t *testing.T) {
		fixture := newIntegrationFixture(t, integrationConfig{Mounts: 2})
		run := &performanceRun{
			label: "strict-two-mount-overlap", root: fixture.mountPath(0), peer: fixture.mountPath(1),
			counter: fixture.counter, results: make(map[string]performanceSample)}
		run.measure(t)
		all[run.label] = run.results
	})

	// Ratios make regressions legible without pretending that a KASAN VM is a
	// service SLO. The raw observations above remain the source of truth.
	for _, operation := range []string{"create", "write-4k", "fsync", "stat-warm", "open-read-close", "rename", "unlink", "bulk-write-acked", "bulk-read"} {
		direct, directOK := all["direct-xfs"][operation]
		one, oneOK := all["strict-one-mount"][operation]
		two, twoOK := all["strict-two-mount-overlap"][operation]
		if !directOK || !oneOK || !twoOK {
			t.Fatalf("performance result %q missing from one or more cases", operation)
		}
		basis := "p50_latency"
		metric := func(sample performanceSample) float64 { return sample.P50US }
		if direct.MiBPerSec != 0 {
			basis = "throughput"
			metric = func(sample performanceSample) float64 { return sample.MiBPerSec }
		}
		directMetric, oneMetric, twoMetric := metric(direct), metric(one), metric(two)
		recordPerformance(t, performanceSample{
			Case: "ratios", Operation: operation, RatioBasis: basis,
			OneDirect: oneMetric / directMetric,
			TwoDirect: twoMetric / directMetric,
			TwoOne:    twoMetric / oneMetric,
		})
	}
}

func (r *performanceRun) measure(t *testing.T) {
	t.Helper()
	work, err := os.MkdirTemp(r.root, "pfs-performance-")
	if err != nil {
		t.Fatalf("create %s work directory: %v", r.label, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Errorf("remove %s work directory: %v", r.label, err)
		}
	})
	peerWork := ""
	if r.peer != "" {
		peerWork = filepath.Join(r.peer, filepath.Base(work))
		if info, err := os.Stat(peerWork); err != nil || !info.IsDir() {
			t.Fatalf("prime peer work directory %s: info=%v err=%v", peerWork, info, err)
		}
	}

	beforeCPU := readPerformanceCPU(t)
	wallStart := time.Now()
	beforeRequests := r.requestSnapshot()
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(31*i + 17)
	}
	paths := make([]string, performanceOperations)
	peerPaths := make([]string, performanceOperations)
	handles := make([]*os.File, performanceOperations)

	latencies := make([]time.Duration, 0, performanceOperations)
	for i := range performanceOperations {
		name := fmt.Sprintf("file-%06d", i)
		paths[i] = filepath.Join(work, name)
		if peerWork != "" {
			peerPaths[i] = filepath.Join(peerWork, name)
			if _, err := os.Stat(peerPaths[i]); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("prime peer negative dentry %s: %v", peerPaths[i], err)
			}
		}
		start := time.Now()
		handles[i], err = os.OpenFile(paths[i], os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		latencies = append(latencies, time.Since(start))
		if err != nil {
			t.Fatalf("create %s: %v", paths[i], err)
		}
	}
	r.recordLatency(t, "create", latencies)

	latencies = latencies[:0]
	for i, handle := range handles {
		if peerWork != "" {
			got, err := os.ReadFile(peerPaths[i])
			if err != nil || len(got) != 0 {
				t.Fatalf("prime peer empty data %s: len=%d err=%v", peerPaths[i], len(got), err)
			}
		}
		start := time.Now()
		n, err := handle.Write(payload)
		latencies = append(latencies, time.Since(start))
		if err != nil || n != len(payload) {
			t.Fatalf("write %s = (%d, %v), want (%d, nil)", paths[i], n, err, len(payload))
		}
		if peerWork != "" {
			got, err := os.ReadFile(peerPaths[i])
			if err != nil || string(got) != string(payload) {
				t.Fatalf("peer bytes after write %s: len=%d err=%v", peerPaths[i], len(got), err)
			}
		}
	}
	r.recordLatency(t, "write-4k", latencies)

	latencies = latencies[:0]
	for i, handle := range handles {
		start := time.Now()
		err := handle.Sync()
		latencies = append(latencies, time.Since(start))
		if err != nil {
			t.Fatalf("fsync %s: %v", paths[i], err)
		}
	}
	r.recordLatency(t, "fsync", latencies)

	latencies = latencies[:0]
	for i, handle := range handles {
		start := time.Now()
		err := handle.Close()
		latencies = append(latencies, time.Since(start))
		if err != nil {
			t.Fatalf("close %s: %v", paths[i], err)
		}
		handles[i] = nil
	}
	r.recordLatency(t, "close", latencies)

	latencies = latencies[:0]
	for _, path := range paths {
		start := time.Now()
		info, err := os.Stat(path)
		latencies = append(latencies, time.Since(start))
		if err != nil || info.Size() != int64(len(payload)) {
			t.Fatalf("warm stat %s: size=%v err=%v", path, sizeOf(info), err)
		}
	}
	r.recordLatency(t, "stat-warm", latencies)

	latencies = latencies[:0]
	for _, path := range paths {
		start := time.Now()
		got, err := os.ReadFile(path)
		latencies = append(latencies, time.Since(start))
		if err != nil || string(got) != string(payload) {
			t.Fatalf("read %s: len=%d err=%v", path, len(got), err)
		}
	}
	r.recordLatency(t, "open-read-close", latencies)

	latencies = latencies[:0]
	for i := range paths {
		renamed := paths[i] + ".renamed"
		if peerWork != "" {
			if _, err := os.Stat(peerPaths[i]); err != nil {
				t.Fatalf("prime peer rename source %s: %v", peerPaths[i], err)
			}
			if _, err := os.Stat(peerPaths[i] + ".renamed"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("prime peer rename target %s: %v", peerPaths[i]+".renamed", err)
			}
		}
		start := time.Now()
		err := os.Rename(paths[i], renamed)
		latencies = append(latencies, time.Since(start))
		if err != nil {
			t.Fatalf("rename %s: %v", paths[i], err)
		}
		paths[i] = renamed
		peerPaths[i] += ".renamed"
	}
	r.recordLatency(t, "rename", latencies)

	latencies = latencies[:0]
	for i, path := range paths {
		if peerWork != "" {
			if _, err := os.Stat(peerPaths[i]); err != nil {
				t.Fatalf("prime peer unlink %s: %v", peerPaths[i], err)
			}
		}
		start := time.Now()
		err := os.Remove(path)
		latencies = append(latencies, time.Since(start))
		if err != nil {
			t.Fatalf("unlink %s: %v", path, err)
		}
		if peerWork != "" {
			if _, err := os.Stat(peerPaths[i]); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("peer still resolves %s after source unlink: %v", peerPaths[i], err)
			}
		}
	}
	r.recordLatency(t, "unlink", latencies)

	r.measureBulk(t, work, peerWork)
	afterRequests := r.requestSnapshot()
	afterCPU := readPerformanceCPU(t)
	r.record(t, performanceSample{
		Case: r.label, Operation: "whole-run", N: performanceOperations,
		Seconds: time.Since(wallStart).Seconds(),
		UserCPU: afterCPU.user - beforeCPU.user, SystemCPU: afterCPU.system - beforeCPU.system,
		Authority: requestDelta(beforeRequests, afterRequests),
	})
}

func (r *performanceRun) measureBulk(t *testing.T, work, peerWork string) {
	t.Helper()
	path := filepath.Join(work, "bulk.bin")
	peerPath := ""
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create bulk file: %v", err)
	}
	if peerWork != "" {
		peerPath = filepath.Join(peerWork, "bulk.bin")
		got, err := os.ReadFile(peerPath)
		if err != nil || len(got) != 0 {
			t.Fatalf("prime peer bulk data: len=%d err=%v", len(got), err)
		}
	}
	payload := make([]byte, performanceBulkChunk)
	seed := uint64(0x9e3779b97f4a7c15)
	fill := func() {
		for i := 0; i < len(payload); i += 8 {
			seed ^= seed << 13
			seed ^= seed >> 7
			seed ^= seed << 17
			binary.LittleEndian.PutUint64(payload[i:], seed)
		}
	}
	wantHash := sha256.New()
	writeStart := time.Now()
	for written := 0; written < performanceBulkBytes; written += len(payload) {
		fill()
		_, _ = wantHash.Write(payload)
		n, err := file.Write(payload)
		if err != nil || n != len(payload) {
			_ = file.Close()
			t.Fatalf("bulk write at %d = (%d, %v)", written, n, err)
		}
	}
	writeElapsed := time.Since(writeStart)
	r.recordThroughput(t, "bulk-write-acked", performanceBulkBytes, writeElapsed)

	syncStart := time.Now()
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("bulk fsync: %v", err)
	}
	r.recordLatency(t, "bulk-fsync", []time.Duration{time.Since(syncStart)})
	if err := file.Close(); err != nil {
		t.Fatalf("close bulk file: %v", err)
	}

	readStart := time.Now()
	gotHash := hashFile(t, path)
	r.recordThroughput(t, "bulk-read", performanceBulkBytes, time.Since(readStart))
	if gotHash != fmt.Sprintf("%x", wantHash.Sum(nil)) {
		t.Fatalf("source bulk hash = %s, want %x", gotHash, wantHash.Sum(nil))
	}
	if peerPath != "" {
		if peerHash := hashFile(t, peerPath); peerHash != gotHash {
			t.Fatalf("peer bulk hash = %s, source = %s", peerHash, gotHash)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove bulk file: %v", err)
	}
}

func (r *performanceRun) recordLatency(t *testing.T, operation string, values []time.Duration) {
	t.Helper()
	if len(values) == 0 {
		t.Fatalf("no values for %s", operation)
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var total time.Duration
	for _, value := range sorted {
		total += value
	}
	sample := performanceSample{
		Case: r.label, Operation: operation, N: len(sorted),
		P50US:  durationUS(percentileDuration(sorted, 50)),
		P90US:  durationUS(percentileDuration(sorted, 90)),
		P99US:  durationUS(percentileDuration(sorted, 99)),
		MaxUS:  durationUS(sorted[len(sorted)-1]),
		MeanUS: durationUS(total) / float64(len(sorted)),
	}
	r.record(t, sample)
}

func (r *performanceRun) recordThroughput(t *testing.T, operation string, bytes int, elapsed time.Duration) {
	t.Helper()
	mib := float64(bytes) / (1 << 20)
	r.record(t, performanceSample{
		Case: r.label, Operation: operation, N: bytes / performanceBulkChunk,
		MiB: mib, Seconds: elapsed.Seconds(), MiBPerSec: mib / elapsed.Seconds(),
	})
}

func (r *performanceRun) record(t *testing.T, sample performanceSample) {
	t.Helper()
	r.results[sample.Operation] = sample
	recordPerformance(t, sample)
}

func recordPerformance(t *testing.T, sample performanceSample) {
	t.Helper()
	encoded, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal performance result: %v", err)
	}
	t.Logf("PORTABLEFS_PERF %s", encoded)
}

func percentileDuration(sorted []time.Duration, percentile int) time.Duration {
	index := (percentile*len(sorted))/100 - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func durationUS(value time.Duration) float64 { return float64(value.Nanoseconds()) / 1e3 }

func hashFile(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s for hash: %v", path, err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		t.Fatalf("hash %s: %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s after hash: %v", path, err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func sizeOf(info fs.FileInfo) int64 {
	if info == nil {
		return -1
	}
	return info.Size()
}

type performanceCPU struct{ user, system float64 }

func readPerformanceCPU(t *testing.T) performanceCPU {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	seconds := func(value unix.Timeval) float64 {
		return float64(value.Sec) + float64(value.Usec)/1e6
	}
	return performanceCPU{user: seconds(usage.Utime), system: seconds(usage.Stime)}
}

func (r *performanceRun) requestSnapshot() map[string]int {
	if r.counter == nil {
		return nil
	}
	result := make(map[string]int, 4)
	for _, kind := range []string{"lookup", "getattr", "reclaim", "other"} {
		result[kind] = r.counter.count(kind)
	}
	return result
}

func requestDelta(before, after map[string]int) map[string]int {
	if after == nil {
		return nil
	}
	result := make(map[string]int, len(after))
	for kind, count := range after {
		result[kind] = count - before[kind]
	}
	return result
}
