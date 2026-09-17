// Package coherencebench contains the filesystem workloads used to establish
// the coherence-v2 baseline. The package deliberately knows nothing about
// PortableFS: callers provide one or two POSIX paths and meter the Authority at
// the transport boundary around each call.
package coherencebench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const FileBytes = 1024

// WorkloadResult is the part of a measurement observable from the filesystem
// client. The integration harness adds Authority request counts from its
// in-process transport meter.
type WorkloadResult struct {
	Scenario    string `json:"scenario"`
	Operations  int    `json:"operations"`
	Files       int    `json:"files,omitempty"`
	Directories int    `json:"directories,omitempty"`
	Workers     int    `json:"workers,omitempty"`
	// TransientRetries is retained for comparison with the v6 JSON records.
	// Protocol 7 treats every enumeration error as a workload failure, so a
	// successful run reports zero.
	TransientRetries         int64   `json:"transient_retries,omitempty"`
	DirectoryScans           int64   `json:"directory_scans,omitempty"`
	IncompleteReadRetries    int64   `json:"incomplete_read_retries,omitempty"`
	VanishedReadRetries      int64   `json:"vanished_read_retries,omitempty"`
	FilesObservedDuringWrite int64   `json:"files_observed_during_write,omitempty"`
	WallSeconds              float64 `json:"wall_seconds"`
}

// Install creates dirCount directories, then creates, writes 1 KiB to, and
// closes fileCount files with the requested worker count. The elapsed time
// includes both the directory and file phases.
func Install(root string, fileCount, dirCount, workers int) (WorkloadResult, error) {
	if fileCount <= 0 || dirCount <= 0 || workers <= 0 {
		return WorkloadResult{}, fmt.Errorf("install shape must be positive: files=%d directories=%d workers=%d", fileCount, dirCount, workers)
	}
	if err := requireEmptyDirectory(root, "install"); err != nil {
		return WorkloadResult{}, err
	}
	start := time.Now()
	directories, err := makeDirectoryTree(root, dirCount)
	if err != nil {
		return WorkloadResult{}, err
	}
	payload := make([]byte, FileBytes)
	for i := range payload {
		payload[i] = byte(31*i + 17)
	}

	jobs := make(chan int)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var firstErr error
	var errOnce sync.Once
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					path := filepath.Join(directories[index%len(directories)], fmt.Sprintf("file-%06d.dat", index))
					if err := createPayload(path, payload); err != nil {
						errOnce.Do(func() {
							firstErr = fmt.Errorf("install file %d: %w", index, err)
							cancel()
						})
						return
					}
				}
			}
		}()
	}
sendJobs:
	for index := 0; index < fileCount; index++ {
		select {
		case <-ctx.Done():
			break sendJobs
		case jobs <- index:
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return WorkloadResult{}, firstErr
	}
	return WorkloadResult{
		Scenario: "install", Operations: fileCount + dirCount, Files: fileCount,
		Directories: dirCount, Workers: workers, WallSeconds: time.Since(start).Seconds(),
	}, nil
}

func makeDirectoryTree(root string, count int) ([]string, error) {
	const childrenPerTop = 39
	directories := make([]string, 0, count)
	for top := 0; len(directories) < count; top++ {
		topPath := filepath.Join(root, fmt.Sprintf("tree-%03d", top))
		if err := os.Mkdir(topPath, 0o700); err != nil {
			return nil, fmt.Errorf("create install directory %s: %w", topPath, err)
		}
		directories = append(directories, topPath)
		for child := 0; child < childrenPerTop && len(directories) < count; child++ {
			path := filepath.Join(topPath, fmt.Sprintf("branch-%03d", child))
			if err := os.Mkdir(path, 0o700); err != nil {
				return nil, fmt.Errorf("create install directory %s: %w", path, err)
			}
			directories = append(directories, path)
		}
	}
	return directories, nil
}

func createPayload(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, err := file.Write(payload)
	if err != nil {
		_ = file.Close()
		return err
	}
	if written != len(payload) {
		_ = file.Close()
		return fmt.Errorf("short write: wrote %d of %d bytes", written, len(payload))
	}
	return file.Close()
}

// PrepareGit creates and commits a clean repository with the requested number
// of tracked 1 KiB files. Repository preparation is outside the measured
// status phases.
func PrepareGit(root string, fileCount int) error {
	if fileCount <= 0 {
		return fmt.Errorf("git file count must be positive: %d", fileCount)
	}
	if err := requireEmptyDirectory(root, "git preparation"); err != nil {
		return err
	}
	if err := runGit(root, "init", "-q"); err != nil {
		return err
	}
	if err := runGit(root, "config", "user.email", "portablefs@example.invalid"); err != nil {
		return err
	}
	if err := runGit(root, "config", "user.name", "PortableFS Baseline"); err != nil {
		return err
	}
	if err := runGit(root, "config", "gc.auto", "0"); err != nil {
		return err
	}
	if err := runGit(root, "config", "maintenance.auto", "false"); err != nil {
		return err
	}
	payload := make([]byte, FileBytes)
	for directory := 0; directory < (fileCount+199)/200; directory++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("src-%03d", directory)), 0o700); err != nil {
			return fmt.Errorf("create git directory %d: %w", directory, err)
		}
	}
	for index := 0; index < fileCount; index++ {
		fillPayload(payload, index)
		path := filepath.Join(root, fmt.Sprintf("src-%03d", index/200), fmt.Sprintf("file-%06d.txt", index))
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			return fmt.Errorf("write git file %d: %w", index, err)
		}
	}
	// The index must be newer than every tracked file. Waiting here, before
	// `git add` writes it, removes Git's racily-clean hash path from both the
	// cold and warm status measurements.
	time.Sleep(1100 * time.Millisecond)
	if err := runGit(root, "add", "."); err != nil {
		return err
	}

	command := exec.Command("git", "-C", root, "ls-files", "-z")
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	tracked, err := command.Output()
	if err != nil {
		return fmt.Errorf("verify git index: %w", err)
	}
	if count := bytes.Count(tracked, []byte{0}); count != fileCount {
		return fmt.Errorf("git add tracked %d files, want %d", count, fileCount)
	}
	if err := runGit(root, "commit", "-q", "-m", "coherence baseline"); err != nil {
		return err
	}
	return nil
}

func requireEmptyDirectory(root, workload string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("inspect %s root %s: %w", workload, root, err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s root %s is not empty", workload, root)
	}
	return nil
}

func fillPayload(payload []byte, index int) {
	seed := sha256.Sum256([]byte(fmt.Sprintf("portablefs-coherence-baseline:%d", index)))
	for i := range payload {
		payload[i] = seed[i%len(seed)]
	}
}

func runGit(root string, args ...string) error {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %v: %w: %s", args, err, bytes.TrimSpace(output))
	}
	return nil
}

// GitStatus runs one clean status over fileCount tracked files.
func GitStatus(root, temperature string, fileCount int) (WorkloadResult, error) {
	start := time.Now()
	command := exec.Command("git", "-C", root, "status", "--porcelain=v1")
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.CombinedOutput()
	elapsed := time.Since(start)
	if err != nil {
		return WorkloadResult{}, fmt.Errorf("git status: %w: %s", err, bytes.TrimSpace(output))
	}
	if len(bytes.TrimSpace(output)) != 0 {
		return WorkloadResult{}, fmt.Errorf("git status reported a dirty repository: %s", bytes.TrimSpace(output))
	}
	return WorkloadResult{Scenario: "git-status-" + temperature, Operations: fileCount, Files: fileCount, WallSeconds: elapsed.Seconds()}, nil
}

// PeerWriteRead creates files through rootA while a reader repeatedly lists
// rootB and validates every published file. It returns only after the reader
// has observed all files through rootB.
func PeerWriteRead(rootA, rootB string, fileCount int) (WorkloadResult, error) {
	if fileCount <= 0 {
		return WorkloadResult{}, fmt.Errorf("peer file count must be positive: %d", fileCount)
	}
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readerDone := make(chan error, 1)
	readerReady := make(chan struct{})
	firstObserved := make(chan struct{})
	var stats peerStats
	go func() { readerDone <- readPublishedFiles(ctx, rootB, fileCount, &stats, readerReady, firstObserved) }()
	select {
	case <-readerReady:
	case err := <-readerDone:
		return WorkloadResult{}, fmt.Errorf("peer reader failed before its first scan: %w", err)
	case <-time.After(5 * time.Second):
		cancel()
		return WorkloadResult{}, errors.Join(errors.New("peer reader did not complete its first scan within 5s"), joinPeerReader(readerDone, 5*time.Second))
	}
	payload := make([]byte, FileBytes)
	for index := 0; index < fileCount; index++ {
		select {
		case err := <-readerDone:
			if err == nil {
				err = errors.New("peer reader finished before the writer published every file")
			}
			return WorkloadResult{}, err
		default:
		}
		fillPayload(payload, index)
		path := filepath.Join(rootA, fmt.Sprintf("file-%06d.dat", index))
		if err := createPayload(path, payload); err != nil {
			cancel()
			return WorkloadResult{}, errors.Join(fmt.Errorf("peer writer file %d: %w", index, err), joinPeerReader(readerDone, 5*time.Second))
		}
		if index == 0 && fileCount > 1 {
			select {
			case <-firstObserved:
			case err := <-readerDone:
				return WorkloadResult{}, fmt.Errorf("peer reader failed before observing the first file: %w", err)
			case <-time.After(30 * time.Second):
				cancel()
				return WorkloadResult{}, errors.Join(errors.New("peer reader did not verify the first file within 30s"), joinPeerReader(readerDone, 5*time.Second))
			}
		}
	}
	stats.writerDone.Store(true)
	select {
	case err := <-readerDone:
		if err != nil {
			return WorkloadResult{}, err
		}
	case <-time.After(10 * time.Minute):
		cancel()
		return WorkloadResult{}, errors.Join(errors.New("peer reader did not finish within 10m after the writer completed"), joinPeerReader(readerDone, 5*time.Second))
	}
	return WorkloadResult{
		Scenario: "two-mount-write-list-read", Operations: 2 * fileCount, Files: fileCount,
		TransientRetries: stats.estale.Load(), DirectoryScans: stats.scans.Load(),
		IncompleteReadRetries: stats.incomplete.Load(), VanishedReadRetries: stats.vanished.Load(),
		FilesObservedDuringWrite: stats.observedDuringWrite.Load(), WallSeconds: time.Since(start).Seconds(),
	}, nil
}

func joinPeerReader(readerDone <-chan error, timeout time.Duration) error {
	select {
	case err := <-readerDone:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("peer reader did not stop within %s", timeout)
	}
}

type peerStats struct {
	estale, scans, incomplete, vanished, observedDuringWrite atomic.Int64
	writerDone                                               atomic.Bool
}

func readPublishedFiles(
	ctx context.Context,
	root string,
	fileCount int,
	stats *peerStats,
	ready chan<- struct{},
	firstObserved chan<- struct{},
) error {
	seen := make(map[string]struct{}, fileCount)
	deadline := time.Now().Add(10 * time.Minute)
	var readyOnce, observedOnce sync.Once
	for len(seen) < fileCount {
		if time.Now().After(deadline) {
			return fmt.Errorf("peer reader observed %d of %d files before timeout", len(seen), fileCount)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		stats.scans.Add(1)
		entries, err := os.ReadDir(root)
		readyOnce.Do(func() { close(ready) })
		if err != nil {
			return fmt.Errorf("list peer directory: %w", err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if _, ok := seen[name]; ok {
				continue
			}
			var index int
			if _, err := fmt.Sscanf(name, "file-%06d.dat", &index); err != nil || index < 0 || index >= fileCount {
				continue
			}
			want := make([]byte, FileBytes)
			fillPayload(want, index)
			got, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				if os.IsNotExist(err) {
					stats.vanished.Add(1)
					continue
				}
				return fmt.Errorf("read peer file %s: %w", name, err)
			}
			if len(got) != len(want) {
				// Enumeration can race the writer between create and close. The
				// next pass retries until the complete file is published.
				stats.incomplete.Add(1)
				continue
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("peer file %s content mismatch", name)
			}
			seen[name] = struct{}{}
			observedOnce.Do(func() { close(firstObserved) })
			if !stats.writerDone.Load() {
				stats.observedDuringWrite.Add(1)
			}
		}
		if len(seen) == fileCount {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
	}
	return nil
}
