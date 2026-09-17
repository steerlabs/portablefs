//go:build linux

package soak

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/coherencebench"
)

const (
	workloadGitFiles   = 5000
	workloadGitCommits = 200
)

// gitWorkload exercises the operations which make a Git working tree hard on
// a coherent filesystem: index-lock publication, object hard links, a long
// checkout sequence, repacking, and replacement of the index during a rebase.
func gitWorkload(t *testing.T, f *fixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	mountRoot := filepath.Join(f.a, "git-portablefs")
	peerRoot := filepath.Join(f.b, "git-portablefs")
	directBase, err := os.MkdirTemp(filepath.Dir(f.root), "soak-git-direct-")
	if err != nil {
		t.Fatalf("create direct-XFS Git root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directBase) })
	directRoot := filepath.Join(directBase, "run")

	f.measure(t, "git-portablefs-history-and-clone", func() error {
		return workloadPrepareGit(ctx, mountRoot, peerRoot)
	})
	f.measure(t, "git-portablefs-checkout-200", func() error {
		return workloadCheckoutEveryCommit(ctx, filepath.Join(mountRoot, "checkout"))
	})
	f.coldRemount(t)
	if err := coherencebench.EvictFilePages(filepath.Join(mountRoot, "checkout")); err != nil {
		t.Fatalf("evict Git file pages for cold status: %v", err)
	}
	// Linux has no unprivileged per-tree dentry eviction. This is cold for file
	// pages and honest about retaining metadata caches, like the v7 baseline.
	f.measure(t, "git-portablefs-status-cold", func() error {
		return workloadGitCleanStatus(ctx, filepath.Join(mountRoot, "checkout"))
	})
	f.measure(t, "git-portablefs-status-warm", func() error {
		return workloadGitCleanStatus(ctx, filepath.Join(mountRoot, "checkout"))
	})
	f.measure(t, "git-portablefs-gc", func() error {
		return workloadGit(ctx, filepath.Join(mountRoot, "checkout"), "gc", "--prune=now")
	})
	f.measure(t, "git-portablefs-rebase", func() error {
		return workloadGitRebase(ctx, filepath.Join(mountRoot, "checkout"))
	})
	f.barrier(t)

	// The direct-XFS execution is deliberately the same workload rather than a
	// copied expected tree. That catches path-sensitive and application-level
	// differences which a manifest generated in advance would miss.
	f.measure(t, "git-direct-xfs", func() error {
		if err := workloadPrepareGit(ctx, directRoot, ""); err != nil {
			return err
		}
		checkout := filepath.Join(directRoot, "checkout")
		if err := workloadCheckoutEveryCommit(ctx, checkout); err != nil {
			return err
		}
		if err := coherencebench.EvictFilePages(checkout); err != nil {
			return fmt.Errorf("evict direct-XFS Git file pages: %w", err)
		}
		if err := workloadGitCleanStatus(ctx, checkout); err != nil {
			return err
		}
		if err := workloadGitCleanStatus(ctx, checkout); err != nil {
			return err
		}
		if err := workloadGit(ctx, checkout, "gc", "--prune=now"); err != nil {
			return err
		}
		return workloadGitRebase(ctx, checkout)
	})

	mountCheckout := filepath.Join(mountRoot, "checkout")
	peerCheckout := filepath.Join(peerRoot, "checkout")
	directCheckout := filepath.Join(directRoot, "checkout")
	for name, checkout := range map[string]string{
		"mount A":    mountCheckout,
		"mount B":    peerCheckout,
		"direct XFS": directCheckout,
	} {
		if err := workloadGit(ctx, checkout, "fsck", "--full", "--strict"); err != nil {
			t.Fatalf("%s Git fsck: %v", name, err)
		}
	}
	mountHash, mountFiles, err := workloadGitWorkingHash(ctx, mountCheckout)
	if err != nil {
		t.Fatalf("hash Git working tree through mount A: %v", err)
	}
	peerHash, peerFiles, err := workloadGitWorkingHash(ctx, peerCheckout)
	if err != nil {
		t.Fatalf("hash Git working tree through mount B: %v", err)
	}
	directHash, directFiles, err := workloadGitWorkingHash(ctx, directCheckout)
	if err != nil {
		t.Fatalf("hash direct-XFS Git working tree: %v", err)
	}
	if mountFiles != workloadGitFiles || peerFiles != workloadGitFiles || directFiles != workloadGitFiles {
		t.Fatalf("Git tracked file counts: mount A=%d mount B=%d direct=%d, want %d", mountFiles, peerFiles, directFiles, workloadGitFiles)
	}
	if mountHash != peerHash || mountHash != directHash {
		t.Fatalf("Git working tree hashes: mount A=%x mount B=%x direct=%x", mountHash, peerHash, directHash)
	}
}

func workloadPrepareGit(ctx context.Context, root, peerRoot string) error {
	seed := filepath.Join(root, "seed")
	bare := filepath.Join(root, "origin.git")
	checkout := filepath.Join(root, "checkout")
	if err := os.Mkdir(root, 0o700); err != nil {
		return fmt.Errorf("create Git workload root: %w", err)
	}
	if err := os.Mkdir(seed, 0o700); err != nil {
		return fmt.Errorf("create Git seed: %w", err)
	}
	if err := workloadGit(ctx, seed, "init", "-q", "-b", "main"); err != nil {
		return err
	}
	if err := workloadGit(ctx, seed, "config", "user.email", "portablefs@example.invalid"); err != nil {
		return err
	}
	if err := workloadGit(ctx, seed, "config", "user.name", "PortableFS Soak"); err != nil {
		return err
	}
	if err := workloadGit(ctx, seed, "config", "gc.auto", "0"); err != nil {
		return err
	}
	for index := 0; index < workloadGitFiles; index++ {
		path := filepath.Join(seed, fmt.Sprintf("src-%03d", index/100), fmt.Sprintf("file-%04d.txt", index))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create Git source directory: %w", err)
		}
		if err := workloadWriteGitFile(path, 0, index); err != nil {
			return err
		}
	}
	if err := workloadGit(ctx, seed, "add", "."); err != nil {
		return err
	}
	if err := workloadGit(ctx, seed, "commit", "-q", "-m", "commit 000"); err != nil {
		return err
	}

	var stopPeer context.CancelFunc
	var peerDone <-chan error
	var peerStatuses *atomic.Int64
	if peerRoot != "" {
		peerSeed := filepath.Join(peerRoot, "seed")
		var peerCtx context.Context
		peerCtx, stopPeer = context.WithCancel(ctx)
		defer stopPeer()
		done := make(chan error, 1)
		peerDone = done
		peerStatuses = &atomic.Int64{}
		started := make(chan struct{})
		go func() {
			done <- workloadGitStatusLoop(peerCtx, peerSeed, peerStatuses, started)
		}()
		select {
		case <-started:
		case err := <-done:
			return fmt.Errorf("mount B Git status loop did not start: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for commit := 1; commit < workloadGitCommits; commit++ {
		paths := make([]string, 0, 25)
		for offset := 0; offset < 25; offset++ {
			index := (commit-1)*25 + offset
			relative := filepath.Join(fmt.Sprintf("src-%03d", index/100), fmt.Sprintf("file-%04d.txt", index))
			if err := workloadWriteGitFile(filepath.Join(seed, relative), commit, index); err != nil {
				if stopPeer != nil {
					stopPeer()
				}
				return err
			}
			paths = append(paths, relative)
		}
		args := []string{"commit", "-q", "--only", "-m", fmt.Sprintf("commit %03d", commit), "--"}
		args = append(args, paths...)
		if err := workloadGit(ctx, seed, args...); err != nil {
			if stopPeer != nil {
				stopPeer()
			}
			return err
		}
		if (commit+1)%25 == 0 {
			log.Printf("PortableFS Git soak prepared %d/%d commits in %s", commit+1, workloadGitCommits, root)
		}
	}
	if stopPeer != nil {
		stopPeer()
		if err := <-peerDone; err != nil {
			return fmt.Errorf("mount B Git status loop: %w", err)
		}
		if peerStatuses.Load() == 0 {
			return errors.New("mount B Git status loop completed no status calls while mount A committed")
		}
	}
	if err := workloadGit(ctx, root, "clone", "-q", "--bare", seed, bare); err != nil {
		return err
	}
	if err := workloadGit(ctx, root, "clone", "-q", bare, checkout); err != nil {
		return err
	}
	if err := workloadGit(ctx, checkout, "config", "user.email", "portablefs@example.invalid"); err != nil {
		return err
	}
	return workloadGit(ctx, checkout, "config", "user.name", "PortableFS Soak")
}

func workloadGitStatusLoop(ctx context.Context, root string, completed *atomic.Int64, started chan<- struct{}) error {
	close(started)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_, err := workloadCommand(ctx, root, map[string]string{
			"GIT_CONFIG_GLOBAL":   "/dev/null",
			"GIT_CONFIG_NOSYSTEM": "1",
			"GIT_OPTIONAL_LOCKS":  "0",
			"GIT_TERMINAL_PROMPT": "0",
			"LC_ALL":              "C",
		}, "git", "status", "--porcelain=v1", "--untracked-files=no")
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		completed.Add(1)
	}
}

func workloadWriteGitFile(path string, commit, index int) error {
	payload := fmt.Sprintf("portablefs coherence v2 git workload\nfile=%04d\ncommit=%03d\n", index, commit)
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		return fmt.Errorf("write Git file %s: %w", path, err)
	}
	return nil
}

func workloadCheckoutEveryCommit(ctx context.Context, root string) error {
	output, err := workloadCommand(ctx, root, nil, "git", "rev-list", "--reverse", "main")
	if err != nil {
		return err
	}
	commits := strings.Fields(string(output))
	if len(commits) != workloadGitCommits {
		return fmt.Errorf("Git history has %d commits, want %d", len(commits), workloadGitCommits)
	}
	for index, commit := range commits {
		if err := workloadGit(ctx, root, "checkout", "-q", "--detach", commit); err != nil {
			return fmt.Errorf("checkout commit %d of %d: %w", index+1, len(commits), err)
		}
	}
	return workloadGit(ctx, root, "checkout", "-q", "main")
}

func workloadGitRebase(ctx context.Context, root string) error {
	if err := workloadGit(ctx, root, "checkout", "-q", "-b", "topic", "main"); err != nil {
		return err
	}
	if err := workloadWriteGitFile(filepath.Join(root, "src-000", "file-0000.txt"), 200, 0); err != nil {
		return err
	}
	if err := workloadGit(ctx, root, "commit", "-q", "-am", "topic change"); err != nil {
		return err
	}
	if err := workloadGit(ctx, root, "checkout", "-q", "main"); err != nil {
		return err
	}
	if err := workloadWriteGitFile(filepath.Join(root, "src-000", "file-0001.txt"), 201, 1); err != nil {
		return err
	}
	if err := workloadGit(ctx, root, "commit", "-q", "-am", "main change"); err != nil {
		return err
	}
	if err := workloadGit(ctx, root, "checkout", "-q", "topic"); err != nil {
		return err
	}
	return workloadGit(ctx, root, "rebase", "main")
}

func workloadGitWorkingHash(ctx context.Context, root string) ([sha256.Size]byte, int, error) {
	output, err := workloadCommand(ctx, root, nil, "git", "ls-files", "-z")
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	paths := bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0})
	hasher := sha256.New()
	for _, rawPath := range paths {
		if len(rawPath) == 0 {
			continue
		}
		path := string(rawPath)
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return [sha256.Size]byte{}, 0, fmt.Errorf("stat tracked file %s: %w", path, err)
		}
		workloadHashField(hasher, []byte(path))
		workloadHashField(hasher, []byte(info.Mode().String()))
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				return [sha256.Size]byte{}, 0, fmt.Errorf("read tracked file %s: %w", path, err)
			}
			workloadHashField(hasher, data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				return [sha256.Size]byte{}, 0, fmt.Errorf("read tracked symlink %s: %w", path, err)
			}
			workloadHashField(hasher, []byte(target))
		} else {
			return [sha256.Size]byte{}, 0, fmt.Errorf("tracked path %s has unsupported mode %s", path, info.Mode())
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, len(paths), nil
}

func workloadHashField(hasher hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

// compilerWorkload builds the repository from source trees on PortableFS and
// direct XFS. GOTMPDIR remains on executable tmpfs because the provisioned XFS
// filesystem is intentionally mounted noexec; source, package reads, and the
// requested -o outputs still go through the filesystems under test.
func compilerWorkload(t *testing.T, f *fixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	source, err := workloadModuleRoot()
	if err != nil {
		t.Fatal(err)
	}
	mountRoot := filepath.Join(f.a, "compiler-portablefs")
	directBase, err := os.MkdirTemp(filepath.Dir(f.root), "soak-compiler-direct-")
	if err != nil {
		t.Fatalf("create compiler direct-XFS base: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directBase) })
	directRoot := filepath.Join(directBase, "run")
	mountSource := filepath.Join(mountRoot, "vcs")
	directSource := filepath.Join(directRoot, "vcs")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		t.Fatalf("create compiler mount root: %v", err)
	}
	if err := os.Mkdir(directRoot, 0o700); err != nil {
		t.Fatalf("create compiler direct-XFS root: %v", err)
	}
	f.measure(t, "compiler-copy-portablefs", func() error {
		return workloadCopyTree(source, mountSource)
	})
	f.measure(t, "compiler-copy-direct-xfs", func() error {
		return workloadCopyTree(source, directSource)
	})

	execRoot, err := os.MkdirTemp("", "portablefs-soak-go-")
	if err != nil {
		t.Fatalf("create compiler executable temp root: %v", err)
	}
	defer os.RemoveAll(execRoot)
	mountEnv, err := workloadGoEnvironment(filepath.Join(execRoot, "mount"))
	if err != nil {
		t.Fatal(err)
	}
	directEnv, err := workloadGoEnvironment(filepath.Join(execRoot, "direct"))
	if err != nil {
		t.Fatal(err)
	}
	mountBinary := filepath.Join(mountRoot, "portablefs")
	directBinary := filepath.Join(directRoot, "portablefs")
	f.measure(t, "compiler-build-portablefs", func() error {
		_, err := workloadCommand(ctx, mountSource, mountEnv, "go", "build", "-p=1", "-trimpath", "-buildvcs=false", "-o", mountBinary, "./cmd/portablefs")
		return err
	})
	f.measure(t, "compiler-test-portablefs", func() error {
		_, err := workloadCommand(ctx, mountSource, mountEnv, "go", "test", "-p=1", "-count=1", "./internal/writeback")
		return err
	})
	f.measure(t, "compiler-build-direct-xfs", func() error {
		_, err := workloadCommand(ctx, directSource, directEnv, "go", "build", "-p=1", "-trimpath", "-buildvcs=false", "-o", directBinary, "./cmd/portablefs")
		return err
	})
	f.measure(t, "compiler-test-direct-xfs", func() error {
		_, err := workloadCommand(ctx, directSource, directEnv, "go", "test", "-p=1", "-count=1", "./internal/writeback")
		return err
	})
	f.barrier(t)

	mountHash, err := workloadFileHash(mountBinary)
	if err != nil {
		t.Fatalf("hash compiler output through mount: %v", err)
	}
	directHash, err := workloadFileHash(directBinary)
	if err != nil {
		t.Fatalf("hash direct-XFS compiler output: %v", err)
	}
	if mountHash != directHash {
		t.Fatalf("compiler output hashes differ: portablefs=%x direct-XFS=%x", mountHash, directHash)
	}
}

func workloadModuleRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get compiler workload directory: %w", err)
	}
	for {
		if info, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil && info.Mode().IsRegular() {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("find vcs module root above %s", directory)
		}
		directory = parent
	}
}

func workloadCopyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect compiler source %s: %w", path, err)
		}
		switch {
		case entry.IsDir():
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
				return fmt.Errorf("create compiler directory %s: %w", target, err)
			}
			return nil
		case entry.Type()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read compiler symlink %s: %w", path, err)
			}
			if err := os.Symlink(link, target); err != nil {
				return fmt.Errorf("copy compiler symlink %s: %w", target, err)
			}
			return nil
		case entry.Type().IsRegular():
			return workloadCopyFile(path, target, info.Mode().Perm())
		default:
			return fmt.Errorf("compiler source %s has unsupported mode %s", path, info.Mode())
		}
	})
}

func workloadCopyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open compiler source %s: %w", source, err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create compiler source copy %s: %w", destination, err)
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return fmt.Errorf("copy compiler source %s: %w", source, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close compiler source copy %s: %w", destination, closeErr)
	}
	return nil
}

func workloadGoEnvironment(root string) (map[string]string, error) {
	cache := filepath.Join(root, "cache")
	temporary := filepath.Join(root, "tmp")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, fmt.Errorf("create Go cache: %w", err)
	}
	if err := os.MkdirAll(temporary, 0o700); err != nil {
		return nil, fmt.Errorf("create Go executable temp directory: %w", err)
	}
	return map[string]string{
		"CGO_ENABLED": "0",
		"GOCACHE":     cache,
		"GOMAXPROCS":  "2",
		"GOTMPDIR":    temporary,
		"GOOS":        "linux",
		"GOARCH":      runtime.GOARCH,
	}, nil
}

func workloadGitCleanStatus(ctx context.Context, directory string) error {
	output, err := workloadCommand(ctx, directory, map[string]string{
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_TERMINAL_PROMPT": "0",
		"LC_ALL":              "C",
	}, "git", "status", "--porcelain=v1")
	if err != nil {
		return err
	}
	if status := bytes.TrimSpace(output); len(status) != 0 {
		return fmt.Errorf("Git status reported a dirty working tree: %s", status)
	}
	return nil
}

func workloadFileHash(path string) ([sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, bufio.NewReader(file)); err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func workloadGit(ctx context.Context, directory string, args ...string) error {
	_, err := workloadCommand(ctx, directory, map[string]string{
		"GIT_AUTHOR_DATE":     "1700000000 +0000",
		"GIT_COMMITTER_DATE":  "1700000000 +0000",
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_TERMINAL_PROMPT": "0",
		"LC_ALL":              "C",
	}, "git", args...)
	return err
}

func workloadCommand(ctx context.Context, directory string, environment map[string]string, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = directory
	command.Env = os.Environ()
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		command.Env = append(command.Env, key+"="+environment[key])
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %v in %s: %w: %s", name, args, directory, err, bytes.TrimSpace(output))
	}
	return output, nil
}
