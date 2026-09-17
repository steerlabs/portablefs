//go:build linux

package soak

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestSoakNPM installs a pinned graph of 447 real packages. The first npm ci
// populates a private cache outside the filesystem under test; the measured
// install has no network fallback, so every published file comes from the
// lockfile and that cache.
func TestSoakNPM(t *testing.T) {
	if isolateSoak(t, 5*time.Minute) {
		return
	}
	f := newFixture(t)
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatalf("the npm soak requires node: %v", err)
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Fatalf("the npm soak requires npm: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	moduleRoot, err := workloadModuleRoot()
	if err != nil {
		t.Fatal(err)
	}
	fixtureRoot := filepath.Join(moduleRoot, "test", "soak", "testdata", "npm")
	seedRoot := filepath.Join(t.TempDir(), "seed")
	cacheRoot := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(seedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := npmCopyManifests(fixtureRoot, seedRoot); err != nil {
		t.Fatal(err)
	}
	f.measure(t, "npm-cache-seed-447-packages", func() error {
		return npmCI(ctx, seedRoot, cacheRoot, false)
	})
	expected, err := treeHashes(filepath.Join(seedRoot, "node_modules"))
	if err != nil {
		t.Fatalf("hash independently seeded npm tree: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(seedRoot, "node_modules")); err != nil {
		t.Fatalf("remove npm cache-seed tree: %v", err)
	}

	projectA := filepath.Join(f.a, "npm-project")
	projectB := filepath.Join(f.b, "npm-project")
	projectAuthority := filepath.Join(f.root, "npm-project")
	if err := os.Mkdir(projectA, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := npmCopyManifests(fixtureRoot, projectA); err != nil {
		t.Fatal(err)
	}
	stopObserver := npmStartPeerObserver(ctx, f, projectB)
	observerStopped := false
	defer func() {
		if !observerStopped {
			_ = stopObserver()
		}
	}()
	f.measure(t, "npm-ci-offline-447-packages", func() error {
		return npmCI(ctx, projectA, cacheRoot, true)
	})
	observerErr := stopObserver()
	observerStopped = true
	if observerErr != nil {
		t.Fatalf("npm mount-B observer: %v", observerErr)
	}
	f.barrier(t)

	if len(expected) < 447 {
		t.Fatalf("npm installed only %d filesystem entries for a 447-package lockfile", len(expected))
	}
	for name, root := range map[string]string{
		"mount A":       filepath.Join(projectA, "node_modules"),
		"mount B":       filepath.Join(projectB, "node_modules"),
		"Authority XFS": filepath.Join(projectAuthority, "node_modules"),
	} {
		got, err := treeHashes(root)
		if err != nil {
			t.Fatalf("hash npm tree through %s: %v", name, err)
		}
		if err := compareTrees(expected, got); err != nil {
			t.Fatalf("npm tree through %s: %v", name, err)
		}
	}
}

func npmCopyManifests(source, destination string) error {
	for _, name := range []string{"package.json", "package-lock.json"} {
		input, err := os.Open(filepath.Join(source, name))
		if err != nil {
			return fmt.Errorf("open npm fixture %s: %w", name, err)
		}
		output, err := os.OpenFile(filepath.Join(destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = input.Close()
			return fmt.Errorf("create npm manifest %s: %w", name, err)
		}
		_, copyErr := io.Copy(output, input)
		inputCloseErr := input.Close()
		outputCloseErr := output.Close()
		if err := errors.Join(copyErr, inputCloseErr, outputCloseErr); err != nil {
			return fmt.Errorf("copy npm manifest %s: %w", name, err)
		}
	}
	return nil
}

func npmCI(ctx context.Context, project, cache string, offline bool) error {
	args := []string{"ci", "--no-audit", "--no-fund"}
	if offline {
		args = append(args, "--offline")
	}
	command := exec.CommandContext(ctx, "npm", args...)
	command.Dir = project
	command.Env = append(os.Environ(),
		"npm_config_cache="+cache,
		"npm_config_loglevel=error",
		"npm_config_update_notifier=false",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm %v in %s: %w: %s", args, project, err, bytes.TrimSpace(output))
	}
	return nil
}

func npmStartPeerObserver(parent context.Context, f *fixture, project string) func() error {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	var scans atomic.Int64
	peerOwned := filepath.Join(f.b, "npm-peer-owned")
	go func() {
		if err := os.Mkdir(peerOwned, 0o700); err != nil {
			done <- fmt.Errorf("create npm peer-owned directory: %w", err)
			return
		}
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
				if err := npmObservePeerOnce(project, peerOwned, scans.Add(1)); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	return func() error {
		cancel()
		err := <-done
		if err == nil && scans.Load() == 0 {
			return errors.New("npm mount-B observer completed no scans")
		}
		return err
	}
}

func npmObservePeerOnce(project, peerOwned string, sequence int64) error {
	for _, manifest := range []string{"package.json", "package-lock.json"} {
		if _, err := os.ReadFile(filepath.Join(project, manifest)); err != nil {
			return fmt.Errorf("read npm manifest through mount B: %w", err)
		}
	}
	heartbeat := filepath.Join(peerOwned, "heartbeat")
	if err := os.WriteFile(heartbeat, []byte(fmt.Sprintf("%d\n", sequence)), 0o600); err != nil {
		return fmt.Errorf("write npm mount-B heartbeat: %w", err)
	}
	if _, err := os.Stat(heartbeat); err != nil {
		return fmt.Errorf("stat npm mount-B heartbeat: %w", err)
	}

	nodeModules := filepath.Join(project, "node_modules")
	entries, err := os.ReadDir(nodeModules)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list node_modules through mount B: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == ".bin" {
			continue
		}
		packageJSON := filepath.Join(nodeModules, entry.Name(), "package.json")
		if _, err := os.ReadFile(packageJSON); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read installed npm package through mount B: %w", err)
		}
		break
	}
	return nil
}
