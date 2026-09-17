//go:build linux

// Package soak exercises protocol 7 through real kernel mounts. It deliberately
// imports only public product APIs: the model observes the same syscalls as apps.
package soak

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	*integrationFixture
	a, b, root string
	barriers   []*os.File
}

func newFixture(t *testing.T) *fixture { return newFixtureConfig(t, integrationConfig{}) }
func newFixtureConfig(t *testing.T, cfg integrationConfig) *fixture {
	t.Helper()
	caseStart := time.Now()
	if os.Getenv("PORTABLEFS_SOAK_TEST") != "1" {
		t.Skip("set PORTABLEFS_SOAK_TEST=1 in the privileged Docker suite")
	}
	dir := os.Getenv("PORTABLEFS_PROFILE_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	logfile, err := os.Create(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+".daemon-authority.log"))
	if err != nil {
		t.Fatal(err)
	}
	prior := log.Writer()
	log.SetOutput(io.MultiWriter(prior, logfile))
	t.Cleanup(func() { log.SetOutput(prior); _ = logfile.Close() })
	f := &fixture{integrationFixture: newIntegrationFixture(t, cfg)}
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-ticker.C:
				out, e := os.Create(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-live.goroutines.txt"))
				if e == nil {
					_ = pprof.Lookup("goroutine").WriteTo(out, 2)
					_ = out.Close()
				}
				counts, _ := json.Marshal(f.counts())
				_ = os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-live.requests.json"), append(counts, '\n'), 0600)
			}
		}
	}()
	t.Cleanup(func() { close(stopWatch); <-watchDone })

	f.a, f.root = f.paths[0], f.volumeRoot
	if len(f.paths) > 1 {
		f.b = f.paths[1]
	} else {
		f.b = f.a
	}
	for _, p := range f.paths {
		h, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		f.barriers = append(f.barriers, h)
	}
	t.Cleanup(func() {
		counts := f.counts()
		total := 0
		for _, n := range counts {
			total += n
		}
		data, _ := json.Marshal(map[string]any{"test": t.Name(), "seconds": time.Since(caseStart).Seconds(), "requests": counts, "total_requests": total, "body_pass": !t.Failed()})
		t.Logf("SOAK_CASE %s", data)
		_ = os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+".case.json"), append(data, '\n'), 0600)
		if t.Failed() {
			f.dump(t, "failure")
		}
		for _, h := range f.barriers {
			_ = h.Close()
		}
	})
	return f
}
func (f *fixture) dump(t *testing.T, label string) {
	dir := os.Getenv("PORTABLEFS_PROFILE_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	name := strings.ReplaceAll(t.Name(), "/", "-") + "-" + label
	out, err := os.Create(filepath.Join(dir, name+".goroutines.txt"))
	if err == nil {
		_ = pprof.Lookup("goroutine").WriteTo(out, 2)
		_ = out.Close()
	}
	f.counter.mu.Lock()
	data, _ := json.MarshalIndent(f.counter.byKind, "", "  ")
	f.counter.mu.Unlock()
	_ = os.WriteFile(filepath.Join(dir, name+".requests.json"), data, 0600)
	t.Logf("diagnostics=%s/%s session=%s", dir, name, f.sessionDiagnostics())
}
func (f *fixture) barrier(t *testing.T) {
	t.Helper()
	for i, h := range f.barriers {
		if err := h.Sync(); err != nil {
			t.Fatalf("run barrier mount %d: %v", i, err)
		}
	}
}
func (f *fixture) counts() map[string]int {
	f.counter.mu.Lock()
	defer f.counter.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.counter.byKind {
		out[k] = v
	}
	return out
}
func (f *fixture) measure(t *testing.T, name string, run func() error) {
	t.Helper()
	before := f.counts()
	start := time.Now()
	err := run()
	after := f.counts()
	total := 0
	for k, v := range after {
		after[k] = v - before[k]
		total += after[k]
	}
	result := map[string]any{"workload": name, "seconds": time.Since(start).Seconds(), "requests": after, "total_requests": total, "pass": err == nil}
	if err != nil {
		result["error"] = err.Error()
	}
	data, _ := json.Marshal(result)
	t.Logf("SOAK_RESULT %s", data)
	if dir := os.Getenv("PORTABLEFS_PROFILE_DIR"); dir != "" {
		path := filepath.Join(dir, "soak-results.jsonl")
		h, e := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if e == nil {
			_, _ = h.Write(append(data, '\n'))
			_ = h.Close()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func treeHashes(root string) (map[string]string, error) {
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			result[rel] = "dir"
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			result[rel] = "link:" + target
			return e
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		result[rel] = fmt.Sprintf("%x", sha256.Sum256(data))
		return nil
	})
	return result, err
}
func compareTrees(want, got map[string]string) error {
	if len(want) != len(got) {
		return fmt.Errorf("tree entries got=%d want=%d", len(got), len(want))
	}
	for p, h := range want {
		if got[p] != h {
			return fmt.Errorf("tree mismatch %s got=%s want=%s", p, got[p], h)
		}
	}
	return nil
}

// Published names are immutable. The channel establishes close-before-open;
// directory walks alone cannot distinguish partial writes from stale reads.
func (f *fixture) peerObserver(t *testing.T) (chan<- string, func() error) {
	published := make(chan string, 256)
	errs := make(chan error, 1)
	base := filepath.Join(f.b, "peer-owned")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := os.OpenFile(filepath.Join(base, "heartbeat"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer heartbeat.Close()
		var first error
		record := func(err error) {
			if first == nil && err != nil {
				first = err
			}
		}
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		sequence := 0
		for {
			select {
			case rel, ok := <-published:
				if !ok {
					errs <- first
					return
				}
				got, err := os.ReadFile(filepath.Join(f.b, rel))
				record(err)
				if err == nil && string(got) != packagePayload(rel) {
					record(fmt.Errorf("close-to-open mismatch %s: %q", rel, got))
				}
			case <-ticker.C:
				_, err := os.ReadDir(f.b)
				record(err)
				data := []byte(fmt.Sprint(sequence))
				sequence++
				_, err = heartbeat.WriteAt(data, 0)
				record(err)
				_, err = heartbeat.Stat()
				record(err)
				got := make([]byte, len(data))
				_, err = heartbeat.ReadAt(got, 0)
				record(err)
				if string(got) != string(data) {
					record(fmt.Errorf("peer heartbeat got %q want %q", got, data))
				}
				// Inspect one changing package directory per tick. Recursively
				// walking all 3,000 directories here would throttle the writer
				// through the publication channel instead of observing it.
				sample := filepath.Join(f.b, "packages", fmt.Sprintf("pkg-%04d", sequence%3000))
				entries, e := os.ReadDir(sample)
				if !os.IsNotExist(e) {
					record(e)
				}
				if len(entries) > 0 {
					p := filepath.Join(sample, entries[0].Name())
					_, e = os.Stat(p)
					if !os.IsNotExist(e) {
						record(e)
					}
					_, e = os.ReadFile(p)
					if !os.IsNotExist(e) {
						record(e)
					}
				}

			}
		}
	}()
	var once sync.Once
	return published, func() error { once.Do(func() { close(published) }); return <-errs }
}
func packagePayload(rel string) string {
	return "portablefs deterministic package content: " + rel + "\n"
}
func TestSoakPackageTree(t *testing.T) {
	if isolateSoak(t, 5*time.Minute) {
		return
	}
	f := newFixture(t)
	f.measure(t, "package-tree-20000-files-3000-directories-two-mounts", func() error {
		if err := os.Mkdir(filepath.Join(f.a, "packages"), 0700); err != nil {
			return err
		}
		published, stop := f.peerObserver(t)
		stopped := false
		defer func() {
			if !stopped {
				_ = stop()
			}
		}()
		expected := map[string]string{}
		for i := 0; i < 3000; i++ {
			rel := fmt.Sprintf("pkg-%04d", i)
			if err := os.Mkdir(filepath.Join(f.a, "packages", rel), 0700); err != nil {
				return err
			}
			expected[rel] = "dir"
		}
		for i := 0; i < 20000; i++ {
			rel := fmt.Sprintf("packages/pkg-%04d/file-%05d.js", i%3000, i)
			data := []byte(packagePayload(rel))
			if err := f.bounded(t, "package write "+rel, 20*time.Second, func() error { return os.WriteFile(filepath.Join(f.a, rel), data, 0600) }); err != nil {
				return err
			}
			expected[strings.TrimPrefix(rel, "packages/")] = fmt.Sprintf("%x", sha256.Sum256(data))
			published <- rel
			if i%2000 == 0 {
				t.Logf("package progress %d/20000", i)
			}
		}
		for i := 0; i < 100; i++ {
			dir := fmt.Sprintf("pkg-%04d", i)
			src := fmt.Sprintf("file-%05d.js", i)
			hard := filepath.Join(dir, "hard.js")
			sym := filepath.Join(dir, "symlink.js")
			if err := os.Link(filepath.Join(f.a, "packages", dir, src), filepath.Join(f.a, "packages", hard)); err != nil {
				return err
			}
			if err := os.Symlink(src, filepath.Join(f.a, "packages", sym)); err != nil {
				return err
			}
			expected[hard] = expected[filepath.Join(dir, src)]
			expected[sym] = "link:" + src
		}
		err := stop()
		stopped = true
		if err != nil {
			return err
		}
		f.barrier(t)
		for _, root := range []string{f.a, f.b, f.root} {
			got, err := treeHashes(filepath.Join(root, "packages"))
			if err != nil {
				return err
			}
			if err = compareTrees(expected, got); err != nil {
				return fmt.Errorf("%s: %w", root, err)
			}
		}
		return nil
	})
}
func TestSoakGit(t *testing.T) {
	if isolateSoak(t, 20*time.Minute) {
		return
	}
	gitWorkload(t, newFixture(t))
}
func TestSoakCompiler(t *testing.T) {
	if isolateSoak(t, 5*time.Minute) {
		return
	}
	compilerWorkload(t, newFixture(t))
}

// A stuck kernel syscall must not prevent the remaining soak cases from running.
// Capture the live wait graph before aborting only this fixture's connections.
func (f *fixture) bounded(t *testing.T, label string, bound time.Duration, run func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- run() }()
	select {
	case err := <-done:
		return err
	case <-time.After(bound):
		f.dump(t, "timeout")
		f.abortConnections(t)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		return fmt.Errorf("%s exceeded %s (fixture connections aborted after capture)", label, bound)
	}
}
func (f *fixture) abortConnections(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Log(err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		own := false
		for _, path := range f.paths {
			if fields[4] == path {
				own = true
			}
		}
		if !own {
			continue
		}
		_, minor, ok := strings.Cut(fields[2], ":")
		if !ok {
			continue
		}
		if err := os.WriteFile(filepath.Join("/sys/fs/fuse/connections", minor, "abort"), []byte("1\n"), 0600); err != nil {
			t.Logf("abort own FUSE connection %s: %v", minor, err)
		}
	}
}

func (f *fixture) coldRemount(t *testing.T) {
	t.Helper()
	f.barrier(t)
	for _, h := range f.barriers {
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f.barriers = nil
	f.unmountAll()
	f.mountAll()
	for _, path := range f.paths {
		h, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		f.barriers = append(f.barriers, h)
	}
}
