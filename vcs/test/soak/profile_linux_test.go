//go:build linux

package soak

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
)

var soakProfileBinaries sync.Map // profile directory -> exact child executable

// Each isolated soak child owns its profiles. The content-addressed executable
// prevents a later source revision from replacing the symbols for an older run.
func preserveSoakProfileBinary(dir string) (string, error) {
	if binary, ok := soakProfileBinaries.Load(dir); ok {
		return binary.(string), nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	source, err := os.Open(executable)
	if err != nil {
		return "", err
	}
	defer source.Close()
	destination, err := os.CreateTemp(dir, ".soak-binary-")
	if err != nil {
		return "", err
	}
	defer os.Remove(destination.Name())
	digest := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, digest), source)
	closeErr := destination.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	name := fmt.Sprintf("soak-%x.test", digest.Sum(nil))
	if err := os.Rename(destination.Name(), filepath.Join(dir, name)); err != nil {
		return "", err
	}
	soakProfileBinaries.Store(dir, name)
	return name, nil
}

func soakProfileName(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)
}

// Profiles are opt-in and surround the same workload the result measures.
// Profiled elapsed times are marked explicitly; they are not benchmark results.
func startSoakProfile(t *testing.T, phase string) (func(), bool) {
	t.Helper()
	dir := os.Getenv("PORTABLEFS_PROFILE_DIR")
	if dir == "" {
		return func() {}, false
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := preserveSoakProfileBinary(dir)
	if err != nil {
		t.Fatalf("preserve soak profile executable: %v", err)
	}
	prefix := fmt.Sprintf("%s-%s-pid%d", soakProfileName(t.Name()), soakProfileName(phase), os.Getpid())
	if run := strings.TrimSpace(os.Getenv("PORTABLEFS_PROFILE_RUN")); run != "" {
		prefix = soakProfileName(run) + "." + prefix
	}
	path := filepath.Join(dir, prefix)
	writeBlock := func(suffix string) {
		file, err := os.Create(path + "." + suffix + ".pprof")
		if err != nil {
			t.Errorf("open soak block profile: %v", err)
			return
		}
		defer file.Close()
		if err := pprof.Lookup("block").WriteTo(file, 0); err != nil {
			t.Errorf("write soak block profile: %v", err)
		}
	}
	writeBlock("block-before")
	cpu, err := os.Create(path + ".cpu.pprof")
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		cpu.Close()
		t.Fatal(err)
	}
	// One sample per millisecond blocked avoids recording every lock handoff.
	runtime.SetBlockProfileRate(1_000_000)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			pprof.StopCPUProfile()
			if err := cpu.Close(); err != nil {
				t.Errorf("close soak CPU profile: %v", err)
			}
			runtime.SetBlockProfileRate(0)
			writeBlock("block")
			metadata, err := json.Marshal(map[string]any{
				"test": t.Name(), "phase": phase, "binary": binary,
				"cpu": prefix + ".cpu.pprof", "block": prefix + ".block.pprof",
				"block_before": prefix + ".block-before.pprof", "profiled": true,
			})
			if err == nil {
				err = os.WriteFile(path+".profile.json", append(metadata, '\n'), 0600)
			}
			if err != nil {
				t.Errorf("write soak profile manifest: %v", err)
			}
			t.Logf("SOAK_PROFILE %s.profile.json (profiled timings include instrumentation overhead)", path)
		})
	}
	// A failed workload still finalizes its profiles before fixture teardown.
	t.Cleanup(stop)
	return stop, true
}

func TestSoakProfilePreservesExecutableAndPhaseArtifacts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORTABLEFS_PROFILE_DIR", dir)
	t.Setenv("PORTABLEFS_PROFILE_RUN", "run/one")
	stop, profiled := startSoakProfile(t, "git/workload")
	if !profiled {
		t.Fatal("explicit profiling directory did not enable profiles")
	}
	stop()
	stop()
	manifests, err := filepath.Glob(filepath.Join(dir, "run-one.*.profile.json"))
	if err != nil || len(manifests) != 1 {
		t.Fatalf("profile manifests=%v err=%v", manifests, err)
	}
	data, err := os.ReadFile(manifests[0])
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"binary", "cpu", "block", "block_before"} {
		name, ok := manifest[key].(string)
		if !ok || filepath.Base(name) != name {
			t.Fatalf("invalid %s filename: %v", key, manifest[key])
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("missing %s artifact: %v (%v)", key, info, err)
		}
	}
	executable, _ := os.Executable()
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, source); err != nil {
		t.Fatal(err)
	}
	if manifest["binary"] != fmt.Sprintf("soak-%x.test", digest.Sum(nil)) {
		t.Fatal("profile binary does not identify this source build")
	}
}

func TestSoakProfileDisabledWithoutDirectory(t *testing.T) {
	t.Setenv("PORTABLEFS_PROFILE_DIR", "")
	stop, enabled := startSoakProfile(t, "unused")
	stop()
	if enabled {
		t.Fatal("profiling enabled without opt-in")
	}
}
