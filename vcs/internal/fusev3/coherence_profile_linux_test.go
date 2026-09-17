//go:build linux

package fusev3

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
)

var baselineProfileBinaries sync.Map

// Profiles cover the real frontend and Authority in this single test process.
// CPU labels separate their inherited workers; allocation views use stack filters.
func startBaselineProfile(t *testing.T, phase string) func() {
	t.Helper()
	dir := os.Getenv("PORTABLEFS_PROFILE_DIR")
	if dir == "" {
		return func() {}
	}
	binaryPath := filepath.Join(dir, coherenceProfilePrefix("fusev3.test"))
	if _, loaded := baselineProfileBinaries.LoadOrStore(binaryPath, true); !loaded {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		destination, err := os.Create(binaryPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(destination, source); err != nil {
			destination.Close()
			t.Fatal(err)
		}
		if err := destination.Close(); err != nil {
			t.Fatal(err)
		}
	}
	prefix := filepath.Join(dir, coherenceProfilePrefix(strings.ReplaceAll(t.Name(), "/", "-")+"-"+phase))
	writeProfile := func(kind, suffix string) {
		file, err := os.Create(prefix + "." + suffix + ".pprof")
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.Lookup(kind).WriteTo(file, 0); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	runtime.GC()
	writeProfile("allocs", "allocs-before")
	cpu, err := os.Create(prefix + ".cpu.pprof")
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		cpu.Close()
		t.Fatal(err)
	}
	previousMutex := runtime.SetMutexProfileFraction(10)
	runtime.SetBlockProfileRate(1000000)
	var once sync.Once
	return func() {
		once.Do(func() {
			pprof.StopCPUProfile()
			if err := cpu.Close(); err != nil {
				t.Error(err)
			}
			runtime.SetMutexProfileFraction(previousMutex)
			runtime.SetBlockProfileRate(0)
			runtime.GC()
			runtime.GC()
			writeProfile("allocs", "allocs-after")
			writeProfile("mutex", "mutex")
			writeProfile("block", "block")
			t.Logf("PORTABLEFS_PROFILE %s (timings include profiling overhead)", prefix)
		})
	}
}

func TestBaselineProfileUsesRunPrefix(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORTABLEFS_PROFILE_DIR", dir)
	t.Setenv("PORTABLEFS_PROFILE_RUN", "run/one")
	stop := startBaselineProfile(t, "proof")
	stop()
	prefix := "run-one." + t.Name() + "-proof"
	for _, name := range []string{"run-one.fusev3.test", prefix + ".cpu.pprof", prefix + ".allocs-before.pprof", prefix + ".allocs-after.pprof", prefix + ".mutex.pprof", prefix + ".block.pprof"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("profile artifact %s: %v (%v)", name, info, err)
		}
	}
}
