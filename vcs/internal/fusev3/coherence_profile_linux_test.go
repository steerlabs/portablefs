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

var baselineProfileBinary sync.Once

// Profiles cover the real frontend and Authority in this single test process.
// CPU labels separate their inherited workers; allocation views use stack filters.
func startBaselineProfile(t *testing.T, phase string) func() {
	t.Helper()
	dir := os.Getenv("PORTABLEFS_PROFILE_DIR")
	if dir == "" {
		return func() {}
	}
	baselineProfileBinary.Do(func() {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		destination, err := os.Create(filepath.Join(dir, "fusev3.test"))
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
	})
	prefix := filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-"+phase)
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
			writeProfile("allocs", "allocs-after")
			writeProfile("mutex", "mutex")
			writeProfile("block", "block")
			t.Logf("PORTABLEFS_PROFILE %s (timings include profiling overhead)", prefix)
		})
	}
}
