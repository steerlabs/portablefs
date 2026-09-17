//go:build linux

package soak

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A deadlocked daemon can also deadlock Unmount. Give each destructive case a
// process boundary so its failure cannot erase evidence from later workloads.
func isolateSoak(t *testing.T, limit time.Duration) bool {
	t.Helper()
	if os.Getenv("PORTABLEFS_SOAK_TEST") != "1" {
		t.Skip("set PORTABLEFS_SOAK_TEST=1 in the privileged Docker suite")
	}
	if os.Getenv("PORTABLEFS_SOAK_CHILD") == t.Name() {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pattern := strings.Split(t.Name(), "/")
	for i, s := range pattern {
		pattern[i] = "^" + regexp.QuoteMeta(s) + "$"
	}
	before := soakMounts()
	cmd := exec.Command(executable, "-test.v", "-test.run="+strings.Join(pattern, "/"), "-test.timeout="+limit.String())
	cmd.Env = append(os.Environ(), "PORTABLEFS_SOAK_CHILD="+t.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(limit + 5*time.Second):
		// The child's Go timeout has already emitted every goroutine. Kernel-held
		// references sometimes delay exit, so release only its newly created mounts.
		for id, path := range soakMounts() {
			if _, old := before[id]; !old {
				_ = os.WriteFile(filepath.Join("/sys/fs/fuse/connections", id, "abort"), []byte("1\n"), 0600)
				_ = exec.Command("fusermount3", "-u", "-z", path).Run()
			}
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		err = fmt.Errorf("isolated test exceeded %s; captured runtime dump and aborted its mounts", limit)
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	for id, path := range soakMounts() {
		if _, old := before[id]; !old {
			_ = os.WriteFile(filepath.Join("/sys/fs/fuse/connections", id, "abort"), []byte("1\n"), 0600)
			_ = exec.Command("fusermount3", "-u", "-z", path).Run()
		}
	}
	if err != nil {
		t.Errorf("isolated workload: %v", err)
	}
	return true
}
func soakMounts() map[string]string {
	result := map[string]string{}
	data, _ := os.ReadFile("/proc/self/mountinfo")
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || !strings.Contains(line, " - fuse.portablefs portablefs:") {
			continue
		}
		_, id, ok := strings.Cut(fields[2], ":")
		if ok {
			result[id] = fields[4]
		}
	}
	return result
}
