//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func startUnreapedMountProcess(t *testing.T) (*mountState, *os.File) {
	t.Helper()
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	child, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "read line; exit 0"}, &os.ProcAttr{
		Files: []*os.File{input, os.Stdout, os.Stderr},
	})
	if err != nil {
		release.Close()
		t.Fatal(err)
	}
	// Wait only during cleanup so assertions observe an unreaped child.
	t.Cleanup(func() {
		release.Close()
		child.Kill()
		if _, err := child.Wait(); err != nil {
			t.Errorf("reap child: %v", err)
		}
	})
	identity, err := processStartIdentity(child.Pid)
	if err != nil {
		t.Fatal(err)
	}
	st := &mountState{PID: child.Pid, ProcessStartIdentity: identity, Strategy: "fuse"}
	if !mountProcessMatches(st) {
		t.Fatal("live child does not match its recorded identity")
	}
	return st, release
}

func waitForMountProcessZombie(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var state string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			t.Fatal(err)
		}
		close := strings.LastIndexByte(string(data), ')')
		if close < 0 {
			t.Fatalf("missing comm terminator in child stat: %q", data)
		}
		fields := strings.Fields(string(data[close+1:]))
		if len(fields) == 0 {
			t.Fatalf("missing state in child stat: %q", data)
		}
		state = fields[0]
		if state == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child %d did not become a zombie; state = %q", pid, state)
}

func TestProcessStartIdentityRejectsZombie(t *testing.T) {
	st, release := startUnreapedMountProcess(t)
	if err := release.Close(); err != nil {
		t.Fatal(err)
	}
	waitForMountProcessZombie(t, st.PID)
	if identity, err := processStartIdentity(st.PID); identity != "" || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("zombie identity = %q, error = %v; want no identity and ENOENT", identity, err)
	}
	if mountProcessMatches(st) {
		t.Fatal("zombie matches the live mount process")
	}
}

func TestStopMountDaemonAcceptsZombie(t *testing.T) {
	for _, alreadyExited := range []bool{true, false} {
		t.Run(fmt.Sprintf("already_exited=%t", alreadyExited), func(t *testing.T) {
			st, release := startUnreapedMountProcess(t)
			if alreadyExited {
				if err := release.Close(); err != nil {
					t.Fatal(err)
				}
				waitForMountProcessZombie(t, st.PID)
			}
			start := time.Now()
			if err := stopMountDaemon(st); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("stopping an exited supervisor took %v", elapsed)
			}
			waitForMountProcessZombie(t, st.PID)
		})
	}
}
