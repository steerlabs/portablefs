package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const (
	testHelperModeEnv  = "PFS_MATRIX_TEST_HELPER_MODE"
	testHelperFIFOEnv  = "PFS_MATRIX_TEST_HELPER_FIFO"
	testHelperReadyEnv = "PFS_MATRIX_TEST_HELPER_READY"
)

// TestMain gives the test binary the same private child entry point as the
// production binary. That lets the regression exercise fork/exec, process
// groups, JSON framing, and the next real case rather than a mock launcher.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == isolatedChildArgument {
		if os.Getenv(testHelperModeEnv) == "hung-syscall" {
			os.Exit(runHungSyscallHelper())
		}
		if err := serveIsolatedChild(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runHungSyscallHelper() int {
	fifo := os.Getenv(testHelperFIFOEnv)
	ready := os.Getenv(testHelperReadyEnv)
	if fifo == "" || ready == "" {
		return 2
	}
	if err := os.WriteFile(ready, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return 3
	}
	// With no FIFO reader, this ordinary open(2) blocks indefinitely. A Go
	// context cannot cancel it; only ownership of the process can bound it.
	file, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		return 4
	}
	_ = file.Close()
	return 5
}

func TestTimedOutSyscallWorkerIsReapedBeforeNextCase(t *testing.T) {
	temp := t.TempDir()
	fifo := filepath.Join(temp, "blocked.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	ready := filepath.Join(temp, "ready")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, isolatedChildArgument)
	command.Env = append(os.Environ(),
		testHelperModeEnv+"=hung-syscall",
		testHelperFIFOEnv+"="+fifo,
		testHelperReadyEnv+"="+ready,
	)
	execution, err := executeIsolatedCommand(command, nil, time.Second)
	if err != nil {
		t.Fatalf("time out owned worker: %v", err)
	}
	if !execution.timedOut {
		t.Fatalf("hung syscall worker was not reported as timed out: %+v", execution)
	}
	if execution.duration < 900*time.Millisecond || execution.duration > 3*time.Second {
		t.Fatalf("hung syscall worker terminated after %s, want the 1s bound (with scheduler tolerance)", execution.duration)
	}
	pidBytes, err := os.ReadFile(ready)
	if err != nil {
		t.Fatalf("worker never entered the blocking syscall: %v", err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatalf("parse worker pid %q: %v", pidBytes, err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("timed-out worker pid %d still exists after executeIsolatedCommand returned: %v", pid, err)
	}

	// The next worker executes a real matrix case through ordinary filesystem
	// syscalls. It must not inherit an actor, descriptor, goroutine, or timeout
	// state from the killed worker.
	entry, ok := findCase("remote_create_visible")
	if !ok {
		t.Fatal("remote_create_visible case missing")
	}
	root := filepath.Join(temp, "shared")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := executeIsolatedCase(entry, isolatedSpec{
		MountA:    root,
		MountB:    root,
		SSHBinary: "pfs-coherence-matrix",
		RunID:     "after-timeout",
	}, caseInputs{}, 5*time.Second)
	if err != nil {
		t.Fatalf("run case after timeout: %v", err)
	}
	if result.Status != statusPass {
		t.Fatalf("case after timeout = %+v, want PASS", result)
	}
}
