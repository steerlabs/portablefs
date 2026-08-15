//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func configureIsolatedProcess(command *exec.Cmd) {
	// Setpgid is applied in the child between fork and exec, so there is no
	// interval in which a timeout can accidentally signal the driver's group.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killIsolatedProcessGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func waitIsolatedProcessGroupGone(pid int, bound time.Duration) error {
	deadline := time.Now().Add(bound)
	for {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("check timed-out worker process group %d: %w", pid, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timed-out worker process group %d still has members %s after SIGKILL; refusing to run a later case", pid, bound)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
