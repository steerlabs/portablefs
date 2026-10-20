//go:build linux

package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func processStartIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// comm is parenthesized and may itself contain spaces or ')'. The last
	// ')' closes comm; fields after it begin with field 3 (state). starttime
	// is field 22, therefore index 19 in this suffix.
	close := strings.LastIndexByte(string(data), ')')
	if close < 0 {
		return "", fmt.Errorf("malformed /proc/%d/stat: missing comm terminator", pid)
	}
	fields := strings.Fields(string(data[close+1:]))
	if len(fields) <= 19 {
		return "", fmt.Errorf("malformed /proc/%d/stat: only %d trailing fields", pid, len(fields))
	}
	// Exited processes retain their starttime until reaped, but cannot serve.
	if fields[0] == "Z" || fields[0] == "X" {
		return "", &os.PathError{Op: "open", Path: fmt.Sprintf("/proc/%d/stat", pid), Err: syscall.ENOENT}
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse /proc/%d/stat starttime: %w", pid, err)
	}
	return strconv.FormatUint(start, 10), nil
}
