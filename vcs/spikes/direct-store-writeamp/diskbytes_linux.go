//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func diskBytesWritten() (uint64, error) {
	file, err := os.Open("/proc/self/io")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if found && key == "write_bytes" {
			written, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse /proc/self/io write_bytes: %w", err)
			}
			return written, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("/proc/self/io has no write_bytes counter")
}
