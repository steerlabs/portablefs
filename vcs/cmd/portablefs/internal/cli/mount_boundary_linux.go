//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"os"
)

func kernelMountBoundaries() ([]kernelMountBoundary, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var out []kernelMountBoundary
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry, ok := parseLinuxMountInfoEntry(scanner.Text())
		if !ok {
			return nil, fmt.Errorf("malformed /proc/self/mountinfo line %q", scanner.Text())
		}
		out = append(out, kernelMountBoundary{
			path:       entry.mountPoint,
			fsType:     entry.fsType,
			source:     entry.source,
			portableFS: entry.fsType == "fuse.portablefs",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
