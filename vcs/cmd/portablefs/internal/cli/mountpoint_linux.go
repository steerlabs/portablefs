//go:build linux

package cli

import (
	"bufio"
	"os"
)

func isMountpoint(path string) bool {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mountPoint, _, _, ok := parseLinuxMountInfoLine(scanner.Text())
		if ok && mountPoint == path {
			return true
		}
	}
	return false
}
