//go:build linux

package main

import (
	"os"
	"syscall"
)

func rawLinksAndAtime(info os.FileInfo) (uint32, int64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint32(stat.Nlink), stat.Atim.Nano(), true
}
