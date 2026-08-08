//go:build linux

package main

import (
	"os"
	"syscall"
)

func describe(info os.FileInfo) *statInfo {
	out := &statInfo{
		Size:    info.Size(),
		Mode:    uint32(info.Mode()),
		Perm:    uint32(info.Mode().Perm()),
		MtimeNs: info.ModTime().UnixNano(),
		IsDir:   info.IsDir(),
		IsLink:  info.Mode()&os.ModeSymlink != 0,
	}
	if raw, ok := info.Sys().(*syscall.Stat_t); ok {
		out.UID, out.GID = raw.Uid, raw.Gid
		out.Ino, out.Nlink = raw.Ino, uint64(raw.Nlink)
		out.AtimeNs = raw.Atim.Sec*1e9 + raw.Atim.Nsec
		out.MtimeNs = raw.Mtim.Sec*1e9 + raw.Mtim.Nsec
	}
	return out
}
