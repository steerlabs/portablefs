//go:build darwin

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
		out.AtimeNs = raw.Atimespec.Sec*1e9 + raw.Atimespec.Nsec
		out.MtimeNs = raw.Mtimespec.Sec*1e9 + raw.Mtimespec.Nsec
	}
	return out
}
