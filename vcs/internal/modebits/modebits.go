package modebits

import "os"

const (
	unixPerm   uint32 = 0o0777
	unixSetuid uint32 = 0o4000
	unixSetgid uint32 = 0o2000
	unixSticky uint32 = 0o1000
	unixAll    uint32 = unixPerm | unixSetuid | unixSetgid | unixSticky
)

func CleanUnix(mode uint32) uint32 { return mode & unixAll }

func FromUnix(mode uint32) os.FileMode {
	mode = CleanUnix(mode)
	out := os.FileMode(mode & unixPerm)
	if mode&unixSetuid != 0 {
		out |= os.ModeSetuid
	}
	if mode&unixSetgid != 0 {
		out |= os.ModeSetgid
	}
	if mode&unixSticky != 0 {
		out |= os.ModeSticky
	}
	return out
}

func ToUnix(mode os.FileMode) uint32 {
	out := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		out |= unixSetuid
	}
	if mode&os.ModeSetgid != 0 {
		out |= unixSetgid
	}
	if mode&os.ModeSticky != 0 {
		out |= unixSticky
	}
	return out
}
