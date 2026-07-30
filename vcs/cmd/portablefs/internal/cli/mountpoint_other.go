//go:build !darwin && !linux

package cli

func isMountpoint(string) bool { return false }
