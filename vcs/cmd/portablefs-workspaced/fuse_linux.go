//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// This is an INIT-only throwaway filesystem, not a PortableFS mount. We write
// the actual negotiated 7.31 reply and detach before exposing the result.
func probeFuse() error {
	path, err := os.MkdirTemp("/run", "workspace-fuse-probe-")
	if err != nil {
		return err
	}
	defer os.Remove(path)
	f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	options := fmt.Sprintf("fd=%d,rootmode=40000,user_id=0,group_id=0", f.Fd())
	if err = unix.Mount("workspace-init-probe", path, "fuse", unix.MS_NOSUID|unix.MS_NODEV, options); err != nil {
		return err
	}
	defer unix.Unmount(path, unix.MNT_DETACH)
	request := make([]byte, 65536)
	n, err := f.Read(request)
	if err != nil {
		return err
	}
	if n < 56 || binary.LittleEndian.Uint32(request[4:]) != 26 {
		return fmt.Errorf("expected FUSE INIT")
	}
	major := binary.LittleEndian.Uint32(request[40:])
	minor := binary.LittleEndian.Uint32(request[44:])
	if major != 7 || minor < 31 {
		return fmt.Errorf("FUSE %d.%d below 7.31", major, minor)
	}
	reply := make([]byte, 80)
	binary.LittleEndian.PutUint32(reply, 80)
	copy(reply[8:16], request[8:16])
	binary.LittleEndian.PutUint32(reply[16:], 7)
	binary.LittleEndian.PutUint32(reply[20:], 31)
	binary.LittleEndian.PutUint32(reply[36:], 128*1024)
	binary.LittleEndian.PutUint32(reply[40:], 1)
	if n, err = f.Write(reply); err != nil || n != len(reply) {
		return fmt.Errorf("FUSE INIT reply: %d: %w", n, err)
	}
	if err = syscall.Unmount(path, 0); err != nil {
		return err
	}
	result, err := json.Marshal(map[string]uint32{"kernel_major": major, "kernel_minor": minor, "negotiated_major": 7, "negotiated_minor": 31})
	if err != nil {
		return err
	}
	return os.WriteFile("/run/portablefs-fuse-init.json", append(result, '\n'), 0644)
}
