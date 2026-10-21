//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

// Native-gate-only throwaway filesystem. fusermount3 grants an ordinary user
// the descriptor; the subsequent kernel STATFS proves INIT was accepted.
func probeFuse() error {
	path, err := os.MkdirTemp("", "workspace-fuse-probe-")
	if err != nil {
		return fmt.Errorf("create FUSE probe directory: %w", err)
	}
	defer os.Remove(path)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create mount-helper socket: %w", err)
	}
	parent := os.NewFile(uintptr(pair[0]), "fuse-helper-parent")
	child := os.NewFile(uintptr(pair[1]), "fuse-helper-child")
	defer parent.Close()
	defer child.Close()
	helper := exec.Command("fusermount3", "-o", "rw,nosuid,nodev,fsname=workspace-native-probe", "--", path)
	helper.Env = append(os.Environ(), "_FUSE_COMMFD=3")
	helper.ExtraFiles = []*os.File{child}
	helper.Stderr = os.Stderr
	if err = helper.Run(); err != nil {
		return fmt.Errorf("mount native FUSE probe: %w", err)
	}
	defer exec.Command("fusermount3", "-u", "-z", "--", path).Run()
	data, ancillary := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, n, _, _, err := unix.Recvmsg(int(parent.Fd()), data, ancillary, 0)
	if err != nil {
		return fmt.Errorf("receive FUSE descriptor: %w", err)
	}
	messages, err := unix.ParseSocketControlMessage(ancillary[:n])
	if err != nil || len(messages) != 1 {
		return fmt.Errorf("invalid FUSE descriptor message: %v", err)
	}
	rights, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(rights) != 1 {
		return fmt.Errorf("invalid FUSE descriptor rights: %v", err)
	}
	f := os.NewFile(uintptr(rights[0]), "fuse-native-probe")
	defer f.Close()
	request := make([]byte, 65536)
	n, err = f.Read(request)
	if err != nil {
		return fmt.Errorf("read kernel FUSE INIT: %w", err)
	}
	if n < 56 || binary.LittleEndian.Uint32(request[4:]) != 26 {
		return fmt.Errorf("expected FUSE INIT")
	}
	major, minor := binary.LittleEndian.Uint32(request[40:]), binary.LittleEndian.Uint32(request[44:])
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
	if n, err = f.Write(reply); err != nil {
		return fmt.Errorf("write FUSE INIT: %w", err)
	} else if n != len(reply) {
		return fmt.Errorf("short FUSE INIT reply: %d", n)
	}
	statResult := make(chan error, 1)
	go func() { var stat unix.Statfs_t; statResult <- unix.Statfs(path, &stat) }()
	n, err = f.Read(request)
	if err != nil {
		return fmt.Errorf("read initialized FUSE request: %w", err)
	}
	if n < 40 || binary.LittleEndian.Uint32(request[4:]) != 17 {
		return fmt.Errorf("expected kernel STATFS after INIT")
	}
	reply = make([]byte, 96)
	binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
	copy(reply[8:16], request[8:16])
	binary.LittleEndian.PutUint32(reply[56:], 4096)
	binary.LittleEndian.PutUint32(reply[60:], 255)
	binary.LittleEndian.PutUint32(reply[64:], 4096)
	if _, err = f.Write(reply); err != nil {
		return fmt.Errorf("write FUSE STATFS: %w", err)
	}
	if err = <-statResult; err != nil {
		return fmt.Errorf("kernel rejected initialized FUSE connection: %w", err)
	}
	if output, err := exec.Command("fusermount3", "-u", "--", path).CombinedOutput(); err != nil {
		return fmt.Errorf("unmount initialized probe: %w: %s", err, output)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"kernel_major": major, "kernel_minor": minor, "negotiated_major": 7, "negotiated_minor": 31, "initialized": true, "uid": strconv.Itoa(os.Getuid())})
}
