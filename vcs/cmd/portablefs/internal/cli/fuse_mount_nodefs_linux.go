//go:build linux

// The FUSE descriptor handoff protocol in this file follows go-fuse v2's
// BSD-licensed mount_linux.go/mount.go implementation (Copyright 2016-2025
// The Go-FUSE Authors), with the execution boundary changed to a caller-pinned
// helper inode.
package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
	"golang.org/x/sys/unix"
)

type startFUSEHelperFunc func(string, []string, *os.ProcAttr) (*os.Process, error)

func mountNodeFS(
	dir string,
	root fs.InodeEmbedder,
	options *fs.Options,
	mechanism, helperPath string,
	beforeServe func(),
) (*fuse.Server, error) {
	rawFS := fs.NewNodeFS(root, options)
	if mechanism == "direct" {
		server, err := fuse.NewServer(rawFS, dir, &options.MountOptions)
		if err != nil {
			return nil, err
		}
		if beforeServe != nil {
			beforeServe()
		}
		go server.Serve()
		if err := server.WaitMount(); err != nil {
			return nil, err
		}
		return server, nil
	}
	if mechanism != "helper" {
		return nil, fmt.Errorf("unsupported Linux FUSE mount mechanism %q", mechanism)
	}
	fd, err := callExactFUSEHelper(helperPath, dir, &options.MountOptions)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	server, err := fuse.NewServer(rawFS, fmt.Sprintf("/dev/fd/%d", fd), &options.MountOptions)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if beforeServe != nil {
		beforeServe()
	}
	go server.Serve()
	if err := server.WaitMount(); err != nil {
		return nil, err
	}
	return server, nil
}

func callExactFUSEHelper(selected, mountPoint string, options *fuse.MountOptions) (int, error) {
	localFDs, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return -1, os.NewSyscallError("socketpair", err)
	}
	local := os.NewFile(uintptr(localFDs[0]), "portablefs-fuse-helper-local")
	remote := os.NewFile(uintptr(localFDs[1]), "portablefs-fuse-helper-remote")
	defer local.Close()
	defer remote.Close()

	argv := []string{selected, mountPoint}
	if mountOptions := exactFUSEMountOptions(options); len(mountOptions) > 0 {
		argv = append(argv, "-o", strings.Join(mountOptions, ","))
	}
	process, err := startPinnedFUSEHelper(
		selected,
		argv,
		[]*os.File{os.Stdin, os.Stdout, os.Stderr, remote},
		os.StartProcess,
	)
	if err != nil {
		return -1, fmt.Errorf("start exact FUSE helper %s: %w", selected, err)
	}
	status, err := process.Wait()
	if err != nil {
		return -1, fmt.Errorf("wait for exact FUSE helper %s: %w", selected, err)
	}
	if !status.Success() {
		return -1, fmt.Errorf("exact FUSE helper %s exited with %v", selected, status.Sys())
	}
	fd, err := receiveFUSEConnection(local)
	if err != nil {
		return -1, fmt.Errorf("receive FUSE descriptor from exact helper %s: %w", selected, err)
	}
	return fd, nil
}

// startPinnedFUSEHelper opens the validated resolved executable first and
// executes that pinned inode through procfs. PATH is never consulted by the
// execution edge and replacing the selected pathname cannot change the inode
// that the kernel executes.
func startPinnedFUSEHelper(selected string, argv []string, files []*os.File, start startFUSEHelperFunc) (*os.Process, error) {
	if err := mounthost.ValidateFUSEHelper(selected); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(selected)
	if err != nil {
		return nil, fmt.Errorf("resolve selected FUSE helper: %w", err)
	}
	fd, err := unix.Open(resolved, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("pin selected FUSE helper: %w", err)
	}
	pinned := os.NewFile(uintptr(fd), resolved)
	defer pinned.Close()
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, fmt.Errorf("inspect pinned FUSE helper: %w", err)
	}
	if err := unix.Stat(resolved, &named); err != nil ||
		opened.Dev != named.Dev || opened.Ino != named.Ino ||
		opened.Mode&unix.S_IFMT != unix.S_IFREG ||
		opened.Uid != 0 || opened.Mode&0o111 == 0 || opened.Mode&0o022 != 0 {
		return nil, fmt.Errorf("selected FUSE helper changed while pinning")
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("missing FUSE helper argv")
	}
	return start(
		fmt.Sprintf("/proc/self/fd/%d", fd),
		argv,
		&os.ProcAttr{
			Env:   []string{"_FUSE_COMMFD=3"},
			Files: files,
		},
	)
}

func exactFUSEMountOptions(options *fuse.MountOptions) []string {
	values := append([]string(nil), options.Options...)
	if options.AllowOther {
		values = append(values, "allow_other")
	}
	if options.FsName != "" {
		values = append(values, "fsname="+options.FsName)
	}
	if options.Name != "" {
		values = append(values, "subtype="+options.Name)
	}
	values = append(values, fmt.Sprintf("max_read=%d", options.MaxWrite))
	if options.IDMappedMount && !containsMountOption(options.Options, "default_permissions") {
		values = append(values, "default_permissions")
	}
	for i := range values {
		values[i] = strings.NewReplacer(`\`, `\\`, `,`, `\,`).Replace(values[i])
	}
	return values
}

func containsMountOption(options []string, expected string) bool {
	for _, option := range options {
		if option == expected {
			return true
		}
	}
	return false
}

func receiveFUSEConnection(local *os.File) (int, error) {
	connection, err := net.FileConn(local)
	if err != nil {
		return -1, err
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("FUSE helper socket is not Unix")
	}
	var data [4]byte
	control := make([]byte, 4*256)
	_, controlBytes, _, _, err := unixConnection.ReadMsgUnix(data[:], control)
	if err != nil {
		return -1, err
	}
	messages, err := syscall.ParseSocketControlMessage(control[:controlBytes])
	if err != nil {
		return -1, err
	}
	if len(messages) != 1 {
		return -1, fmt.Errorf("expected one FUSE descriptor control message, got %d", len(messages))
	}
	fds, err := syscall.ParseUnixRights(&messages[0])
	if err != nil {
		return -1, err
	}
	if len(fds) != 1 || fds[0] < 0 {
		return -1, fmt.Errorf("expected one valid FUSE descriptor, got %v", fds)
	}
	return fds[0], nil
}
