package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// fuseAvailable reports whether this host can create FUSE mounts, with a
// human-actionable reason when it cannot.
func fuseAvailable() (bool, string) {
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/dev/fuse"); err != nil {
			return false, "/dev/fuse not present (install fuse3 / load the fuse kernel module)"
		}
		if _, err := exec.LookPath("fusermount3"); err != nil {
			if _, err := exec.LookPath("fusermount"); err != nil {
				return false, "fusermount3/fusermount not in PATH (apt install fuse3)"
			}
		}
		return true, ""
	default:
		return false, "FUSE benchmarks are Linux-only (macOS mounts use FSKit); run the harness in docker/Linux, or use -transport core"
	}
}

// buildFuseTransport starts an in-process authority and mounts it via the
// benchmount binary as a subprocess, returning a localFS pointed at the
// mountpoint.
func buildFuseTransport(work string, cfg benchConfig, mountBin string) (benchFS, func(), error) {
	if ok, reason := fuseAvailable(); !ok {
		if os.Getenv("PFSBENCH_MOUNT_ONLY") == "skip" {
			log.Printf("SKIP fuse transport: %s", reason)
			os.Exit(0)
		}
		return nil, nil, fmt.Errorf("fuse transport unavailable: %s (set PFSBENCH_MOUNT_ONLY=skip to skip)", reason)
	}
	if mountBin == "" {
		return nil, nil, fmt.Errorf("fuse transport needs -mount-bin (go build -o benchmount ./bench/cmd/benchmount)")
	}
	addr, stopAuth, err := startAuthority(context.Background(), "127.0.0.1:0", filepath.Join(work, "authority.wal"))
	if err != nil {
		return nil, nil, err
	}
	mountpoint := filepath.Join(work, "mnt")
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		stopAuth()
		return nil, nil, err
	}
	f := &fuseFS{
		localFS:    newLocalFS(mountpoint),
		mountBin:   mountBin,
		addr:       addr,
		mountpoint: mountpoint,
		cfg:        cfg,
	}
	if err := f.mount(); err != nil {
		stopAuth()
		return nil, nil, err
	}
	cleanup := func() {
		_ = f.unmount()
		stopAuth()
	}
	return f, cleanup, nil
}

// fuseFS is a localFS over a real kernel mountpoint, plus mount lifecycle so
// Fresh() can drop kernel + client caches by remounting.
type fuseFS struct {
	*localFS
	mountBin   string
	addr       string
	mountpoint string
	cfg        benchConfig
	proc       *exec.Cmd
}

// args builds the benchmount flag list for this config. benchmount is
// bench-only and reads no product environment variables; every swept knob is
// an explicit flag. (fsync on the mount forces the covering write-back
// session to the authority, so localFS.SyncDurable is a real durability
// barrier.)
func (f *fuseFS) args() []string {
	args := []string{
		"-addr", f.addr,
		"-mount", f.mountpoint,
		"-pool", strconv.Itoa(f.cfg.Pool),
		"-session-ttl-ms", strconv.Itoa(f.cfg.SessionTTLMs),
	}
	if f.cfg.WriteThrough {
		args = append(args, "-write-through")
	}
	if f.cfg.NegativeCache {
		args = append(args, "-negcache")
	}
	if f.cfg.NoReaddirPlus {
		args = append(args, "-no-readdirplus")
	}
	return args
}

// mount starts the mount subprocess and waits until the volume is visible at
// the mountpoint: a marker created straight at the authority must appear
// through the kernel path.
func (f *fuseFS) mount() error {
	cli, err := fsproto.Dial(f.addr, 1)
	if err != nil {
		return err
	}
	defer cli.Close()
	marker := fmt.Sprintf(".pfsbench-ready-%d", time.Now().UnixNano())
	if _, st, err := cli.Create(marker, 0o644); err != nil || st != fsproto.OK {
		return fmt.Errorf("create ready marker: st=%d err=%v", st, err)
	}

	cmd := exec.Command(f.mountBin, f.args()...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	f.proc = cmd
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(filepath.Join(f.mountpoint, marker)); err == nil {
			if st, _ := cli.Remove(marker); st != fsproto.OK {
				return fmt.Errorf("remove ready marker: status %d", st)
			}
			return nil
		}
		if cmd.ProcessState != nil {
			return fmt.Errorf("mount process exited before becoming ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = f.unmount()
	return fmt.Errorf("mount did not become ready within 30s")
}

// unmount signals the mount (its handler runs the unmount flush barrier) and
// falls back to fusermount/umount if it does not exit promptly.
func (f *fuseFS) unmount() error {
	if f.proc == nil || f.proc.Process == nil {
		return nil
	}
	_ = f.proc.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- f.proc.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		if _, err := exec.LookPath("fusermount3"); err == nil {
			_ = exec.Command("fusermount3", "-u", f.mountpoint).Run()
		} else {
			_ = exec.Command("fusermount", "-u", f.mountpoint).Run()
		}
		_ = f.proc.Process.Kill()
		<-done
	}
	f.proc = nil
	return nil
}

// Fresh remounts: kernel dentry/attr/page caches and the client's attr/version
// caches are all dropped — the strongest cold-read definition available.
func (f *fuseFS) Fresh() error {
	if err := f.unmount(); err != nil {
		return err
	}
	return f.mount()
}

func (f *fuseFS) Close() error { return f.unmount() }
