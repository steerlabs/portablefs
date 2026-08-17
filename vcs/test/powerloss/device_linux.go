//go:build linux

package powerloss

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The device layer. Everything here shells out to the same tools an operator
// would use, deliberately: a Go reimplementation of losetup or dmsetup would
// be a second thing to trust, and the point of this harness is to reduce the
// number of things being trusted, not raise it.
//
// Every helper is fail-closed. A command that does not exist, a device that
// does not appear, and a teardown that does not complete are all errors, never
// a quiet continue: this harness runs on a shared self-hosted runner, and a
// leaked device-mapper target would break the next run rather than this one.

// FilesystemCommands is what any instrument here needs: a loop-backed XFS it
// can make, mount and check.
var FilesystemCommands = []string{"losetup", "blockdev", "findmnt", "mkfs.xfs", "mount", "umount", "xfs_repair"}

// LogWritesCommands is what the power-cut instrument additionally needs.
var LogWritesCommands = []string{"dmsetup"}

// Runner executes external commands and narrates them. Trace is where the
// narration goes; a nil Trace runs silently.
type Runner struct {
	Trace io.Writer
}

// Run executes a command and returns its combined output. The output is folded
// into the error because these tools say what went wrong on stderr and a bare
// exit status is unreadable in a CI log.
func (r Runner) Run(name string, arguments ...string) (string, error) {
	if r.Trace != nil {
		fmt.Fprintf(r.Trace, "powerloss: %s %s\n", name, strings.Join(arguments, " "))
	}
	command := exec.Command(name, arguments...)
	// dmsetup in a container has no udev to cooperate with, and waiting for
	// cookies that will never be dropped hangs the run instead of failing it.
	command.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("powerloss: %s %s: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// RequireFilesystemSupport reports the first reason this machine cannot make
// and mount a loop-backed XFS, or nil. The caller decides whether that is a
// skip or a failure; this function never decides for it.
func RequireFilesystemSupport() error {
	if os.Geteuid() != 0 {
		return errors.New("this harness needs root: it creates loop devices and filesystem mounts")
	}
	for _, name := range FilesystemCommands {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("%s is not installed", name)
		}
	}
	return nil
}

// RequireLogWritesSupport reports the first reason this machine cannot record
// a write log, or nil. It is separate from RequireFilesystemSupport because
// the process-level instrument runs without device mapper, and folding the two
// together would make it skip for a prerequisite it does not need.
func RequireLogWritesSupport(runner Runner) error {
	if err := RequireFilesystemSupport(); err != nil {
		return err
	}
	for _, name := range LogWritesCommands {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("%s is not installed", name)
		}
	}
	targets, err := runner.Run("dmsetup", "targets")
	if err != nil {
		return fmt.Errorf("device mapper is not usable: %w", err)
	}
	if !strings.Contains(targets, "log-writes") {
		return errors.New("the dm-log-writes target is not loaded; modprobe dm-log-writes first (it is a kernel module, not something this harness can supply)")
	}
	return nil
}

// LoopDevice is a file attached to a loop device.
type LoopDevice struct {
	Image  string
	Device string
	runner Runner
}

// AttachLoop creates a sparse image of the given size and attaches it. The
// image is created rather than reused so a replay always starts from zeros,
// which is what makes a replayed cut the real device state and not the
// previous cut plus this one.
func AttachLoop(runner Runner, image string, size int64) (*LoopDevice, error) {
	if err := os.Remove(image); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("powerloss: clear %s: %w", image, err)
	}
	file, err := os.OpenFile(image, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("powerloss: create %s: %w", image, err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("powerloss: size %s: %w", image, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("powerloss: close %s: %w", image, err)
	}
	return AttachLoopImage(runner, image)
}

// AttachLoopImage attaches an image that already holds the content it should,
// which is how a replayed cut is mounted.
func AttachLoopImage(runner Runner, image string) (*LoopDevice, error) {
	output, err := runner.Run("losetup", "--show", "--find", image)
	if err != nil {
		return nil, err
	}
	device := strings.TrimSpace(output)
	if device == "" {
		return nil, fmt.Errorf("powerloss: losetup attached %s but named no device", image)
	}
	return &LoopDevice{Image: image, Device: device, runner: runner}, nil
}

// Sectors reports the device length in 512-byte units, which is what a
// device-mapper table wants.
func (l *LoopDevice) Sectors() (int64, error) {
	output, err := l.runner.Run("blockdev", "--getsz", l.Device)
	if err != nil {
		return 0, err
	}
	sectors, err := strconv.ParseInt(strings.TrimSpace(output), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("powerloss: blockdev reported %q for %s: %w", strings.TrimSpace(output), l.Device, err)
	}
	return sectors, nil
}

// Detach releases the loop device. It never removes the image: after a failed
// run the log image is the only evidence of what the device was asked to do.
func (l *LoopDevice) Detach() error {
	if l == nil || l.Device == "" {
		return nil
	}
	_, err := l.runner.Run("losetup", "--detach", l.Device)
	if err == nil {
		l.Device = ""
	}
	return err
}

// LogWrites is a dm-log-writes target: every bio the filesystem sends to Path
// is passed to the target device and recorded, in order and with its barriers,
// on the log device.
type LogWrites struct {
	Name   string
	Path   string
	Target *LoopDevice
	Log    *LoopDevice
	runner Runner
}

// CreateLogWrites stacks a fresh dm-log-writes target over two fresh images.
//
// The name must be unique on the machine: the device-mapper namespace is
// kernel-global and shared with every other container and job on the runner,
// so a fixed name would collide with a concurrent run instead of failing it.
func CreateLogWrites(runner Runner, directory, name string, targetSize, logSize int64) (device *LogWrites, err error) {
	target, err := AttachLoop(runner, filepath.Join(directory, name+"-target.img"), targetSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = target.Detach()
		}
	}()
	log, err := AttachLoop(runner, filepath.Join(directory, name+"-log.img"), logSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = log.Detach()
		}
	}()
	sectors, err := target.Sectors()
	if err != nil {
		return nil, err
	}
	table := fmt.Sprintf("0 %d log-writes %s %s", sectors, target.Device, log.Device)
	if _, err := runner.Run("dmsetup", "create", name, "--table", table); err != nil {
		return nil, err
	}
	device = &LogWrites{Name: name, Path: filepath.Join("/dev/mapper", name), Target: target, Log: log, runner: runner}
	// Containers have no udev, so the device node the table just created is not
	// published on its own. mknodes is the documented substitute and is a
	// no-op where udev did the work already.
	if _, err := runner.Run("dmsetup", "mknodes", name); err != nil {
		_ = device.Remove()
		return nil, err
	}
	if _, statErr := os.Stat(device.Path); statErr != nil {
		_ = device.Remove()
		return nil, fmt.Errorf("powerloss: device-mapper accepted the table but %s never appeared: %w", device.Path, statErr)
	}
	return device, nil
}

// Mark inserts an operator mark into the log. The harness takes one
// immediately after every durability claim, and the mark's position in the log
// is what a later replay cuts at.
func (d *LogWrites) Mark(label string) error {
	if !markPattern.MatchString(label) {
		return fmt.Errorf("powerloss: %q is not a safe mark name", label)
	}
	_, err := d.runner.Run("dmsetup", "message", d.Name, "0", "mark", label)
	return err
}

// Release removes the device-mapper target while leaving the loop devices
// attached.
//
// This is the step that makes the log readable. The target's own destructor is
// what flushes the last queued entries and rewrites the superblock with the
// final entry count, so a log read before it has run is short by an
// unpredictable amount - and a short log is a log that understates what
// reached the device, which would make every cut optimistic. It retries
// because a just-unmounted filesystem can hold the device briefly.
func (d *LogWrites) Release() error {
	if d == nil || d.Name == "" {
		return nil
	}
	var removeErr error
	for attempt := range 25 {
		if _, removeErr = d.runner.Run("dmsetup", "remove", d.Name); removeErr == nil {
			d.Name = ""
			return nil
		}
		if attempt == 24 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return removeErr
}

// Remove tears the whole stack down. It reports the first failure rather than
// the last so a leak is attributed correctly.
func (d *LogWrites) Remove() error {
	if d == nil {
		return nil
	}
	var failures []error
	if err := d.Release(); err != nil {
		failures = append(failures, err)
	}
	if err := d.Log.Detach(); err != nil {
		failures = append(failures, err)
	}
	if err := d.Target.Detach(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// ParseLogDevice reads the log the target wrote.
//
// It refuses to run while the target still exists, and it reads the loop
// device rather than the backing file. Both are the same rule from two
// directions: the target must have been released so its destructor has flushed
// the last entries and the final superblock, and the read must go through the
// page cache the loop device serves rather than the file underneath it, which
// the loop driver has not necessarily written back yet. Reading the file early
// is exactly how this harness first reported an empty log for a device that
// had recorded thousands of writes.
func (d *LogWrites) ParseLogDevice() (*Log, func() error, error) {
	if d.Name != "" {
		return nil, nil, fmt.Errorf("powerloss: the %s target is still live; release it before reading the log or the log will be short", d.Name)
	}
	if d.Log == nil || d.Log.Device == "" {
		return nil, nil, fmt.Errorf("powerloss: the log device has already been detached")
	}
	file, err := os.Open(d.Log.Device)
	if err != nil {
		return nil, nil, fmt.Errorf("powerloss: open log device: %w", err)
	}
	info, err := os.Stat(d.Log.Image)
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("powerloss: stat log image: %w", err)
	}
	log, err := ParseLog(file, info.Size())
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return log, file.Close, nil
}

// ReplayImage writes the device image a power cut ending at endEntry would
// have left, to a fresh sparse file of exactly size bytes.
func ReplayImage(log *Log, image string, size int64, endEntry int) error {
	if err := os.Remove(image); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("powerloss: clear replay image: %w", err)
	}
	file, err := os.OpenFile(image, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("powerloss: create replay image: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(size); err != nil {
		return fmt.Errorf("powerloss: size replay image: %w", err)
	}
	if err := log.ReplayTo(file, endEntry); err != nil {
		return err
	}
	return file.Sync()
}

// MountXFS mounts a device and returns the unmount. options is passed
// verbatim; the harness uses the same option set production does so a recovery
// difference cannot be blamed on a different mount.
func MountXFS(runner Runner, device, mountpoint, options string) (func() error, error) {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return nil, fmt.Errorf("powerloss: create mountpoint: %w", err)
	}
	if _, err := runner.Run("mount", "-t", "xfs", "-o", options, device, mountpoint); err != nil {
		return nil, err
	}
	return func() error {
		var last error
		for attempt := range 25 {
			if _, err := runner.Run("umount", mountpoint); err == nil {
				return nil
			} else {
				last = err
			}
			if attempt == 24 {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		return last
	}, nil
}

// CheckXFS runs xfs_repair in its read-only mode.
//
// It must be called on an already-recovered filesystem: xfs_repair -n refuses
// a dirty log rather than replaying it, so the caller mounts and unmounts
// first. That order is the point - the mount is what exercises XFS log
// recovery on the replayed image, and this is the check that recovery left a
// structurally sound filesystem rather than one that merely mounted.
func CheckXFS(runner Runner, device string) error {
	output, err := runner.Run("xfs_repair", "-n", device)
	if err != nil {
		return fmt.Errorf("powerloss: the replayed filesystem is not structurally sound after recovery: %w", err)
	}
	// xfs_repair -n exits zero while printing what it WOULD fix, so the exit
	// status alone is not the gate.
	for _, marker := range []string{"would fix", "would correct", "would have", "corrupt", "bad magic", "would rebuild", "would reset"} {
		if strings.Contains(strings.ToLower(output), marker) {
			return fmt.Errorf("powerloss: xfs_repair -n found damage on the replayed filesystem it would repair:\n%s", strings.TrimSpace(output))
		}
	}
	return nil
}
