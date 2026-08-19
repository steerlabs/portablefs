//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const integrationWriteFragmentBytes = 1 << 20

func deterministicIntegrationData(size, seed int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte((i*131 + seed) % 251)
	}
	return data
}

func requireSyscallWrite(t *testing.T, operation string, write func() (int, error), want int) {
	t.Helper()
	written, err := write()
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
	if written != want {
		t.Fatalf("%s wrote %d bytes, want %d", operation, written, want)
	}
}

func requireFallocate(t *testing.T, file *os.File, mode uint32, offset, length int64, operation string) {
	t.Helper()
	if err := unix.Fallocate(int(file.Fd()), mode, offset, length); err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}

func requireExactFile(t *testing.T, path string, want []byte, operation string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: read %s: %v", operation, path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: content length %d, want %d; first mismatch near %q versus %q",
			operation, len(got), len(want), truncate(got), truncate(want))
	}
}

func TestStrictKernelLargePositionedWritesAndAppendBoundary(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	const payloadSize = 2*integrationWriteFragmentBytes + 12345

	t.Run("positioned", func(t *testing.T) {
		const offset = 4093
		path := f.join(0, "positioned")
		initial := deterministicIntegrationData(8192, 3)
		mustWrite(t, path, initial, 0o600)
		file := mustOpenFile(t, path, os.O_RDWR, 0)
		payload := deterministicIntegrationData(payloadSize, 17)
		requireSyscallWrite(t, "one positioned write larger than a transaction fragment", func() (int, error) {
			return unix.Pwrite(int(file.Fd()), payload, offset)
		}, len(payload))

		want := append(append([]byte(nil), initial[:offset]...), payload...)
		requireExactFile(t, f.join(1, "positioned"), want, "positioned transaction through the peer mount")
		requireSize(t, f.join(1, "positioned"), int64(len(want)), "positioned transaction size")
	})

	t.Run("append", func(t *testing.T) {
		path := f.join(0, "append")
		prefix := deterministicIntegrationData(7777, 29)
		mustWrite(t, path, prefix, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY|os.O_APPEND, 0)
		payload := deterministicIntegrationData(payloadSize, 31)
		requireSyscallWrite(t, "one O_APPEND write larger than a transaction fragment", func() (int, error) {
			return unix.Write(int(file.Fd()), payload)
		}, len(payload))
		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "append"), want, "append through the peer mount")
		requireSize(t, f.join(1, "append"), int64(len(want)), "append size")
	})

	t.Run("pwrite on an append descriptor still appends", func(t *testing.T) {
		// POSIX gives O_APPEND precedence over an explicit offset, and the kernel
		// resolves that before the request reaches this daemon.
		path := f.join(0, "append-pwrite")
		prefix := deterministicIntegrationData(4096, 37)
		mustWrite(t, path, prefix, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY|os.O_APPEND, 0)
		payload := deterministicIntegrationData(1024, 41)
		requireSyscallWrite(t, "pwrite at offset zero on an O_APPEND descriptor", func() (int, error) {
			return unix.Pwrite(int(file.Fd()), payload, 0)
		}, len(payload))
		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "append-pwrite"), want, "pwrite on an append descriptor")
	})

	t.Run("per-call append", func(t *testing.T) {
		// Stock Linux does not forward RWF_APPEND: the kernel resolves it locally
		// against its own i_size and sends an ordinary positioned write. That is
		// exact while this mount's i_size is the object's EOF, which is the only
		// state a single writer can be in, and is a disclosed deviation otherwise.
		path := f.join(0, "per-call-append")
		prefix := deterministicIntegrationData(6001, 47)
		mustWrite(t, path, prefix, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY, 0)
		payload := deterministicIntegrationData(payloadSize, 53)
		requireSyscallWrite(t, "RWF_APPEND write", func() (int, error) {
			return unix.Pwritev2(int(file.Fd()), [][]byte{payload}, 0, unix.RWF_APPEND)
		}, len(payload))
		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "per-call-append"), want, "RWF_APPEND placement")
	})

	t.Run("per-call noappend", func(t *testing.T) {
		// RWF_NOAPPEND is the other flag stock FUSE does not forward. On a shared
		// volume the kernel's offset is not evidence of anything -- inferring
		// "positioned" from it would misplace the ordinary appends whose offsets
		// are equally stale -- so an O_APPEND description keeps appending. This is
		// a disclosed deviation, asserted here so it cannot change silently.
		path := f.join(0, "per-call-noappend")
		prefix := deterministicIntegrationData(8192, 59)
		mustWrite(t, path, prefix, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY|os.O_APPEND, 0)
		payload := deterministicIntegrationData(1024, 61)
		written, err := unix.Pwritev2(int(file.Fd()), [][]byte{payload}, 2048, unix.RWF_NOAPPEND)
		if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL) {
			t.Skip("RWF_NOAPPEND requires Linux 6.9 or newer")
		}
		if err != nil || written != len(payload) {
			t.Fatalf("RWF_NOAPPEND write = (%d, %v), want %d bytes", written, err, len(payload))
		}
		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "per-call-noappend"), want, "RWF_NOAPPEND placement")
	})

	t.Run("fcntl append toggle", func(t *testing.T) {
		path := f.join(0, "fcntl-append")
		prefix := deterministicIntegrationData(5003, 71)
		mustWrite(t, path, prefix, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY, 0)
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil {
			t.Fatalf("get descriptor flags before O_APPEND toggle: %v", err)
		}
		if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFL, flags|unix.O_APPEND); err != nil {
			t.Fatalf("toggle O_APPEND with F_SETFL: %v", err)
		}
		payload := deterministicIntegrationData(payloadSize, 73)
		requireSyscallWrite(t, "write after F_SETFL O_APPEND", func() (int, error) {
			return unix.Write(int(file.Fd()), payload)
		}, len(payload))
		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "fcntl-append"), want, "F_SETFL O_APPEND placement")
	})
}

func TestStrictKernelSharedFallocateMutations(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	var filesystem unix.Statfs_t
	if err := unix.Statfs(f.mountPath(0), &filesystem); err != nil {
		t.Fatalf("statfs strict mount: %v", err)
	}
	block := int(filesystem.Bsize)
	if block <= 0 {
		t.Fatalf("strict mount reported invalid filesystem block size %d", block)
	}

	newFile := func(t *testing.T, name string, blocks int) (*os.File, []byte) {
		t.Helper()
		data := deterministicIntegrationData(blocks*block, len(name)*19)
		path := f.join(0, name)
		mustWrite(t, path, data, 0o600)
		return mustOpenFile(t, path, os.O_RDWR, 0), data
	}

	t.Run("allocate", func(t *testing.T) {
		file, initial := newFile(t, "allocate", 2)
		requireFallocate(t, file, 0, int64(3*block), int64(2*block), "allocate beyond EOF")
		want := append(append([]byte(nil), initial...), make([]byte, 3*block)...)
		requireExactFile(t, f.join(1, "allocate"), want, "allocated file through peer mount")
	})

	t.Run("keep size", func(t *testing.T) {
		file, initial := newFile(t, "keep", 2)
		requireFallocate(t, file, unix.FALLOC_FL_KEEP_SIZE, int64(4*block), int64(2*block), "allocate with KEEP_SIZE")
		requireExactFile(t, f.join(1, "keep"), initial, "KEEP_SIZE file through peer mount")
	})

	t.Run("punch hole", func(t *testing.T) {
		file, initial := newFile(t, "punch", 6)
		requireFallocate(t, file, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, int64(2*block), int64(2*block), "punch aligned hole")
		want := append([]byte(nil), initial...)
		clear(want[2*block : 4*block])
		requireExactFile(t, f.join(1, "punch"), want, "punched file through peer mount")
	})

	t.Run("zero range", func(t *testing.T) {
		file, initial := newFile(t, "zero", 6)
		requireFallocate(t, file, unix.FALLOC_FL_ZERO_RANGE|unix.FALLOC_FL_KEEP_SIZE, int64(block), int64(2*block), "zero aligned range")
		want := append([]byte(nil), initial...)
		clear(want[block : 3*block])
		requireExactFile(t, f.join(1, "zero"), want, "zeroed file through peer mount")
	})

	// Stock Linux forwards exactly KEEP_SIZE, PUNCH_HOLE, and ZERO_RANGE to a
	// FUSE server: fuse_file_fallocate refuses every other mode with EOPNOTSUPP
	// before the request is built, so no userspace filesystem on this profile can
	// deliver COLLAPSE_RANGE, INSERT_RANGE, or UNSHARE_RANGE however much its
	// backing store supports them. The authority and its XFS do implement all
	// three -- the control below proves it on the same filesystem -- and the mode
	// still never reaches them, which is why this is the kernel interface's
	// boundary rather than a gap in the write path. Each refusal is pinned to
	// zero authority requests so a future PortableFS-side refusal, which would be
	// a real regression, cannot hide behind the same errno.
	for _, test := range []struct {
		name   string
		mode   uint32
		blocks int
	}{
		{name: "collapse range", mode: unix.FALLOC_FL_COLLAPSE_RANGE, blocks: 6},
		{name: "insert range", mode: unix.FALLOC_FL_INSERT_RANGE, blocks: 5},
		{name: "unshare range", mode: unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE, blocks: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := strings.ReplaceAll(test.name, " ", "-")
			file, initial := newFile(t, name, test.blocks)
			var err error
			requests := f.countRequests("fallocate", func() {
				err = unix.Fallocate(int(file.Fd()), test.mode, int64(2*block), int64(block))
			})
			if !errors.Is(err, syscall.EOPNOTSUPP) {
				t.Fatalf("fallocate mode %#o through the strict mount = %v, want EOPNOTSUPP from the kernel", test.mode, err)
			}
			if requests != 0 {
				t.Fatalf("the refused mode %#o still reached the authority %d times", test.mode, requests)
			}
			requireExactFile(t, f.join(1, name), initial, "file the refused mode must have left alone")

			// The control runs the same mode against the same XFS through a file
			// the volume never publishes, so nothing here is a mutation behind the
			// authority's back.
			controlPath := filepath.Join(f.writeStagingRoot, name+"-control")
			control := mustOpenFile(t, controlPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			defer func() {
				_ = control.Close()
				_ = os.Remove(controlPath)
			}()
			if _, err := control.Write(deterministicIntegrationData(test.blocks*block, 7)); err != nil {
				t.Fatalf("seed the backing-XFS control file: %v", err)
			}
			if err := unix.Fallocate(int(control.Fd()), test.mode, int64(2*block), int64(block)); err != nil {
				t.Fatalf("fallocate mode %#o directly on the backing XFS: %v (this mode is meant to be supported there)", test.mode, err)
			}
		})
	}
}

func TestStrictKernelSharedCopyFileRangeAndCrossClassBoundary(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, Routes: "local/\n"})
	sourceData := deterministicIntegrationData(3*4096+37, 67)
	mustWrite(t, f.join(0, "source"), sourceData, 0o600)
	destinationData := deterministicIntegrationData(2*4096, 83)
	mustWrite(t, f.join(0, "destination"), destinationData, 0o600)
	source := mustOpenFile(t, f.join(0, "source"), os.O_RDONLY, 0)
	destination := mustOpenFile(t, f.join(0, "destination"), os.O_RDWR, 0)

	offIn, offOut := int64(123), int64(777)
	copied, err := unix.CopyFileRange(int(source.Fd()), &offIn, int(destination.Fd()), &offOut, 4099, 0)
	if err != nil {
		t.Fatalf("partial SHARED to SHARED copy_file_range: %v", err)
	}
	if copied != 4099 || offIn != 4222 || offOut != 4876 {
		t.Fatalf("partial copy result copied=%d offIn=%d offOut=%d", copied, offIn, offOut)
	}
	want := append([]byte(nil), destinationData...)
	copy(want[777:4876], sourceData[123:4222])
	requireExactFile(t, f.join(1, "destination"), want, "partial copy through peer mount")

	offIn, offOut = int64(len(sourceData)-19), int64(len(want)+31)
	copied, err = unix.CopyFileRange(int(source.Fd()), &offIn, int(destination.Fd()), &offOut, 8192, 0)
	if err != nil {
		t.Fatalf("EOF-clipped SHARED to SHARED copy_file_range: %v", err)
	}
	if copied != 19 || offIn != int64(len(sourceData)) {
		t.Fatalf("EOF-clipped copy result copied=%d offIn=%d, want 19 and %d", copied, offIn, len(sourceData))
	}
	want = append(want, make([]byte, 31)...)
	want = append(want, sourceData[len(sourceData)-19:]...)
	requireExactFile(t, f.join(1, "destination"), want, "EOF-clipped copy through peer mount")

	copied, err = unix.CopyFileRange(int(source.Fd()), &offIn, int(destination.Fd()), &offOut, 1, 0)
	if err != nil || copied != 0 {
		t.Fatalf("copy at EOF = (%d, %v), want (0, nil)", copied, err)
	}

	mustMkdir(t, f.join(0, "local"))
	mustWrite(t, f.join(0, "local", "machine"), []byte("local"), 0o600)
	local := mustOpenFile(t, f.join(0, "local", "machine"), os.O_RDWR, 0)
	// A copy that spans the two classes is never one authority operation: the
	// classes have no shared backing store to copy inside. The daemon answers
	// EXDEV, and stock Linux does not hand that to userspace --
	// vfs_copy_file_range retries EXDEV and EOPNOTSUPP through its own generic
	// read/write path -- so the syscall completes as ordinary I/O across the
	// boundary, exactly what cp(1) would have done. The contract worth pinning is
	// therefore the one that is observable and that matters: the authority is
	// never asked to copy into or out of a machine-local object.
	for _, test := range []struct {
		name string
		in   *os.File
		out  *os.File
	}{
		{name: "SHARED to LOCAL", in: source, out: local},
		{name: "LOCAL to SHARED", in: local, out: destination},
	} {
		var copied int
		var copyErr error
		requests := f.countRequests("copy-file-range", func() {
			offIn, offOut := int64(0), int64(0)
			copied, copyErr = unix.CopyFileRange(int(test.in.Fd()), &offIn, int(test.out.Fd()), &offOut, 1, 0)
		})
		if copyErr != nil || copied != 1 {
			t.Fatalf("%s copy_file_range = (%d, %v), want (1, nil) through the kernel's generic fallback", test.name, copied, copyErr)
		}
		if requests != 0 {
			t.Fatalf("%s copy_file_range reached the authority %d times; the graft boundary must refuse the accelerated path", test.name, requests)
		}
	}
}

func TestStrictKernelTmpfileFirstLinkAndExclusiveNonlinkable(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	linkable, err := unix.Open(f.mountPath(0), unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("create linkable O_TMPFILE: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Close(linkable); err != nil {
			t.Errorf("close linkable O_TMPFILE: %v", err)
		}
	})
	payload := deterministicIntegrationData(8193, 101)
	requireSyscallWrite(t, "write linkable O_TMPFILE", func() (int, error) {
		return unix.Write(linkable, payload)
	}, len(payload))
	// linkat(2) with AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH, which the
	// production data-plane identity does not have and must not be given. The
	// kernel refuses it in do_linkat before any filesystem is consulted, so the
	// refusal says nothing about this mount, and the capability-free idiom
	// open(2) documents for O_TMPFILE -- /proc/self/fd/<n> with AT_SYMLINK_FOLLOW
	// -- is the one that has to work.
	if err := unix.Linkat(linkable, "", unix.AT_FDCWD, f.join(0, "empty-path-tmpfile"), unix.AT_EMPTY_PATH); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("unprivileged AT_EMPTY_PATH link = %v, want ENOENT from the kernel", err)
	}
	requireAbsent(t, f.join(1, "empty-path-tmpfile"), "AT_EMPTY_PATH link the kernel refused")
	linked := f.join(0, "linked-tmpfile")
	if err := unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", linkable), unix.AT_FDCWD, linked, unix.AT_SYMLINK_FOLLOW); err != nil {
		t.Fatalf("first link of O_TMPFILE: %v", err)
	}
	requireExactFile(t, f.join(1, "linked-tmpfile"), payload, "linked O_TMPFILE through peer mount")

	exclusive, err := unix.Open(f.mountPath(0), unix.O_TMPFILE|unix.O_RDWR|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("create exclusive O_TMPFILE: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Close(exclusive); err != nil {
			t.Errorf("close exclusive O_TMPFILE: %v", err)
		}
	})
	// Same idiom, so the refusal here is the O_EXCL tmpfile's own unlinkability
	// rather than a missing capability: the kernel never marks it I_LINKABLE.
	err = unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", exclusive), unix.AT_FDCWD, f.join(0, "must-not-link"), unix.AT_SYMLINK_FOLLOW)
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("link O_EXCL O_TMPFILE = %v, want ENOENT", err)
	}
	requireAbsent(t, f.join(1, "must-not-link"), "exclusive O_TMPFILE")
}

func TestStrictKernelSyncfsSucceeds(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	root, err := unix.Open(f.mountPath(0), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open strict mount root for syncfs: %v", err)
	}
	defer func() {
		if err := unix.Close(root); err != nil {
			t.Errorf("close strict mount root: %v", err)
		}
	}()
	if err := unix.Syncfs(root); err != nil {
		t.Fatalf("syncfs strict mount: %v", err)
	}
}
