//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"os"
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

func TestStrictKernelLargeWriteTransactionsPreservePositionedAndAppendData(t *testing.T) {
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
		payload := deterministicIntegrationData(payloadSize, 41)
		requireSyscallWrite(t, "one append write larger than a transaction fragment", func() (int, error) {
			return unix.Write(int(file.Fd()), payload)
		}, len(payload))

		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "append"), want, "append transaction through the peer mount")
		requireSize(t, f.join(1, "append"), int64(len(want)), "append transaction size")
	})

	t.Run("per-call append", func(t *testing.T) {
		path := f.join(0, "per-call-append")
		prefix := deterministicIntegrationData(6001, 47)
		mustWrite(t, path, prefix, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY, 0)
		payload := deterministicIntegrationData(payloadSize, 53)
		requireSyscallWrite(t, "one RWF_APPEND write larger than a transaction fragment", func() (int, error) {
			return unix.Pwritev2(int(file.Fd()), [][]byte{payload}, 0, unix.RWF_APPEND)
		}, len(payload))

		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "per-call-append"), want, "RWF_APPEND transaction through the peer mount")
		requireSize(t, f.join(1, "per-call-append"), int64(len(want)), "RWF_APPEND transaction size")
	})

	t.Run("per-call noappend", func(t *testing.T) {
		const offset = 2049
		path := f.join(0, "per-call-noappend")
		initial := deterministicIntegrationData(payloadSize+8192, 59)
		mustWrite(t, path, initial, 0o600)
		file := mustOpenFile(t, path, os.O_WRONLY|os.O_APPEND, 0)
		payload := deterministicIntegrationData(payloadSize, 61)
		requireSyscallWrite(t, "one RWF_NOAPPEND write larger than a transaction fragment", func() (int, error) {
			return unix.Pwritev2(int(file.Fd()), [][]byte{payload}, offset, unix.RWF_NOAPPEND)
		}, len(payload))

		want := append([]byte(nil), initial...)
		copy(want[offset:], payload)
		requireExactFile(t, f.join(1, "per-call-noappend"), want, "RWF_NOAPPEND transaction through the peer mount")
		requireSize(t, f.join(1, "per-call-noappend"), int64(len(want)), "RWF_NOAPPEND transaction size")
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
		requireSyscallWrite(t, "one write after F_SETFL O_APPEND larger than a transaction fragment", func() (int, error) {
			return unix.Write(int(file.Fd()), payload)
		}, len(payload))

		want := append(append([]byte(nil), prefix...), payload...)
		requireExactFile(t, f.join(1, "fcntl-append"), want, "F_SETFL O_APPEND transaction through the peer mount")
		requireSize(t, f.join(1, "fcntl-append"), int64(len(want)), "F_SETFL O_APPEND transaction size")
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

	t.Run("collapse range", func(t *testing.T) {
		file, initial := newFile(t, "collapse", 6)
		requireFallocate(t, file, unix.FALLOC_FL_COLLAPSE_RANGE, int64(2*block), int64(block), "collapse aligned interior range")
		want := append(append([]byte(nil), initial[:2*block]...), initial[3*block:]...)
		requireExactFile(t, f.join(1, "collapse"), want, "collapsed file through peer mount")
	})

	t.Run("insert range", func(t *testing.T) {
		file, initial := newFile(t, "insert", 5)
		requireFallocate(t, file, unix.FALLOC_FL_INSERT_RANGE, int64(2*block), int64(block), "insert aligned interior range")
		want := make([]byte, 0, len(initial)+block)
		want = append(want, initial[:2*block]...)
		want = append(want, make([]byte, block)...)
		want = append(want, initial[2*block:]...)
		requireExactFile(t, f.join(1, "insert"), want, "inserted file through peer mount")
	})

	t.Run("unshare range", func(t *testing.T) {
		file, initial := newFile(t, "unshare", 4)
		requireFallocate(t, file, unix.FALLOC_FL_UNSHARE_RANGE|unix.FALLOC_FL_KEEP_SIZE, 0, int64(len(initial)), "unshare complete allocated range")
		requireExactFile(t, f.join(1, "unshare"), initial, "unshared file through peer mount")
	})
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
	for _, test := range []struct {
		name string
		in   *os.File
		out  *os.File
	}{
		{name: "SHARED to LOCAL", in: source, out: local},
		{name: "LOCAL to SHARED", in: local, out: destination},
	} {
		offIn, offOut := int64(0), int64(0)
		copied, err := unix.CopyFileRange(int(test.in.Fd()), &offIn, int(test.out.Fd()), &offOut, 1, 0)
		if copied != -1 || !errors.Is(err, syscall.EXDEV) {
			t.Fatalf("%s copy_file_range = (%d, %v), want (-1, EXDEV)", test.name, copied, err)
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
	linked := f.join(0, "linked-tmpfile")
	if err := unix.Linkat(linkable, "", unix.AT_FDCWD, linked, unix.AT_EMPTY_PATH); err != nil {
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
	err = unix.Linkat(exclusive, "", unix.AT_FDCWD, f.join(0, "must-not-link"), unix.AT_EMPTY_PATH)
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
