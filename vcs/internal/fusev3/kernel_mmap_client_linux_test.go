//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A file-backed page fault is invisible to Go's syscall scheduler. Faulting a
// mapping served by this same process can stop GC while GC stops its FUSE
// workers. Keep the application in a separate process, as in production.
type kernelMmapClient struct {
	t     *testing.T
	size  int
	input io.WriteCloser
	reply io.ReadCloser
}

func startKernelMmapClient(t *testing.T, fd, protection, size int) *kernelMmapClient {
	t.Helper()
	copyFD, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(copyFD), "mmap application description")
	defer file.Close()
	// testing cancels t.Context before Cleanup; the child must first unmap and
	// close its inherited description while this test's FUSE server still lives.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKernelMmapClientProcess$")
	cmd.Env = append(os.Environ(), "PFS_KERNEL_MMAP_CLIENT="+strconv.Itoa(protection)+":"+strconv.Itoa(size))
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			t.Error("mmap application exit", err)
		}
	})
	return &kernelMmapClient{t: t, size: size, input: input, reply: reply}
}

func (c *kernelMmapClient) check(want []byte) {
	c.t.Helper()
	if len(want) != c.size {
		c.t.Fatal("mmap expected page size", len(want), c.size)
	}
	c.call('r', want)
}
func (c *kernelMmapClient) store(value byte) { c.t.Helper(); c.call('w', []byte{value}) }
func (c *kernelMmapClient) call(operation byte, payload []byte) {
	c.t.Helper()
	if _, err := c.input.Write(append([]byte{operation}, payload...)); err != nil {
		c.t.Fatal("mmap application request", err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(c.reply, reply[:]); err != nil || reply[0] != 0 {
		diagnostic, _ := io.ReadAll(c.reply)
		c.t.Fatalf("mmap application operation %q: reply=%d err=%v %s", operation, reply[0], err, diagnostic)
	}
}

func TestKernelMmapClientProcess(t *testing.T) {
	value := os.Getenv("PFS_KERNEL_MMAP_CLIENT")
	if value == "" {
		return
	}
	mode, length, ok := strings.Cut(value, ":")
	protection, err := strconv.Atoi(mode)
	if err != nil || protection != unix.PROT_READ && protection != unix.PROT_READ|unix.PROT_WRITE {
		t.Fatal("mmap application protection", value)
	}
	size, err := strconv.Atoi(length)
	if !ok || err != nil || size <= 0 {
		t.Fatal("mmap application length", value)
	}
	file := os.NewFile(3, "mmap application description")
	defer file.Close()
	mapping, err := unix.Mmap(3, 0, size, protection, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapping)
	var operation [1]byte
	for {
		if _, err := io.ReadFull(os.Stdin, operation[:]); err == io.EOF {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		switch operation[0] {
		case 'r':
			want := make([]byte, len(mapping))
			if _, err := io.ReadFull(os.Stdin, want); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mapping, want) {
				t.Fatal("mapped contents differ from expected page")
			}
		case 'w':
			var value [1]byte
			if _, err := io.ReadFull(os.Stdin, value[:]); err != nil {
				t.Fatal(err)
			}
			mapping[0] = value[0]
			if mapping[0] != value[0] {
				t.Fatal("private mapping did not retain application write")
			}
		default:
			t.Fatal("unknown mmap application operation", operation)
		}
		if _, err := os.Stdout.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
	}
}
