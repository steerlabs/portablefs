//go:build linux

package workspaceadmission

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func reviewFDs(t *testing.T) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestReviewChildCannotObtainWritableWord(t *testing.T) {
	if os.Getenv("REVIEW_CHILD") == "1" {
		// Unprivileged child: fd 3 is the read-only gate description.
		for _, mode := range []int{unix.O_RDONLY, unix.O_RDWR} {
			if fd, err := unix.Open("/proc/self/fd/3", mode, 0); err == nil {
				unix.Close(fd)
				t.Fatal("child reopened root-owned admission inode", mode)
			}
		}
		page, err := unix.Mmap(3, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil {
			t.Fatal("child mmap read-only", err)
		}
		defer unix.Munmap(page)
		if err := unix.Mprotect(page, unix.PROT_READ|unix.PROT_WRITE); err == nil {
			t.Fatal("child made mapping writable")
		}
		if writable, err := unix.Mmap(3, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err == nil {
			unix.Munmap(writable)
			t.Fatal("child mapped writable admission word")
		}
		if _, err := unix.Pwrite(3, []byte{1}, 128); !errors.Is(err, unix.EBADF) {
			t.Fatal("child pwrite", err)
		}
		if err := unix.Fallocate(3, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, 4096); !errors.Is(err, unix.EBADF) {
			t.Fatal("child fallocate", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root")
	}
	before := reviewFDs(t)
	b := binding(t)
	g, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	// Root-side reopen of the child's read-only description.
	if fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", files[0].Fd()), unix.O_RDWR, 0); err == nil {
		_, werr := unix.Pwrite(fd, []byte{1}, 128)
		_, merr := unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if werr == nil || merr == nil {
			t.Fatal("root bypassed gate seals")
		}
		t.Logf("root reopen O_RDWR ok; pwrite=%v mmap-rw=%v fallocate=%v", werr, merr, unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, 4096))
		unix.Close(fd)
	}
	dir, err := os.MkdirTemp("", "workspace-admission-review-child-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "gate.test")
	if err := os.WriteFile(child, binary, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(child, "-test.run", "^TestReviewChildCannotObtainWritableWord$", "-test.v")
	cmd.Env = append(os.Environ(), "REVIEW_CHILD=1")
	cmd.ExtraFiles = []*os.File{files[0]}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged child: %v\n%s", err, out)
	}
	_ = files[0].Close()
	_ = files[1].Close()
	if err := g.Dispose(); err != nil {
		t.Fatal(err)
	}
	// Rejected adoption disposes both descriptors.
	g2, _ := New(b)
	f2, _ := g2.ChildFiles()
	bad := b
	bad.Incarnation[0] ^= 1
	if _, err := Adopt(f2[0], f2[1], bad, nil); err == nil {
		t.Fatal("mismatched binding adopted")
	}
	_ = g2.Dispose()
	after := reviewFDs(t)
	t.Logf("fds before=%d after=%d", before, after)
	if after != before {
		t.Errorf("descriptor leak: %d -> %d", before, after)
	}
}
