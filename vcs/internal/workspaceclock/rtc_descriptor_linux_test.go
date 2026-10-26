//go:build linux

package workspaceclock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

type descriptorBackend struct {
	*backend
	file *os.File
}

func (b descriptorBackend) RTCFile() *os.File { return b.file }

func TestOwnerDuplicatesReadOnlyDescriptionWithoutReopening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rtc-test-description")
	if err := os.WriteFile(path, []byte("ab"), 0400); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	owner := New(descriptorBackend{backend: &backend{}, file: source}, nil)
	a, err := owner.DuplicateRTC()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := owner.DuplicateRTC()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, file := range []*os.File{a, b} {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("writable duplicate", flags, err)
		}
		flags, err = unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("duplicate inherited across unrelated exec", flags, err)
		}
	}
	bytes := make([]byte, 1)
	if _, err = a.Read(bytes); err != nil || string(bytes) != "a" {
		t.Fatal(err, string(bytes))
	}
	if _, err = b.Read(bytes); err != nil || string(bytes) != "b" {
		t.Fatal("independent reopening replaced dup", err, string(bytes))
	}
	if _, err = AdoptRTC(a); !errors.Is(err, ErrUnavailable) {
		t.Fatal("real child accepted injected regular file as RTC", err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.DuplicateRTC(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed owner duplicated source", err)
	}
}
