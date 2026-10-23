//go:build linux

package mountcontrol

import (
	"errors"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// Count the exact pipe, including every duplicated description, rather than
// runtime/test-harness descriptors that may open independently of this test.
func bootstrapPipeFDCount(t *testing.T, pipe unix.Stat_t) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); errors.Is(err, unix.EBADF) {
			continue // The directory reader or an unrelated owner has closed it.
		} else if err != nil {
			t.Fatal(err)
		}
		if stat.Dev == pipe.Dev && stat.Ino == pipe.Ino {
			count++
		}
	}
	return count
}

func TestBootstrapPipeFDAccountingDetectsRetainedCopy(t *testing.T) {
	rights := r4Pipe()
	defer rights.Close()
	var pipe unix.Stat_t
	if err := unix.Fstat(rights.FDs[0], &pipe); err != nil {
		t.Fatal(err)
	}
	copy, err := unix.FcntlInt(uintptr(rights.FDs[0]), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(copy)
	unrelated := r4Pipe()
	defer unrelated.Close()
	rights.Close()
	if n := bootstrapPipeFDCount(t, pipe); n != 1 {
		t.Fatalf("retained handoff copy count %d != 1", n)
	}
}
