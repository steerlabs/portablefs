//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// This small real-kernel prerequisite proof needs neither XFS nor an Authority.
// Runner image tests can execute the exact startup capture as their normal UID.
func TestKernelAbortCaptureBeforeServing(t *testing.T) {
	if os.Getenv(envFUSE) != "1" {
		t.Skip("set PORTABLEFS_FUSE_TEST=1 for the real kernel lifecycle proof")
	}
	for attempt := range 3 {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			point := filepath.Join(t.TempDir(), "mount")
			if err := os.Mkdir(point, 0700); err != nil {
				t.Fatal(err)
			}
			name := "portablefs:abort-lifecycle-" + filepath.Base(filepath.Dir(point))
			server, err := fuse.NewServer(fs.NewNodeFS(&fs.Inode{}, &fs.Options{}), point, &fuse.MountOptions{FsName: name, Name: "portablefs"})
			if err != nil {
				t.Fatal(err)
			}
			// Capture must not issue a FUSE request: no serving loop exists yet.
			installed, captureErr := captureKernelMount(name, point)
			go server.Serve()
			t.Cleanup(func() { _ = server.Unmount(); _ = installed.abortFile.close() })
			if captureErr != nil {
				t.Fatal(captureErr)
			}
			if err := server.WaitMount(); err != nil {
				t.Fatal(err)
			}
			if current, err := installed.abortFile.current(); err != nil || !current {
				t.Fatalf("captured abort inode = %t, %v", current, err)
			}
			if _, err := os.ReadDir(point); err != nil {
				t.Fatalf("ordinary mounted I/O: %v", err)
			}
			if err := server.Unmount(); err != nil {
				t.Fatalf("normal unmount retained a startup root reference: %v", err)
			}
			if _, err := installed.absent(); err != nil {
				t.Fatalf("normal unmount absence: %v", err)
			}
			if err := installed.abortFile.close(); err != nil {
				t.Fatal(err)
			}
			if _, err := installed.abortFile.file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed abort descriptor remains usable: %v", err)
			}
		})
	}
}
