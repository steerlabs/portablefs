//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestPinnedFUSEHelperExecutionIgnoresHostilePATH(t *testing.T) {
	trusted := "/bin/true"
	if _, err := os.Stat(trusted); err != nil {
		t.Skipf("trusted system executable unavailable: %v", err)
	}
	hostileDir := t.TempDir()
	marker := filepath.Join(hostileDir, "executed")
	hostile := filepath.Join(hostileDir, "fusermount3")
	if err := os.WriteFile(hostile, []byte("#!/bin/sh\n: > \""+marker+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", hostileDir+":"+os.Getenv("PATH"))
	process, err := startPinnedFUSEHelper(
		trusted,
		[]string{trusted},
		[]*os.File{os.Stdin, os.Stdout, os.Stderr},
		os.StartProcess,
	)
	if err != nil {
		t.Fatal(err)
	}
	status, err := process.Wait()
	if err != nil || !status.Success() {
		t.Fatalf("pinned helper status = %v, err = %v", status, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("hostile PATH helper executed: %v", err)
	}
}

func TestExactFUSEMountOptions(t *testing.T) {
	options := exactFUSEMountOptions(&fuse.MountOptions{
		Options:    []string{"nodev"},
		AllowOther: true,
		FsName:     "portablefs:mnt_test",
		Name:       "portablefs",
		MaxWrite:   1 << 20,
	})
	got := strings.Join(options, ",")
	for _, expected := range []string{
		"nodev", "allow_other", "fsname=portablefs:mnt_test",
		"subtype=portablefs", "max_read=1048576",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("options %q do not contain %q", got, expected)
		}
	}
}
