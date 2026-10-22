//go:build linux

package cli

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWorkspaceGateFlagsCannotEnableManagedMount(t *testing.T) {
	var ordinary mountOpts
	fs := newFlagSet("mount")
	addMountFlags(fs, &ordinary)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}
	if err := refuseManagedWorkspaceMount(&ordinary); err != nil {
		t.Fatal("ordinary mount acquired a gate", err)
	}
	for _, kind := range []string{"paired", "single", "same", "background"} {
		t.Run(kind, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			gate, err := unix.FcntlInt(reader.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := unix.FcntlInt(reader.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				t.Fatal(err)
			}
			opts := mountOpts{foreground: true, workspaceGateFD: gate, workspaceOwnerFD: owner}
			switch kind {
			case "single":
				_ = unix.Close(owner)
				opts.workspaceOwnerFD = 0
			case "same":
				_ = unix.Close(owner)
				opts.workspaceOwnerFD = gate
			case "background":
				opts.foreground = false
			}
			err = refuseManagedWorkspaceMount(&opts)
			if err == nil {
				t.Fatal("managed launch returned success")
			}
			if kind == "paired" && !strings.Contains(err.Error(), "unavailable") {
				t.Fatal(err)
			}
			for _, fd := range []int{opts.workspaceGateFD, opts.workspaceOwnerFD} {
				if fd > 2 {
					if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
						t.Fatal("managed refusal leaked inherited fd")
					}
				}
			}
		})
	}
}
