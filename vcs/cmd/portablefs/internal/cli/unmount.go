package cli

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
	"golang.org/x/sys/unix"
)

type unmountOps struct {
	goos           string
	direct         func(string, int) error
	combinedOut    func(string, ...string) ([]byte, error)
	validateHelper func(string) error
}

func hostUnmountOps() unmountOps {
	return unmountOps{
		goos:   runtime.GOOS,
		direct: unix.Unmount,
		combinedOut: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		validateHelper: mounthost.ValidateFUSEHelper,
	}
}

// platformUnmountRecorded proves that the exact recorded kernel object is
// the sole mount at the path immediately before issuing the path-based
// detach. This prevents path reuse or a stacked foreign mount from turning a
// valid old state record into authority to unmount somebody else's object.
func platformUnmountRecorded(st *mountState) error {
	present, err := recordedKernelMountPresent(st)
	if err != nil {
		return fmt.Errorf("refuse path unmount because exact kernel identity is not proven: %w", err)
	}
	if !present {
		return fmt.Errorf("refuse path unmount because the exact recorded kernel mount is absent")
	}
	return platformUnmountWith(st, hostUnmountOps())
}

func platformUnmountWith(st *mountState, ops unmountOps) error {
	switch st.Strategy {
	case "fskit":
		if ops.goos != "darwin" {
			return fmt.Errorf("recorded FSKit mount cannot be unmounted on %s", ops.goos)
		}
		if st.MountMechanism != "" && st.MountMechanism != "fskit-system" {
			return fmt.Errorf("invalid recorded FSKit unmount mechanism %q", st.MountMechanism)
		}
		out, err := ops.combinedOut("/sbin/umount", st.MountPath)
		if err != nil {
			return commandUnmountError([]string{"/sbin/umount", st.MountPath}, out, err)
		}
		return nil
	case "fuse":
		if ops.goos != "linux" {
			return fmt.Errorf("recorded FUSE mount cannot be unmounted on %s", ops.goos)
		}
		switch st.MountMechanism {
		case "direct":
			if err := ops.direct(st.MountPath, 0); err != nil {
				return fmt.Errorf("direct umount(2) %s: %w", st.MountPath, err)
			}
			return nil
		case "helper":
			if !filepath.IsAbs(st.FUSEHelperPath) || filepath.Clean(st.FUSEHelperPath) != st.FUSEHelperPath {
				return fmt.Errorf("recorded FUSE helper path %q is not an exact absolute path", st.FUSEHelperPath)
			}
			if ops.validateHelper == nil {
				return fmt.Errorf("recorded FUSE helper cannot be revalidated")
			}
			if err := ops.validateHelper(st.FUSEHelperPath); err != nil {
				return fmt.Errorf("recorded FUSE helper is no longer trusted: %w", err)
			}
			argv := []string{st.FUSEHelperPath, "-u", st.MountPath}
			out, err := ops.combinedOut(argv[0], argv[1:]...)
			if err != nil {
				return commandUnmountError(argv, out, err)
			}
			return nil
		default:
			return fmt.Errorf("recorded FUSE mount has no deterministic unmount mechanism")
		}
	default:
		return fmt.Errorf("unsupported recorded mount strategy %q", st.Strategy)
	}
}

func commandUnmountError(argv []string, output []byte, err error) error {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return fmt.Errorf("%s: %w (output: %s)", strings.Join(argv, " "), err, text)
}
