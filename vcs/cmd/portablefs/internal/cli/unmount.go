package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
	"golang.org/x/sys/unix"
)

type unmountOps struct {
	goos           string
	direct         func(string, int) error
	combinedOut    func(string, ...string) ([]byte, error)
	validateHelper func(string) error
}

// platformUnmountBudget bounds the external unmount helper.
//
// `/sbin/umount` on a wedged mount blocks in the same uninterruptible kernel
// wait that made portablefsd unkillable, and the CLI used to wait on it with
// exec.Command(...).CombinedOutput() — no deadline, and an output read that
// cannot finish until every descriptor the child holds is closed. That is the
// second half of why `portablefs umount` hung indefinitely.
//
// It is now bounded, the child is killed and its pipes are released at the
// deadline (WaitDelay), and the command answers a definite verdict.
//
// A var so tests compress it; production never changes it.
var platformUnmountBudget = 30 * time.Second

// errPlatformUnmountAbandoned marks an unmount helper that never returned. The
// detach is neither known-failed nor known-succeeded; the caller re-reads the
// kernel mount table (which always answers) to decide.
var errPlatformUnmountAbandoned = errors.New("platform unmount helper did not return within its budget")

func hostUnmountOps() unmountOps {
	return unmountOps{
		goos:           runtime.GOOS,
		direct:         unix.Unmount,
		combinedOut:    boundedCombinedOutput,
		validateHelper: mounthost.ValidateFUSEHelper,
	}
}

func boundedCombinedOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), platformUnmountBudget)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// A DETACH IS NEVER AN INTERACTIVE ACT. Handing the helper this process's
	// stdin lets it stop and wait for input that a non-tty caller — a script, a
	// CI job, the operator's own `< /dev/null` — can never supply. It gets
	// nothing to read.
	cmd.Stdin = nil
	// WaitDelay is what makes the ceiling real: past it, Go closes the pipes it
	// owns rather than waiting for a child that may be pinned in the kernel to
	// release them.
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return out, fmt.Errorf("%w after %s", errPlatformUnmountAbandoned, platformUnmountBudget)
	}
	return out, err
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
