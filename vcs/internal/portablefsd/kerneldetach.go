package portablefsd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// THE DAEMON MUST NEVER CALL unmount(2) ON ONE OF ITS OWN THREADS.
//
// This is the single mechanism behind the worst failure this product has
// produced: a portablefsd that could not be killed and bricked the machine for
// PortableFS until reboot.
//
// unmount(2) on a FSKit mount is serviced by the filesystem extension. When the
// extension stops answering — it crashed, it was killed, or the mount is wedged
// behind a reply that will never arrive — the calling thread parks in an
// UNINTERRUPTIBLE kernel wait. Nothing in userspace can retract it: the Go
// runtime cannot preempt a thread inside a syscall, a context deadline does not
// reach the kernel, and a signal is not delivered to an uninterruptible sleeper.
//
// The consequences compound:
//
//   - SIGTERM/SIGKILL cannot complete. exit1() must wait for every thread of the
//     task to leave the kernel. One pinned thread means the process sits in the
//     "trying to exit" state (`?Es` in ps) forever. It cannot be signalled again,
//     cannot be sampled, and is not reaped.
//   - The state-directory flock is a descriptor lock. A process that never
//     finishes exiting never closes its descriptors, so the lock is never
//     released and EVERY later portablefsd fails with "another portablefsd owns
//     ...: resource temporarily unavailable".
//   - Killing the FSKit extension does not help: the unmount request is already
//     queued inside the kernel against a provider that is gone.
//
// So the syscall is issued by a SHORT-LIVED CHILD PROCESS instead. If the kernel
// pins that child, the child — not the daemon — is the thing that cannot exit.
// The daemon abandons it after a bounded wait, answers a definite verdict, and
// remains fully terminable. This is requirement (a) and (b) of the fix: no code
// path in portablefsd may leave portablefsd itself pinned in the kernel, and a
// teardown that genuinely cannot complete must be detached from the process
// whose life depends on it.
//
// /sbin/umount is the helper because it is the exact system binary this product
// already uses for FSKit detach from the CLI, and `umount -f` is exactly
// unmount(2) with MNT_FORCE. The daemon proves the exact kernel mount identity
// through getfsstat(2) — which never resolves a pathname through a mounted
// filesystem and therefore always answers — immediately before and after.

// kernelDetachHelper is the exact system binary allowed to issue unmount(2) on
// this daemon's behalf. A var so tests can point it at another root-owned
// binary; production never changes it.
var kernelDetachHelper = "/sbin/umount"

// kernelDetachBudget bounds ONE out-of-process kernel detach attempt. It is
// strictly under unmountTransactionBudget so the transaction can still publish
// a verdict for the request that started it.
//
// A var so tests can compress it; production never changes it.
var kernelDetachBudget = 20 * time.Second

// runKernelDetach is a seam: tests replace it to drive the abandonment and
// failure shapes without a wedged kernel mount.
var runKernelDetach = execKernelDetachHelper

// kernelDetachAbandonedError is the definite verdict for a kernel detach whose
// helper did not return within the budget. It is NOT "the unmount failed" and
// it is NOT "the unmount succeeded": the syscall is still outstanding inside the
// kernel, held by a process that is no longer this daemon's problem.
type kernelDetachAbandonedError struct {
	mountPath string
	budget    time.Duration
	pid       int
}

func (e *kernelDetachAbandonedError) Error() string {
	return fmt.Sprintf(
		"kernel detach of %s did not return within %s and was abandoned in helper pid %d; "+
			"the kernel is still waiting on the filesystem extension for this mount. "+
			"portablefsd stayed responsive and remains terminable; re-run `portablefs umount` "+
			"once the extension is restarted, or `portablefs umount --force` to detach with "+
			"the unshipped tail parked as a durable recovery job",
		e.mountPath, e.budget, e.pid,
	)
}

// abandonedKernelDetach reports whether err is an abandoned (still outstanding)
// kernel detach rather than a refusal.
func abandonedKernelDetach(err error) bool {
	var abandoned *kernelDetachAbandonedError
	return errors.As(err, &abandoned)
}

// validateKernelDetachHelper proves the helper is the system binary and not a
// user-writable replacement. A daemon that would exec an attacker-controlled
// path here would be handing out its own privileges.
func validateKernelDetachHelper(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("kernel detach helper %q is not an exact absolute path", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect kernel detach helper %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("kernel detach helper %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("kernel detach helper %s is group- or world-writable", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("kernel detach helper %s is not owned by root", path)
	}
	return nil
}

// execKernelDetachHelper runs the helper as a child process and waits at most
// budget for it.
//
// The wait is bounded by construction, not by cooperation:
//
//   - The child's stdout/stderr are a regular FILE, never a pipe. A pipe would
//     make the parent's output read depend on every descriptor the child holds
//     being closed, which reintroduces exactly the unbounded wait this function
//     exists to remove.
//   - Past the budget the child is signalled best-effort and ABANDONED. One
//     goroutine remains parked in Wait for a child that may never die; it holds
//     no lock, pins no thread in the kernel, and cannot delay process exit.
//   - Nothing here ever calls into the mounted filesystem.
func execKernelDetachHelper(budget time.Duration, mountPath string, args ...string) error {
	if budget <= 0 {
		return fmt.Errorf("kernel detach budget must be positive")
	}
	if err := validateKernelDetachHelper(kernelDetachHelper); err != nil {
		return err
	}
	log, err := os.CreateTemp("", "portablefsd-detach-*.log")
	if err != nil {
		return fmt.Errorf("open kernel detach helper output: %w", err)
	}
	logPath := log.Name()
	defer func() {
		_ = log.Close()
		_ = os.Remove(logPath)
	}()

	cmd := exec.Command(kernelDetachHelper, args...)
	cmd.Stdin = nil
	cmd.Stdout = log
	cmd.Stderr = log
	// The helper must never inherit a working directory inside a mount, and it
	// must never be able to demand input: a detach is not an interactive act.
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start kernel detach helper for %s: %w", mountPath, err)
	}
	pid := cmd.Process.Pid

	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case waitErr := <-waited:
		if waitErr == nil {
			return nil
		}
		return fmt.Errorf(
			"kernel detach helper for %s: %w%s",
			mountPath, waitErr, kernelDetachHelperOutput(logPath),
		)
	case <-timer.C:
		// Best effort only. A helper pinned in an uninterruptible kernel wait
		// ignores this exactly the way the daemon used to — which is precisely
		// why the syscall lives out here.
		_ = cmd.Process.Kill()
		return &kernelDetachAbandonedError{mountPath: mountPath, budget: budget, pid: pid}
	}
}

func kernelDetachHelperOutput(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}
	if len(text) > 2048 {
		text = text[:2048] + "…"
	}
	return " (output: " + text + ")"
}
