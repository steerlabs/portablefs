package hostctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

// RequireNormalAdmission reads the shared public activation contract. Callers
// hold their account/start transition until accepted work is durably visible;
// the outgoing host then excludes starts and inventories that work before any
// service removal. Invalid, replaced and expired nonterminal records all defer.
func RequireNormalAdmission(stateDir string) error {
	directory, err := privatepath.OpenExistingDir(filepath.Join(stateDir, "host"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect product update admission: %w", err)
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), LeaseName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open product update admission: %w", err)
	}
	file := os.NewFile(uintptr(fd), LeaseName)
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Mode&0o777 != 0o600 || opened.Uid != uint32(os.Geteuid()) || opened.Nlink != 1 || opened.Size <= 0 || opened.Size > MaxFrameBytes {
		return fmt.Errorf("unsafe product update admission")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxFrameBytes+1))
	if err != nil || len(raw) > MaxFrameBytes {
		return fmt.Errorf("invalid bounded product update admission: %v", err)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), LeaseName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Size != named.Size || opened.Mtim != named.Mtim || opened.Ctim != named.Ctim {
		return fmt.Errorf("product update admission changed while read")
	}
	parent, err := directory.Stat()
	if err != nil {
		return err
	}
	namedParent, err := os.Lstat(directory.Name())
	if err != nil || !os.SameFile(parent, namedParent) {
		return fmt.Errorf("product update admission directory changed")
	}
	lease, err := DecodeExact[ActivationLease](raw)
	if err != nil {
		return fmt.Errorf("decode product update admission: %w", err)
	}
	if err := ValidateActivationLease(lease, time.Now()); err != nil {
		return fmt.Errorf("validate product update admission: %w", err)
	}
	if lease.Phase != PhaseTargetComplete && lease.Phase != PhaseRollbackComplete {
		return fmt.Errorf("PortableFS update is pending")
	}
	return nil
}
