package cli

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

// deadVolumeMountPath is a canonical absolute path; nothing is ever created
// there. Every filesystem answer for it comes from the stubbed statter, which
// is the point: identification must not need a working filesystem.
const deadVolumeMountPath = "/Volumes/portablefs-dead"

// stubMountIdentification replaces the two ways this package learns about a
// mount path: the path statter and the kernel mount table. Both are restored
// when the test ends.
func stubMountIdentification(
	t *testing.T,
	lstat func(string) (fs.FileInfo, error),
	table func(string) ([]kernelMountIdentity, error),
) {
	t.Helper()
	priorLstat, priorTable := lstatMountPath, kernelMountsAt
	if lstat != nil {
		lstatMountPath = lstat
	}
	if table != nil {
		kernelMountsAt = table
	}
	t.Cleanup(func() {
		lstatMountPath = priorLstat
		kernelMountsAt = priorTable
	})
}

// deadFilesystemStatter models a volume the kernel has marked dead: every
// pathname that resolves through it — including its own mount point — fails
// with EIO. Paths outside it are answered normally.
func deadFilesystemStatter(deadPath string) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) {
		if path == deadPath || strings.HasPrefix(path, deadPath+"/") {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: syscall.EIO}
		}
		return os.Lstat(path)
	}
}

func livePortableFSMountTable(mountPath, attachRef string) func(string) ([]kernelMountIdentity, error) {
	return func(path string) ([]kernelMountIdentity, error) {
		if path != mountPath {
			return nil, nil
		}
		return []kernelMountIdentity{{
			fsType: fskitidentity.FSType,
			path:   mountPath,
			source: fskitidentity.ResourcePrefix + attachRef,
		}}, nil
	}
}

// TestCanonicalMountPathAcceptsADeadVolumeWithAMatchingKernelMount is the
// Defect 2 reproduction: `portablefs umount` canonicalizes its argument before
// doing anything else, and that canonicalization lstat'ed the mount point.
// A dead volume answers EIO for exactly that lstat, so the CLI refused to
// detach precisely when detaching was the remedy — even though umount(2)
// itself succeeds instantly. Identification must come from the kernel mount
// table instead.
func TestCanonicalMountPathAcceptsADeadVolumeWithAMatchingKernelMount(t *testing.T) {
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		livePortableFSMountTable(deadVolumeMountPath, "att_AAAAAAAAAAAAAAAAAAAAAA"),
	)
	got, err := canonicalMountPath(deadVolumeMountPath)
	if err != nil {
		t.Fatalf("canonicalMountPath of a dead volume with a live kernel mount: %v", err)
	}
	if got != deadVolumeMountPath {
		t.Fatalf("canonicalMountPath = %q, want %q", got, deadVolumeMountPath)
	}
}

// TestCanonicalMountPathKeepsAnEIOWithNoKernelMount is the honest other half:
// an EIO with NOTHING mounted at the path is not a dead PortableFS volume, so
// it must not be silently accepted as one.
func TestCanonicalMountPathKeepsAnEIOWithNoKernelMount(t *testing.T) {
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		func(string) ([]kernelMountIdentity, error) { return nil, nil },
	)
	if _, err := canonicalMountPath(deadVolumeMountPath); err == nil {
		t.Fatal("canonicalMountPath accepted an unreadable path with no kernel mount")
	} else if !errors.Is(err, syscall.EIO) {
		t.Fatalf("canonicalMountPath error = %v, want the underlying EIO", err)
	}
}

// TestCanonicalMountPathRefusesStackedKernelMounts: a path with two mounts is
// ambiguous, and PortableFS never guesses which object it owns.
func TestCanonicalMountPathRefusesStackedKernelMounts(t *testing.T) {
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		func(string) ([]kernelMountIdentity, error) {
			return []kernelMountIdentity{
				{fsType: fskitidentity.FSType, path: deadVolumeMountPath, source: fskitidentity.ResourcePrefix + "att_AAAAAAAAAAAAAAAAAAAAAA"},
				{fsType: "apfs", path: deadVolumeMountPath, source: "/dev/disk3s5"},
			}, nil
		},
	)
	_, err := canonicalMountPath(deadVolumeMountPath)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("stacked kernel mounts = %v, want an ambiguity refusal", err)
	}
}

// TestCanonicalMountPathStillResolvesHealthyPaths guards the ordinary path:
// the mount-table consultation is reached only when the statter fails with
// something other than ENOENT.
func TestCanonicalMountPathStillResolvesHealthyPaths(t *testing.T) {
	stubMountIdentification(t, nil, func(string) ([]kernelMountIdentity, error) {
		t.Error("a healthy path must not need the kernel mount table")
		return nil, nil
	})
	dir := t.TempDir()
	got, err := canonicalMountPath(dir)
	if err != nil {
		t.Fatalf("canonicalMountPath of a healthy directory: %v", err)
	}
	if got == "" {
		t.Fatal("canonicalMountPath returned an empty path for a healthy directory")
	}
}
