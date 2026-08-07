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

// stubMountIdentification replaces the three ways this package learns about a
// mount path: the path statter, the kernel mount table and the live daemon's
// attach inventory. The inventory defaults to "no daemon is running" so a test
// never depends on a real control socket; stubLiveDaemonAttaches overrides it.
// All are restored when the test ends.
func stubMountIdentification(
	t *testing.T,
	lstat func(string) (fs.FileInfo, error),
	table func(string) ([]kernelMountIdentity, error),
) {
	t.Helper()
	priorLstat, priorTable := lstatMountPath, kernelMountsAt
	priorAttaches := liveDaemonAttachMountPaths
	if lstat != nil {
		lstatMountPath = lstat
	}
	if table != nil {
		kernelMountsAt = table
	}
	liveDaemonAttachMountPaths = func() ([]string, error) { return nil, nil }
	t.Cleanup(func() {
		lstatMountPath = priorLstat
		kernelMountsAt = priorTable
		liveDaemonAttachMountPaths = priorAttaches
	})
}

// stubLiveDaemonAttaches makes a live portablefsd report exactly these attach
// mount paths. Call it after stubMountIdentification.
func stubLiveDaemonAttaches(t *testing.T, paths ...string) {
	t.Helper()
	prior := liveDaemonAttachMountPaths
	liveDaemonAttachMountPaths = func() ([]string, error) {
		return append([]string(nil), paths...), nil
	}
	t.Cleanup(func() { liveDaemonAttachMountPaths = prior })
}

// unresponsiveFilesystemStatter models the incident shape: the mount point
// itself no longer answers — ETIMEDOUT while the kernel is still waiting on an
// extension that will never reply.
func unresponsiveFilesystemStatter(
	deadPath string,
	errno syscall.Errno,
) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) {
		if path == deadPath || strings.HasPrefix(path, deadPath+"/") {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: errno}
		}
		return os.Lstat(path)
	}
}

func noKernelMounts(string) ([]kernelMountIdentity, error) { return nil, nil }

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

// TestCanonicalMountPathAcceptsDeadResidueWithALiveDaemonAttach is the §6
// defect-3 reproduction.
//
// The incident left a shape the classification did not cover: the mount point
// answered EIO, the kernel had NO mount at that path any more, and portablefsd
// still owned a LIVE attach there holding the write-back tail. Only
// EIO-with-a-matching-kernel-mount proceeded, so the CLI refused precisely
// when the daemon-owned detach was the remedy, and the only recovery left was
// calling the daemon control API by hand.
func TestCanonicalMountPathAcceptsDeadResidueWithALiveDaemonAttach(t *testing.T) {
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		noKernelMounts,
	)
	stubLiveDaemonAttaches(t, deadVolumeMountPath)
	got, err := canonicalMountPath(deadVolumeMountPath)
	if err != nil {
		t.Fatalf("canonicalMountPath of dead residue with a live daemon attach: %v", err)
	}
	if got != deadVolumeMountPath {
		t.Fatalf("canonicalMountPath = %q, want %q", got, deadVolumeMountPath)
	}
}

// TestCanonicalMountPathAcceptsATimedOutMountPointWithALiveDaemonAttach:
// ETIMEDOUT is the same fact as EIO — the pathname cannot be resolved THROUGH
// the filesystem — and must classify identically.
func TestCanonicalMountPathAcceptsATimedOutMountPointWithALiveDaemonAttach(t *testing.T) {
	stubMountIdentification(t,
		unresponsiveFilesystemStatter(deadVolumeMountPath, syscall.ETIMEDOUT),
		noKernelMounts,
	)
	stubLiveDaemonAttaches(t, deadVolumeMountPath)
	got, err := canonicalMountPath(deadVolumeMountPath)
	if err != nil {
		t.Fatalf("canonicalMountPath of a timed-out mount point with a live attach: %v", err)
	}
	if got != deadVolumeMountPath {
		t.Fatalf("canonicalMountPath = %q, want %q", got, deadVolumeMountPath)
	}
}

// TestCanonicalMountPathAcceptsATimedOutMountPointWithAMatchingKernelMount
// keeps the already-covered arm working for ETIMEDOUT too.
func TestCanonicalMountPathAcceptsATimedOutMountPointWithAMatchingKernelMount(t *testing.T) {
	stubMountIdentification(t,
		unresponsiveFilesystemStatter(deadVolumeMountPath, syscall.ETIMEDOUT),
		livePortableFSMountTable(deadVolumeMountPath, "att_AAAAAAAAAAAAAAAAAAAAAA"),
	)
	got, err := canonicalMountPath(deadVolumeMountPath)
	if err != nil {
		t.Fatalf("canonicalMountPath of a timed-out mount point with a kernel mount: %v", err)
	}
	if got != deadVolumeMountPath {
		t.Fatalf("canonicalMountPath = %q, want %q", got, deadVolumeMountPath)
	}
}

// TestCanonicalMountPathKeepsAnUnresponsivePathWithNoAttachAndNoKernelMount is
// the honest other half: with neither a kernel mount nor a live attach there is
// no evidence this path is a PortableFS mount at all, so the underlying error
// stands.
func TestCanonicalMountPathKeepsAnUnresponsivePathWithNoAttachAndNoKernelMount(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EIO, syscall.ETIMEDOUT} {
		t.Run(errno.Error(), func(t *testing.T) {
			stubMountIdentification(t,
				unresponsiveFilesystemStatter(deadVolumeMountPath, errno),
				noKernelMounts,
			)
			stubLiveDaemonAttaches(t, "/Volumes/some-other-mount")
			_, err := canonicalMountPath(deadVolumeMountPath)
			if err == nil {
				t.Fatal("canonicalMountPath accepted an unreadable path with no kernel mount and no attach")
			}
			if !errors.Is(err, errno) {
				t.Fatalf("canonicalMountPath error = %v, want the underlying %v", err, errno)
			}
		})
	}
}

// TestCanonicalMountPathKeepsANonUnresponsiveErrorEvenWithALiveAttach: a
// permission or name error is not the dead-residue shape. Only EIO/ETIMEDOUT
// mean "the filesystem cannot answer"; everything else is a real refusal and
// must not be laundered by the daemon inventory.
func TestCanonicalMountPathKeepsANonUnresponsiveErrorEvenWithALiveAttach(t *testing.T) {
	stubMountIdentification(t,
		unresponsiveFilesystemStatter(deadVolumeMountPath, syscall.EACCES),
		noKernelMounts,
	)
	stubLiveDaemonAttaches(t, deadVolumeMountPath)
	_, err := canonicalMountPath(deadVolumeMountPath)
	if err == nil {
		t.Fatal("canonicalMountPath accepted a permission error as dead residue")
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("canonicalMountPath error = %v, want the underlying EACCES", err)
	}
}

// TestCanonicalMountPathDoesNotConsultTheDaemonWhenAKernelMountAnswers keeps
// the cheap identification first: the daemon is only asked once the kernel
// mount table has come up empty.
func TestCanonicalMountPathDoesNotConsultTheDaemonWhenAKernelMountAnswers(t *testing.T) {
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		livePortableFSMountTable(deadVolumeMountPath, "att_AAAAAAAAAAAAAAAAAAAAAA"),
	)
	prior := liveDaemonAttachMountPaths
	liveDaemonAttachMountPaths = func() ([]string, error) {
		t.Error("a matching kernel mount must not need the daemon attach inventory")
		return nil, nil
	}
	t.Cleanup(func() { liveDaemonAttachMountPaths = prior })
	if _, err := canonicalMountPath(deadVolumeMountPath); err != nil {
		t.Fatalf("canonicalMountPath: %v", err)
	}
}
