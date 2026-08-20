//go:build linux

package cellhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// isXFS reports whether a path lives on XFS. The usage measurement is an XFS
// mechanism (xfs_qm_statvfs on a PROJINHERIT directory with limits), and no
// other filesystem can stand in for the numbers. The code path is still worth
// exercising everywhere - it is where a missing volume must become
// ErrVolumeAbsent rather than a zero reading - so the tests below run on any
// filesystem and only make quantitative claims on XFS.
func isXFS(t *testing.T, path string) bool {
	t.Helper()
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		t.Fatal(err)
	}
	return uint64(filesystem.Type) == xfsMagic
}

// TestMeasureUsageDistinguishesAnAbsentVolume: admission reads this answer, so
// "the placement is gone" must never arrive as "the placement uses nothing".
func TestMeasureUsageDistinguishesAnAbsentVolume(t *testing.T) {
	fixture := newPlacementFixture(t)
	if err := removeTreeBeneath(fixture.cellRoot, testVolumeID); err != nil {
		t.Fatal(err)
	}
	usedBytes, usedInodes, err := fixture.host.MeasureUsage(testVolumeID)
	if err == nil {
		t.Fatal("measuring an absent volume succeeded")
	}
	if usedBytes != 0 || usedInodes != 0 {
		t.Fatalf("a failed measurement reported usage: %d bytes, %d inodes", usedBytes, usedInodes)
	}
	if isXFS(t, fixture.cellRoot) {
		if !errors.Is(err, ErrVolumeAbsent) {
			t.Fatalf("measure error = %v, want ErrVolumeAbsent", err)
		}
		return
	}
	// Off XFS the cell root itself is refused before the volume is looked up:
	// the projection this measurement depends on does not exist there, and a
	// cell-wide reading must never be reported as one volume's usage.
	if errors.Is(err, ErrVolumeAbsent) {
		t.Fatalf("a non-XFS cell root produced ErrVolumeAbsent: %v", err)
	}
}

func TestMeasureUsageRefusesAnInvalidVolumeID(t *testing.T) {
	fixture := newPlacementFixture(t)
	for _, volumeID := range []string{"", "not-a-uuid", "../escape", testVolumeID + "/.."} {
		if _, _, err := fixture.host.MeasureUsage(volumeID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("MeasureUsage(%q) = %v, want ErrInvalid", volumeID, err)
		}
	}
}

// TestMeasureUsageReadsTheProjectDirectory exercises the measurement itself.
// On XFS the numbers are checked for internal consistency against the same
// statfs the authority's Volume.StatFS reads; the project-scoped values
// themselves require a provisioned project with hard limits, which the
// privileged XFS batteries under scripts/ set up.
func TestMeasureUsageReadsTheProjectDirectory(t *testing.T) {
	fixture := newPlacementFixture(t)
	if !isXFS(t, fixture.cellRoot) {
		t.Skip("usage measurement is an XFS projection; no other filesystem answers it")
	}
	volumePath := filepath.Join(fixture.cellRoot, testVolumeID)
	if err := os.MkdirAll(volumePath, 0o700); err != nil {
		t.Fatal(err)
	}
	usedBytes, usedInodes, err := fixture.host.MeasureUsage(testVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(volumePath, &filesystem); err != nil {
		t.Fatal(err)
	}
	if want := (filesystem.Blocks - filesystem.Bfree) * uint64(filesystem.Bsize); usedBytes != want {
		t.Fatalf("used bytes = %d, want %d", usedBytes, want)
	}
	if want := filesystem.Files - filesystem.Ffree; usedInodes != want {
		t.Fatalf("used inodes = %d, want %d", usedInodes, want)
	}
}
