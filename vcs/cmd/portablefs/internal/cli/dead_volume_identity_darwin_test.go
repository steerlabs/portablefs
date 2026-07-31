//go:build darwin

package cli

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

// TestRecordedMountIdentityClassifiesADeadVolumeFromTheKernelMountTable pins
// the second half of the dead-volume detach: after canonicalization, umount
// classifies the recorded mount. That classification used statfs(2) of the
// mount path, which resolves into the dead filesystem and returns EIO, so
// `recordedKernelMountPresent` reported an error and umount refused to drain,
// signal, or detach. getfsstat reports mount point + filesystem type + source
// without entering the filesystem, so a dead volume classifies exactly like a
// live one and proceeds to the daemon-owned detach.
func TestRecordedMountIdentityClassifiesADeadVolumeFromTheKernelMountTable(t *testing.T) {
	st := validFSKitMountState(t, deadVolumeMountPath)
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		livePortableFSMountTable(deadVolumeMountPath, st.AttachRef),
	)
	present, err := recordedKernelMountPresent(&st)
	if err != nil {
		t.Fatalf("classify a dead volume with a live kernel mount: %v", err)
	}
	if !present {
		t.Fatal("a dead volume with a MATCHING kernel mount must classify as present (dead-volume detach path)")
	}
}

// TestRecordedMountIdentityReportsAbsentWithNoKernelMount is the honest
// distinction: EIO with NO kernel mount at the path is a stale record, which
// umount reconciles instead of detaching.
func TestRecordedMountIdentityReportsAbsentWithNoKernelMount(t *testing.T) {
	st := validFSKitMountState(t, deadVolumeMountPath)
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		func(string) ([]kernelMountIdentity, error) { return nil, nil },
	)
	present, err := recordedKernelMountPresent(&st)
	if err != nil {
		t.Fatalf("classify an absent mount: %v", err)
	}
	if present {
		t.Fatal("no kernel mount at the path must classify as absent (stale-record reconcile)")
	}
}

// TestRecordedMountIdentityRefusesAForeignKernelMount keeps the exactness the
// statfs classifier had: a mount at the recorded path that is not this
// release's FSKit object with this attach's source is never ours to detach.
func TestRecordedMountIdentityRefusesAForeignKernelMount(t *testing.T) {
	st := validFSKitMountState(t, deadVolumeMountPath)
	for _, tc := range []struct {
		name  string
		mount kernelMountIdentity
	}{
		{"foreign filesystem type", kernelMountIdentity{
			fsType: "apfs", path: deadVolumeMountPath, source: "/dev/disk3s5",
		}},
		{"other attach source", kernelMountIdentity{
			fsType: fskitidentity.FSType, path: deadVolumeMountPath,
			source: fskitidentity.ResourcePrefix + "att_BBBBBBBBBBBBBBBBBBBBBB",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubMountIdentification(t,
				deadFilesystemStatter(deadVolumeMountPath),
				func(string) ([]kernelMountIdentity, error) {
					return []kernelMountIdentity{tc.mount}, nil
				},
			)
			present, err := recordedKernelMountPresent(&st)
			if present || err == nil {
				t.Fatalf("foreign kernel mount = present %v, err %v; want a refusal", present, err)
			}
		})
	}
}

// TestRecordedMountIdentityRefusesStackedKernelMounts mirrors the
// canonicalization refusal: PortableFS never acts on an ambiguous path.
func TestRecordedMountIdentityRefusesStackedKernelMounts(t *testing.T) {
	st := validFSKitMountState(t, deadVolumeMountPath)
	stubMountIdentification(t,
		deadFilesystemStatter(deadVolumeMountPath),
		func(string) ([]kernelMountIdentity, error) {
			return []kernelMountIdentity{
				{fsType: fskitidentity.FSType, path: deadVolumeMountPath, source: fskitidentity.ResourcePrefix + st.AttachRef},
				{fsType: "apfs", path: deadVolumeMountPath, source: "/dev/disk3s5"},
			}, nil
		},
	)
	present, err := recordedKernelMountPresent(&st)
	if present {
		t.Fatal("stacked kernel mounts must never classify as an owned mount")
	}
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("stacked kernel mounts = %v, want an ambiguity refusal", err)
	}
}
