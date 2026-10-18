//go:build linux

package cellhost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

// This is the root helper's boundary, not an authority-service capability.
// Keep real ioctls and quota queries here: fake command runners cannot prove
// that XFS projects constrain the provisioned volume's actual descriptors.
func TestProvisionedVolumeEnforcesXFSProjectQuotaAndConfinement(t *testing.T) {
	cellRoot := os.Getenv("PORTABLEFS_CELLHOST_XFS_TEST_ROOT")
	if cellRoot == "" {
		t.Skip("PORTABLEFS_CELLHOST_XFS_TEST_ROOT is required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("cell helper XFS boundary test requires root")
	}
	xfsQuota, err := exec.LookPath("xfs_quota")
	if err != nil {
		t.Fatal(err)
	}
	serviceID := func(name string) uint32 {
		t.Helper()
		id, err := strconv.ParseUint(os.Getenv(name), 10, 32)
		if err != nil || id < 1000 || id == 1<<32-1 {
			t.Fatalf("%s must name a usable test service identity", name)
		}
		return uint32(id)
	}
	unique := uint64(time.Now().UnixNano()) & 0xffffffffffff
	plan := cellplan.EffectiveVolumePlan{VolumePlan: cellplan.VolumePlan{
		VolumeID:   fmt.Sprintf("22222222-2222-4222-8222-%012x", unique),
		ProjectID:  uint32(100_000 + unique%1_000_000),
		ServiceUID: serviceID("PORTABLEFS_SERVICE_UID"), ServiceGID: serviceID("PORTABLEFS_SERVICE_GID"),
		QuotaBytes: 128 << 20, QuotaInodes: 20_000,
	}}
	host := &Host{cfg: Config{CellRoot: cellRoot}}
	fd, err := host.ensureVolumeDirectory(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(cellRoot, plan.VolumeID)) })
	quotaCommand := func(t *testing.T, command string) {
		t.Helper()
		out, err := exec.Command(xfsQuota, "-x", "-c", command, cellRoot).CombinedOutput()
		if err != nil {
			t.Fatalf("xfs_quota %q: %v: %s", command, err, out)
		}
	}
	quotaCommand(t, fmt.Sprintf("project -s -p %s %d", filepath.Join(cellRoot, plan.VolumeID), plan.ProjectID))
	limit, err := xfsHardLimitCommand(plan)
	if err != nil {
		t.Fatal(err)
	}
	quotaCommand(t, limit)
	if err := verifyProvisionedVolume(fd, plan); err != nil {
		t.Fatalf("exact project, quota, owner and mode rejected: %v", err)
	}
	t.Run("missing project inheritance", func(t *testing.T) {
		xfsIO, err := exec.LookPath("xfs_io")
		if err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(xfsIO, "-c", "chattr -P", filepath.Join(cellRoot, plan.VolumeID)).CombinedOutput()
		if err != nil {
			t.Fatalf("clear project inheritance: %v: %s", err, output)
		}
		t.Cleanup(func() {
			quotaCommand(t, fmt.Sprintf("project -s -p %s %d", filepath.Join(cellRoot, plan.VolumeID), plan.ProjectID))
		})
		if err := verifyProvisionedVolume(fd, plan); err == nil || !strings.Contains(err.Error(), "project isolation mismatch") {
			t.Fatalf("missing project inheritance: %v", err)
		}
	})
	wrongProject := plan
	wrongProject.ProjectID++
	if err := verifyProvisionedVolume(fd, wrongProject); err == nil || !strings.Contains(err.Error(), "project isolation mismatch") {
		t.Fatalf("wrong project identity: %v", err)
	}
	for _, test := range []struct {
		name          string
		bytes, inodes uint64
	}{
		{"wrong bytes", plan.QuotaBytes / 2, plan.QuotaInodes},
		{"wrong inodes", plan.QuotaBytes, plan.QuotaInodes / 2},
		{"zero bytes", 0, plan.QuotaInodes},
		{"zero inodes", plan.QuotaBytes, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			quotaCommand(t, fmt.Sprintf("limit -p bhard=%dk ihard=%d %d", test.bytes/1024, test.inodes, plan.ProjectID))
			t.Cleanup(func() { quotaCommand(t, limit) })
			if err := verifyProvisionedVolume(fd, plan); err == nil || !strings.Contains(err.Error(), "hard quota mismatch") {
				t.Fatalf("unequal quota accepted or not queried: %v", err)
			}
		})
	}
	for _, test := range []struct {
		name     string
		uid, gid int
		mode     uint32
	}{
		{"wrong owner", 0, int(plan.ServiceGID), 0o700},
		{"wrong group", int(plan.ServiceUID), 0, 0o700},
		{"wrong mode", int(plan.ServiceUID), int(plan.ServiceGID), 0o750},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := unix.Fchown(fd, test.uid, test.gid); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fchmod(fd, test.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Fchown(fd, int(plan.ServiceUID), int(plan.ServiceGID)); err != nil {
					t.Error(err)
				}
				if err := unix.Fchmod(fd, 0o700); err != nil {
					t.Error(err)
				}
			})
			if err := verifyProvisionedVolume(fd, plan); err == nil || !strings.Contains(err.Error(), "ownership/mode mismatch") {
				t.Fatalf("unequal owner/mode accepted: %v", err)
			}
		})
	}
	rootInfo, err := os.Stat(cellRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("service-replaceable parent", func(t *testing.T) {
		if err := os.Chmod(cellRoot, rootInfo.Mode().Perm()|0o022); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(cellRoot, rootInfo.Mode().Perm()); err != nil {
				t.Error(err)
			}
		})
		if opened, err := host.openVolumeDirectory(plan.VolumeID, false); err == nil {
			_ = unix.Close(opened)
			t.Fatal("service-replaceable volume parent accepted")
		} else if !strings.Contains(err.Error(), "cell root must be root-owned") {
			t.Fatal(err)
		}
	})
	if err := verifyProvisionedVolume(fd, plan); err != nil {
		t.Fatal(err)
	}
	opened, err := host.openVolumeDirectory(plan.VolumeID, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(opened)
}
