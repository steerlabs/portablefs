//go:build linux

package cellhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

type recordedCommand struct {
	executable string
	arguments  []string
}

type fenceRunner struct{ calls []recordedCommand }

type directXFSQuotaRunner struct {
	xfsQuota string
	calls    int
}

func (runner *directXFSQuotaRunner) Run(ctx context.Context, _ string, arguments ...string) ([]byte, error) {
	for index, argument := range arguments {
		if argument == runner.xfsQuota {
			runner.calls++
			return exec.CommandContext(ctx, argument, arguments[index+1:]...).CombinedOutput()
		}
	}
	return nil, errors.New("cellhost test: transient command omitted xfs_quota")
}

func (runner *fenceRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, recordedCommand{executable: executable, arguments: append([]string(nil), arguments...)})
	if len(arguments) > 0 && arguments[0] == "is-active" {
		return nil, errors.New("inactive")
	}
	return nil, nil
}

func TestFenceUsesFixedSystemctlShapeAndRequiresBothUnitsInactive(t *testing.T) {
	runner := &fenceRunner{}
	host := &Host{cfg: Config{SystemctlBinary: "/usr/bin/systemctl", Runner: runner}}
	volumeID := "22222222-2222-4222-8222-222222222222"
	absent, err := host.fence(context.Background(), volumeID)
	if err != nil || !absent {
		t.Fatalf("fence = %v, %v", absent, err)
	}
	service := "portablefs-authority@" + volumeID + ".service"
	socket := "portablefs-authority@" + volumeID + ".socket"
	want := []recordedCommand{
		{"/usr/bin/systemctl", []string{"kill", "--kill-whom=all", "--signal=SIGKILL", service}},
		{"/usr/bin/systemctl", []string{"stop", service, socket}},
		{"/usr/bin/systemctl", []string{"is-active", "--quiet", service}},
		{"/usr/bin/systemctl", []string{"is-active", "--quiet", socket}},
		{"/usr/bin/systemctl", []string{"show", "--property=ControlGroup", "--value", service}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("fence commands = %#v, want %#v", runner.calls, want)
	}
}

func TestNewRejectsPathTraversalConfiguration(t *testing.T) {
	_, err := New(Config{
		CellID: "11111111-1111-4111-8111-111111111111", CellRoot: "/srv/portablefs/../escape",
		ConfigRoot: "/etc/portablefs/volumes", StateRoot: "/var/lib/portablefs/volumes",
		SystemdUnitRoot: "/etc/systemd/system", SysusersRoot: "/var/lib/portablefs-cell-helper/sysusers.d",
		XFSQuotaBinary: "/usr/sbin/xfs_quota", SystemctlBinary: "/usr/bin/systemctl",
		SystemdRunBinary: "/usr/bin/systemd-run", SysusersBinary: "/usr/bin/systemd-sysusers",
	})
	if err == nil {
		t.Fatal("path-traversing root was accepted")
	}
}

func TestSafeRootAcceptsGeneratedSystemdInstancePath(t *testing.T) {
	path := "/etc/systemd/system/portablefs-authority@22222222-2222-4222-8222-222222222222.service.d"
	if !safeRoot(path) {
		t.Fatalf("generated systemd instance path was rejected: %s", path)
	}
	for _, unsafe := range []string{
		"/etc/systemd/system/portablefs-authority@../../other.service.d",
		"/etc/systemd/system/portablefs-authority@volume%2fescape.service.d",
	} {
		if safeRoot(unsafe) {
			t.Fatalf("unsafe derived path was accepted: %s", unsafe)
		}
	}
}

func TestServiceIdentityConfigIsStableAndCollisionFree(t *testing.T) {
	first := cellplan.VolumePlan{
		VolumeID: "22222222-2222-4222-8222-222222222222", ServiceUID: 210000, ServiceGID: 210000,
	}
	second := first
	second.VolumeID = "22222222-2222-4222-8222-222222222223"
	firstName, firstPayload, err := serviceIdentityConfig(first)
	if err != nil {
		t.Fatal(err)
	}
	repeatedName, repeatedPayload, err := serviceIdentityConfig(first)
	if err != nil {
		t.Fatal(err)
	}
	secondName, _, err := serviceIdentityConfig(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstName != repeatedName || !reflect.DeepEqual(firstPayload, repeatedPayload) {
		t.Fatal("service identity derivation is not deterministic")
	}
	if firstName == secondName {
		t.Fatal("distinct full volume IDs produced the same service account name")
	}
	if len(firstName) != 30 || !regexp.MustCompile(`^pfs-[a-z2-7]+$`).MatchString(firstName) {
		t.Fatalf("service account name %q is not a portable 30-character name", firstName)
	}
	payload := string(firstPayload)
	for _, expected := range []string{
		"g " + firstName + " 210000\n",
		"u " + firstName + " 210000:" + firstName,
		first.VolumeID,
		"/nonexistent /usr/sbin/nologin\n",
	} {
		if !strings.Contains(payload, expected) {
			t.Fatalf("service identity configuration %q does not contain %q", payload, expected)
		}
	}
}

func TestXFSHardLimitUsesKiBNotFilesystemBlocks(t *testing.T) {
	plan := cellplan.VolumePlan{ProjectID: 43001, QuotaBytes: 256 << 20, QuotaInodes: 20_000}
	command, err := xfsHardLimitCommand(plan)
	if err != nil {
		t.Fatal(err)
	}
	if command != "limit -p bhard=262144k ihard=20000 43001" {
		t.Fatalf("quota command = %q", command)
	}
	plan.QuotaBytes++
	if _, err := xfsHardLimitCommand(plan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unaligned quota error = %v, want ErrInvalid", err)
	}
}

func TestXFSQuotaTransientPreservesHostMountNamespace(t *testing.T) {
	arguments := transientArguments(
		"portablefs-xfs-project-volume", "/usr/sbin/xfs_quota",
		[]string{"-x", "-c", "typed command", "/srv/portablefs"},
		"CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN", false,
	)
	joined := strings.Join(arguments, "\n")
	for _, forbidden := range []string{"PrivateDevices=yes", "PrivateTmp=yes"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("XFS quota transient contains mount-namespace isolation %q", forbidden)
		}
	}
	for _, required := range []string{
		"--wait", "--collect", "--unit=portablefs-xfs-project-volume",
		"CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN",
		"/usr/sbin/xfs_quota", "typed command", "/srv/portablefs",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("XFS quota transient is missing %q: %q", required, joined)
		}
	}

	sysusers := strings.Join(transientArguments(
		"portablefs-sysusers-volume", "/usr/bin/systemd-sysusers", []string{"/state/volume.conf"},
		"CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER", true,
	), "\n")
	for _, required := range []string{"PrivateDevices=yes", "PrivateTmp=yes"} {
		if !strings.Contains(sysusers, required) {
			t.Fatalf("sysusers transient is missing %q", required)
		}
	}
}

func TestAuthorityServiceDropInBindsDedicatedProjectScopedWriteStaging(t *testing.T) {
	plan := cellplan.VolumePlan{ServiceUID: 210000, ServiceGID: 210001}
	dropIn := authorityServiceDropIn(
		plan,
		"/srv/portablefs/volume",
		"/etc/portablefs/volumes/volume",
		"/var/lib/portablefs/volumes/volume",
		"/srv/portablefs/.portablefs-control/volume/write-staging",
	)
	want := "[Service]\n" +
		"User=210000\n" +
		"Group=210001\n" +
		"BindPaths=/srv/portablefs/volume:/srv/portablefs-volume\n" +
		"BindReadOnlyPaths=/etc/portablefs/volumes/volume:/run/portablefs-volume\n" +
		"BindPaths=/var/lib/portablefs/volumes/volume:/var/lib/portablefs-volume\n" +
		"BindPaths=/srv/portablefs/.portablefs-control/volume/write-staging:/var/lib/portablefs-write-staging\n"
	if dropIn != want {
		t.Fatalf("service drop-in = %q, want %q", dropIn, want)
	}
}

func TestWriteStagingIsAtomicPinnedAndSharesTheVolumeProjectQuota(t *testing.T) {
	cellRoot := os.Getenv("PORTABLEFS_CELLHOST_XFS_TEST_ROOT")
	if cellRoot == "" {
		t.Skip("PORTABLEFS_CELLHOST_XFS_TEST_ROOT is required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("write-staging host boundary test requires root")
	}
	xfsQuota, err := exec.LookPath("xfs_quota")
	if err != nil {
		t.Fatal(err)
	}
	uid64, err := strconv.ParseUint(os.Getenv("PORTABLEFS_SERVICE_UID"), 10, 32)
	if err != nil || uid64 < 1000 {
		t.Fatal("PORTABLEFS_SERVICE_UID must name the test service identity")
	}
	gid64, err := strconv.ParseUint(os.Getenv("PORTABLEFS_SERVICE_GID"), 10, 32)
	if err != nil || gid64 < 1000 {
		t.Fatal("PORTABLEFS_SERVICE_GID must name the test service identity")
	}
	unique := uint64(time.Now().UnixNano()) & 0xffffffffffff
	volumeID := fmt.Sprintf("22222222-2222-4222-8222-%012x", unique)
	volumePath := filepath.Join(cellRoot, volumeID)
	if err := os.Mkdir(volumePath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join(cellRoot, ".portablefs-control", volumeID))
		_ = os.RemoveAll(volumePath)
	})
	projectID := uint32(100_000 + time.Now().UnixNano()%1_000_000)
	quotaBytes := uint64(128 << 20)
	quotaInodes := uint64(20_000)
	for _, command := range []string{
		fmt.Sprintf("project -s -p %s %d", volumePath, projectID),
		fmt.Sprintf("limit -p bhard=%dk ihard=%d %d", quotaBytes/1024, quotaInodes, projectID),
	} {
		if output, err := exec.Command(xfsQuota, "-x", "-c", command, cellRoot).CombinedOutput(); err != nil {
			t.Fatalf("xfs_quota %q: %v: %s", command, err, output)
		}
	}
	plan := cellplan.VolumePlan{
		VolumeID: volumeID, ProjectID: projectID, ServiceUID: uint32(uid64), ServiceGID: uint32(gid64),
		QuotaBytes: quotaBytes, QuotaInodes: quotaInodes,
	}
	runner := &directXFSQuotaRunner{xfsQuota: xfsQuota}
	host := &Host{cfg: Config{CellRoot: cellRoot, XFSQuotaBinary: xfsQuota, SystemdRunBinary: "/usr/bin/systemd-run", Runner: runner}}
	stagingPath, err := host.ensureWriteStaging(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(cellRoot, ".portablefs-control", volumeID, "write-staging")
	if stagingPath != wantPath {
		t.Fatalf("staging path = %q, want %q", stagingPath, wantPath)
	}
	stagingFD, err := host.openWriteStaging(volumeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProjectDirectory(stagingFD, plan, plan.ServiceUID, plan.ServiceGID, 0o700, "write staging"); err != nil {
		_ = unix.Close(stagingFD)
		t.Fatal(err)
	}
	_ = unix.Close(stagingFD)
	for _, path := range []string{filepath.Join(cellRoot, ".portablefs-control"), filepath.Join(cellRoot, ".portablefs-control", volumeID)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o711 {
			t.Fatalf("control parent %q = %d:%d %o, want 0:0 711", path, stat.Uid, stat.Gid, info.Mode().Perm())
		}
	}
	volumeControlPath := filepath.Join(cellRoot, ".portablefs-control", volumeID)
	if err := os.Chmod(volumeControlPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if fd, err := host.openWriteStaging(volumeID); err == nil {
		_ = unix.Close(fd)
		t.Fatal("observation accepted a service-replaceable staging parent")
	}
	if _, err := host.ensureWriteStaging(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stagingPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := host.ensureWriteStaging(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 {
		t.Fatalf("idempotent staging migration ran xfs_quota %d times, want 1", runner.calls)
	}
	info, err := os.Stat(stagingPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("reconciled staging mode = %o, want 700", info.Mode().Perm())
	}
}
