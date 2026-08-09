//go:build linux

package cellhost

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

type recordedCommand struct {
	executable string
	arguments  []string
}

type fenceRunner struct{ calls []recordedCommand }

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
