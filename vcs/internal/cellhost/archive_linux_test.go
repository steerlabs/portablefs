//go:build linux

package cellhost

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type workerRunner struct{ calls []recordedCommand }

func (runner *workerRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, recordedCommand{executable: executable, arguments: append([]string(nil), arguments...)})
	if len(arguments) > 0 && arguments[0] == "is-active" {
		return nil, errors.New("inactive")
	}
	return nil, nil
}

func TestQuotaDecisionRaisesEitherDimensionAndRefusesLowering(t *testing.T) {
	plan := cellplan.VolumePlan{QuotaBytes: 2 << 20, QuotaInodes: 200}
	first, raise, err := quotaDecision(plan, signedQuota{Bytes: plan.QuotaBytes, Inodes: plan.QuotaInodes}, appliedQuota{})
	if err != nil || !first || !raise {
		t.Fatalf("first quota decision = first:%t raise:%t err:%v", first, raise, err)
	}
	first, raise, err = quotaDecision(plan, signedQuota{Bytes: plan.QuotaBytes, Inodes: plan.QuotaInodes}, appliedQuota{Bytes: 1 << 20, Inodes: 200})
	if err != nil || first || !raise {
		t.Fatalf("byte raise decision = first:%t raise:%t err:%v", first, raise, err)
	}
	_, _, err = quotaDecision(plan, signedQuota{Bytes: plan.QuotaBytes, Inodes: plan.QuotaInodes}, appliedQuota{Bytes: 3 << 20, Inodes: 200})
	if !errors.Is(err, ErrQuotaLowering) {
		t.Fatalf("quota lowering error = %v", err)
	}
}

func TestLaunchConfigsAndWorkerDropInsUsePinnedBinds(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("launch config ownership is part of the privileged helper contract")
	}
	host, roots := archiveTestHost(t)
	plan := archiveTestPlan()
	writeArchiveCredentials(t, host, archiveCredentialLines(), 0o600)
	if err := host.WriteArchiverConfig(plan); err != nil {
		t.Fatal(err)
	}
	if err := host.WriteArchiverDropIns(plan); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(roots.config, plan.VolumeID, archiveConfigName))
	if err != nil {
		t.Fatal(err)
	}
	var decoded ArchiverConfig
	if err := json.Unmarshal(config, &decoded); err != nil || decoded.PlacementSequence != 2 || decoded.ChunkSizeBytes != 8<<20 {
		t.Fatalf("archiver config = %+v, %v", decoded, err)
	}
	dropIn, err := os.ReadFile(filepath.Join(roots.units, archiverUnit(plan.VolumeID)+".d", "10-portablefs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"BindReadOnlyPaths=" + filepath.Join(roots.cell, plan.VolumeID) + ":/srv/portablefs-volume",
		"BindPaths=" + filepath.Join(roots.state, plan.VolumeID, archiveResultDirectoryName) + ":/var/lib/portablefs-volume-archive",
		"User=200001", "Group=200001"} {
		if !strings.Contains(string(dropIn), required) {
			t.Fatalf("archiver drop-in omits %q: %s", required, dropIn)
		}
	}
	plan.ArchiveTo = nil
	plan.RestoreFrom = &cellplan.RestoreSource{SealedEpoch: 1, Attempt: "33333333-3333-4333-8333-333333333333",
		ManifestDigestSHA256: strings.Repeat("a", 64), ManifestSizeBytes: 10, PackCount: 1, SealedAllocatedBytes: 1, SealedInodes: 1}
	if err := host.WriteHydratorConfig(plan, HydratorModeRestoreNamespace); err != nil {
		t.Fatal(err)
	}
	if err := host.WriteHydratorDropIns(plan, HydratorModeRestoreNamespace); err != nil {
		t.Fatal(err)
	}
	hydratorDropIn, err := os.ReadFile(filepath.Join(roots.units, hydratorUnit(plan.VolumeID)+".d", "10-portablefs.conf"))
	if err != nil || !strings.Contains(string(hydratorDropIn), "BindPaths="+filepath.Join(roots.cell, plan.VolumeID)+":/srv/portablefs-volume") {
		t.Fatalf("namespace hydrator drop-in = %s, %v", hydratorDropIn, err)
	}
	if err := host.WriteHydratorDropIns(plan, HydratorModeServe); err != nil {
		t.Fatal(err)
	}
	hydratorDropIn, _ = os.ReadFile(filepath.Join(roots.units, hydratorUnit(plan.VolumeID)+".d", "10-portablefs.conf"))
	if strings.Contains(string(hydratorDropIn), ":/srv/portablefs-volume") {
		t.Fatalf("serve hydrator retained data-directory access: %s", hydratorDropIn)
	}
}

func TestResultReadersAreStrictBoundedAndReportAbsence(t *testing.T) {
	host, roots := archiveTestHost(t)
	if _, err := host.ReadArchiveSealed(testVolumeID); !errors.Is(err, ErrArchiveSealedAbsent) {
		t.Fatalf("missing archive seal = %v", err)
	}
	directory := filepath.Join(roots.state, testVolumeID, archiveResultDirectoryName)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	record := ArchiveSealedRecord{Version: 1, VolumeID: testVolumeID, CellID: testCellID, SealedEpoch: 7,
		Attempt: "33333333-3333-4333-8333-333333333333", Manifest: controlplane.ObjectRef{Key: "manifest", SizeBytes: 1, SHA256: strings.Repeat("a", 64)},
		Packs: []controlplane.ObjectRef{{Key: "pack", SizeBytes: 2, SHA256: strings.Repeat("b", 64)}}, RootDigest: strings.Repeat("c", 64),
		SealedAllocatedBytes: 4096, SealedInodes: 1, FormatVersion: 1, ChunkSizeBytes: 8 << 20, KeyVersion: "default", WrittenUnix: 1}
	writeJSONResult(t, filepath.Join(directory, archiveSealedName), record)
	read, err := host.ReadArchiveSealed(testVolumeID)
	if err != nil || read.Attempt != record.Attempt {
		t.Fatalf("read archive seal = %+v, %v", read, err)
	}
	writeJSONResult(t, filepath.Join(directory, restoreNamespaceReadyName), map[string]any{"version": 1, "volume_id": testVolumeID,
		"sealed_epoch": 7, "attempt": record.Attempt, "entries": 1, "written_unix": 2, "unknown": true})
	if _, err := host.ReadRestoreNamespaceReady(testVolumeID); err == nil {
		t.Fatal("namespace-ready reader accepted an unknown field")
	}
}

// archiveCredentialLines is a complete, well-formed root-provisioned archive
// credential file: every key archivestore.LoadConfigFile requires, and nothing
// it does not understand.
func archiveCredentialLines() []string {
	return []string{
		"PORTABLEFS_ARCHIVE_ENDPOINT=https://objects.example.com",
		"PORTABLEFS_ARCHIVE_REGION=us-east-1",
		"PORTABLEFS_ARCHIVE_BUCKET=portablefs-archive",
		"PORTABLEFS_ARCHIVE_ACCESS_KEY_ID=AKIAEXAMPLECELLKEY",
		"PORTABLEFS_ARCHIVE_SECRET_ACCESS_KEY=an-example-secret-access-key",
		"PORTABLEFS_ARCHIVE_CHECKSUM_CAPABILITY=crc64nvme-full-object",
	}
}

func writeArchiveCredentials(t *testing.T, host *Host, lines []string, mode os.FileMode) {
	t.Helper()
	body := ""
	if len(lines) != 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(host.cfg.ArchiveCredentialsPath, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(host.cfg.ArchiveCredentialsPath, mode); err != nil {
		t.Fatal(err)
	}
}

// The Manager places export and hydration work only on cells that answer true
// here, so the answer must track the credentials file exactly - not merely its
// existence. A file that is present but cannot be parsed into a usable store
// admits a whole archive cycle whose only possible outcome is a failure the
// operator sees late and somewhere else.
func TestArchiveConfiguredTracksUsableCredentials(t *testing.T) {
	host, _ := archiveTestHost(t)
	if host.ArchiveConfigured() {
		t.Fatal("absent archive credentials reported as configured")
	}
	writeArchiveCredentials(t, host, nil, 0o600)
	if host.ArchiveConfigured() {
		t.Fatal("empty archive credentials reported as configured")
	}
	writeArchiveCredentials(t, host, archiveCredentialLines(), 0o600)
	if !host.ArchiveConfigured() {
		t.Fatal("usable archive credentials reported as unconfigured")
	}
	// Credentials the whole cell can read are not credentials this helper will
	// stage, so they are not a capability either.
	writeArchiveCredentials(t, host, archiveCredentialLines(), 0o644)
	if host.ArchiveConfigured() {
		t.Fatal("world-readable archive credentials reported as configured")
	}
}

// Every way a present credentials file can still be unusable. Each case is one
// mutation of the well-formed file, so a true answer would be the parse failing
// to notice rather than the case being weak.
func TestArchiveConfiguredRefusesMalformedCredentials(t *testing.T) {
	for name, mutate := range map[string]func([]string) []string{
		// The name stays inside cellhost's pinned path charset: t.TempDir embeds
		// the subtest name in the fixture root, and safeRoot refuses '='.
		"not a key-value assignment": func(lines []string) []string {
			return append(lines, "credentials")
		},
		"unknown key": func(lines []string) []string {
			return append(lines, "PORTABLEFS_ARCHIVE_ROLE_ARN=arn:aws:iam::1:role/x")
		},
		"missing bucket": func(lines []string) []string {
			return append(lines[:2:2], lines[3:]...)
		},
		"empty secret": func(lines []string) []string {
			lines[4] = "PORTABLEFS_ARCHIVE_SECRET_ACCESS_KEY="
			return lines
		},
		"duplicate key": func(lines []string) []string {
			return append(lines, lines[1])
		},
		"quoted value": func(lines []string) []string {
			lines[2] = `PORTABLEFS_ARCHIVE_BUCKET="portablefs-archive"`
			return lines
		},
		"endpoint carries a path": func(lines []string) []string {
			lines[0] = "PORTABLEFS_ARCHIVE_ENDPOINT=https://objects.example.com/archive"
			return lines
		},
		"plaintext endpoint off loopback": func(lines []string) []string {
			lines[0] = "PORTABLEFS_ARCHIVE_ENDPOINT=http://objects.example.com"
			return lines
		},
		"unknown checksum capability": func(lines []string) []string {
			lines[5] = "PORTABLEFS_ARCHIVE_CHECKSUM_CAPABILITY=sha256"
			return lines
		},
	} {
		t.Run(name, func(t *testing.T) {
			host, _ := archiveTestHost(t)
			writeArchiveCredentials(t, host, mutate(archiveCredentialLines()), 0o600)
			if host.ArchiveConfigured() {
				t.Fatalf("archive credentials with %s reported as configured", name)
			}
		})
	}
}

type archiveRoots struct{ cell, config, state, units string }

func archiveTestHost(t *testing.T) (*Host, archiveRoots) {
	t.Helper()
	root := t.TempDir()
	roots := archiveRoots{cell: filepath.Join(root, "cell"), config: filepath.Join(root, "config"), state: filepath.Join(root, "state"), units: filepath.Join(root, "units")}
	sysusers := filepath.Join(root, "sysusers")
	for _, directory := range []string{roots.cell, roots.config, roots.state, roots.units, sysusers} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	credentials := filepath.Join(root, "archive.env")
	host, err := New(Config{CellID: testCellID, CellRoot: roots.cell, ConfigRoot: roots.config, StateRoot: roots.state,
		SystemdUnitRoot: roots.units, SysusersRoot: sysusers, ArchiveCredentialsPath: credentials,
		XFSQuotaBinary: "/xfs_quota", SystemctlBinary: "/systemctl", SystemdRunBinary: "/systemd-run", SysusersBinary: "/sysusers", Runner: &workerRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	return host, roots
}

func archiveTestPlan() cellplan.VolumePlan {
	return cellplan.VolumePlan{VolumeID: testVolumeID, AuthorityGeneration: 7, PlacementSequence: 2,
		ServiceUID: 200001, ServiceGID: 200001, ArchiveTo: &cellplan.ArchiveTarget{Attempt: "33333333-3333-4333-8333-333333333333", KeyVersion: "default"}}
}

func writeJSONResult(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}
