//go:build linux

package powerloss

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The privileged gates for the power-loss harness.
//
// These follow the same discipline as the XFS and FUSE gates elsewhere in the
// repository - a named environment variable per prerequisite, a t.Skipf that
// says which one is missing, and a REQUIRED switch the CI job sets that turns
// every skip into a hard failure. The reason is the same one recorded on
// requireProvisionedXFS: without the REQUIRED switch a broken provisioner
// presents as a green run with a silent skip.
//
// One rule is inverted here relative to those gates. They fail when the test
// process is root, because root makes their DAC assertions vacuous. This
// harness REQUIRES root, because it creates loop devices, a device-mapper
// target and filesystem mounts. It keeps the data plane unprivileged the same
// way the deployment does: the authority, the mount and the workload driver
// are all spawned as the service identity, never as root.
const (
	envPowerLoss     = "PORTABLEFS_POWERLOSS_TEST"
	envRequired      = "PORTABLEFS_POWERLOSS_REQUIRED"
	envWorkDir       = "PORTABLEFS_POWERLOSS_WORK_DIR"
	envBinDir        = "PORTABLEFS_POWERLOSS_BIN_DIR"
	envCredsDir      = "PORTABLEFS_POWERLOSS_CREDS_DIR"
	envProvisioner   = "PORTABLEFS_POWERLOSS_PROVISIONER"
	envServiceUID    = "PORTABLEFS_POWERLOSS_SERVICE_UID"
	envServiceGID    = "PORTABLEFS_POWERLOSS_SERVICE_GID"
	envVolume        = "PORTABLEFS_POWERLOSS_VOLUME"
	envProjectID     = "PORTABLEFS_POWERLOSS_PROJECT_ID"
	envAuthorityPort = "PORTABLEFS_POWERLOSS_AUTHORITY_PORT"
	envImageSize     = "PORTABLEFS_POWERLOSS_IMAGE_SIZE"
	envCheckpoints   = "PORTABLEFS_POWERLOSS_CHECKPOINTS"
	envBarrierPoints = "PORTABLEFS_POWERLOSS_BARRIER_POINTS"
	envKillRounds    = "PORTABLEFS_POWERLOSS_KILL_ROUNDS"
	// envCapabilityLifetime must agree with the --lifetime the entrypoint
	// minted the capability set with. The shipped authority default is 15
	// minutes, which a run that replays a two-gigabyte device once per cut
	// outlives, and an attach refused for an expired capability would be
	// reported as a durability failure. The capability window is not what this
	// harness measures.
	envCapabilityLifetime = "PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME"
)

// hostGate is the prerequisite set both instruments share: root, a scratch
// directory, and the tools to make and mount a loop-backed XFS.
type hostGate struct {
	workDir string
	runner  Runner
}

// deviceGate adds the dm-log-writes prerequisites the power-cut instrument
// needs. It is a separate gate so the process-level instrument does not skip
// for a device-mapper target it never uses.
type deviceGate struct{ hostGate }

// skipOrFail is the single place the REQUIRED switch is honoured, so no gate
// in this package can accidentally implement a softer version of it.
func skipOrFail(t *testing.T, format string, arguments ...any) {
	t.Helper()
	reason := fmt.Sprintf(format, arguments...)
	if os.Getenv(envRequired) == "1" {
		t.Fatalf("%s=1 but %s", envRequired, reason)
	}
	t.Skipf("the power-loss harness is not runnable here: %s", reason)
}

func requireHostGate(t *testing.T) hostGate {
	t.Helper()
	if os.Getenv(envPowerLoss) != "1" {
		skipOrFail(t, "%s is not set to 1", envPowerLoss)
	}
	workDir := os.Getenv(envWorkDir)
	if workDir == "" {
		skipOrFail(t, "%s names no scratch directory for the device images", envWorkDir)
	}
	if !filepath.IsAbs(workDir) || filepath.Clean(workDir) != workDir {
		t.Fatalf("%s must be a clean absolute path, got %q", envWorkDir, workDir)
	}
	if err := RequireFilesystemSupport(); err != nil {
		skipOrFail(t, "%v", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", envWorkDir, err)
	}
	return hostGate{workDir: workDir, runner: Runner{Trace: testWriter{t}}}
}

func requireDeviceGate(t *testing.T) deviceGate {
	t.Helper()
	return deviceGate{hostGate: requireLogWrites(t, requireHostGate(t))}
}

// requireLogWrites layers the device-mapper prerequisite onto an already
// resolved host gate, so a test that needs both the authority and a write log
// reports whichever prerequisite is actually missing.
func requireLogWrites(t *testing.T, gate hostGate) hostGate {
	t.Helper()
	if err := RequireLogWritesSupport(gate.runner); err != nil {
		skipOrFail(t, "%v", err)
	}
	return gate
}

// authorityGate adds everything needed to run the real authority and mount
// binaries on top of a provisioned cell.
type authorityGate struct {
	hostGate
	binDir      string
	credsDir    string
	provisioner string
	volume      string
	projectID   uint32
	serviceUID  uint32
	serviceGID  uint32
	port        int
	imageSize   int64
	checkpoints int
	barriers    int
	killRounds  int
	capability  string
	// capabilityWindow is the parsed form of capability, the window the
	// credential set was minted with.
	capabilityWindow time.Duration
}

// capabilityBound is what the authority is told to honour. It is deliberately
// wider than the minted window: the credential tool back-dates not_before by a
// second, so a token minted for exactly capabilityWindow declares a window one
// second longer, and volumecap refuses a declared window larger than the
// authority's bound.
func (g authorityGate) capabilityBound() time.Duration { return g.capabilityWindow + time.Minute }

func requireAuthorityGate(t *testing.T) authorityGate {
	t.Helper()
	gate := authorityGate{hostGate: requireHostGate(t)}
	gate.binDir = requiredPath(t, envBinDir)
	gate.credsDir = requiredPath(t, envCredsDir)
	gate.provisioner = requiredPath(t, envProvisioner)
	gate.volume = os.Getenv(envVolume)
	if gate.volume == "" {
		skipOrFail(t, "%s names no volume", envVolume)
	}
	gate.projectID = uint32(requiredNumber(t, envProjectID))
	gate.serviceUID = uint32(requiredNumber(t, envServiceUID))
	gate.serviceGID = uint32(requiredNumber(t, envServiceGID))
	gate.port = int(requiredNumber(t, envAuthorityPort))
	if gate.serviceUID == 0 || gate.serviceGID == 0 {
		t.Fatalf("%s/%s must name an unprivileged identity; the data plane never runs as root", envServiceUID, envServiceGID)
	}
	for _, binary := range []string{"portablefs-authority", "portablefs-mount-v3", "pfs-powerloss-driver"} {
		if _, err := os.Stat(filepath.Join(gate.binDir, binary)); err != nil {
			skipOrFail(t, "%s does not contain %s: %v", envBinDir, binary, err)
		}
	}
	if _, err := exec.LookPath("fusermount3"); err != nil {
		skipOrFail(t, "fusermount3 is not installed; strict mount fencing cannot be proved")
	}
	gate.imageSize = optionalNumber(t, envImageSize, 2<<30)
	gate.checkpoints = int(optionalNumber(t, envCheckpoints, 12))
	gate.barriers = int(optionalNumber(t, envBarrierPoints, 8))
	gate.killRounds = int(optionalNumber(t, envKillRounds, 3))
	gate.capability = os.Getenv(envCapabilityLifetime)
	if gate.capability == "" {
		skipOrFail(t, "%s does not say what capability window the credential set was minted with", envCapabilityLifetime)
	}
	parsed, err := time.ParseDuration(gate.capability)
	if err != nil || parsed <= 0 {
		t.Fatalf("%s=%q is not a positive duration: %v", envCapabilityLifetime, gate.capability, err)
	}
	gate.capabilityWindow = parsed
	return gate
}

func requiredPath(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		skipOrFail(t, "%s is not set", name)
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		t.Fatalf("%s must be a clean absolute path, got %q", name, value)
	}
	if _, err := os.Stat(value); err != nil {
		skipOrFail(t, "%s=%q does not exist: %v", name, value, err)
	}
	return value
}

func requiredNumber(t *testing.T, name string) int64 {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		skipOrFail(t, "%s is not set", name)
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		t.Fatalf("%s=%q is not a non-negative number: %v", name, raw, err)
	}
	return value
}

func optionalNumber(t *testing.T, name string, fallback int64) int64 {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		t.Fatalf("%s=%q is not a positive number: %v", name, raw, err)
	}
	return value
}

// testWriter routes command narration into the test log, so a failure shows
// the exact device commands that led to it.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", trimNewline(string(p)))
	return len(p), nil
}

func trimNewline(value string) string {
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == '\r') {
		value = value[:len(value)-1]
	}
	return value
}

// waitFor polls until condition holds or the bound expires, and reports what
// it was waiting for. Every wait in this harness is bounded and named: an
// unbounded one would turn a broken prerequisite into a hung job.
func waitFor(bound time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return condition()
}
