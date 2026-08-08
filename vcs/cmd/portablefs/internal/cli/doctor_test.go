package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
)

// doctorTestEnv is testEnv plus an isolated mount-state directory (doctor
// reads real mount state; tests must never see the developer's).
func doctorTestEnv(t *testing.T) (*cmdEnv, *bytes.Buffer, string) {
	t.Helper()
	e, stdout, _ := testEnv(t)
	stateBase := t.TempDir()
	e.stateDir = filepath.Join(stateBase, "portablefs")
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateBase
		}
		return baseGetenv(k)
	}
	return e, stdout, filepath.Join(e.stateDir, "mounts")
}

// fakeDoctor stubs every process/network boundary to a safe default; tests
// override the axis they exercise.
func fakeDoctor(t *testing.T, e *cmdEnv, o commonOpts) *doctorRun {
	t.Helper()
	r := newDoctorRun(e, o)
	r.goos = "linux"
	r.httpDo = func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("no network in tests")
	}
	r.runCmd = func(name string, args ...string) (string, error) {
		t.Fatalf("unexpected process run: %s %v", name, args)
		return "", nil
	}
	r.hostCheck = func(transport mounthost.Transport) mounthost.Facts {
		return mounthost.Facts{
			Transport: transport,
			State:     mounthost.Unverified,
			Summary:   "no definite blocker found; mount not verified",
		}
	}
	r.verifiedMount = func(mounthost.Transport) (string, bool, error) { return "", false, nil }
	r.daemonHealthy = func(string) bool { return false }
	return r
}

// doctorBaseline is a healthy Linux setup with nothing mounted.
func doctorBaseline(t *testing.T) (*cmdEnv, *bytes.Buffer, *doctorRun, string) {
	t.Helper()
	e, stdout, stateDir := doctorTestEnv(t)
	r := fakeDoctor(t, e, commonOpts{})
	return e, stdout, r, stateDir
}

func pluginkitFake(t *testing.T, byID map[string]string) func(string, ...string) (string, error) {
	return func(name string, args ...string) (string, error) {
		t.Helper()
		if name != "pluginkit" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		id := args[len(args)-1]
		out, ok := byID[id]
		if !ok {
			return "", fmt.Errorf("exit status 1") // pluginkit: no matches
		}
		return out, nil
	}
}

func requireContains(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestDoctorAllChecksPassOnLinux(t *testing.T) {
	_, stdout, r, _ := doctorBaseline(t)
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"UNKNOWN  mount transport: no definite blocker found; mount not verified",
		"SKIP  fskit inventory: FSKit is macOS-only",
		"SKIP  portablefsd:",
		"SKIP  attaches: attach status is read from portablefsd (macOS-only)",
		"PASS  mounts: no mounts recorded",
		"no definite problems found; 1 check(s) remain unverified",
	)
}

func TestDoctorFskitExtensionStates(t *testing.T) {
	const releaseID = "dev.portablefs.PortableFSApp.PortableFSExt"
	cases := []struct {
		name       string
		byID       map[string]string
		wantRC     int
		wantOutput []string
	}{
		{
			"not registered",
			map[string]string{},
			0,
			[]string{
				"UNKNOWN  fskit inventory: no matching PlugInKit registration was listed",
				"does not establish FSKit mountability",
			},
		},
		{
			"disabled",
			map[string]string{releaseID: "-    " + releaseID + "(1.0.0)"},
			0,
			[]string{
				"UNKNOWN  fskit inventory: PlugInKit election is inventory only",
				releaseID + "  election=minus",
			},
		},
		{
			"registered with the default election (leading spaces)",
			map[string]string{releaseID: "     " + releaseID + "(1.0)"},
			0,
			[]string{
				"UNKNOWN  fskit inventory: PlugInKit election is inventory only",
				releaseID + "  election=default",
			},
		},
		{
			"registered with an unknown election",
			map[string]string{releaseID: "?    " + releaseID + "(1.0.0)"},
			0,
			[]string{
				"UNKNOWN  fskit inventory: PlugInKit election is inventory only",
				releaseID + "  election=unknown",
			},
		},
		{
			"enabled",
			map[string]string{releaseID: "+    " + releaseID + "(1.0.0)"},
			0,
			[]string{"UNKNOWN  fskit inventory:", releaseID + "  election=plus"},
		},
		{
			"dev harness fallback",
			map[string]string{"dev.portablefs.oss.KitDev.PortableFSDev": "+    dev.portablefs.oss.KitDev.PortableFSDev(1.0.0)"},
			0,
			[]string{"UNKNOWN  fskit inventory:", "dev.portablefs.oss.KitDev.PortableFSDev  election=plus"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stdout, r, _ := doctorBaseline(t)
			r.goos = "darwin"
			r.runCmd = pluginkitFake(t, tc.byID)
			if rc := r.execute(); rc != tc.wantRC {
				t.Fatalf("rc = %d, want %d\n%s", rc, tc.wantRC, stdout.String())
			}
			requireContains(t, stdout.String(), tc.wantOutput...)
		})
	}
}

// Historical mount logs do not upgrade PlugInKit inventory into an enablement
// verdict. Only a current mount is authoritative.
func TestDoctorFskitHistoricalLogRemainsInventoryOnly(t *testing.T) {
	const releaseID = "dev.portablefs.PortableFSApp.PortableFSExt"
	_, stdout, r, stateDir := doctorBaseline(t)
	r.goos = "darwin"
	r.runCmd = pluginkitFake(t, map[string]string{releaseID: "+    " + releaseID + "(1.0.0)"})
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logBody := "portablefs mount: mount -t pfs /tmp/w: exit status 71\n" +
		`the "pfs" FSKit extension is not enabled: install PortableFS.app, then in System Settings...` + "\n"
	if err := os.WriteFile(filepath.Join(stateDir, "deadbeef00000000.log"), []byte(logBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"UNKNOWN  fskit inventory: PlugInKit election is inventory only",
		releaseID+"  election=plus",
		"no definite problems found",
	)
}

func TestDoctorDaemonDownWithLiveFskitMountFails(t *testing.T) {
	const releaseID = "dev.portablefs.PortableFSApp.PortableFSExt"
	_, stdout, r, stateDir := doctorBaseline(t)
	r.goos = "darwin"
	r.runCmd = pluginkitFake(t, map[string]string{releaseID: "+    " + releaseID + "(1.0.0)"})
	r.daemonHealthy = func(string) bool { return false }
	r.verifiedMount = func(transport mounthost.Transport) (string, bool, error) {
		if transport == mounthost.FSKit {
			return "/Users/me/work", true, nil
		}
		return "", false, nil
	}
	r.e.mountHealthFn = func(*mountState) string { return "live" }
	fskitState := validFSKitMountState(t, "/Users/me/work")
	fskitState.VolumeID = "vol1"
	if err := writeMountState(stateDir, fskitState); err != nil {
		t.Fatal(err)
	}
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  portablefsd: not answering on",
		"fskit mounts are recorded live (e.g. /Users/me/work)",
		"fix: run `portablefs umount /Users/me/work` and mount again",
		"PASS  mounts: 1 mount(s), all live",
	)
}

func TestDoctorMountHealthFailures(t *testing.T) {
	_, stdout, r, stateDir := doctorBaseline(t)
	r.e.mountHealthFn = func(st *mountState) string {
		if st.Status == mountStatusCredentialExpired {
			return mountStatusCredentialExpired
		}
		return "stale"
	}
	staleState := validFuseMountState(t, "/tmp/stale")
	staleState.VolumeID = "vol1"
	staleState.PID = 3999999
	if err := writeMountState(stateDir, staleState); err != nil {
		t.Fatal(err)
	}
	expiredState := validFuseMountState(t, "/tmp/expired")
	expiredState.VolumeID = "vol2"
	expiredState.Status = mountStatusCredentialExpired
	expiredState.StatusChangedAtMs = 1700000000000
	if err := writeMountState(stateDir, expiredState); err != nil {
		t.Fatal(err)
	}
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  mounts: 2 mount(s): 1 stale, 1 credential-expired",
		"/tmp/stale  vol1@main  fuse  stale",
		"/tmp/expired  vol2@main  fuse  credential-expired",
		// A v3 mount capability is single-use and is never renewed, so the
		// only repair for a credential-expired mount is mounting again with a
		// fresh one — which is what the remedy says, with no other command in
		// it to send the operator somewhere that cannot help.
		"fix: clean up stale mounts with `portablefs umount /tmp/stale`; mount credential-expired paths again with a fresh volume mount capability (a v3 capability is single-use and is never renewed)",
	)
}

func TestDoctorJSONOutput(t *testing.T) {
	_, stdout, r, _ := doctorBaseline(t)
	r.opts.jsonOut = true
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	var out struct {
		Checks  []doctorResult `json:"checks"`
		Failed  int            `json:"failed"`
		Unknown int            `json:"unknown"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("doctor --json must emit one JSON document: %v\n%s", err, stdout.String())
	}
	if len(out.Checks) != len(doctorChecks()) || out.Failed != 0 || out.Unknown != 1 {
		t.Fatalf("unexpected JSON shape: %+v", out)
	}
}

func TestDoctorCommandRegistered(t *testing.T) {
	if _, ok := findCommand("doctor"); !ok {
		t.Fatal("doctor must be registered in the command table")
	}
	text, ok := commandHelp("doctor")
	if !ok {
		t.Fatal("doctor must have detailed help")
	}
	for _, want := range []string{"Read-only", "PASS, FAIL, UNKNOWN, or SKIP", "Exit code 1", "PlugInKit"} {
		if !strings.Contains(text, want) {
			t.Fatalf("doctor help missing %q", want)
		}
	}
	if !strings.Contains(rootHelp(), "doctor") {
		t.Fatal("root help must list doctor")
	}
}
