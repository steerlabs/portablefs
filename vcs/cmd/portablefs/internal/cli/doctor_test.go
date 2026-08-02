package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func writeDoctorProfile(t *testing.T, e *cmdEnv, token string) {
	t.Helper()
	cfg := &Config{CurrentProfile: "default", Profiles: map[string]Profile{
		"default": {APIUrl: "https://api.example.com", APIToken: token},
	}}
	if err := saveConfig(e.configPath, cfg); err != nil {
		t.Fatal(err)
	}
}

// doctorTransport fakes the probe transport: one status for unauthenticated
// requests, one for bearer-authenticated ones, with an optional min-CLI
// header on every response.
func doctorTransport(unauthStatus, authStatus int, minVersion string) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		status := unauthStatus
		if req.Header.Get("authorization") != "" {
			status = authStatus
		}
		h := http.Header{}
		if minVersion != "" {
			h.Set(minCLIVersionHeader, minVersion)
		}
		return &http.Response{
			StatusCode: status,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"UNAUTHORIZED","message":"x"}}`)),
		}, nil
	}
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

// doctorBaseline is a fully healthy Linux setup: saved profile, reachable
// server (401 unauthenticated), accepted token (200).
func doctorBaseline(t *testing.T) (*cmdEnv, *bytes.Buffer, *doctorRun, string) {
	t.Helper()
	e, stdout, stateDir := doctorTestEnv(t)
	writeDoctorProfile(t, e, "tok")
	r := fakeDoctor(t, e, commonOpts{})
	r.httpDo = doctorTransport(401, 200, "")
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
		"PASS  config:",
		"default -> https://api.example.com  (active)",
		"PASS  server: https://api.example.com answered (HTTP 401)",
		"PASS  token: saved token accepted (HTTP 200)",
		"SKIP  version: server does not advertise a minimum CLI version",
		"UNKNOWN  mount transport: no definite blocker found; mount not verified",
		"SKIP  fskit inventory: FSKit is macOS-only",
		"SKIP  portablefsd:",
		"PASS  mounts: no mounts recorded",
		"no definite problems found; 1 check(s) remain unverified",
	)
}

func TestDoctorConfigParseFailure(t *testing.T) {
	e, stdout, _ := doctorTestEnv(t)
	if err := os.MkdirAll(filepath.Dir(e.configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.configPath, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := fakeDoctor(t, e, commonOpts{})
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  config:",
		"fix: fix or remove the file, then run `portablefs login` to recreate it",
		"SKIP  server: connection settings unresolved",
		"1 problem(s) found",
	)
}

func TestDoctorNoServerConfigured(t *testing.T) {
	e, stdout, _ := doctorTestEnv(t)
	r := fakeDoctor(t, e, commonOpts{})
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"PASS  config:",
		"no profiles saved yet",
		"FAIL  server: no server configured",
		"fix: run `portablefs login`",
		"SKIP  token: no server to verify a token against",
	)
}

func TestDoctorServerUnreachable(t *testing.T) {
	_, stdout, r, _ := doctorBaseline(t)
	r.httpDo = func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial tcp: connection refused")
	}
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  server: https://api.example.com is not reachable: dial tcp: connection refused",
		"fix: check the URL in the config file and your network",
		"FAIL  token: could not verify the token",
		"SKIP  version: server unreachable",
	)
}

func TestDoctorTokenRejected(t *testing.T) {
	_, stdout, r, _ := doctorBaseline(t)
	r.httpDo = doctorTransport(401, 401, "")
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"PASS  server:",
		"FAIL  token: the server rejected the saved token (HTTP 401)",
		"fix: run `portablefs login`",
	)
}

func TestDoctorTokenSkippedWhenNoneSaved(t *testing.T) {
	e, stdout, _ := doctorTestEnv(t)
	writeDoctorProfile(t, e, "")
	r := fakeDoctor(t, e, commonOpts{})
	r.httpDo = doctorTransport(401, 200, "")
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(), "SKIP  token: no saved token for this profile")
}

func TestDoctorVersionSkewFails(t *testing.T) {
	e, stdout, r, _ := doctorBaseline(t)
	e.version = "v1.0.0"
	r.httpDo = doctorTransport(401, 200, "9.9.9")
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  version: this CLI is v1.0.0 but the server requires at least 9.9.9",
		"fix: upgrade with: curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh",
	)
}

func TestDoctorVersionDevBuildFailsClosed(t *testing.T) {
	e, stdout, r, _ := doctorBaseline(t)
	e.version = "dev"
	r.httpDo = doctorTransport(401, 200, "9.9.9")
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		`FAIL  version: "dev" is not a stamped release version, so compatibility with server minimum 9.9.9 cannot be verified`,
		"fix: install a stamped release with: "+upgradeCommand(),
	)
}

func TestDoctorInvalidServerMinimumFailsClosed(t *testing.T) {
	e, stdout, r, _ := doctorBaseline(t)
	e.version = "v9.9.9"
	r.httpDo = doctorTransport(401, 200, "latest")
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		`FAIL  version: server sent invalid minimum CLI version "latest"`,
		"fix: fix the server's "+minCLIVersionHeader+" response header",
	)
}

func TestDoctorVersionMeetsMinimum(t *testing.T) {
	e, stdout, r, _ := doctorBaseline(t)
	e.version = "v2.1.0"
	r.httpDo = doctorTransport(401, 200, "2.0.0")
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(), "PASS  version: CLI v2.1.0 meets the server minimum 2.0.0")
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
		// A credential-expired mount is an ENDED ACCESS LEASE, and four of the
		// five typed answers that end one leave the account credential
		// untouched. Leading with `portablefs login` prescribed a repair that
		// cannot mint a lease; the remount that can is now the instruction, and
		// login is qualified rather than commanded.
		"fix: clean up stale mounts with `portablefs umount /tmp/stale`; remount credential-expired paths to mint a fresh access lease (run `portablefs login` first only if the saved account credential is also rejected — the mount log names which)",
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
