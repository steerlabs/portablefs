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
)

// doctorTestEnv is testEnv plus an isolated mount-state directory (doctor
// reads real mount state; tests must never see the developer's).
func doctorTestEnv(t *testing.T) (*cmdEnv, *bytes.Buffer, string) {
	t.Helper()
	e, stdout, _ := testEnv(t)
	stateBase := t.TempDir()
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateBase
		}
		return ""
	}
	return e, stdout, filepath.Join(stateBase, "portablefs", "mounts")
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
		"SKIP  fskit extension: FSKit is macOS-only",
		"SKIP  portablefsd:",
		"PASS  mounts: no mounts recorded",
		"no problems found",
	)
}

func TestDoctorConfigParseFailure(t *testing.T) {
	e, stdout, _ := doctorTestEnv(t)
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
		"fix: upgrade with: curl -fsSL https://api.example.com/install | sh",
	)
}

func TestDoctorVersionDevBypassPasses(t *testing.T) {
	e, stdout, r, _ := doctorBaseline(t)
	e.version = "dev"
	r.httpDo = doctorTransport(401, 200, "9.9.9")
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(), `PASS  version: "dev" build skips the version check (server minimum 9.9.9)`)
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
			1,
			[]string{
				"FAIL  fskit extension: no PortableFS FSKit extension is registered",
				"fix: install PortableFS.app into /Applications and launch it once",
				"FILE SYSTEM EXTENSIONS",
			},
		},
		{
			"disabled",
			map[string]string{releaseID: "-    " + releaseID + "(1.0.0)"},
			1,
			[]string{
				"FAIL  fskit extension: extension " + releaseID + " is registered but disabled",
				"fix: enable it in System Settings",
				"the per-app list's toggle is unreliable on macOS 26",
			},
		},
		{
			"registered with the default election (leading spaces)",
			map[string]string{releaseID: "     " + releaseID + "(1.0)"},
			1,
			[]string{
				"FAIL  fskit extension: extension " + releaseID + " is registered but has never been enabled",
				"fix: enable it in System Settings",
			},
		},
		{
			"registered with an unknown election",
			map[string]string{releaseID: "?    " + releaseID + "(1.0.0)"},
			1,
			[]string{
				"FAIL  fskit extension: extension " + releaseID + " is registered but has never been enabled",
				"fix: enable it in System Settings",
			},
		},
		{
			"enabled",
			map[string]string{releaseID: "+    " + releaseID + "(1.0.0)"},
			0,
			[]string{"PASS  fskit extension: extension " + releaseID + " is registered and enabled"},
		},
		{
			"dev harness fallback",
			map[string]string{"dev.portablefs.oss.KitDev.PortableFSDev": "+    dev.portablefs.oss.KitDev.PortableFSDev(1.0.0)"},
			0,
			[]string{"PASS  fskit extension: extension dev.portablefs.oss.KitDev.PortableFSDev is registered and enabled"},
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

// TestDoctorFskitPostUpdateStaleness: pluginkit says enabled, but the last
// mount attempt's log carries the kernel's not-enabled refusal — the known
// post-update registration staleness whose fix is toggling the extension.
func TestDoctorFskitPostUpdateStaleness(t *testing.T) {
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
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  fskit extension: extension "+releaseID+" is enabled, but the last mount attempt failed as if it were not (post-update registration staleness",
		"fix: toggle the extension off and on in System Settings",
		"then retry the mount",
	)
}

func TestDoctorDaemonDownWithLiveFskitMountFails(t *testing.T) {
	const releaseID = "dev.portablefs.PortableFSApp.PortableFSExt"
	_, stdout, r, stateDir := doctorBaseline(t)
	r.goos = "darwin"
	r.runCmd = pluginkitFake(t, map[string]string{releaseID: "+    " + releaseID + "(1.0.0)"})
	r.daemonHealthy = func(string) bool { return false }
	if err := writeMountState(stateDir, mountState{
		MountPath: "/Users/me/work", VolumeID: "vol1", Branch: "main",
		PID: os.Getpid(), Strategy: "fskit",
	}); err != nil {
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
	if err := writeMountState(stateDir, mountState{
		MountPath: "/tmp/stale", VolumeID: "vol1", Branch: "main",
		PID: 3999999, Strategy: "fuse",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeMountState(stateDir, mountState{
		MountPath: "/tmp/expired", VolumeID: "vol2", Branch: "main",
		PID: os.Getpid(), Strategy: "fuse", Status: mountStatusCredentialExpired,
	}); err != nil {
		t.Fatal(err)
	}
	if rc := r.execute(); rc != 1 {
		t.Fatalf("rc = %d, want 1\n%s", rc, stdout.String())
	}
	requireContains(t, stdout.String(),
		"FAIL  mounts: 2 mount(s): 1 stale, 1 credential-expired",
		"/tmp/stale  vol1@main  fuse  stale",
		"/tmp/expired  vol2@main  fuse  credential-expired",
		"fix: clean up stale mounts with `portablefs umount /tmp/stale`; run `portablefs login` and remount credential-expired paths",
	)
}

func TestDoctorJSONOutput(t *testing.T) {
	_, stdout, r, _ := doctorBaseline(t)
	r.opts.jsonOut = true
	if rc := r.execute(); rc != 0 {
		t.Fatalf("rc = %d, want 0\n%s", rc, stdout.String())
	}
	var out struct {
		Checks []doctorResult `json:"checks"`
		Failed int            `json:"failed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("doctor --json must emit one JSON document: %v\n%s", err, stdout.String())
	}
	if len(out.Checks) != len(doctorChecks()) || out.Failed != 0 {
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
	for _, want := range []string{"Read-only", "PASS, FAIL, or SKIP", "Exit code 1", "pluginkit"} {
		if !strings.Contains(text, want) {
			t.Fatalf("doctor help missing %q", want)
		}
	}
	if !strings.Contains(rootHelp(), "doctor") {
		t.Fatal("root help must list doctor")
	}
}
