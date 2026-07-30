package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
)

func TestLegacyProfileCADoesNotSurviveConfigDecodeEncode(t *testing.T) {
	data := []byte(`{"currentProfile":"default","profiles":{"default":{"apiUrl":"https://api.example","apiToken":"tok","managerUrl":"https://manager.example","managerToken":"mgr","dataPlaneCaPem":"stale-trust"}}}`)
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "dataPlaneCaPem") || strings.Contains(string(encoded), "stale-trust") {
		t.Fatalf("legacy cached trust survived config round trip: %s", encoded)
	}
}

// testEnv returns a cmdEnv wired to buffers, isolated config/state/socket
// paths, and an instant device-flow sleeper. The isolated socket is essential:
// tests must never discover or interrogate a real PortableFS daemon belonging
// to the account running the suite.
func testEnv(t *testing.T) (*cmdEnv, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	frontendSocket := filepath.Join(t.TempDir(), "portablefsd", "pfs.sock")
	e := &cmdEnv{
		stdout: stdout,
		stderr: stderr,
		getenv: func(key string) string {
			if key == fskitSocketEnv {
				return frontendSocket
			}
			return ""
		},
		version:           "test",
		configPath:        filepath.Join(t.TempDir(), "private-config", "config.json"),
		lifecycleStateDir: filepath.Join(t.TempDir(), "state", "portablefs"),
		stateDir:          filepath.Join(t.TempDir(), "operational-state", "portablefs"),
		sleepFn:           func(time.Duration) {},
		// Tests must never launch a real browser; individual tests override
		// this to record the URL they would have opened.
		openURLFn:         func(string) error { return errNoTestBrowser },
		kernelInventoryFn: func() ([]string, error) { return nil, nil },
	}
	return e, stdout, stderr
}

var errNoTestBrowser = fmt.Errorf("no browser in tests")

func TestDefaultConfigPathIgnoresMutableHomeEnvironment(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "fake-home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "fake-xdg"))
	home, err := accountpath.Home()
	if err != nil {
		t.Fatal(err)
	}
	got, err := defaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "portablefs", "config.json")
	if got != want {
		t.Fatalf("default config = %q, want %q", got, want)
	}
}

func TestConfigSaveLoadRoundtripAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	want := &Config{
		CurrentProfile: "work",
		Profiles: map[string]Profile{
			"work": {APIUrl: "https://api.example.com", APIToken: "tok", ManagerUrl: "https://mgr.example.com", ManagerToken: "mtok"},
		},
	}
	if err := saveConfig(path, want); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config perms = %o, want 0600 (the file holds bearer tokens)", perm)
	}
	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.CurrentProfile != "work" || got.Profiles["work"] != want.Profiles["work"] {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestLoadConfigMissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("missing config must not error: %v", err)
	}
	if cfg.CurrentProfile != "default" || len(cfg.Profiles) != 0 {
		t.Fatalf("unexpected empty config: %+v", cfg)
	}
}

func TestLoadConfigRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"currentProfile":"default","profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := loadConfig(link); err == nil {
		t.Fatalf("loadConfig symlink error = %v", err)
	}
}

func TestSaveConfigRefusesSymlinkWithoutFollowingIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg := &Config{CurrentProfile: "default", Profiles: map[string]Profile{}}
	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("saveConfig accepted a symlink config path")
	}
	if body, err := os.ReadFile(victim); err != nil || string(body) != "do not overwrite" {
		t.Fatalf("symlink target changed: body=%q err=%v", body, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("refused config symlink was replaced: mode=%v", info.Mode())
	}
}

func TestResolveSettingsPrecedenceFlagEnvFile(t *testing.T) {
	cfg := &Config{
		CurrentProfile: "default",
		Profiles: map[string]Profile{
			"default": {APIUrl: "https://file.example.com", APIToken: "file-tok", ManagerUrl: "https://file-mgr.example.com", ManagerToken: "file-mtok"},
		},
	}
	env := map[string]string{
		"PORTABLEFS_API_URL":   "https://env.example.com",
		"PORTABLEFS_API_TOKEN": "env-tok",
	}
	getenv := func(k string) string { return env[k] }

	// Flag beats env beats file.
	s := resolveSettings(cfg, "", getenv, settings{apiURL: "https://flag.example.com"})
	if s.apiURL != "https://flag.example.com" {
		t.Fatalf("flag must win: %q", s.apiURL)
	}
	if s.apiToken != "env-tok" {
		t.Fatalf("env must beat file: %q", s.apiToken)
	}
	if s.managerURL != "https://file-mgr.example.com" || s.managerToken != "file-mtok" {
		t.Fatalf("file values must fill the rest: %+v", s)
	}
}

func TestManagerEndpointFallsBackToAPI(t *testing.T) {
	s := settings{apiURL: "https://api.example.com", apiToken: "tok"}
	url, token := s.managerEndpoint()
	if url != "https://api.example.com" || token != "tok" {
		t.Fatalf("manager must fall back to the API origin/token: %q %q", url, token)
	}
	s.managerURL, s.managerToken = "https://mgr.example.com", "mtok"
	url, token = s.managerEndpoint()
	if url != "https://mgr.example.com" || token != "mtok" {
		t.Fatalf("explicit manager config must win: %q %q", url, token)
	}
}

func TestLoginTokenStoresProfileAndSwitchesCurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ttk_x" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"volumes":[]}`))
	}))
	defer srv.Close()

	e, stdout, _ := testEnv(t)
	if rc := e.run([]string{"login", srv.URL, "--token", "ttk_x", "--profile", "staging"}); rc != 0 {
		t.Fatalf("login rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "logged in to "+srv.URL) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	cfg, err := loadConfig(e.configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CurrentProfile != "staging" {
		t.Fatalf("login must switch currentProfile, got %q", cfg.CurrentProfile)
	}
	if p := cfg.Profiles["staging"]; p.APIUrl != srv.URL || p.APIToken != "ttk_x" {
		t.Fatalf("stored profile wrong: %+v", p)
	}

	// A second profile lives alongside; logout removes only the named one.
	if rc := e.run([]string{"login", srv.URL, "--token", "ttk_x", "--profile", "default"}); rc != 0 {
		t.Fatal("second login failed")
	}
	if rc := e.run([]string{"logout", "--profile", "staging"}); rc != 0 {
		t.Fatal("logout failed")
	}
	cfg, _ = loadConfig(e.configPath)
	if _, ok := cfg.Profiles["staging"]; ok {
		t.Fatal("logout must remove the profile")
	}
	if _, ok := cfg.Profiles["default"]; !ok {
		t.Fatal("logout must not touch other profiles")
	}
}

func TestLoginRejectedTokenReportsClearly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"code":"VOLUME_UNAUTHORIZED","message":"Unauthorized."}}`))
	}))
	defer srv.Close()

	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"login", srv.URL, "--token", "bad"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "rejected the token") {
		t.Fatalf("stderr must name the bad token: %q", stderr.String())
	}
}

func TestLoginVerifyTreats404AsOlderServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":"VOLUME_NOT_FOUND","message":"Not found."}}`))
	}))
	defer srv.Close()

	e, _, _ := testEnv(t)
	if rc := e.run([]string{"login", srv.URL, "--token", "ttk_x"}); rc != 0 {
		t.Fatalf("a 404 on /v1/volumes is an older server, not a bad token; rc = %d", rc)
	}
}

func TestCommandUsesEnvWhenNoConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer env-tok" {
			w.WriteHeader(401)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/branches") {
			_, _ = w.Write([]byte(`{"branches":[{"name":"main","headCommitId":"cmt_1","branchMode":"legacy_manifest"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"volume":{"id":"vol_1","tenantId":"t1"},"branch":{"name":"main","headCommitId":"cmt_1"},"head":{"id":"cmt_1","treeHash":"sha256:aa"},"activeLeases":0,"activeDelegations":0}`))
	}))
	defer srv.Close()

	e, stdout, _ := testEnv(t)
	env := map[string]string{"PORTABLEFS_API_URL": srv.URL, "PORTABLEFS_API_TOKEN": "env-tok"}
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if value := env[k]; value != "" {
			return value
		}
		return baseGetenv(k)
	}
	if rc := e.run([]string{"status", "vol_1"}); rc != 0 {
		t.Fatalf("rc = %d, stderr", rc)
	}
	if !strings.Contains(stdout.String(), "cmt_1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
