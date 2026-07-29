package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPerfOptionsFromEnv(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}

	// Default: the v6 baseline — write-back is adaptive (no mount mode), the
	// negative cache is capability-auto (neither force flag set).
	p := perfOptionsFromEnv(env(nil))
	if p.negativeCache || p.negativeCacheOff {
		t.Fatalf("default must be capability-auto: %+v", p)
	}

	// The one remaining knob: force the negative cache on or off.
	p = perfOptionsFromEnv(env(map[string]string{"PORTABLEFS_NEGATIVE_CACHE": "1"}))
	if !p.negativeCache || p.negativeCacheOff {
		t.Fatalf("PORTABLEFS_NEGATIVE_CACHE=1 must force on: %+v", p)
	}
	p = perfOptionsFromEnv(env(map[string]string{"PORTABLEFS_NEGATIVE_CACHE": "0"}))
	if p.negativeCache || !p.negativeCacheOff {
		t.Fatalf("PORTABLEFS_NEGATIVE_CACHE=0 must force off: %+v", p)
	}

	// The retired write-back knobs are inert: the authority decides
	// delegation adaptively, batching is fixed, fsync is always the
	// authority barrier.
	p = perfOptionsFromEnv(env(map[string]string{
		"PORTABLEFS_WRITEBACK":         "1",
		"PORTABLEFS_FLUSH_MS":          "100",
		"PORTABLEFS_FLUSH_MAX_RECORDS": "64",
		"PORTABLEFS_FLUSH_MAX_BYTES":   "1048576",
	}))
	if p.negativeCache || p.negativeCacheOff {
		t.Fatalf("retired env knobs must be inert: %+v", p)
	}
}

func TestMountStateRoundtripAndListing(t *testing.T) {
	dir := t.TempDir()
	st := mountState{
		MountPath:    "/tmp/work",
		VolumeID:     "vol_1",
		Branch:       "main",
		PID:          os.Getpid(),
		Strategy:     "fuse",
		AuthorityURL: "127.0.0.1:2050",
		StartedAtMs:  42,
	}
	if err := writeMountState(dir, st); err != nil {
		t.Fatalf("writeMountState: %v", err)
	}
	got, err := readMountState(dir, "/tmp/work")
	if err != nil || got == nil {
		t.Fatalf("readMountState: %v %v", got, err)
	}
	if !reflect.DeepEqual(*got, st) {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	list, err := listMountStates(dir)
	if err != nil || len(list) != 1 || list[0].VolumeID != "vol_1" {
		t.Fatalf("listMountStates: %v %v", list, err)
	}
	if err := removeMountState(dir, "/tmp/work"); err != nil {
		t.Fatalf("removeMountState: %v", err)
	}
	if got, _ := readMountState(dir, "/tmp/work"); got != nil {
		t.Fatal("state must be gone after remove")
	}
	if err := removeMountState(dir, "/tmp/work"); err != nil {
		t.Fatalf("removing a missing state must be a no-op: %v", err)
	}
}

func TestMountStateKeyIsStableAndSafe(t *testing.T) {
	a, b := mountStateKey("/tmp/work"), mountStateKey("/tmp/work")
	if a != b {
		t.Fatal("key must be deterministic")
	}
	if a == mountStateKey("/tmp/other") {
		t.Fatal("different paths must not collide")
	}
	if strings.ContainsAny(a, "/\\ ") {
		t.Fatalf("key must be filesystem-safe: %q", a)
	}
}

func TestPidAlive(t *testing.T) {
	if !pidAlive(os.Getpid()) {
		t.Fatal("own pid must be alive")
	}
	if pidAlive(0) || pidAlive(-1) {
		t.Fatal("non-positive pids are never alive")
	}
}

func TestMountsCommandListsState(t *testing.T) {
	e, stdout, _ := testEnv(t)
	stateHome := t.TempDir()
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return ""
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMountState(dir, mountState{MountPath: "/tmp/w1", VolumeID: "vol_live", Branch: "main", PID: os.Getpid(), Strategy: "fuse"}); err != nil {
		t.Fatal(err)
	}
	if err := writeMountState(dir, mountState{MountPath: "/tmp/w2", VolumeID: "vol_dead", Branch: "main", PID: 4194000, Strategy: "fskit"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"mounts"}); rc != 0 {
		t.Fatalf("mounts rc = %d", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "vol_live") || !strings.Contains(out, "live") {
		t.Fatalf("mounts output must show the live mount: %q", out)
	}
	if !strings.Contains(out, "vol_dead") || !strings.Contains(out, "stale") {
		t.Fatalf("mounts output must flag the dead daemon: %q", out)
	}
}

func TestMountsJSONNeverExposesPersistedAccessToken(t *testing.T) {
	e, stdout, _ := testEnv(t)
	stateHome := t.TempDir()
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return ""
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "pfal_secret_that_must_not_reach_stdout"
	if err := writeMountState(dir, mountState{
		MountPath: "/tmp/w", VolumeID: "vol_1", Branch: "main",
		PID: os.Getpid(), Strategy: "fuse",
		AccessLease: &leaseState{
			AccessLeaseID: "pfal_1",
			AccessToken:   secret,
			ExpiresAtMs:   1700000600000,
			ControlSeq:    "7",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"mounts", "--json"}); rc != 0 {
		t.Fatalf("mounts --json rc = %d", rc)
	}
	out := stdout.String()
	if strings.Contains(out, secret) || strings.Contains(out, "accessToken") {
		t.Fatalf("mounts --json exposed persisted credential: %q", out)
	}
	for _, want := range []string{`"mountPath": "/tmp/w"`, `"volumeId": "vol_1"`, `"health": "live"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("mounts --json missing %s: %q", want, out)
		}
	}
}

func TestSameOriginGatesTenancyOwnership(t *testing.T) {
	cases := []struct {
		name       string
		managerURL string
		apiURL     string
		want       bool
	}{
		{"empty manager defaults to api origin", "", "https://cloud.example.com", true},
		{"identical unified origin", "https://cloud.example.com", "https://cloud.example.com", true},
		{"unified with differing paths", "https://cloud.example.com/x", "https://cloud.example.com/y", true},
		{"split self-host ports", "http://127.0.0.1:18788", "http://127.0.0.1:18787", false},
		{"split hosts", "https://mgr.example.com", "https://api.example.com", false},
		{"scheme mismatch is split", "http://cloud.example.com", "https://cloud.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameOrigin(tc.managerURL, tc.apiURL); got != tc.want {
				t.Fatalf("sameOrigin(%q, %q) = %v, want %v", tc.managerURL, tc.apiURL, got, tc.want)
			}
		})
	}
}

// TestResolveVolumeTeamIDUnifiedOriginSkipsLookup proves the CLI never asserts
// tenancy (nor even calls the API) against a unified control plane; the split
// path still resolves the volume's tenant from the API head call.
func TestResolveVolumeTeamIDUnifiedOriginSkipsLookup(t *testing.T) {
	e, _, _ := testEnv(t)
	unified := settings{apiURL: "https://cloud.example.com", apiToken: "k", managerURL: "https://cloud.example.com"}
	if got := e.resolveVolumeTeamID(unified, "vol", "main"); got != "" {
		t.Fatalf("unified origin must not assert a teamId, got %q", got)
	}
}
