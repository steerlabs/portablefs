package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPerfOptionsFromEnv(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}

	// Default: the v8 baseline — write-back is adaptive (no mount mode), the
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

func validFuseMountState(t *testing.T, mountPath string) mountState {
	t.Helper()
	processIdentity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return mountState{
		MountPath:            mountPath,
		VolumeID:             "vol_1",
		Branch:               "main",
		PID:                  os.Getpid(),
		ProcessStartIdentity: processIdentity,
		Strategy:             "fuse",
		MountInstanceID:      "mnt_AAAAAAAAAAAAAAAAAAAAAA",
		KernelMountID:        "42",
		MountTargetDevice:    1,
		MountTargetInode:     2,
		MountMechanism:       "direct",
		DataPlaneTransport:   dataPlaneTransportPlaintext,
		AuthorityURL:         "127.0.0.1:2050",
		StartedAtMs:          42,
	}
}

func validFSKitMountState(t *testing.T, mountPath string) mountState {
	t.Helper()
	st := validFuseMountState(t, mountPath)
	st.Strategy = "fskit"
	st.FSType = defaultFskitType
	st.AttachRef = "att_AAAAAAAAAAAAAAAAAAAAAA"
	st.KernelMountID = ""
	st.MountMechanism = "fskit-system"
	return st
}

func writeRawMountState(t *testing.T, dir string, st mountState) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mountStatePath(dir, st.MountPath), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMountStateRoundtripAndListing(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := validFuseMountState(t, "/tmp/work")
	st.DataPlaneTransport = dataPlaneTransportTLSPrivateCA
	st.DataPlaneServerName = "router.example"
	st.DataPlaneCAPath = "/state/ca/abc.pem"
	st.DataPlaneCASHA256 = strings.Repeat("a", 64)
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

func TestListMountStatesFailsClosedOnCorruptRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "0000000000000000.json")
	if err := os.WriteFile(path, []byte("{broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listMountStates(dir); err == nil || !strings.Contains(err.Error(), "parse mount state record") {
		t.Fatalf("corrupt inventory error = %v", err)
	}
}

func TestListMountStatesRejectsWrongCanonicalKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "0000000000000000.json")
	data, err := json.Marshal(validFuseMountState(t, "/tmp/work"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listMountStates(dir); err == nil || !strings.Contains(err.Error(), "does not match canonical path key") {
		t.Fatalf("wrong-key inventory error = %v", err)
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
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return baseGetenv(k)
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	live := validFuseMountState(t, "/tmp/w1")
	live.VolumeID = "vol_live"
	if err := writeMountState(dir, live); err != nil {
		t.Fatal(err)
	}
	dead := validFSKitMountState(t, "/tmp/w2")
	dead.VolumeID = "vol_dead"
	dead.PID = 4194000
	dead.ProcessStartIdentity = "1"
	if err := writeMountState(dir, dead); err != nil {
		t.Fatal(err)
	}
	e.mountHealthFn = func(st *mountState) string {
		if st.PID == os.Getpid() {
			return "live"
		}
		return "stale"
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
	e.mountHealthFn = func(*mountState) string { return "live" }
	stateHome := t.TempDir()
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return baseGetenv(k)
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "pfal_secret_that_must_not_reach_stdout"
	st := validFuseMountState(t, "/tmp/w")
	st.ManagerURL = "https://manager.example"
	st.AccessLeaseReleaseOperationID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	st.AccessLease = &leaseState{
		AccessLeaseID: "pfal_1",
		AccessToken:   secret,
		ExpiresAtMs:   1700000600000,
		ControlSeq:    "7",
	}
	if err := writeMountState(dir, st); err != nil {
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
		{"case and default port normalized", "HTTPS://CLOUD.EXAMPLE.COM:443/x", "https://cloud.example.com/y", true},
		{"split self-host ports", "http://127.0.0.1:18788", "http://127.0.0.1:18787", false},
		{"split hosts", "https://mgr.example.com", "https://api.example.com", false},
		{"scheme mismatch is split", "http://cloud.example.com", "https://cloud.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sameOrigin(tc.managerURL, tc.apiURL)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
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
	got, err := e.resolveVolumeTeamID(unified, "vol", "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("unified origin must not assert a teamId, got %q", got)
	}
}

func TestSameOriginRejectsAmbiguousEndpoints(t *testing.T) {
	for _, endpoint := range []string{"cloud.example.com", "https://user@cloud.example.com", "file:///tmp/socket", "https://cloud.example.com:bad", "https://cloud.example.com:0"} {
		if _, err := sameOrigin(endpoint, "https://cloud.example.com"); err == nil {
			t.Fatalf("ambiguous manager endpoint %q accepted", endpoint)
		}
	}
}

func TestReadMountStateRejectsPartialLeaseTransaction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mounts")
	mountPath := filepath.Join(t.TempDir(), "mount")
	st := validFuseMountState(t, mountPath)
	st.ManagerURL = "https://manager.example"
	writeRawMountState(t, dir, st)
	if _, err := readMountState(dir, mountPath); err == nil ||
		!strings.Contains(err.Error(), "incomplete access-lease transaction identity") {
		t.Fatalf("partial lease state error = %v", err)
	}
	if _, err := listMountStates(dir); err == nil ||
		!strings.Contains(err.Error(), "incomplete access-lease transaction identity") {
		t.Fatalf("partial lease inventory error = %v", err)
	}
	if _, err := os.Stat(mountStatePath(dir, mountPath)); err != nil {
		t.Fatalf("partial lease state was not preserved: %v", err)
	}
}

func TestMountStateValidationRejectsInvalidV2Shapes(t *testing.T) {
	base := validFuseMountState(t, "/tmp/strict-mount")
	managed := base
	managed.ManagerURL = "https://manager.example"
	managed.AccessLeaseReleaseOperationID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	managed.AccessLease = &leaseState{
		AccessLeaseID: "pfal_1",
		AccessToken:   "token",
		ExpiresAtMs:   1700000600000,
		ControlSeq:    "7",
	}
	if err := validateMountStateRecord("valid-direct", &base); err != nil {
		t.Fatalf("valid direct state rejected: %v", err)
	}
	if err := validateMountStateRecord("valid-managed", &managed); err != nil {
		t.Fatalf("valid managed state rejected: %v", err)
	}
	fskit := validFSKitMountState(t, "/tmp/strict-fskit")
	if err := validateMountStateRecord("valid-fskit", &fskit); err != nil {
		t.Fatalf("valid FSKit state rejected: %v", err)
	}
	expired := base
	expired.Status = mountStatusCredentialExpired
	expired.StatusChangedAtMs = 1700000000000
	if err := validateMountStateRecord("valid-status", &expired); err != nil {
		t.Fatalf("valid credential status rejected: %v", err)
	}
	forced := base
	forced.ForceParkAcknowledged = true
	forced.ForceRecoveryJobID = "job" + strings.Repeat("a", 32)
	if err := validateMountStateRecord("valid-force", &forced); err != nil {
		t.Fatalf("valid force acknowledgement rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*mountState)
	}{
		{"non-canonical path", func(st *mountState) { st.MountPath += "/.." }},
		{"invalid volume", func(st *mountState) { st.VolumeID = "bad/volume" }},
		{"missing branch", func(st *mountState) { st.Branch = "" }},
		{"missing pid", func(st *mountState) { st.PID = 0 }},
		{"missing process incarnation", func(st *mountState) { st.ProcessStartIdentity = "" }},
		{"missing mount instance", func(st *mountState) { st.MountInstanceID = "" }},
		{"missing target device", func(st *mountState) { st.MountTargetDevice = 0 }},
		{"missing started time", func(st *mountState) { st.StartedAtMs = 0 }},
		{"missing authority", func(st *mountState) { st.AuthorityURL = "" }},
		{"unknown strategy", func(st *mountState) { st.Strategy = "auto" }},
		{"fuse attach", func(st *mountState) { st.AttachRef = "att_AAAAAAAAAAAAAAAAAAAAAA" }},
		{"fuse missing kernel id", func(st *mountState) { st.KernelMountID = "" }},
		{"fuse helper mismatch", func(st *mountState) { st.FUSEHelperPath = "/usr/bin/mount.fuse" }},
		{"unknown transport", func(st *mountState) { st.DataPlaneTransport = "" }},
		{"plaintext TLS name", func(st *mountState) { st.DataPlaneServerName = "router.example" }},
		{"partial manager", func(st *mountState) { st.ManagerURL = "https://manager.example" }},
		{"lease missing sequence", func(st *mountState) {
			*st = managed
			lease := *managed.AccessLease
			st.AccessLease = &lease
			st.AccessLease.ControlSeq = ""
		}},
		{"lease noncanonical sequence", func(st *mountState) {
			*st = managed
			lease := *managed.AccessLease
			st.AccessLease = &lease
			st.AccessLease.ControlSeq = "07"
		}},
		{"unknown status", func(st *mountState) { st.Status = "degraded" }},
		{"status missing timestamp", func(st *mountState) { st.Status = mountStatusCredentialExpired }},
		{"orphan status timestamp", func(st *mountState) { st.StatusChangedAtMs = 1 }},
		{"job without acknowledgement", func(st *mountState) { st.ForceRecoveryJobID = "job" + strings.Repeat("a", 32) }},
		{"invalid recovery job", func(st *mountState) {
			st.ForceParkAcknowledged = true
			st.ForceRecoveryJobID = "job-invalid"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := base
			tc.mutate(&st)
			if err := validateMountStateRecord(tc.name, &st); err == nil {
				t.Fatalf("invalid state accepted: %+v", st)
			}
		})
	}

	fskitForce := validFSKitMountState(t, "/tmp/strict-fskit-force")
	fskitForce.ForceParkAcknowledged = true
	if err := validateMountStateRecord("fskit force", &fskitForce); err == nil {
		t.Fatal("FSKit force acknowledgement accepted")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*mountState)
	}{
		{"missing FSKit type", func(st *mountState) { st.FSType = "" }},
		{"foreign FSKit type", func(st *mountState) { st.FSType = "portablefs" }},
		{"missing FSKit attach", func(st *mountState) { st.AttachRef = "" }},
		{"FSKit kernel id", func(st *mountState) { st.KernelMountID = "42" }},
		{"FSKit FUSE mechanism", func(st *mountState) { st.MountMechanism = "direct" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := validFSKitMountState(t, "/tmp/strict-fskit-"+strings.ReplaceAll(tc.name, " ", "-"))
			tc.mutate(&st)
			if err := validateMountStateRecord(tc.name, &st); err == nil {
				t.Fatalf("invalid FSKit state accepted: %+v", st)
			}
		})
	}
}

func TestWriteMountStateRejectsInvalidRecordBeforePublication(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mounts")
	st := validFuseMountState(t, "/tmp/write-invalid")
	st.ManagerURL = "https://manager.example"
	if err := writeMountState(dir, st); err == nil {
		t.Fatal("partial lease transaction was written")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("invalid write created state directory: %v", err)
	}
}

func TestUpdateMountStateRejectsInvalidMutationAndPreservesRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mounts")
	st := validFuseMountState(t, "/tmp/update-invalid")
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	updated, err := updateMountState(dir, st.MountPath, func(current *mountState) {
		current.Status = mountStatusCredentialExpired
	})
	if err == nil || updated {
		t.Fatalf("invalid update result = updated %v, err %v", updated, err)
	}
	got, err := readMountState(dir, st.MountPath)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Status != "" || got.StatusChangedAtMs != 0 {
		t.Fatalf("invalid update changed persisted record: %+v", got)
	}
	updated, err = updateMountState(dir, st.MountPath, func(current *mountState) {
		current.Status = mountStatusCredentialExpired
		current.StatusChangedAtMs = 1700000000000
	})
	if err != nil || !updated {
		t.Fatalf("valid update result = updated %v, err %v", updated, err)
	}
	got, err = readMountState(dir, st.MountPath)
	if err != nil || got == nil || got.Status != mountStatusCredentialExpired ||
		got.StatusChangedAtMs != 1700000000000 {
		t.Fatalf("valid update was not persisted: state %+v, err %v", got, err)
	}
}

func TestReadAndListMountStateUseStrictJSON(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{"unknown field", `,"futureGuess":true}`},
		{"second value", `} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "mounts")
			st := validFuseMountState(t, "/tmp/strict-json-"+strings.ReplaceAll(tc.name, " ", "-"))
			data, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data[:len(data)-1], tc.suffix...)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(mountStatePath(dir, st.MountPath), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readMountState(dir, st.MountPath); err == nil {
				t.Fatal("strict read accepted incompatible JSON")
			}
			if _, err := listMountStates(dir); err == nil {
				t.Fatal("strict list accepted incompatible JSON")
			}
		})
	}
}
