package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

func validFuseMountState(t *testing.T, mountPath string) mountState {
	t.Helper()
	processIdentity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return mountState{SchemaVersion: mountStateSchemaVersion,
		MountPath:            mountPath,
		VolumeID:             "vol_1",
		PID:                  os.Getpid(),
		ProcessStartIdentity: processIdentity,
		Strategy:             "fuse",
		Engine:               mountEngineFuseV3,
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
	st.Engine = mountEngineDaemonV3
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

func mountStateReaders() map[string]func(string, string) ([]mountState, error) {
	return map[string]func(string, string) ([]mountState, error){
		"lookup": func(dir, mountPath string) ([]mountState, error) {
			st, err := readMountState(dir, mountPath)
			if err != nil || st == nil {
				return nil, err
			}
			return []mountState{*st}, nil
		},
		"inventory": func(dir, _ string) ([]mountState, error) { return listMountStates(dir) },
	}
}

func TestMountStateReadersExcludeReplacementDuringRead(t *testing.T) {
	for _, fixture := range []struct {
		name string
		make func(*testing.T, string) mountState
	}{
		{"fuse", validFuseMountState},
		{"fskit", validFSKitMountState},
	} {
		for name, read := range mountStateReaders() {
			t.Run(fixture.name+"/"+name, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "mounts")
				st := fixture.make(t, "/tmp/replace-during-read")
				if err := writeMountState(dir, st); err != nil {
					t.Fatal(err)
				}
				next := st
				next.Status = mountStatusCredentialExpired
				next.StatusChangedAtMs = 123
				originalRead := mountStateReadFile
				t.Cleanup(func() { mountStateReadFile = originalRead })
				writerBlocked := false
				mountStateReadFile = func(path string) ([]byte, error) {
					parent, err := privatepath.OpenExistingDir(dir)
					if err != nil {
						return nil, err
					}
					defer parent.Close()
					fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
					if err != nil {
						return nil, err
					}
					file := os.NewFile(uintptr(fd), path)
					defer file.Close()
					writer, err := privatepath.OpenLockFile(parent, dir, filepath.Base(path)+".lock")
					if err != nil {
						return nil, err
					}
					defer writer.Close()
					// Other readers must remain admissible during this read.
					if err := unix.Flock(int(writer.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
						return nil, err
					}
					if err := unix.Flock(int(writer.Fd()), unix.LOCK_UN); err != nil {
						return nil, err
					}
					// Force the writer's turn between open and validation. With
					// the old unlocked reader it replaces this exact open inode,
					// and ValidateOpenFile below deterministically sees nlink 0.
					err = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB)
					switch {
					case err == nil:
						defer unix.Flock(int(writer.Fd()), unix.LOCK_UN)
						if err := writeMountStateUnlocked(dir, next); err != nil {
							return nil, err
						}
					case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
						writerBlocked = true
					default:
						return nil, err
					}
					if err := privatepath.ValidateOpenFile(parent, dir, filepath.Base(path), file); err != nil {
						return nil, err
					}
					return io.ReadAll(file)
				}
				got, err := read(dir, st.MountPath)
				if err != nil {
					t.Fatal(err)
				}
				if !writerBlocked || len(got) != 1 || !reflect.DeepEqual(got[0], st) {
					t.Fatalf("read = %+v, writer blocked = %v", got, writerBlocked)
				}
				mountStateReadFile = originalRead
				// The read must release its lock, allowing the next version to
				// publish and become visible without retries or sleeps.
				if err := writeMountState(dir, next); err != nil {
					t.Fatal(err)
				}
				got, err = read(dir, st.MountPath)
				if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], next) {
					t.Fatalf("read replacement = %+v, err %v", got, err)
				}
			})
		}
	}
}

func TestMountStateReadersPreservePrivateFileChecks(t *testing.T) {
	for name, read := range mountStateReaders() {
		for _, target := range []string{"record", "lock"} {
			for _, tamper := range []string{"hardlink", "symlink", "permissions"} {
				t.Run(name+"/"+target+"/"+tamper, func(t *testing.T) {
					dir := filepath.Join(t.TempDir(), "mounts")
					st := validFuseMountState(t, "/tmp/private-record")
					if err := writeMountState(dir, st); err != nil {
						t.Fatal(err)
					}
					path := mountStatePath(dir, st.MountPath)
					if target == "lock" {
						path += ".lock"
					}
					var err error
					switch tamper {
					case "hardlink":
						err = os.Link(path, path+".alias")
					case "symlink":
						if err = os.Rename(path, path+".target"); err == nil {
							err = os.Symlink(path+".target", path)
						}
					case "permissions":
						err = os.Chmod(path, 0o644)
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err := read(dir, st.MountPath); err == nil {
						t.Fatal("unsafe private file accepted")
					}
				})
			}
		}
	}
}

func TestMountStateReadersDoNotCreateMissingDirectory(t *testing.T) {
	for name, read := range mountStateReaders() {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "absent", "mounts")
			got, err := read(dir, "/tmp/absent-record")
			if err != nil || len(got) != 0 {
				t.Fatalf("missing read = %+v, err %v", got, err)
			}
			if _, err := os.Lstat(filepath.Dir(dir)); !os.IsNotExist(err) {
				t.Fatalf("read created missing directory: %v", err)
			}
		})
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

func TestFUSERenewalEventUpdatesSnapshotAndPerMountLog(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := validFuseMountState(t, "/tmp/renewal-observation")
	st.AuthorizationSessionID = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	st.MountEnrollmentID = "enrollment-1"
	st.AuthorizationDeadlineAtMs = time.Now().Add(time.Minute).UnixMilli()
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	events, err := mountlog.New(&output, "linux-fuse", st.MountInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	event := mountenrollment.RenewalEvent{
		Kind:       mountenrollment.RenewalRetrying,
		ObservedAt: now,
		Status: mountenrollment.RenewalStatus{
			AuthorizationDeadline: now.Add(10 * time.Minute),
			LastSuccess:           now.Add(-time.Minute),
			NextAttempt:           now.Add(time.Second),
			Sequence:              2,
			ConsecutiveFailures:   1,
			LastError:             "temporary Manager failure",
		},
	}
	recordFUSERenewalEvent(events, dir, st.MountPath, st.MountEnrollmentID, event, nil)
	got, err := readMountState(dir, st.MountPath)
	if err != nil || got == nil {
		t.Fatalf("read renewed mount state: %+v, %v", got, err)
	}
	if got.AuthorizationDeadlineAtMs != event.Status.AuthorizationDeadline.UnixMilli() ||
		got.LastReauthorizationAtMs != event.Status.LastSuccess.UnixMilli() ||
		got.NextReauthorizationAtMs != event.Status.NextAttempt.UnixMilli() ||
		got.ReauthorizationFailures != 1 || got.ReauthorizationError != event.Status.LastError {
		t.Fatalf("renewal snapshot = %+v", got)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"kind":"renewal.retrying"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"component":"linux-fuse"`)) {
		t.Fatalf("per-mount renewal log = %q", output.String())
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

func TestMountStateValidationRejectsIncompleteCurrentShapes(t *testing.T) {
	base := validFuseMountState(t, "/tmp/strict-mount")
	if err := validateMountStateRecord("valid", &base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*mountState)
	}{
		{"non-canonical path", func(st *mountState) { st.MountPath += "/.." }},
		{"invalid volume", func(st *mountState) { st.VolumeID = "bad/volume" }},

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

		{"unknown status", func(st *mountState) { st.Status = "degraded" }},
		{"status missing timestamp", func(st *mountState) { st.Status = mountStatusCredentialExpired }},
		{"orphan status timestamp", func(st *mountState) { st.StatusChangedAtMs = 1 }},
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
	st.Engine = ""
	if err := writeMountState(dir, st); err == nil {
		t.Fatal("incomplete current state was written")
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

func TestCurrentCLIPrivateFormatsRejectUnequalMarkers(t *testing.T) {
	state := validFuseMountState(t, "/tmp/current-format")
	for _, version := range []int{0, mountStateSchemaVersion + 1, -1} {
		state.SchemaVersion = version
		if err := validateMountStateRecord("test", &state); err == nil {
			t.Fatalf("mount state version %d accepted", version)
		}
	}
	intent := mountIntent{SchemaVersion: mountIntentSchemaVersion, Phase: "starting", MountPath: "/tmp/current-format", OperationOwnerPID: os.Getpid(), OperationOwnerStartIdentity: "test", UpdatedAtMs: 1}
	if err := validateMountIntent("test", &intent); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{0, mountIntentSchemaVersion - 1, mountIntentSchemaVersion + 1} {
		intent.SchemaVersion = version
		if err := validateMountIntent("test", &intent); err == nil {
			t.Fatalf("mount intent version %d accepted", version)
		}
	}
}
