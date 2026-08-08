package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

// TestResolveLocalDirsPrecedence pins the documented precedence: explicit
// --local-dir flags win and update the persisted per-mount record; no flags
// reuses the record; --no-local-dirs clears it and disables the volume's
// declaration file for this mount.
func TestResolveLocalDirsPrecedence(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	const vol, mnt = "vol_1", "/mnt/w"

	// Explicit flags: normalized, persisted, volume file enabled.
	o := &mountOpts{branch: "main", localDirs: stringListFlag{"node_modules/", "agent-app/.venv"}}
	dirs, volFile, err := resolveLocalDirs(o, stateDir, vol, mnt)
	if err != nil {
		t.Fatalf("explicit flags: %v", err)
	}
	if strings.Join(dirs, ",") != "agent-app/.venv,node_modules" || !volFile {
		t.Fatalf("explicit flags = %v volFile=%v", dirs, volFile)
	}

	// A later mount with no flags reuses the persisted record.
	o = &mountOpts{branch: "main"}
	dirs, volFile, err = resolveLocalDirs(o, stateDir, vol, mnt)
	if err != nil {
		t.Fatalf("persisted reuse: %v", err)
	}
	if strings.Join(dirs, ",") != "agent-app/.venv,node_modules" || !volFile {
		t.Fatalf("persisted reuse = %v volFile=%v", dirs, volFile)
	}

	// The record is keyed per volume+branch+mountPath: a different branch
	// starts clean.
	o = &mountOpts{branch: "dev"}
	dirs, _, err = resolveLocalDirs(o, stateDir, vol, mnt)
	if err != nil || len(dirs) != 0 {
		t.Fatalf("different branch must not inherit: %v %v", dirs, err)
	}

	// New explicit flags replace the persisted set.
	o = &mountOpts{branch: "main", localDirs: stringListFlag{"target"}}
	if _, _, err := resolveLocalDirs(o, stateDir, vol, mnt); err != nil {
		t.Fatal(err)
	}
	o = &mountOpts{branch: "main"}
	dirs, _, _ = resolveLocalDirs(o, stateDir, vol, mnt)
	if strings.Join(dirs, ",") != "target" {
		t.Fatalf("explicit flags must replace persisted state: %v", dirs)
	}

	// --no-local-dirs clears the record and disables the volume file.
	o = &mountOpts{branch: "main", noLocalDirs: true}
	dirs, volFile, err = resolveLocalDirs(o, stateDir, vol, mnt)
	if err != nil || len(dirs) != 0 || volFile {
		t.Fatalf("--no-local-dirs = %v volFile=%v err=%v", dirs, volFile, err)
	}
	o = &mountOpts{branch: "main"}
	dirs, _, _ = resolveLocalDirs(o, stateDir, vol, mnt)
	if len(dirs) != 0 {
		t.Fatalf("cleared record must stay cleared: %v", dirs)
	}

	// The two flags are mutually exclusive.
	o = &mountOpts{branch: "main", localDirs: stringListFlag{"x"}, noLocalDirs: true}
	if _, _, err := resolveLocalDirs(o, stateDir, vol, mnt); err == nil {
		t.Fatal("--local-dir with --no-local-dirs must be refused")
	}
}

// TestMountRejectsInvalidLocalDirsEarly pins that flag validation fails in
// the PARENT process with an actionable message, before any daemonizing or
// network work.
func TestMountRejectsInvalidLocalDirsEarly(t *testing.T) {
	cases := map[string][]string{
		"absolute":  {"--local-dir", "/abs"},
		"escape":    {"--local-dir", "../up"},
		"empty":     {"--local-dir", ""},
		"duplicate": {"--local-dir", "node_modules", "--local-dir", "node_modules/"},
		"nested":    {"--local-dir", "node_modules", "--local-dir", "node_modules/.cache"},
		"exclusive": {"--local-dir", "node_modules", "--no-local-dirs"},
	}
	for name, flags := range cases {
		e, _, stderr := testEnv(t)
		args := append([]string{"mount", "vol_1", filepath.Join(t.TempDir(), "m")}, flags...)
		if rc := e.run(args); rc == 0 {
			t.Fatalf("%s: mount accepted invalid local-dir flags %v", name, flags)
		}
		if stderr.Len() == 0 {
			t.Fatalf("%s: expected an error message", name)
		}
	}
}

// TestLocalDirsRecordSurvivesBesideBacking pins the storage convention: the
// persisted record sits BESIDE the volume's backing tree (never inside it,
// where its name could collide with a route root) under the portablefsd-style
// <stateBase>/local/<storageID> layout, so grafted content and its
// configuration survive clean unmounts together.
func TestLocalDirsRecordSurvivesBesideBacking(t *testing.T) {
	mountsDir := filepath.Join(t.TempDir(), "state", "portablefs", "mounts")
	backing := localDirsBackingRoot(mountsDir, "vol_1")
	if !strings.HasPrefix(backing, filepath.Join(filepath.Dir(mountsDir), "local")+string(filepath.Separator)) {
		t.Fatalf("backing root %q must live under <stateBase>/local/", backing)
	}
	for _, sidecar := range []string{
		localDirsRecordPath(mountsDir, "vol_1", "main", "/mnt/w"),
		localRoutesRecordPath(mountsDir, "vol_1"),
	} {
		if strings.HasPrefix(sidecar, backing+string(filepath.Separator)) {
			t.Fatalf("sidecar %q must not live inside the backing tree", sidecar)
		}
	}
	if err := writePersistedLocalDirs(mountsDir, "vol_1", "main", "/mnt/w", []string{"node_modules"}); err != nil {
		t.Fatal(err)
	}
	got, err := readPersistedLocalDirs(mountsDir, "vol_1", "main", "/mnt/w")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "node_modules" {
		t.Fatalf("persisted local dirs = %v", got)
	}
	if got, err := readPersistedLocalDirs(mountsDir, "vol_2", "main", "/mnt/w"); err != nil || got != nil {
		t.Fatal("records must be keyed per mount identity")
	}
}

func TestPersistedLocalDirsCorruptionFailsMountResolution(t *testing.T) {
	mountsDir := filepath.Join(t.TempDir(), "state", "portablefs", "mounts")
	path := localDirsRecordPath(mountsDir, "vol_1", "main", "/mnt/w")
	if err := privatepath.WriteFileAtomic(path, []byte("{broken\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := readPersistedLocalDirs(mountsDir, "vol_1", "main", "/mnt/w"); err == nil {
		t.Fatal("corrupt persisted local-dirs record was treated as empty")
	}
}
