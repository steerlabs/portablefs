package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// recordRoutedMount publishes a FUSE mount state carrying an activated route
// set, the shape `route`, `status` and `prune-local` all read.
func recordRoutedMount(t *testing.T, e *cmdEnv, mountPath, volumeID, patterns string) localroutes.RuleSet {
	t.Helper()
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := localroutes.Parse([]byte(patterns))
	if err != nil {
		t.Fatal(err)
	}
	st := validFuseMountState(t, mountPath)
	st.VolumeID = volumeID
	st.LocalRoutes = rules.Patterns()
	st.LocalRouteRevision = rules.RevisionHex()
	st.LocalBackingRoot = localDirsBackingRoot(dir, volumeID)
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalRoutesRecord(dir, volumeID, mountRoutes{rules: rules, revision: rules.RevisionHex(), declared: true}, 1); err != nil {
		t.Fatal(err)
	}
	return rules
}

// TestRouteExplainsOnePath pins the diagnostic's shape: local vs shared, the
// deciding rule, the route root, the backing path, and the revision.
func TestRouteExplainsOnePath(t *testing.T) {
	e, stdout, _ := testEnv(t)
	mnt := t.TempDir()
	rules := recordRoutedMount(t, e, mnt, "vol_1", "node_modules/\n/target/\n")
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	backing := localDirsBackingRoot(dir, "vol_1")
	if err := os.MkdirAll(filepath.Join(backing, "agent-app", "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backing, "agent-app", "node_modules", "dep.js"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	if rc := e.run([]string{"route", filepath.Join(mnt, "agent-app", "node_modules", "react", "index.js")}); rc != 0 {
		t.Fatalf("route rc=%d stdout=%s", rc, stdout)
	}
	out := stdout.String()
	for _, want := range []string{
		"storage      machine-local",
		"rule         **/node_modules/",
		"route root   agent-app/node_modules",
		filepath.Join(backing, "agent-app", "node_modules"),
		rules.RevisionHex()[:12],
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route output missing %q:\n%s", want, out)
		}
	}

	// A shared path says so, and names no rule.
	stdout.Reset()
	if rc := e.run([]string{"route", filepath.Join(mnt, "src", "main.go"), "--json"}); rc != 0 {
		t.Fatalf("route --json rc=%d", rc)
	}
	var ans routeAnswer
	if err := json.Unmarshal(stdout.Bytes(), &ans); err != nil {
		t.Fatal(err)
	}
	if ans.Storage != "shared" || ans.Rule != "" || ans.VolumePath != "src/main.go" {
		t.Fatalf("shared answer = %+v", ans)
	}
	if ans.Revision != rules.RevisionHex() {
		t.Fatalf("revision = %q", ans.Revision)
	}

	// A path outside every mount is an error, not a guess.
	stdout.Reset()
	if rc := e.run([]string{"route", t.TempDir()}); rc == 0 {
		t.Fatal("a path outside every mount must fail")
	}
}

// TestBackingIdentityAcrossMounts pins the identity the whole feature rests
// on: the same volume remounted anywhere reuses its machine-local backing,
// and a different volume at the same mountpoint never inherits it.
func TestBackingIdentityAcrossMounts(t *testing.T) {
	e, _, _ := testEnv(t)
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	first := localDirsBackingRoot(dir, "vol_1")
	if second := localDirsBackingRoot(dir, "vol_1"); second != first {
		t.Fatalf("remounting the same volume must reuse %q, got %q", first, second)
	}
	if other := localDirsBackingRoot(dir, "vol_2"); other == first {
		t.Fatal("a different volume at the same mountpoint must not inherit the backing")
	}
	// The per-mount --local-dir record is keyed per mount, and lives beside
	// the shared backing tree rather than inside it.

}

// TestPruneLocalReclaimsOnlyOrphans pins the reclamation command end to end:
// dry-run by default, live backing untouched, orphans reported and then
// removed only with --delete.
func TestPruneLocalReclaimsOnlyOrphans(t *testing.T) {
	e, stdout, _ := testEnv(t)
	mnt := t.TempDir()
	recordRoutedMount(t, e, mnt, "vol_1", "node_modules/\n")
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	backing := localDirsBackingRoot(dir, "vol_1")
	live := filepath.Join(backing, "agent-app", "node_modules")
	orphan := filepath.Join(backing, ".venv", "lib")
	for _, p := range []string{live, orphan} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "f"), []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A volume this machine knows nothing about: entirely orphaned.
	stale := filepath.Join(localBackingDir(dir), localdirs.StorageID("vol_gone"))
	if err := os.MkdirAll(filepath.Join(stale, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}

	if rc := e.run([]string{"prune-local"}); rc != 0 {
		t.Fatalf("prune-local rc=%d out=%s", rc, stdout)
	}
	out := stdout.String()
	if !strings.Contains(out, "would remove") || !strings.Contains(out, ".venv") {
		t.Fatalf("dry run must list the orphan:\n%s", out)
	}
	if strings.Contains(out, "agent-app") {
		t.Fatalf("dry run must not list live backing:\n%s", out)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("dry run removed data: %v", err)
	}

	// --volume narrows to one volume.
	stdout.Reset()
	if rc := e.run([]string{"prune-local", "--volume", "vol_1", "--json"}); rc != 0 {
		t.Fatalf("prune-local --volume rc=%d", rc)
	}
	var scoped struct {
		Removed bool       `json:"removed"`
		Orphans []pruneRow `json:"orphans"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &scoped); err != nil {
		t.Fatal(err)
	}
	if scoped.Removed || len(scoped.Orphans) != 1 || scoped.Orphans[0].Path != ".venv" || scoped.Orphans[0].VolumeID != "vol_1" {
		t.Fatalf("scoped dry run = %+v", scoped)
	}

	// --delete reclaims the orphans and nothing else.
	stdout.Reset()
	if rc := e.run([]string{"prune-local", "--delete"}); rc != 0 {
		t.Fatalf("prune-local --delete rc=%d out=%s", rc, stdout)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan survived --delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(live, "f")); err != nil {
		t.Fatalf("live backing was reclaimed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("an unknown volume's backing tree survived: %v", err)
	}

	// Asking for both a dry run and a deletion is a contradiction.
	if rc := e.run([]string{"prune-local", "--delete", "--dry-run"}); rc == 0 {
		t.Fatal("--delete with --dry-run must be refused")
	}
}

// TestStatusReportsLocalRoutes pins the status lines: revision, effective
// patterns, and per-root backing with its disk usage.
func TestStatusReportsLocalRoutes(t *testing.T) {
	e, _, _ := testEnv(t)
	mnt := t.TempDir()
	rules := recordRoutedMount(t, e, mnt, "vol_1", "node_modules/\n")
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	backing := localDirsBackingRoot(dir, "vol_1")
	if err := os.MkdirAll(filepath.Join(backing, "agent-app", "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backing, "agent-app", "node_modules", "dep.js"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	row, err := e.localRoutesOf("vol_1")
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.Revision != rules.RevisionHex() || strings.Join(row.Patterns, " ") != "**/node_modules/" {
		t.Fatalf("status row = %+v", row)
	}
	if len(row.Roots) != 1 || row.Roots[0].Path != "agent-app/node_modules" || row.Roots[0].Bytes != 10 {
		t.Fatalf("status roots = %+v", row.Roots)
	}
	if row.Roots[0].Backing != filepath.Join(backing, "agent-app", "node_modules") {
		t.Fatalf("status backing = %q", row.Roots[0].Backing)
	}
	// A volume with no routes reports nothing rather than an empty section.
	if got, err := e.localRoutesOf("vol_2"); err != nil || got != nil {
		t.Fatalf("unrouted volume = %+v", got)
	}
}

func TestStatusEmptyFSKitDeclarationOutranksStaleFUSERouteRecord(t *testing.T) {
	e, _, _ := testEnv(t)
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	st := validFSKitMountState(t, t.TempDir())
	st.VolumeID = "vol_empty_mac"
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	stale, err := localroutes.Parse([]byte("/cache/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLocalRoutesRecord(dir, st.VolumeID, mountRoutes{
		rules: stale, revision: stale.RevisionHex(), declared: true,
	}, 1); err != nil {
		t.Fatal(err)
	}
	if got, err := e.localRoutesOf(st.VolumeID); err != nil || got != nil {
		t.Fatalf("empty live FSKit declaration inherited stale FUSE routing: %+v", got)
	}
}
