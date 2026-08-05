package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
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
	a := localDirsRecordPath(dir, "vol_1", "main", "/mnt/a")
	b := localDirsRecordPath(dir, "vol_1", "main", "/mnt/b")
	if a == b {
		t.Fatal("two mounts of one volume must keep distinct --local-dir records")
	}
	for _, p := range []string{a, b, localRoutesRecordPath(dir, "vol_1")} {
		if strings.HasPrefix(p, first+string(filepath.Separator)) {
			t.Fatalf("sidecar %q must not live inside the backing tree", p)
		}
	}
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
	row := e.localRoutesOf("vol_1", "main")
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
	if got := e.localRoutesOf("vol_2", "main"); got != nil {
		t.Fatalf("unrouted volume = %+v", got)
	}
}

func TestStatusUsesFSKitVolumeBranchBacking(t *testing.T) {
	e, _, _ := testEnv(t)
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	st := validFSKitMountState(t, t.TempDir())
	st.VolumeID = "vol_mac"
	st.Branch = "feature"
	st.LocalDirs = []string{"cache"}
	st.LocalDirsDeclared = true
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	backing := portablefsd.LocalBackingRoot(filepath.Join(filepath.Dir(dir), "portablefsd"), st.VolumeID, st.Branch)
	if err := os.MkdirAll(filepath.Join(backing, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backing, "cache", "artifact"), []byte("mac-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	row := e.localRoutesOf(st.VolumeID, st.Branch)
	if row == nil || row.Backing != backing || strings.Join(row.Patterns, ",") != "/cache/" {
		t.Fatalf("FSKit status row = %+v", row)
	}
	if row.PerMachine || row.Revision != "" {
		t.Fatalf("FSKit status invented per-machine provenance or canonical revision: %+v", row)
	}
	if len(row.Roots) != 1 || row.Roots[0].Path != "cache" || row.Roots[0].Bytes != int64(len("mac-bytes")) {
		t.Fatalf("FSKit status roots = %+v", row.Roots)
	}
	if row.Roots[0].Backing != filepath.Join(backing, "cache") {
		t.Fatalf("FSKit status backing = %q", row.Roots[0].Backing)
	}
	if got := e.localRoutesOf(st.VolumeID, "main"); got != nil {
		t.Fatalf("another branch inherited FSKit backing: %+v", got)
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
	st.Branch = "main"
	st.LocalDirsDeclared = true
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
	if got := e.localRoutesOf(st.VolumeID, st.Branch); got != nil {
		t.Fatalf("empty live FSKit declaration inherited stale FUSE routing: %+v", got)
	}
}

func TestPruneLocalProtectsPossiblyLiveFSKitBacking(t *testing.T) {
	e, _, _ := testEnv(t)
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	st := validFSKitMountState(t, t.TempDir())
	st.VolumeID = "vol_mac"
	st.Branch = "feature"
	st.LocalDirs = []string{"cache"}
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	backing := portablefsd.LocalBackingRoot(filepath.Join(filepath.Dir(dir), "portablefsd"), st.VolumeID, st.Branch)
	artifact := filepath.Join(backing, "cache", "artifact")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(filepath.Dir(dir), "portablefsd", "local"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(filepath.Dir(dir), "portablefsd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := collectPruneRows(dir, "", true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(artifact); err != nil || string(got) != "keep" {
		t.Fatalf("possibly-live FSKit backing was changed: %q, %v", got, err)
	}
}

func TestPruneLocalProtectsDurableFSKitAttachWithoutMountRecord(t *testing.T) {
	e, _, _ := testEnv(t)
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	const volumeID, branch = "vol_durable_mac", "feature"
	daemonState := filepath.Join(filepath.Dir(dir), "portablefsd")
	if err := os.MkdirAll(daemonState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(daemonState, 0o700); err != nil {
		t.Fatal(err)
	}
	registry, err := json.Marshal(map[string]any{
		"version": 2,
		"attaches": []map[string]any{{
			"ref": "att_AAAAAAAAAAAAAAAAAAAAAA", "volumeId": volumeID, "branch": branch,
			"mountPath": "/Volumes/DurableMac", "authorityUrl": "127.0.0.1:2050",
			"dataPlaneTransport": "plaintext", "options": map[string]any{}, "identityEpoch": 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(daemonState, "attaches.json"), registry, 0o600); err != nil {
		t.Fatal(err)
	}
	backing := portablefsd.LocalBackingRoot(daemonState, volumeID, branch)
	artifact := filepath.Join(backing, "cache", "artifact")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(daemonState, "local"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := collectPruneRows(dir, "", true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(artifact); err != nil || string(got) != "keep" {
		t.Fatalf("durable FSKit attach backing was changed: %q, %v", got, err)
	}
}

func TestPruneLocalFailsClosedBeforeDeletingUnknownFSKitBacking(t *testing.T) {
	e, _, _ := testEnv(t)
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(filepath.Dir(dir), "portablefsd", "local", strings.Repeat("a", 32), "cache", "artifact")
	if err := os.MkdirAll(filepath.Dir(unknown), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(filepath.Dir(dir), "portablefsd", "local"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(filepath.Dir(dir), "portablefsd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unknown, []byte("unknown-owner"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also stage an ordinary FUSE orphan. The FSKit proof failure is a
	// preflight: no earlier tree may be partially deleted before it is found.
	fuseOrphan := filepath.Join(localBackingDir(dir), localdirs.StorageID("vol_old"), "cache", "artifact")
	if err := os.MkdirAll(filepath.Dir(fuseOrphan), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(localBackingDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fuseOrphan, []byte("fuse-orphan"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, onlyVolume := range []string{"", "vol_selected"} {
		if _, err := collectPruneRows(dir, onlyVolume, true); err == nil || !strings.Contains(err.Error(), "no mount or durable daemon attach") {
			t.Fatalf("unknown FSKit backing prune --volume=%q error = %v", onlyVolume, err)
		}
	}
	for _, p := range []string{unknown, fuseOrphan} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("failed-closed prune changed %s: %v", p, err)
		}
	}
}

// declaringVolume is a VolumeReader stub carrying (or not carrying) a route
// declaration, for the revision and --local-dir refusal rules.
type declaringVolume struct{ declaration *string }

func (d *declaringVolume) Lookup(_ context.Context, p string) (fsproto.Attr, clientcore.Status) {
	if p == localdirs.VolumeConfigPath && d.declaration != nil {
		return fsproto.Attr{Kind: "file", Size: int64(len(*d.declaration))}, fsproto.OK
	}
	return fsproto.Attr{}, fsproto.ENOENT
}

func (d *declaringVolume) Read(_ context.Context, p string, _ *clientcore.NodeState, _ int64, _ int) ([]byte, clientcore.Status) {
	if p == localdirs.VolumeConfigPath && d.declaration != nil {
		return []byte(*d.declaration), fsproto.OK
	}
	return nil, fsproto.ENOENT
}

func (d *declaringVolume) Readdir(_ context.Context, _ string) ([]clientcore.DirEntry, clientcore.Status) {
	return nil, fsproto.ENOENT
}

// TestReportedRevisionIsTheDeclarationAlone pins the contract the authority
// enforces: the revision a mount answers for is exactly the hash of the
// volume's declaration, so every machine mounting one volume reports one
// value. Per-machine route additions are the topology skew that check exists
// to refuse, so they are rejected outright on a volume that declares routes,
// and on a volume that declares none they leave the revision untouched.
func TestReportedRevisionIsTheDeclarationAlone(t *testing.T) {
	ctx := context.Background()
	text := "# machine-local\nnode_modules/\n"
	declared, err := localroutes.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}

	// Declaring volume, no flags: routes and revision both come from it.
	routes, err := resolveRoutes(ctx, &declaringVolume{declaration: &text}, localDirsMountConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if routes.revision != declared.RevisionHex() || routes.perMachine || !routes.declared {
		t.Fatalf("declared routing = %+v", routes)
	}
	if strings.Join(routes.rules.Patterns(), " ") != "**/node_modules/" {
		t.Fatalf("declared patterns = %v", routes.rules.Patterns())
	}

	// Declaring volume plus --local-dir: refused, with a message that says
	// where to put the rule instead.
	_, err = resolveRoutes(ctx, &declaringVolume{declaration: &text}, localDirsMountConfig{dirs: []string{"target"}})
	if err == nil {
		t.Fatal("--local-dir on a declaring volume must be refused")
	}
	for _, want := range []string{localdirs.VolumeConfigPath, "shared", "--local-dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q must mention %q", err, want)
		}
	}

	// A declaration holding only comments still means the volume owns
	// routing, so the flag is refused there too.
	commented := "# routes are managed centrally\n"
	if _, err := resolveRoutes(ctx, &declaringVolume{declaration: &commented}, localDirsMountConfig{dirs: []string{"target"}}); err == nil {
		t.Fatal("--local-dir must be refused whenever a declaration exists")
	}

	// Volume with NO declaration: the legacy per-machine path stays open, and
	// the revision reported is still the declaration's — the empty one — so
	// the rule "revision == hash(declaration)" holds without exception.
	routes, err = resolveRoutes(ctx, &declaringVolume{}, localDirsMountConfig{dirs: []string{"node_modules"}})
	if err != nil {
		t.Fatal(err)
	}
	if !routes.perMachine || routes.declared {
		t.Fatalf("undeclared routing = %+v", routes)
	}
	if routes.revision != emptyRoutesRevision() {
		t.Fatalf("revision = %q, want the empty-declaration revision", routes.revision)
	}
	if strings.Join(routes.rules.Patterns(), " ") != "/node_modules/" {
		t.Fatalf("per-machine patterns = %v", routes.rules.Patterns())
	}
	// A mount state recording that pair validates; claiming the flag rules'
	// own hash as the revision does not.
	st := validFuseMountState(t, t.TempDir())
	st.LocalRoutes = routes.rules.Patterns()
	st.LocalRouteRevision = routes.revision
	st.LocalRoutesPerMachine = true
	if err := validatePersistedLocalRoutes(&st); err != nil {
		t.Fatalf("per-machine record rejected: %v", err)
	}
	st.LocalRouteRevision = routes.rules.RevisionHex()
	if err := validatePersistedLocalRoutes(&st); err == nil {
		t.Fatal("per-machine routes must not claim a revision of their own")
	}
}

// TestMountRejectsPatternLocalDirFlags pins that --local-dir stays a literal
// path: patterns belong in the volume's declaration, where they are validated
// as a whole and become part of the revision.
func TestMountRejectsPatternLocalDirFlags(t *testing.T) {
	for _, value := range []string{"node_*", "**/node_modules", ".git", ".git/objects", ".portablefs"} {
		e, _, stderr := testEnv(t)
		rc := e.run([]string{"mount", "vol_1", filepath.Join(t.TempDir(), "m"), "--local-dir", value})
		if rc == 0 {
			t.Fatalf("--local-dir %q was accepted", value)
		}
		if stderr.Len() == 0 {
			t.Fatalf("--local-dir %q must fail with an explanation", value)
		}
	}
}
