package localdirs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// These tests pin the graft CONTRACT at the backing-op layer (the layer every
// FUSE node method is a thin adapter over), mirroring the semantics proven
// end-to-end for portablefsd in vcs/internal/portablefsd/localdirs_test.go:
// shadowing, root-exists-exactly-when-mkdir'd, EXDEV at the boundary, EISDIR
// for non-directory creation at the root, ancestor-rename carry, the npm-ci
// wholesale rebuild, readdir merging, and open handles surviving rm -rf.

func TestNormalize(t *testing.T) {
	got, err := Normalize([]string{
		" node_modules ",
		"agent-app/node_modules",
		"agent-app/node_modules/", // duplicate after cleaning
		"node_modules/.vite",      // nested inside node_modules; dropped
		"agent-app/.next",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"agent-app/.next", "agent-app/node_modules", "node_modules"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("normalize=%v want %v", got, want)
	}

	for _, bad := range []string{"..", "../up", "/abs", "a/../../b"} {
		if _, err := Normalize([]string{bad}); err == nil {
			t.Fatalf("Normalize(%q) accepted, want error", bad)
		}
	}
	for _, trap := range []string{".portablefs", VolumeConfigPath} {
		if _, err := Normalize([]string{trap}); err == nil {
			t.Fatalf("Normalize(%q) accepted config-shadowing graft", trap)
		}
	}
	// "." and empty entries are dropped rather than rejected.
	got, err = Normalize([]string{"", "  "})
	if err != nil || len(got) != 0 {
		t.Fatalf("blank dirs=%v err=%v", got, err)
	}
}

func TestValidateStrict(t *testing.T) {
	if err := ValidateStrict([]string{"node_modules", "agent-app/.venv"}); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	cases := map[string][]string{
		"empty":     {""},
		"absolute":  {"/abs"},
		"escape":    {"../up"},
		"duplicate": {"node_modules", "node_modules/"},
		"nested":    {"node_modules", "node_modules/.cache"},
	}
	for name, dirs := range cases {
		if err := ValidateStrict(dirs); err == nil {
			t.Fatalf("%s: ValidateStrict(%v) accepted, want error", name, dirs)
		}
	}
}

func TestParseVolumeConfig(t *testing.T) {
	dirs, bad := ParseVolumeConfig([]byte(`
# per-machine dependency dirs
node_modules
agent-app/.venv   # python env
/absolute-is-invalid
../escape-is-invalid

target
`))
	if strings.Join(dirs, ",") != "node_modules,agent-app/.venv,target" {
		t.Fatalf("dirs=%v", dirs)
	}
	if len(bad) != 2 {
		t.Fatalf("bad lines=%v", bad)
	}
}

// TestBackingIdentityIsVolumeKeyed pins the storage identity: a machine-local
// dependency tree belongs to the VOLUME, not to a mountpoint, a branch, or a
// mount instance.
func TestBackingIdentityIsVolumeKeyed(t *testing.T) {
	a := StorageID("vol_1")
	if a != StorageID("vol_1") {
		t.Fatal("storage id must be deterministic")
	}
	if a == StorageID("vol_2") {
		t.Fatal("distinct volumes must not collide")
	}
	if len(a) != 32 {
		t.Fatalf("storage id %q must keep portablefsd's 32-hex convention", a)
	}
	// The same volume remounted anywhere reuses its backing; a different
	// volume at the same mountpoint can never inherit it.
	base := t.TempDir()
	if BackingRoot(base, "vol_1") != BackingRoot(base, "vol_1") {
		t.Fatal("a remount of the same volume must reuse its backing tree")
	}
	if BackingRoot(base, "vol_1") == BackingRoot(base, "vol_2") {
		t.Fatal("two volumes must never share a backing tree")
	}
}

func rulesFor(t *testing.T, text string) localroutes.RuleSet {
	t.Helper()
	rs, err := localroutes.Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse rules %q: %v", text, err)
	}
	return rs
}

// newGrafts builds a graft set from literal (anchored) roots, the shape the
// --local-dir flag produces.
func newGrafts(t *testing.T, dirs ...string) *Grafts {
	t.Helper()
	var text strings.Builder
	for _, d := range dirs {
		pattern, err := localroutes.LiteralPattern(d)
		if err != nil {
			t.Fatal(err)
		}
		text.WriteString(pattern + "\n")
	}
	return newGraftsWithRules(t, rulesFor(t, text.String()))
}

func newGraftsWithRules(t *testing.T, rules localroutes.RuleSet) *Grafts {
	t.Helper()
	g, err := New(Config{BackingRoot: filepath.Join(t.TempDir(), "local", "sid"), Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if g == nil {
		t.Fatal("expected a non-nil graft set")
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestOwnerAndNilFastPath(t *testing.T) {
	g := newGrafts(t, "node_modules", "agent-app/node_modules")
	cases := map[string]string{
		"node_modules":            "node_modules",
		"node_modules/react":      "node_modules",
		"node_modules2":           "",
		"agent-app":               "",
		"agent-app/node_modules":  "agent-app/node_modules",
		"agent-app/node_modulesX": "",
		"src/main.go":             "",
		"":                        "",
	}
	for p, want := range cases {
		if got := g.Owner(p); got != want {
			t.Fatalf("Owner(%q)=%q want %q", p, got, want)
		}
	}

	// The nil receiver is the non-graft mount's hot path.
	var nilG *Grafts
	if nilG.Owner("node_modules") != "" || nilG.Patterns() != nil {
		t.Fatal("nil Grafts must behave as no grafts")
	}
	if roots, eno := nilG.ActiveRootsUnder(""); roots != nil || eno != 0 {
		t.Fatal("nil Grafts must report no active roots")
	}
	if eno, handled := nilG.VolumeRenameCheck("a", "b"); handled || eno != 0 {
		t.Fatal("nil Grafts must not intercept renames")
	}
	if nilG.HasActiveRouteUnder("a") {
		t.Fatal("nil Grafts must hold no backing")
	}
}

// TestFloatingRuleInstantiatesRootsAtAnyDepth pins the pattern-era rule that
// no fixed list can express: a directory created at a depth nobody enumerated
// becomes a graft root the moment it matches, and everything under it is
// machine-local from that instant.
func TestFloatingRuleInstantiatesRootsAtAnyDepth(t *testing.T) {
	g := newGraftsWithRules(t, rulesFor(t, "node_modules/\n"))

	deep := "services/api/handlers/node_modules"
	if got := g.Owner(deep); got != deep {
		t.Fatalf("Owner(%q)=%q; a floating rule must own it at any depth", deep, got)
	}
	if _, eno := g.Lstat(deep); eno != syscall.ENOENT {
		t.Fatalf("pre-mkdir lstat errno=%d want ENOENT (rules never synthesize)", eno)
	}
	// mkdir instantiates the root, scaffold and all, exactly like a
	// configured one.
	if eno := g.Mkdir(deep, 0o755); eno != 0 {
		t.Fatalf("mkdir at depth errno=%d", eno)
	}
	if st, eno := g.Lstat(deep); eno != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		t.Fatalf("instantiated root lstat errno=%d mode=%o", eno, st.Mode)
	}
	fd, eno := g.Create(deep+"/pkg.json", uint32(os.O_RDWR), 0o644)
	if eno != 0 {
		t.Fatalf("create under instantiated root errno=%d", eno)
	}
	_ = syscall.Close(fd)
	// It is a root, not a file: the same directory-rule guards apply.
	if _, eno := g.Create(deep, uint32(os.O_RDWR), 0o644); eno != syscall.EISDIR {
		t.Fatalf("create at instantiated root errno=%d want EISDIR", eno)
	}
	// A nested match is inside the outer root, which owns the whole subtree.
	nested := deep + "/pkg/node_modules"
	if got := g.Owner(nested); got != deep {
		t.Fatalf("Owner(%q)=%q want the topmost root %q", nested, got, deep)
	}
	roots, eno := g.ActiveRootsUnder("")
	if eno != 0 || strings.Join(roots, ",") != deep {
		t.Fatalf("active roots = %v errno=%d", roots, eno)
	}
	// The instantiated root is served locally, so its inode carries the local
	// marker the frontend routes on.
	if st, eno := g.Lstat(deep); eno != 0 || LocalIno(st.Ino)&localInoMarker == 0 {
		t.Fatalf("instantiated root ino %x lacks the local marker bit (errno=%d)", st.Ino, eno)
	}
}

// TestRootExistsExactlyWhenMkdirred pins the core rule: a graft rule owns the
// name but synthesizes nothing.
func TestRootExistsExactlyWhenMkdirred(t *testing.T) {
	g := newGrafts(t, "node_modules")

	if _, eno := g.Lstat("node_modules"); eno != syscall.ENOENT {
		t.Fatalf("pre-mkdir lstat errno=%d want ENOENT", eno)
	}
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatalf("mkdir root errno=%d", eno)
	}
	st, eno := g.Lstat("node_modules")
	if eno != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		t.Fatalf("post-mkdir lstat errno=%d mode=%o", eno, st.Mode)
	}
	if eno := g.Mkdir("node_modules", 0o755); eno != syscall.EEXIST {
		t.Fatalf("re-mkdir errno=%d want EEXIST", eno)
	}

	// The root can only ever be a directory.
	if _, eno := g.Create("node_modules", uint32(os.O_RDWR), 0o644); eno != syscall.EISDIR {
		t.Fatalf("create at root errno=%d want EISDIR", eno)
	}
	if eno := g.Symlink("elsewhere", "node_modules"); eno != syscall.EISDIR {
		t.Fatalf("symlink at root errno=%d want EISDIR", eno)
	}
}

// TestScaffoldIsStorageNotNamespace pins that a nested rule's scaffold
// directories (agent-app for agent-app/node_modules) do not make the root
// exist, and root creation works without any prior scaffold.
func TestScaffoldIsStorageNotNamespace(t *testing.T) {
	g := newGrafts(t, "agent-app/node_modules")
	if eno := g.Mkdir("agent-app/node_modules", 0o755); eno != 0 {
		t.Fatalf("mkdir nested root errno=%d (scaffold must be created on demand)", eno)
	}
	if _, eno := g.Lstat("agent-app/node_modules"); eno != 0 {
		t.Fatalf("nested root missing after mkdir: errno=%d", eno)
	}
}

func TestFileRoundTripAndTypeGuards(t *testing.T) {
	g := newGrafts(t, "node_modules")
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}

	fd, eno := g.Create("node_modules/package.json", uint32(os.O_RDWR), 0o644)
	if eno != 0 {
		t.Fatalf("create errno=%d", eno)
	}
	if _, err := syscall.Write(fd, []byte(`{"name":"dep"}`)); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(fd)

	fd, eno = g.Open("node_modules/package.json", uint32(os.O_RDONLY))
	if eno != 0 {
		t.Fatalf("open errno=%d", eno)
	}
	buf := make([]byte, 64)
	n, _ := syscall.Read(fd, buf)
	_ = syscall.Close(fd)
	if string(buf[:n]) != `{"name":"dep"}` {
		t.Fatalf("read=%q", buf[:n])
	}

	// Symlinks round-trip with st_size == target length.
	if eno := g.Symlink("package.json", "node_modules/dep-link"); eno != 0 {
		t.Fatalf("symlink errno=%d", eno)
	}
	st, eno := g.Lstat("node_modules/dep-link")
	if eno != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFLNK || st.Size != int64(len("package.json")) {
		t.Fatalf("symlink lstat errno=%d mode=%o size=%d", eno, st.Mode, st.Size)
	}
	if target, eno := g.Readlink("node_modules/dep-link"); eno != 0 || target != "package.json" {
		t.Fatalf("readlink=%q errno=%d", target, eno)
	}

	// POSIX type guards.
	if eno := g.Mkdir("node_modules/pkg", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Remove("node_modules/pkg", false); eno != syscall.EISDIR {
		t.Fatalf("unlink dir errno=%d want EISDIR", eno)
	}
	if eno := g.Remove("node_modules/package.json", true); eno != syscall.ENOTDIR {
		t.Fatalf("rmdir file errno=%d want ENOTDIR", eno)
	}
	fd, _ = g.Create("node_modules/pkg/f", uint32(os.O_RDWR), 0o644)
	_ = syscall.Close(fd)
	if eno := g.Remove("node_modules/pkg", true); eno != syscall.ENOTEMPTY {
		t.Fatalf("rmdir non-empty errno=%d want ENOTEMPTY", eno)
	}

	// setattr: chmod + truncate.
	if eno := g.Setattr("node_modules/package.json", SetattrRequest{SetMode: true, Mode: 0o755, SetSize: true, Size: 4}); eno != 0 {
		t.Fatalf("setattr errno=%d", eno)
	}
	st, _ = g.Lstat("node_modules/package.json")
	if st.Size != 4 || st.Mode&0o777 != 0o755 {
		t.Fatalf("setattr result mode=%o size=%d", st.Mode, st.Size)
	}
}

// TestBoundarySemantics pins EXDEV across the graft boundary in every
// direction, including of the root itself, and rename-within (npm's staging
// pattern) with the NOREPLACE emulation.
func TestBoundarySemantics(t *testing.T) {
	g := newGrafts(t, "node_modules", "target")
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	fd, _ := g.Create("node_modules/inside.txt", uint32(os.O_RDWR), 0o644)
	_ = syscall.Close(fd)

	// Boundary crossings the VOLUME nodes must answer with EXDEV.
	for _, tc := range [][2]string{
		{"node_modules/inside.txt", "moved.txt"}, // graft -> volume
		{"outside.txt", "node_modules/moved"},    // volume -> graft
		{"node_modules", "node_modules_old"},     // the root itself out of its rule
		{"src", "node_modules"},                  // a volume dir over the root
	} {
		if eno, handled := g.VolumeRenameCheck(tc[0], tc[1]); !handled || eno != syscall.EXDEV {
			t.Fatalf("VolumeRenameCheck(%q -> %q) = (%d,%v) want EXDEV", tc[0], tc[1], eno, handled)
		}
	}
	// An ancestor rename with no graft-owned endpoint, no active backing
	// under it, and no change in what the rules route passes through.
	if _, handled := g.VolumeRenameCheck("agent-app", "agent-app-v2"); handled {
		t.Fatal("ancestor rename must reach the authority")
	}

	// The LOCAL rename path enforces the same rule for renames the kernel
	// sends to graft nodes: same-rule renames succeed, cross-rule fails.
	if eno := g.Rename("node_modules/inside.txt", "target/inside.txt", 0); eno != syscall.EXDEV {
		t.Fatalf("cross-graft rename errno=%d want EXDEV", eno)
	}
	if eno := g.Mkdir("node_modules/pkg", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Rename("node_modules/inside.txt", "node_modules/pkg/staged.txt", 0); eno != 0 {
		t.Fatalf("in-graft rename errno=%d", eno)
	}
	if _, eno := g.Lstat("node_modules/inside.txt"); eno != syscall.ENOENT {
		t.Fatalf("stale source lstat errno=%d want ENOENT", eno)
	}
	if _, eno := g.Lstat("node_modules/pkg/staged.txt"); eno != 0 {
		t.Fatalf("moved file lstat errno=%d", eno)
	}

	// RENAME_NOREPLACE (flag bit 1) refuses to clobber.
	fd, _ = g.Create("node_modules/a", uint32(os.O_RDWR), 0o644)
	_ = syscall.Close(fd)
	fd, _ = g.Create("node_modules/b", uint32(os.O_RDWR), 0o644)
	_ = syscall.Close(fd)
	if eno := g.Rename("node_modules/a", "node_modules/b", 1); eno != syscall.EEXIST {
		t.Fatalf("noreplace rename errno=%d want EEXIST", eno)
	}
	// RENAME_EXCHANGE is not supported.
	if eno := g.Rename("node_modules/a", "node_modules/b", 2); eno != syscall.EINVAL {
		t.Fatalf("exchange rename errno=%d want EINVAL", eno)
	}
}

func TestHardLinksStayInsideOneGraft(t *testing.T) {
	g := newGrafts(t, "node_modules", "target")
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Mkdir("target", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	fd, eno := g.Create("node_modules/source", uint32(os.O_RDWR), 0o644)
	if eno != 0 {
		t.Fatal(eno)
	}
	if _, err := syscall.Write(fd, []byte("shared")); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(fd)

	if eno := g.Link("node_modules/source", "node_modules/alias"); eno != 0 {
		t.Fatalf("same-graft link errno=%d", eno)
	}
	source, eno := g.Lstat("node_modules/source")
	if eno != 0 {
		t.Fatal(eno)
	}
	alias, eno := g.Lstat("node_modules/alias")
	if eno != 0 {
		t.Fatal(eno)
	}
	if source.Ino != alias.Ino || source.Nlink != 2 || alias.Nlink != 2 {
		t.Fatalf("source=%+v alias=%+v", source, alias)
	}
	if eno := g.Remove("node_modules/source", false); eno != 0 {
		t.Fatal(eno)
	}
	alias, eno = g.Lstat("node_modules/alias")
	if eno != 0 || alias.Nlink != 1 {
		t.Fatalf("surviving alias=%+v errno=%d", alias, eno)
	}

	for _, tc := range [][2]string{
		{"node_modules/alias", "outside"},
		{"outside", "node_modules/from-volume"},
		{"node_modules/alias", "target/cross-graft"},
	} {
		if eno := g.Link(tc[0], tc[1]); eno != syscall.EXDEV {
			t.Fatalf("Link(%q,%q) errno=%d want EXDEV", tc[0], tc[1], eno)
		}
	}
	if eno := g.Link("node_modules", "node_modules/dir-alias"); eno != syscall.EPERM {
		t.Fatalf("directory link errno=%d want EPERM", eno)
	}
	if eno := g.Link("node_modules/alias", "node_modules"); eno != syscall.EISDIR {
		t.Fatalf("link over graft root errno=%d want EISDIR", eno)
	}
}

// TestWholesaleRebuild pins the npm-ci pattern: rm -rf of the graft root
// (children first, then the root) and recreation from scratch.
func TestWholesaleRebuild(t *testing.T) {
	g := newGrafts(t, "node_modules")
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Mkdir("node_modules/react", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	fd, _ := g.Create("node_modules/react/index.js", uint32(os.O_RDWR), 0o644)
	_ = syscall.Close(fd)

	// Removing the non-empty root is ENOTEMPTY like any directory.
	if eno := g.Remove("node_modules", true); eno != syscall.ENOTEMPTY {
		t.Fatalf("remove non-empty root errno=%d want ENOTEMPTY", eno)
	}

	// rm -rf: children first, then the root itself.
	if eno := g.Remove("node_modules/react/index.js", false); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Remove("node_modules/react", true); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Remove("node_modules", true); eno != 0 {
		t.Fatal(eno)
	}

	// Gone without a trace: ENOENT, no phantom listing entry.
	if _, eno := g.Lstat("node_modules"); eno != syscall.ENOENT {
		t.Fatalf("post-removal lstat errno=%d want ENOENT", eno)
	}
	if roots, eno := g.ActiveRootsUnder(""); eno != 0 || len(roots) != 0 {
		t.Fatalf("post-removal active roots=%v errno=%d want empty", roots, eno)
	}

	// Recreate from scratch: fresh, empty directory.
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatalf("recreate errno=%d", eno)
	}
	ents, eno := g.ReadDirNames("node_modules")
	if eno != 0 || len(ents) != 0 {
		t.Fatalf("recreated root listing=%v errno=%d", ents, eno)
	}
	fd, eno = g.Create("node_modules/fresh.txt", uint32(os.O_RDWR), 0o644)
	if eno != 0 {
		t.Fatalf("post-rebuild create errno=%d", eno)
	}
	_ = syscall.Close(fd)
}

// TestOpenHandleSurvivesWholesaleRemoval pins open-after-unlink under rm -rf:
// an open backing fd keeps serving reads and writes after the file and the
// whole graft root are removed — plain POSIX, because handles are fds.
func TestOpenHandleSurvivesWholesaleRemoval(t *testing.T) {
	g := newGrafts(t, "node_modules")
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	fd, eno := g.Create("node_modules/held.txt", uint32(os.O_RDWR), 0o644)
	if eno != 0 {
		t.Fatal(eno)
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte("before")); err != nil {
		t.Fatal(err)
	}

	if eno := g.Remove("node_modules/held.txt", false); eno != 0 {
		t.Fatal(eno)
	}
	if eno := g.Remove("node_modules", true); eno != 0 {
		t.Fatal(eno)
	}

	if _, err := syscall.Pwrite(fd, []byte("after"), 0); err != nil {
		t.Fatalf("write after unlink: %v", err)
	}
	buf := make([]byte, 16)
	n, err := syscall.Pread(fd, buf, 0)
	if err != nil || string(buf[:n]) != "aftere" {
		t.Fatalf("read after unlink = %q err=%v", buf[:n], err)
	}
}

// TestAncestorRenameOfActiveGraftIsEBUSY pins the semantics that replaced the
// old carry-and-persist behavior. A shared ancestor holding machine-local
// backing cannot be renamed at all: the declared rules are the only source of
// routing truth, so there is no rule to rewrite, and moving the backing under
// a name the declaration never mentioned is exactly the drift that made the
// revision guard the wrong object.
func TestAncestorRenameOfActiveGraftIsEBUSY(t *testing.T) {
	g := newGrafts(t, "agent-app/node_modules", "unrelated")
	before := g.RevisionHex()

	// With no backing yet there is nothing to break, and the rename is a pure
	// routing question: agent-app-v2/node_modules is not a configured route,
	// so ownership would flip — refuse it.
	if eno, handled := g.VolumeRenameCheck("agent-app", "agent-app-v2"); !handled || eno != syscall.EBUSY {
		t.Fatalf("ownership-flipping rename = (%d,%v) want EBUSY", eno, handled)
	}

	if eno := g.Mkdir("agent-app/node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	fd, _ := g.Create("agent-app/node_modules/keep.txt", uint32(os.O_RDWR), 0o644)
	if _, err := syscall.Write(fd, []byte("kept")); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(fd)

	// Now the subtree holds real machine-local storage: EBUSY, the errno
	// Linux answers for renaming a directory containing a mount point. NOT
	// EXDEV — a copy+delete fallback would copy the backing into the volume.
	if eno, handled := g.VolumeRenameCheck("agent-app", "agent-app-v2"); !handled || eno != syscall.EBUSY {
		t.Fatalf("ancestor rename over active backing = (%d,%v) want EBUSY", eno, handled)
	}
	// Renaming ONTO a name whose subtree holds backing is refused the same
	// way, in the same direction of caution.
	if eno, handled := g.VolumeRenameCheck("docs", "agent-app"); !handled || eno != syscall.EBUSY {
		t.Fatalf("rename over an active subtree = (%d,%v) want EBUSY", eno, handled)
	}

	// The refusal changed nothing: the rules, the revision, and the backing
	// are exactly as declared.
	if got := strings.Join(g.Patterns(), ","); got != "/agent-app/node_modules/,/unrelated/" {
		t.Fatalf("patterns=%v; a rename must never mutate the route set", got)
	}
	if g.RevisionHex() != before {
		t.Fatal("a rename must never change the revision the mount reports")
	}
	if g.Owner("agent-app/node_modules/keep.txt") != "agent-app/node_modules" {
		t.Fatal("the declared route must still own its path")
	}
	if g.Owner("agent-app-v2/node_modules") != "" {
		t.Fatal("no route may appear at a name the declaration never mentioned")
	}
}

// TestRenameFlipRefusalIsPathBased pins the check that makes ownership flips
// impossible without enumerating the volume: it is decided from the rules
// alone, before the rename is applied.
func TestRenameFlipRefusalIsPathBased(t *testing.T) {
	// A floating rule routes by name at any depth, so moving a shared
	// ancestor changes nothing about what is local — allowed.
	g := newGraftsWithRules(t, rulesFor(t, "node_modules/\n"))
	if eno, handled := g.VolumeRenameCheck("agent-app", "agent-app-v2"); handled {
		t.Fatalf("floating rules must leave ancestor renames alone: (%d,%v)", eno, handled)
	}
	// …until the subtree actually holds backing.
	if eno := g.Mkdir("agent-app/node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	if eno, handled := g.VolumeRenameCheck("agent-app", "agent-app-v2"); !handled || eno != syscall.EBUSY {
		t.Fatalf("ancestor rename over active backing = (%d,%v) want EBUSY", eno, handled)
	}

	// A wildcard ancestor discriminates exactly like a literal one.
	w := newGraftsWithRules(t, rulesFor(t, "/apps/*/dist/\n"))
	if eno, handled := w.VolumeRenameCheck("apps/web", "apps/api"); handled {
		t.Fatalf("a rename between two paths the same rule matches must pass: (%d,%v)", eno, handled)
	}
	if eno, handled := w.VolumeRenameCheck("apps/web", "vendor/web"); !handled || eno != syscall.EBUSY {
		t.Fatalf("moving out of a wildcard's reach = (%d,%v) want EBUSY", eno, handled)
	}
	// Moving a plain shared directory around stays a plain rename.
	if eno, handled := w.VolumeRenameCheck("docs", "papers"); handled {
		t.Fatalf("unrelated rename = (%d,%v), want pass-through", eno, handled)
	}
}

// TestConcurrencySanity hammers matching, listing merges, and creates
// concurrently; run with -race this pins that the rule set is immutable and
// shareable without synchronization.
func TestConcurrencySanity(t *testing.T) {
	g := newGrafts(t, "node_modules", "carry/kit")
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = g.Owner("node_modules/some/dep")
				_ = g.Owner("src/main.go")
				_, _ = g.ActiveRootsUnder("")
				p := fmt.Sprintf("node_modules/w%d-%d", w, i%8)
				if fd, eno := g.Create(p, uint32(os.O_RDWR), 0o644); eno == 0 {
					_ = syscall.Close(fd)
				}
				_ = g.Remove(p, false)
			}
		}(w)
	}
	for i := 0; i < 64; i++ {
		if g.Owner("carry/kit/x") != "carry/kit" || g.Owner("carried/kit/x") != "" {
			t.Fatal("routing must be a pure function of the declaration")
		}
	}
	close(stop)
	wg.Wait()
}

func TestGraftOperationsCannotEscapeBackingCapability(t *testing.T) {
	host := t.TempDir()
	backing := filepath.Join(host, "local", "sid")
	outside := filepath.Join(host, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "secret")
	if err := os.WriteFile(sentinel, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{BackingRoot: backing, Rules: rulesFor(t, "/node_modules/\n")})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if eno := g.Mkdir("node_modules", 0o755); eno != 0 {
		t.Fatal(eno)
	}
	fd, eno := g.Create("node_modules/source", uint32(os.O_RDWR), 0o644)
	if eno != 0 {
		t.Fatal(eno)
	}
	_ = syscall.Close(fd)

	relativeEscape, err := filepath.Rel(filepath.Join(backing, "node_modules"), outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "relative", target: filepath.ToSlash(relativeEscape)},
		{name: "absolute", target: outside},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := "node_modules/" + tc.name
			if eno := g.Symlink(tc.target, link); eno != 0 {
				t.Fatal(eno)
			}
			if target, eno := g.Readlink(link); eno != 0 || target != tc.target {
				t.Fatalf("readlink=%q errno=%d", target, eno)
			}
			if _, eno := g.Lstat(link); eno != 0 {
				t.Fatalf("lstat symlink errno=%d", eno)
			}
			if fd, eno := g.Open(link+"/secret", uint32(os.O_RDONLY)); eno == 0 {
				_ = syscall.Close(fd)
				t.Fatal("open escaped backing capability")
			}
			if fd, eno := g.Create(link+"/created", uint32(os.O_RDWR), 0o644); eno == 0 {
				_ = syscall.Close(fd)
				t.Fatal("create escaped backing capability")
			}
			if eno := g.Mkdir(link+"/created-dir", 0o755); eno == 0 {
				t.Fatal("mkdir escaped backing capability")
			}
			if eno := g.Rename("node_modules/source", link+"/renamed", 0); eno == 0 {
				t.Fatal("rename escaped backing capability")
			}
			if eno := g.Link("node_modules/source", link+"/linked"); eno == 0 {
				t.Fatal("link escaped backing capability")
			}
			if eno := g.Symlink("x", link+"/nested-link"); eno == 0 {
				t.Fatal("symlink creation escaped backing capability")
			}
			if eno := g.Remove(link+"/secret", false); eno == 0 {
				t.Fatal("remove escaped backing capability")
			}
			if _, eno := g.ReadDirNames(link); eno == 0 {
				t.Fatal("readdir escaped backing capability")
			}
			if eno := g.Fsync(link + "/secret"); eno == 0 {
				t.Fatal("fsync escaped backing capability")
			}
			if eno := g.Setattr(link+"/secret", SetattrRequest{SetMode: true, Mode: 0}); eno == 0 {
				t.Fatal("setattr escaped backing capability")
			}
			if got, err := os.ReadFile(sentinel); err != nil || string(got) != "outside" {
				t.Fatalf("outside sentinel changed: %q, %v", got, err)
			}
			for _, name := range []string{"created", "created-dir", "renamed", "linked", "nested-link"} {
				if _, err := os.Lstat(filepath.Join(outside, name)); !os.IsNotExist(err) {
					t.Fatalf("outside %s exists after rejected operation: %v", name, err)
				}
			}
		})
	}

	if err := os.MkdirAll(filepath.Join(backing, "node_modules", "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backing, "node_modules", "real", "inside"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if eno := g.Symlink("real", "node_modules/safe"); eno != 0 {
		t.Fatal(eno)
	}
	fd, eno = g.Open("node_modules/safe/inside", uint32(os.O_RDONLY))
	if eno != 0 {
		t.Fatalf("safe in-graft relative symlink rejected: %d", eno)
	}
	buf := make([]byte, 2)
	n, err := syscall.Read(fd, buf)
	_ = syscall.Close(fd)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("safe symlink read=%q, %v", buf[:n], err)
	}
}
