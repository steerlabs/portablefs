package localdirs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPruneBackingReclaimsOnlyOrphans pins the reclamation rule: backing a
// current rule still routes is never touched, and backing nothing routes is
// reported as ONE topmost tree — with dry-run (remove=false) changing nothing
// on disk.
func TestPruneBackingReclaimsOnlyOrphans(t *testing.T) {
	backing := filepath.Join(t.TempDir(), "local", StorageID("vol_1"))
	rules := rulesFor(t, "node_modules/\n/target/\n")
	g, err := New(Config{BackingRoot: backing, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	// Live backing under the current rules, at two depths.
	for _, root := range []string{"node_modules", "agent-app/node_modules", "target"} {
		if eno := g.Mkdir(root, 0o755); eno != 0 {
			t.Fatalf("mkdir %s errno=%d", root, eno)
		}
		fd, eno := g.Create(root+"/dep.js", 0o2 /*O_RDWR*/, 0o644)
		if eno != 0 {
			t.Fatalf("create in %s errno=%d", root, eno)
		}
		_ = closeFD(fd)
	}
	_ = g.Close()

	// Backing left behind by rules that are no longer declared: a whole
	// former root, and a scaffold path leading only to one.
	mkdirAllHost(t, filepath.Join(backing, ".venv", "lib"))
	writeHost(t, filepath.Join(backing, ".venv", "lib", "python"), "stale")
	mkdirAllHost(t, filepath.Join(backing, "services", "api", "dist"))
	writeHost(t, filepath.Join(backing, "services", "api", "dist", "bundle.js"), "stale bundle")

	orphans, err := PruneBacking(backing, rules, false)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, o := range orphans {
		paths = append(paths, o.Path)
	}
	if strings.Join(paths, ",") != ".venv,services" {
		t.Fatalf("orphans = %v; only unrouted backing may be reclaimed, reported topmost", paths)
	}
	for _, o := range orphans {
		if o.Bytes == 0 || o.Files == 0 {
			t.Fatalf("orphan %+v must carry its size so an operator can judge it", o)
		}
	}
	// Dry run changed nothing.
	if _, err := os.Stat(filepath.Join(backing, ".venv", "lib", "python")); err != nil {
		t.Fatalf("dry run removed data: %v", err)
	}

	if _, err := PruneBacking(backing, rules, true); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{".venv", "services"} {
		if _, err := os.Stat(filepath.Join(backing, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s survived reclamation: %v", gone, err)
		}
	}
	for _, kept := range []string{"node_modules/dep.js", "agent-app/node_modules/dep.js", "target/dep.js"} {
		if _, err := os.Stat(filepath.Join(backing, filepath.FromSlash(kept))); err != nil {
			t.Fatalf("live backing %s was reclaimed: %v", kept, err)
		}
	}

	// A volume with no known routes at all (retired, or never mounted on this
	// machine since the record was written) has nothing reachable: every
	// top-level subtree is an orphan.
	all, err := PruneBacking(backing, rulesFor(t, ""), false)
	if err != nil {
		t.Fatal(err)
	}
	paths = paths[:0]
	for _, o := range all {
		paths = append(paths, o.Path)
	}
	if strings.Join(paths, ",") != "agent-app,node_modules,target" {
		t.Fatalf("unrouted volume orphans = %v", paths)
	}
}

func TestBackingUsageAndMissingRootsAreQuiet(t *testing.T) {
	base := t.TempDir()
	backing := filepath.Join(base, "local", StorageID("vol_1"))
	mkdirAllHost(t, filepath.Join(backing, "node_modules", "react"))
	writeHost(t, filepath.Join(backing, "node_modules", "react", "index.js"), "0123456789")

	bytes, files, err := BackingUsage(backing, "node_modules")
	if err != nil || bytes != 10 || files != 1 {
		t.Fatalf("usage = (%d,%d,%v)", bytes, files, err)
	}
	// Inspecting a volume with no backing must not CREATE the backing.
	absent := filepath.Join(base, "local", StorageID("vol_2"))
	if bytes, files, err := BackingUsage(absent, ""); err != nil || bytes != 0 || files != 0 {
		t.Fatalf("absent backing usage = (%d,%d,%v)", bytes, files, err)
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatal("inspecting a volume must never create its backing tree")
	}
	if orphans, err := PruneBacking(absent, rulesFor(t, ""), true); err != nil || orphans != nil {
		t.Fatalf("absent backing prune = (%v,%v)", orphans, err)
	}
}

func mkdirAllHost(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeHost(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func closeFD(fd int) error {
	f := os.NewFile(uintptr(fd), "graft")
	return f.Close()
}
