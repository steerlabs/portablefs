package portablefsd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		panic(err)
	}
	root, err := os.MkdirTemp(base, "pfs-daemon-tests-")
	if err != nil {
		panic(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		panic(err)
	}
	if err := os.Setenv("TMPDIR", root); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireCaseExactGraftBacking gates every test that activates a machine-local
// graft.
//
// Graft activation now PROBES the backing filesystem and refuses when it folds
// names the shared namespace keeps distinct (localcasesafety.go). On a stock
// Mac the test temp root is case-insensitive APFS, so PortableFS genuinely
// refuses to serve grafts there, and a graft test on such a host is asserting
// behaviour the product deliberately does not provide.
//
// That is a skip with a stated reason, never a quiet pass and never a rewritten
// assertion: the tests below are the specification of what a graft does once a
// case-exact backing exists, and they run in full on any host that has one
// (Linux CI, or a Mac whose state dir is on an APFS (Case-sensitive) volume).
func requireCaseExactGraftBacking(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if caseExact, why := hostGroundTruth(t, dir); !caseExact {
		t.Skipf("SKIP (not a pass): the backing filesystem under %s folds names by %s, "+
			"so graft activation refuses on this host by design (see ErrBackingCaseUnsafe). "+
			"Run this test on a case-sensitive filesystem - Linux CI, or a Mac with the daemon "+
			"state dir on an APFS (Case-sensitive) volume - to exercise it.", dir, why)
	}
}

// graftTestDir is privateTestDir for tests that activate a graft.
func graftTestDir(t *testing.T) string {
	t.Helper()
	requireCaseExactGraftBacking(t)
	return privateTestDir(t)
}
