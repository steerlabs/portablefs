package portablefsd

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/confinedfs"
)

// hostGroundTruth answers "does this directory's filesystem really keep
// case-colliding and NFC/NFD-colliding names apart?" using nothing but plain os
// calls on names the probe never uses.
//
// It exists so the probe is checked against the host rather than against
// itself. A probe validated by its own constants would pass on a machine where
// it had the verdict exactly backwards.
func hostGroundTruth(t *testing.T, dir string) (caseExact bool, why string) {
	t.Helper()
	pairs := []struct {
		kind, first, second string
	}{
		{"letter case", "GroundTruth", "groundtruth"},
		// Precomposed U+00FC against decomposed u + U+0308, written as escapes
		// so the two spellings cannot be normalized into one by tooling. These
		// are deliberately different names from the ones the probe uses.
		{"Unicode normalization", "gr\u00fcnd", "gru\u0308nd"},
	}
	for _, pair := range pairs {
		first := filepath.Join(dir, pair.first)
		second := filepath.Join(dir, pair.second)
		if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
			t.Fatalf("ground truth: write %s: %v", first, err)
		}
		_, err := os.Lstat(second)
		if err == nil {
			_ = os.Remove(first)
			_ = os.Remove(second)
			return false, pair.kind
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("ground truth: lstat %s: %v", second, err)
		}
		if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
			t.Fatalf("ground truth: write %s: %v", second, err)
		}
		body, err := os.ReadFile(first)
		if err != nil {
			t.Fatalf("ground truth: read back %s: %v", first, err)
		}
		folded := string(body) != "first"
		_ = os.Remove(first)
		_ = os.Remove(second)
		if folded {
			return false, pair.kind
		}
	}
	return true, ""
}

func openProbedBacking(t *testing.T, dir string) *confinedfs.Root {
	t.Helper()
	root, err := confinedfs.Open(dir, 0o700)
	if err != nil {
		t.Fatalf("open backing capability at %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func backingEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the backing root %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestBackingCaseProbeAgreesWithTheHostItRunsOn is the load-bearing test. It
// runs on every platform and requires the probe's verdict to equal what the
// host actually does, so the same test proves the refusal on an
// APFS-case-insensitive Mac and the acceptance on a case-sensitive CI
// filesystem without either result being hard-coded.
func TestBackingCaseProbeAgreesWithTheHostItRunsOn(t *testing.T) {
	dir := t.TempDir()
	caseExact, why := hostGroundTruth(t, dir)
	root := openProbedBacking(t, dir)

	err := verifyBackingCaseSafety(root, dir)
	if errors.Is(err, ErrBackingProbeIncomplete) {
		t.Fatalf("the probe could not reach a verdict on an ordinary temporary directory: %v", err)
	}
	switch {
	case caseExact && err != nil:
		t.Fatalf("host at %s really keeps colliding names apart, but the probe refused it: %v", dir, err)
	case !caseExact && err == nil:
		t.Fatalf("host at %s really folds names by %s, and the probe accepted it as case-exact; "+
			"a graft on this backing would silently overwrite one of two distinct volume names", dir, why)
	case !caseExact && !errors.Is(err, ErrBackingCaseUnsafe):
		t.Fatalf("the probe refused a folding backing with the wrong error kind: %v", err)
	}
	if !caseExact {
		// Not a skip: the refusal IS the assertion on this machine. The message
		// records which host behaviour produced it.
		t.Logf("host at %s folds names by %s; the probe refused activation as required: %v", dir, why, err)
	} else {
		t.Logf("host at %s is case-exact; the probe accepted it", dir)
	}
}

// TestBackingCaseProbeRefusesThisMacsDefaultBacking states the macOS
// expectation explicitly. A Mac whose temporary directory turns out to be
// case-sensitive is a legitimately different machine, so it says so loudly
// rather than failing.
func TestBackingCaseProbeRefusesThisMacsDefaultBacking(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("this expectation is about the default APFS backing on macOS")
	}
	dir := t.TempDir()
	caseExact, _ := hostGroundTruth(t, dir)
	if caseExact {
		t.Skipf("the backing at %s is case-sensitive on this Mac, so there is no folding to refuse; "+
			"the cross-platform agreement test covers the accepting direction", dir)
	}
	root := openProbedBacking(t, dir)
	err := verifyBackingCaseSafety(root, dir)
	if !errors.Is(err, ErrBackingCaseUnsafe) {
		t.Fatalf("graft activation on a case-insensitive APFS backing must refuse with ErrBackingCaseUnsafe, got %v", err)
	}
	// The refusal has to be actionable, not merely correct.
	for _, want := range []string{dir, "case-sensitive", "-state-dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not tell the operator what to do; %q is missing from: %v", want, err)
		}
	}
}

// TestBackingCaseProbeCleansUpAfterItself covers both verdicts: a refusal must
// not leave the probe's colliding files sitting in a directory the user still
// owns, and neither must a pass.
func TestBackingCaseProbeCleansUpAfterItself(t *testing.T) {
	dir := t.TempDir()
	root := openProbedBacking(t, dir)
	for round := range 3 {
		_ = verifyBackingCaseSafety(root, dir)
		if names := backingEntries(t, dir); len(names) != 0 {
			t.Fatalf("round %d: the probe left %v behind in the backing root", round, names)
		}
	}
}

// TestBackingCaseProbeToleratesPreExistingProbeState covers the two ways names
// can already be present: a leftover probe directory from a crashed run, and
// files at the exact colliding names the probe uses. Neither may change the
// verdict, and neither may be left behind.
func TestBackingCaseProbeToleratesPreExistingProbeState(t *testing.T) {
	dir := t.TempDir()
	caseExact, _ := hostGroundTruth(t, dir)

	stale := filepath.Join(dir, caseProbePrefix+strings.Repeat("ab", caseProbeNonceHex/2))
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatalf("plant a stale probe directory: %v", err)
	}
	// Plant the colliding names inside it too, exactly as a crash mid-probe
	// would have left them.
	if err := os.WriteFile(filepath.Join(stale, caseProbeUpper), []byte("stale"), 0o600); err != nil {
		t.Fatalf("plant a stale probe file: %v", err)
	}
	// A rule-shaped name that merely starts with the prefix must survive: the
	// sweep is not allowed to delete anything but its own exact shape.
	bystander := filepath.Join(dir, caseProbePrefix+"not-a-nonce")
	if err := os.MkdirAll(bystander, 0o700); err != nil {
		t.Fatalf("plant a bystander directory: %v", err)
	}

	root := openProbedBacking(t, dir)
	err := verifyBackingCaseSafety(root, dir)
	if errors.Is(err, ErrBackingProbeIncomplete) {
		t.Fatalf("pre-existing probe state made the probe unable to reach a verdict: %v", err)
	}
	if caseExact != (err == nil) {
		t.Fatalf("pre-existing probe state changed the verdict (host case-exact=%t, probe err=%v)", caseExact, err)
	}
	if _, statErr := os.Stat(stale); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the stale probe directory survived the sweep: %v", statErr)
	}
	if _, statErr := os.Stat(bystander); statErr != nil {
		t.Fatalf("the sweep deleted a directory that was not a probe directory: %v", statErr)
	}
}

// TestBackingCaseProbeReportsAVanishedBackingAsIncomplete is the distinction
// that keeps the refusal honest. A backing root that disappears mid-probe says
// nothing about case behaviour, so it must not be reported as a folding backing
// - and it must certainly not be reported as a safe one.
func TestBackingCaseProbeReportsAVanishedBackingAsIncomplete(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "backing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create the backing root: %v", err)
	}
	root := openProbedBacking(t, dir)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove the backing root underneath the open capability: %v", err)
	}
	err := verifyBackingCaseSafety(root, dir)
	if err == nil {
		t.Fatal("a backing root that no longer exists must not be reported as a case-exact backing")
	}
	if errors.Is(err, ErrBackingCaseUnsafe) {
		t.Fatalf("a vanished backing root was reported as case-folding: %v", err)
	}
	if !errors.Is(err, ErrBackingProbeIncomplete) {
		t.Fatalf("a vanished backing root must report an incomplete probe, got %v", err)
	}
}

// TestOpenLocalBackingRefusesAFoldingBackingAndLeaksNothing exercises the only
// acquisition path the daemon has. A refused activation must return no
// capability at all: an open descriptor handed back alongside an error is
// exactly how a "refused" graft would end up serving.
func TestOpenLocalBackingRefusesAFoldingBacking(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "local", "storage-id")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create the backing root: %v", err)
	}
	caseExact, why := hostGroundTruth(t, dir)
	root, err := openLocalBacking(dir)
	if caseExact {
		if err != nil {
			t.Fatalf("openLocalBacking refused a case-exact backing: %v", err)
		}
		_ = root.Close()
		return
	}
	if !errors.Is(err, ErrBackingCaseUnsafe) {
		t.Fatalf("openLocalBacking on a backing that folds by %s returned %v, want ErrBackingCaseUnsafe", why, err)
	}
	if root != nil {
		_ = root.Close()
		t.Fatal("openLocalBacking returned a usable backing capability alongside its refusal")
	}
	if names := backingEntries(t, dir); len(names) != 0 {
		t.Fatalf("the refused activation left %v in the backing root", names)
	}
}
