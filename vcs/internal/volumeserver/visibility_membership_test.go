package volumeserver

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileVisibilityMembershipSurvivesRestartUntilFencingProof(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "strict-membership")
	registry, disposition, err := OpenFileVisibilityMembership(path, "volume-a", false)
	if err != nil || disposition != PriorEpochStrictMountsFenced {
		t.Fatalf("open fresh membership = %v, %v", disposition, err)
	}
	id := SessionID{1}
	if err := registry.Activate(id); err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, disposition, err := OpenFileVisibilityMembership(path, "volume-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != PriorEpochUnproven {
		t.Fatalf("restart disposition = %v, want unproven", disposition)
	}
	if _, _, err := OpenFileVisibilityMembership(path, "volume-a", false); err == nil {
		t.Fatal("second authority acquired the same membership lock")
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}

	fenced, disposition, err := OpenFileVisibilityMembership(path, "volume-a", true)
	if err != nil || disposition != PriorEpochStrictMountsFenced {
		t.Fatalf("open after fencing proof = %v, %v", disposition, err)
	}
	if len(fenced.active) != 0 {
		t.Fatal("fencing proof did not clear prior membership")
	}
	if err := fenced.Close(); err != nil {
		t.Fatal(err)
	}
}

// -prior-strict-mounts-fenced stays an explicit human assertion, but it stops
// being an invisible one: the exact mounts it erased are durably recorded and
// reported before the record it erases is rewritten.
func TestFileVisibilityMembershipAuditsOperatorAssertedFencing(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "strict-membership")
	registry, _, err := OpenFileVisibilityMembership(path, "volume-a", false)
	if err != nil {
		t.Fatal(err)
	}
	first, second := SessionID{1}, SessionID{2}
	for _, id := range []SessionID{first, second} {
		if err := registry.Activate(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}

	fenced, disposition, err := OpenFileVisibilityMembership(path, "volume-a", true)
	if err != nil || disposition != PriorEpochStrictMountsFenced {
		t.Fatalf("open after fencing proof = %v, %v", disposition, err)
	}
	defer fenced.Close()
	cleared := fenced.ClearedByOperatorAssertion()
	if len(cleared) != 2 || cleared[0] != first || cleared[1] != second {
		t.Fatalf("cleared set = %x, want both prior mounts", cleared)
	}
	audit, err := os.ReadFile(path + visibilityMembershipAuditSuffix)
	if err != nil {
		t.Fatalf("read durable audit: %v", err)
	}
	for _, id := range cleared {
		if !strings.Contains(string(audit), hex.EncodeToString(id[:])) {
			t.Fatalf("audit does not name cleared mount %x:\n%s", id, audit)
		}
	}
	if strings.Count(string(audit), "prior-strict-mounts-fenced") != 2 {
		t.Fatalf("audit did not record one assertion per cleared mount:\n%s", audit)
	}

	// A run that clears nothing asserts nothing.
	if err := fenced.Close(); err != nil {
		t.Fatal(err)
	}
	again, _, err := OpenFileVisibilityMembership(path, "volume-a", true)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if len(again.ClearedByOperatorAssertion()) != 0 {
		t.Fatal("an empty record reported an operator assertion")
	}
}

func TestFileVisibilityMembershipIsBoundToOneVolume(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "strict-membership")
	registry, _, err := OpenFileVisibilityMembership(path, "volume-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenFileVisibilityMembership(path, "volume-b", false); err == nil {
		t.Fatal("membership file was accepted for a different volume")
	}
}
