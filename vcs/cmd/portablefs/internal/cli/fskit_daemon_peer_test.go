package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutablePeer(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestFSKitConfigRejectsDaemonOverride(t *testing.T) {
	_, err := fskitConfigFromEnv(func(name string) string {
		if name == fskitDaemonEnv {
			return "/tmp/untrusted-portablefsd"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), fskitDaemonEnv+" is unsupported") {
		t.Fatalf("expected unsupported daemon override error, got %v", err)
	}
}

func TestFindPortablefsdNeverSearchesPATH(t *testing.T) {
	dir := t.TempDir()
	pathCandidate := filepath.Join(dir, "portablefsd")
	writeExecutablePeer(t, pathCandidate, "not the embedded peer")
	t.Setenv("PATH", dir)

	got, err := findPortablefsd("")
	if err == nil {
		if got == pathCandidate {
			t.Fatalf("findPortablefsd selected PATH candidate %s", got)
		}
		t.Fatalf("expected the test executable to have no embedded sibling, got %s", got)
	}
	if strings.Contains(err.Error(), pathCandidate) {
		t.Fatalf("PATH candidate leaked into exact-sibling resolution: %v", err)
	}
}

func TestOpenPortablefsdPeerRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-portablefsd")
	writeExecutablePeer(t, target, "peer")
	link := filepath.Join(dir, "portablefsd")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := openPortablefsdPeer(link)
	if err == nil {
		t.Fatal("expected final symlink to be rejected")
	}
}

func TestPortablefsdPeerDetectsNamedInodeReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portablefsd")
	writeExecutablePeer(t, path, "original peer")
	peer, err := openPortablefsdPeer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.close()

	oldPath := filepath.Join(dir, "portablefsd.old")
	if err := os.Rename(path, oldPath); err != nil {
		t.Fatal(err)
	}
	writeExecutablePeer(t, path, "replacement peer")

	err = peer.validate()
	if err == nil || !strings.Contains(err.Error(), "changed while pinned") {
		t.Fatalf("expected pinned inode replacement error, got %v", err)
	}
}
