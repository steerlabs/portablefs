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

func TestFSKitConfigRejectsSocketOverrides(t *testing.T) {
	for _, variable := range []string{fskitSocketEnv, fskitControlEnv} {
		t.Run(variable, func(t *testing.T) {
			_, err := fskitConfigFromEnv(func(name string) string {
				if name == variable {
					return "/tmp/untrusted.sock"
				}
				return ""
			})
			if err == nil || !strings.Contains(err.Error(), variable+" is unsupported") {
				t.Fatalf("expected unsupported socket override error, got %v", err)
			}
		})
	}
}

func TestFSKitConfigUsesOnlyCanonicalExternalControlState(t *testing.T) {
	home, err := resolveFSKitAccountHome()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := fskitConfigFromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".local", "state", "portablefs", "portablefsd", "control.sock")
	if cfg.controlSock != want {
		t.Fatalf("control socket = %q, want %q", cfg.controlSock, want)
	}
	if strings.Contains(cfg.controlSock, "Group Containers") {
		t.Fatalf("shell CLI control entered the app-group path: %q", cfg.controlSock)
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
		t.Fatalf("expected the test executable to have no embedded service peer, got %s", got)
	}
	if strings.Contains(err.Error(), pathCandidate) {
		t.Fatalf("PATH candidate leaked into exact-sibling resolution: %v", err)
	}
}

func TestExactPortablefsdPathUsesSealedServiceApp(t *testing.T) {
	app := filepath.Join(t.TempDir(), "PortableFS.app")
	cli := filepath.Join(app, "Contents", "Helpers", "portablefs")
	if err := os.MkdirAll(filepath.Dir(cli), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutablePeer(t, cli, "cli")

	got, err := exactPortablefsdPath(cli)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(
		app,
		"Contents", "Library", "LaunchAgents", "PortableFSDService.app",
		"Contents", "MacOS", "portablefsd",
	)
	if got != want {
		t.Fatalf("daemon path = %q, want %q", got, want)
	}
}

func TestExactPortablefsdPathRejectsUnsealedCLI(t *testing.T) {
	cli := filepath.Join(t.TempDir(), "portablefs")
	writeExecutablePeer(t, cli, "cli")
	if _, err := exactPortablefsdPath(cli); err == nil ||
		!strings.Contains(err.Error(), "Contents/Helpers") {
		t.Fatalf("unsealed CLI error = %v", err)
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
