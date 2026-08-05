package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// skipWithoutFUSE gates the real-kernel-mount tests on the prerequisites that
// can be checked without attempting a mount. Some containerized Linux hosts
// expose /dev/fuse and a helper but still deny the mount syscall; that final
// capability is handled by skipIfFUSEMountForbidden below. The graft semantics
// are pinned unconditionally by vcs/internal/localdirs's unit tests; this file
// proves the kernel-facing wiring end to end where a kernel mount is permitted.
func skipWithoutFUSE(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("real-FUSE test requires linux")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("/dev/fuse not available")
	}
	if _, err := exec.LookPath("fusermount3"); err != nil {
		if _, err := exec.LookPath("fusermount"); err != nil {
			t.Skip("fusermount3/fusermount not in PATH")
		}
	}
}

// skipIfFUSEMountForbidden distinguishes a host capability restriction from a
// PortableFS mount failure. EPERM while go-fuse is performing the kernel mount
// means the test host does not permit FUSE (for example, an unprivileged CI
// container). Every other error remains a hard test failure.
func skipIfFUSEMountForbidden(t *testing.T, err error) {
	t.Helper()
	if err != nil &&
		strings.HasPrefix(err.Error(), "mount ") &&
		(errors.Is(err, syscall.EPERM) || strings.Contains(strings.ToLower(err.Error()), "operation not permitted")) {
		t.Skipf("host does not permit a real FUSE mount: %v", err)
	}
}

// seedClient returns an fsproto client for direct authority writes/asserts.
func seedClient(t *testing.T, addr string) *fsproto.Client {
	t.Helper()
	c, err := fsproto.Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func seedFile(t *testing.T, c *fsproto.Client, path, content string) {
	t.Helper()
	if _, st, err := c.Create(path, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create %s: st=%d err=%v", path, st, err)
	}
	if _, st, err := c.Write(path, 0, []byte(content), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed write %s: st=%d err=%v", path, st, err)
	}
}

func seedMkdir(t *testing.T, c *fsproto.Client, path string) {
	t.Helper()
	if _, st, err := c.Mkdir(path, 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("seed mkdir %s: st=%d err=%v", path, st, err)
	}
}

func lsNames(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// TestFUSELocalDirsEndToEnd drives the full graft contract through a real
// kernel mount: shadowing, root lifecycle, EXDEV, readdir merge, the npm-ci
// wholesale rebuild, ancestor-rename carry, no authority I/O under grafts,
// and the .portablefs/local-dirs volume declaration.
func TestFUSELocalDirsEndToEnd(t *testing.T) {
	skipWithoutFUSE(t)
	addr := newTestAuthority(t)
	seed := seedClient(t, addr)

	// Volume content: a Linux-native node_modules (the shadow target), an app
	// tree, and an in-volume graft declaration for "target".
	seedMkdir(t, seed, "agent-app")
	seedMkdir(t, seed, "agent-app/node_modules")
	seedFile(t, seed, "agent-app/node_modules/linux-only.so", "volume binary")
	seedFile(t, seed, "agent-app/package.json", `{"scripts":{"dev":"vite"}}`)
	seedMkdir(t, seed, ".portablefs")
	// The volume DECLARES its routes; routing is volume-wide state, so this
	// file is the only source of it and of the revision every mount reports.
	seedFile(t, seed, localdirs.VolumeConfigPath, "# machine-local dirs\ntarget/\n/agent-app/node_modules/\n")

	mnt := t.TempDir()
	backing := filepath.Join(t.TempDir(), "local", "sid")
	m, err := mountFUSE(addr, &sessionTokenSource{}, dataPlaneTransport{Mode: dataPlaneTransportPlaintext}, mnt, "mnt_AAAAAAAAAAAAAAAAAAAAAA", "direct", "", perfOptions{}, localDirsMountConfig{
		backingRoot: backing,
	})
	if err != nil {
		skipIfFUSEMountForbidden(t, err)
		t.Fatalf("mountFUSE: %v", err)
	}
	installTestDirectDetach(t, m, mnt, "mnt_AAAAAAAAAAAAAAAAAAAAAA")
	unmounted := false
	t.Cleanup(func() {
		if !unmounted {
			if err := m.Unmount(); err != nil {
				t.Errorf("cleanup unmount: %v", err)
			}
			if err := m.Wait(); err != nil {
				t.Errorf("cleanup wait: %v", err)
			}
		}
	})
	// The mount serves exactly what the volume declares, and answers for
	// exactly that declaration's revision — the value every peer computes
	// from the same bytes.
	if got := strings.Join(m.routes.rules.Patterns(), " "); got != "**/target/ /agent-app/node_modules/" {
		t.Fatalf("effective routes = %q (the volume declaration)", got)
	}
	declared, err := localroutes.Parse([]byte("# machine-local dirs\ntarget/\n/agent-app/node_modules/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.routes.revision != declared.RevisionHex() || m.routes.perMachine || !m.routes.declared {
		t.Fatalf("reported revision = %q perMachine=%v declared=%v; it must be the declaration's alone",
			m.routes.revision, m.routes.perMachine, m.routes.declared)
	}
	// A per-machine addition on a volume that declares its routes is refused:
	// it would hide from this machine a directory every peer treats as
	// shared, and no revision could describe that honestly.
	if _, err := resolveRoutes(context.Background(), m.vol, localDirsMountConfig{
		dirs:        []string{"crates/target"},
		backingRoot: backing,
	}); err == nil || !strings.Contains(err.Error(), localdirs.VolumeConfigPath) {
		t.Fatalf("--local-dir on a declaring volume = %v, want an actionable refusal", err)
	}

	app := filepath.Join(mnt, "agent-app")
	nm := filepath.Join(app, "node_modules")

	// Shadowing: the rule owns the name outright — the volume's subtree is
	// hidden even before any local directory exists.
	if _, err := os.Lstat(nm); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("pre-mkdir lstat = %v, want ENOENT", err)
	}
	if got := lsNames(t, app); got != "package.json" {
		t.Fatalf("pre-mkdir listing = %q", got)
	}

	// mkdir starts the machine-local view empty; content round-trips.
	if err := os.Mkdir(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := lsNames(t, nm); got != "" {
		t.Fatalf("fresh graft listing = %q, want empty (volume subtree stays hidden)", got)
	}
	if err := os.WriteFile(filepath.Join(nm, "darwin-or-linux-dep"), []byte("local bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(nm, "darwin-or-linux-dep"))
	if err != nil || string(data) != "local bytes" {
		t.Fatalf("graft read = %q, %v", data, err)
	}
	if got := lsNames(t, app); got != "node_modules,package.json" {
		t.Fatalf("merged listing = %q", got)
	}

	// The rest of the tree still comes from the volume.
	pkg, err := os.ReadFile(filepath.Join(app, "package.json"))
	if err != nil || string(pkg) != `{"scripts":{"dev":"vite"}}` {
		t.Fatalf("volume read = %q, %v", pkg, err)
	}

	// Inode identity: graft inos live in the marked local range.
	var st syscall.Stat_t
	if err := syscall.Lstat(nm, &st); err != nil {
		t.Fatal(err)
	}
	if st.Ino&(1<<63) == 0 {
		t.Fatalf("graft root ino %x lacks the local marker bit", st.Ino)
	}

	// EXDEV at the boundary, both directions and for the root itself.
	if err := os.Rename(filepath.Join(nm, "darwin-or-linux-dep"), filepath.Join(app, "escaped")); !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("graft->volume rename = %v, want EXDEV", err)
	}
	if err := os.Rename(filepath.Join(app, "package.json"), filepath.Join(nm, "entered")); !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("volume->graft rename = %v, want EXDEV", err)
	}
	if err := os.Rename(nm, filepath.Join(app, "node_modules_old")); !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("root rename = %v, want EXDEV", err)
	}

	// A graft rule is a directory rule.
	if _, err := os.Create(filepath.Join(mnt, "target")); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("create at graft root = %v, want EISDIR", err)
	}

	// npm-ci wholesale rebuild: rm -rf, honest absence, recreate empty.
	if err := os.RemoveAll(nm); err != nil {
		t.Fatalf("rm -rf graft root: %v", err)
	}
	if got := lsNames(t, app); got != "package.json" {
		t.Fatalf("post-removal listing = %q (no phantom root)", got)
	}
	if err := os.Mkdir(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := lsNames(t, nm); got != "" {
		t.Fatalf("recreated graft listing = %q", got)
	}
	if err := os.WriteFile(filepath.Join(nm, "fresh.txt"), []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Open handles survive rm -rf of the root (delete-on-last-close via fd).
	held, err := os.OpenFile(filepath.Join(nm, "held.txt"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.WriteString("held bytes"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(nm); err != nil {
		t.Fatalf("rm -rf with open handle: %v", err)
	}
	if _, err := held.WriteAt([]byte("HELD"), 0); err != nil {
		t.Fatalf("write after unlink: %v", err)
	}
	buf := make([]byte, 16)
	n, _ := held.ReadAt(buf, 0)
	if string(buf[:n]) != "HELD bytes" {
		t.Fatalf("read after unlink = %q", buf[:n])
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nm, 0o755); err != nil {
		t.Fatal(err)
	}

	// Renaming a shared ancestor of ACTIVE machine-local backing is EBUSY —
	// the errno Linux gives for renaming a directory that contains a mount
	// point. Not EXDEV: a copy+delete fallback would copy machine-local
	// backing into shared storage.
	if err := os.WriteFile(filepath.Join(nm, "keep.txt"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(app, filepath.Join(mnt, "agent-app-v2")); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("ancestor rename over active backing = %v, want EBUSY", err)
	}
	// Nothing moved, and the declared routing is untouched.
	if got, err := os.ReadFile(filepath.Join(nm, "keep.txt")); err != nil || string(got) != "kept" {
		t.Fatalf("refused rename disturbed the backing: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(mnt, "agent-app-v2")); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("refused rename left a destination behind: %v", err)
	}
	// A shared directory with no machine-local backing under it, whose move
	// changes nothing about what the rules route, renames normally.
	if err := os.Mkdir(filepath.Join(mnt, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(mnt, "docs"), filepath.Join(mnt, "papers")); err != nil {
		t.Fatalf("ordinary shared rename must still work: %v", err)
	}

	// The in-volume declaration routes "target" at ANY depth: a directory
	// created deep in the tree becomes a graft root the moment it matches,
	// with no configured list naming it.
	deep := filepath.Join(app, "crates", "engine", "target")
	if err := os.MkdirAll(filepath.Join(app, "crates", "engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "debug.bin"), []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := lsNames(t, filepath.Join(app, "crates", "engine")); got != "target" {
		t.Fatalf("deep listing = %q", got)
	}

	// The authority never saw ANY graft content — the shadowed subtree is
	// intact and the local names do not exist volume-side.
	if a, st, err := seed.Getattr("agent-app/node_modules/linux-only.so"); err != nil || st != fsproto.OK || a.Size != int64(len("volume binary")) {
		t.Fatalf("authority shadowed file st=%d attr=%+v err=%v", st, a, err)
	}
	for _, p := range []string{
		"agent-app/node_modules/keep.txt",
		"agent-app/node_modules/fresh.txt",
		"agent-app/crates/engine/target/debug.bin",
	} {
		if _, st, err := seed.Getattr(p); err != nil || st != fsproto.ENOENT {
			t.Fatalf("authority must never see %s: st=%d err=%v", p, st, err)
		}
	}

	if err := m.Unmount(); err != nil {
		t.Fatal(err)
	}
	if err := m.Wait(); err != nil {
		t.Fatal(err)
	}
	unmounted = true
}

// TestFUSELocalDirsComposeWithWriteback proves grafts and the adaptive
// write-back engine compose: volume writes drain to the authority at unmount
// while graft writes stay local.
func TestFUSELocalDirsComposeWithWriteback(t *testing.T) {
	skipWithoutFUSE(t)
	addr := newTestAuthority(t)
	seed := seedClient(t, addr)

	mnt := t.TempDir()
	m, err := mountFUSE(addr, &sessionTokenSource{}, dataPlaneTransport{Mode: dataPlaneTransportPlaintext}, mnt, "mnt_BBBBBBBBBBBBBBBBBBBBBB", "direct", "", perfOptionsFromEnv(func(string) string { return "" }), localDirsMountConfig{
		dirs:        []string{"node_modules"},
		backingRoot: filepath.Join(t.TempDir(), "local", "sid"),
	})
	if err != nil {
		skipIfFUSEMountForbidden(t, err)
		t.Fatalf("mountFUSE: %v", err)
	}
	installTestDirectDetach(t, m, mnt, "mnt_BBBBBBBBBBBBBBBBBBBBBB")
	unmounted := false
	defer func() {
		if !unmounted {
			if err := m.Unmount(); err != nil {
				t.Errorf("cleanup unmount: %v", err)
			}
			if err := m.Wait(); err != nil {
				t.Errorf("cleanup wait: %v", err)
			}
		}
	}()

	if err := os.Mkdir(filepath.Join(mnt, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mnt, "node_modules", "dep.js"), []byte("local"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mnt, "src.go"), []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The unmount drain barrier flushes any delegated write-back tail.
	if err := m.Unmount(); err != nil {
		t.Fatal(err)
	}
	if err := m.Wait(); err != nil {
		t.Fatal(err)
	}
	unmounted = true

	if data, st, err := seed.Read("src.go", 0, 64); err != nil || st != fsproto.OK || string(data) != "shared" {
		t.Fatalf("volume write must drain at unmount: %q st=%d err=%v", data, st, err)
	}
	if _, st, err := seed.Getattr("node_modules/dep.js"); err != nil || st != fsproto.ENOENT {
		t.Fatalf("graft write must never flush: st=%d err=%v", st, err)
	}
}

func installTestDirectDetach(t *testing.T, m *fuseMount, mountPath, mountInstanceID string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("direct FUSE detach test helper is Linux-only")
	}
	kernelMountID, err := captureFUSEKernelMountID(mountPath, mountInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	state := mountState{
		MountPath:       mountPath,
		Strategy:        "fuse",
		MountInstanceID: mountInstanceID,
		KernelMountID:   kernelMountID,
		MountMechanism:  "direct",
	}
	m.detachExact = func() error { return platformUnmountRecorded(&state) }
}
