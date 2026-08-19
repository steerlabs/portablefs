//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// The machine-local route contract, against a real kernel.
//
// These mounts stand in for different machines: they share one authority and one
// XFS volume, and each has its own per-machine backing tree. That is what makes
// "the volume never sees this" and "the other machine never sees this" two
// separate, checkable statements rather than one.

const integrationRouteDeclaration = "node_modules/\n/target/\n"

func newRoutedFixture(t *testing.T, cfg integrationConfig) *integrationFixture {
	t.Helper()
	cfg.Routes = integrationRouteDeclaration
	return newIntegrationFixture(t, cfg)
}

// authorityRequests reports the FILESYSTEM requests that crossed the wire while
// fn ran, and what they were. It is the measurement the whole mechanism exists
// to move.
//
// Session keepalive, the visibility long poll and its acknowledgments, and the
// cleanup lane are excluded: none of them is an operation on the tree, they all
// run whether or not anything is happening, and counting them would measure the
// clock rather than the filesystem.
func (f *integrationFixture) authorityRequests(fn func()) (int, string) {
	before := f.counter.filesystem()
	fn()
	after := f.counter.filesystem()
	delta := make(map[string]int, len(after))
	total := 0
	for kind, count := range after {
		if remaining := count - before[kind]; remaining > 0 {
			delta[kind] = remaining
			total += remaining
		}
	}
	return total, fmt.Sprint(delta)
}

// authorityChanges reports the requests that would change the volume or read
// its content, and what they were.
func (f *integrationFixture) authorityChanges(fn func()) (int, string) {
	before := f.counter.changes()
	fn()
	after := f.counter.changes()
	delta := make(map[string]int, len(after))
	total := 0
	for kind, count := range after {
		if remaining := count - before[kind]; remaining > 0 {
			delta[kind] = remaining
			total += remaining
		}
	}
	return total, fmt.Sprint(delta)
}

func (h *countingHandler) changes() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]int, len(h.byKind))
	for kind, count := range h.byKind {
		switch kind {
		case "mkdir", "create", "unlink", "rename", "write", "setattr", "read", "readdir":
			out[kind] = count
		}
	}
	return out
}

func (h *countingHandler) filesystem() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]int, len(h.byKind))
	for kind, count := range h.byKind {
		switch kind {
		case "keepalive", "next-visibility", "ack-visibility", "reclaim":
			continue
		}
		out[kind] = count
	}
	return out
}

// warmVolumePath resolves a shared path so that walking through it costs
// nothing later. The volume directories ABOVE a route root are ordinary shared
// directories and resolving them is ordinary authority work; what is under test
// is that nothing BELOW the root ever reaches the authority.
func warmVolumePath(t *testing.T, mount, path string) {
	t.Helper()
	for current := path; strings.HasPrefix(current, mount); current = filepath.Dir(current) {
		if _, err := os.Stat(current); err != nil && !os.IsNotExist(err) {
			t.Fatalf("warm %s: %v", current, err)
		}
		if current == mount {
			return
		}
	}
}

func TestGraftedSubtreeReachesTheAuthorityZeroTimes(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	root := f.join(0, "node_modules")
	mustMkdir(t, root)
	warmVolumePath(t, f.mountPath(0), root)

	// A dependency-tree shape: nested directories, files, a symlink, a rename,
	// a directory listing, and reading it all back. On the volume every one of
	// these is at least one authority round trip.
	count, kinds := f.authorityRequests(func() {
		for _, package_ := range []string{"lodash", "react", "typescript"} {
			mustMkdir(t, filepath.Join(root, package_))
			mustMkdir(t, filepath.Join(root, package_, "dist"))
			mustWrite(t, filepath.Join(root, package_, "package.json"), []byte(`{"name":"`+package_+`"}`), 0o644)
			mustWrite(t, filepath.Join(root, package_, "dist", "index.js"), []byte("module.exports = {}"), 0o644)
		}
		if err := os.Symlink("../lodash/dist/index.js", filepath.Join(root, "react", "linked.js")); err != nil {
			t.Fatalf("symlink inside the graft: %v", err)
		}
		if err := os.Rename(filepath.Join(root, "typescript"), filepath.Join(root, "typescript-5")); err != nil {
			t.Fatalf("rename inside the graft: %v", err)
		}
		requireDirectoryNames(t, root, []string{"lodash", "react", "typescript-5"}, "graft listing")
		requireContent(t, filepath.Join(root, "lodash", "package.json"), []byte(`{"name":"lodash"}`), "graft content")
		requireContent(t, filepath.Join(root, "react", "dist", "index.js"), []byte("module.exports = {}"), "graft content at depth")
	})
	if count != 0 {
		t.Fatalf("a dependency tree built entirely inside a graft cost %d authority requests %s, want 0", count, kinds)
	}

	// And it really is on machine-local disk, at its volume-relative path.
	if _, err := os.Stat(filepath.Join(f.backing[0], "node_modules", "lodash", "package.json")); err != nil {
		t.Fatalf("graft content is not in the machine-local backing tree: %v", err)
	}
}

func TestAGraftIsInvisibleToTheOtherMachine(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 2})
	mustMkdir(t, f.join(0, "node_modules"))
	mustWrite(t, f.join(0, "node_modules", "marker"), []byte("machine zero"), 0o644)
	// The name is owned by the rule on every mount, so the second machine sees
	// its own (absent) graft rather than the first machine's content.
	requireAbsent(t, f.join(1, "node_modules"), "the other machine's graft")
	mustMkdir(t, f.join(1, "node_modules"))
	requireAbsent(t, f.join(1, "node_modules", "marker"), "content of the other machine's graft")
	requireDirectoryNames(t, f.join(1, "node_modules"), nil, "second machine's own graft")
}

func TestTheWholesaleRebuildShapeWorksUnderAFloatingPattern(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	// The npm-ci shape at depth: a floating rule owns the name wherever it is.
	mustMkdir(t, f.join(0, "packages"))
	mustMkdir(t, f.join(0, "packages", "app"))
	root := f.join(0, "packages", "app", "node_modules")

	warmVolumePath(t, f.mountPath(0), filepath.Dir(root))
	for pass := range 3 {
		// The measurement here is deliberately of MUTATIONS and data, not of
		// every request. `rm -rf` opens the graft root's parent directory to get
		// a descriptor to unlink through, and that parent is a shared directory
		// -- opening and stat-ing it is ordinary shared work that would happen
		// whatever the entry it is about to remove turns out to be. What must
		// not happen is any of it reaching the volume as a change, or as a read
		// of content: those are the requests that would mean machine-local data
		// had escaped into shared storage.
		count, kinds := f.authorityChanges(func() {
			mustMkdir(t, root)
			for _, package_ := range []string{"a", "b", "c"} {
				mustMkdir(t, filepath.Join(root, package_))
				mustWrite(t, filepath.Join(root, package_, "index.js"), []byte("x"), 0o644)
			}
			if err := os.RemoveAll(root); err != nil {
				t.Fatalf("pass %d: rm -rf the graft root: %v", pass, err)
			}
			requireAbsent(t, root, "removed graft root")
		})
		if count != 0 {
			t.Fatalf("pass %d of the wholesale rebuild cost %d authority requests %s, want 0", pass, count, kinds)
		}
	}
	// The volume never learned any of it.
	requireDirectoryNames(t, f.join(0, "packages", "app"), nil, "the volume directory that held the graft")
}

func TestMkdirAtDepthInstantiatesARoute(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 2})
	// Build a volume path on one machine and let the other observe it, so the
	// route root is created in a directory that genuinely came from the volume.
	for _, element := range []string{"a", "a/b", "a/b/c", "a/b/c/d"} {
		mustMkdir(t, f.join(0, element))
	}
	waitUntil(t, 5*time.Second, "the volume path to reach the second machine", func() bool {
		_, err := os.Stat(f.join(1, "a/b/c/d"))
		return err == nil
	})
	root := f.join(1, "a/b/c/d/node_modules")
	warmVolumePath(t, f.mountPath(1), filepath.Dir(root))
	count, kinds := f.authorityRequests(func() { mustMkdir(t, root) })
	if count != 0 {
		t.Fatalf("instantiating a route root five levels down cost %d authority requests %s, want 0", count, kinds)
	}
	mustWrite(t, filepath.Join(root, "installed"), []byte("yes"), 0o644)
	// The first machine sees the volume directory, and nothing in it.
	requireDirectoryNames(t, f.join(0, "a/b/c/d"), nil, "the volume directory holding the other machine's graft")
}

func TestRenamingAnAncestorOfAnActiveGraftIsEBUSY(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	mustMkdir(t, f.join(0, "packages"))
	mustMkdir(t, f.join(0, "packages", "node_modules"))
	mustWrite(t, f.join(0, "packages", "node_modules", "installed"), []byte("yes"), 0o644)

	err := os.Rename(f.join(0, "packages"), f.join(0, "modules"))
	if err == nil {
		t.Fatal("renaming a shared ancestor of an active graft succeeded; the machine-local subtree would have been left behind under a name nothing resolves")
	}
	if errors.Is(err, syscall.EXDEV) {
		t.Fatal("renaming a shared ancestor of an active graft answered EXDEV; that is the errno that invites a recursive copy, and the copy would move machine-local content into shared storage")
	}
	requireErrno(t, err, syscall.EBUSY, "rename of a shared ancestor of an active graft")
	// The graft and the directory are both untouched.
	requireContent(t, f.join(0, "packages", "node_modules", "installed"), []byte("yes"), "graft after the refused rename")

	// With the machine-local content gone the same rename is ordinary: a rule
	// that owns a name nothing has created holds no data to strand.
	if err := os.RemoveAll(f.join(0, "packages", "node_modules")); err != nil {
		t.Fatalf("remove the graft: %v", err)
	}
	if err := os.Rename(f.join(0, "packages"), f.join(0, "modules")); err != nil {
		t.Fatalf("rename of an ancestor with no machine-local content: %v", err)
	}
}

func TestTheGraftBoundaryIsEXDEV(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	mustMkdir(t, f.join(0, "node_modules"))
	mustMkdir(t, f.join(0, "node_modules", "lodash"))
	mustWrite(t, f.join(0, "node_modules", "lodash", "index.js"), []byte("x"), 0o644)
	mustMkdir(t, f.join(0, "src"))
	mustWrite(t, f.join(0, "src", "main.js"), []byte("y"), 0o644)

	requireErrno(t, os.Rename(f.join(0, "node_modules", "lodash"), f.join(0, "src", "lodash")),
		syscall.EXDEV, "rename out of a graft")
	requireErrno(t, os.Rename(f.join(0, "src", "main.js"), f.join(0, "node_modules", "main.js")),
		syscall.EXDEV, "rename into a graft")
	requireErrno(t, os.Rename(f.join(0, "node_modules"), f.join(0, "target")),
		syscall.EXDEV, "rename of a route root into a different rule's subtree")
	requireErrno(t, os.Rename(f.join(0, "node_modules"), f.join(0, "modules")),
		syscall.EXDEV, "rename of a route root out onto the volume")
	requireErrno(t, os.Link(f.join(0, "node_modules", "lodash", "index.js"), f.join(0, "src", "linked.js")),
		syscall.EXDEV, "hard link out of a graft")

	// Renames entirely inside one graft are ordinary.
	if err := os.Rename(f.join(0, "node_modules", "lodash"), f.join(0, "node_modules", "lodash-4")); err != nil {
		t.Fatalf("rename inside one graft: %v", err)
	}
}

func TestGraftDentriesRemainUsableAcrossRenameUnlinkAndHardlink(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	root := f.join(0, "node_modules")
	mustMkdir(t, root)

	mustWrite(t, filepath.Join(root, "before.js"), []byte("renamed"), 0o644)
	if err := os.Rename(filepath.Join(root, "before.js"), filepath.Join(root, "after.js")); err != nil {
		t.Fatalf("rename grafted file: %v", err)
	}
	requireContent(t, filepath.Join(root, "after.js"), []byte("renamed"), "renamed grafted file")

	mustMkdir(t, filepath.Join(root, "before-dir"))
	if err := os.Rename(filepath.Join(root, "before-dir"), filepath.Join(root, "after-dir")); err != nil {
		t.Fatalf("rename grafted directory: %v", err)
	}
	mustWrite(t, filepath.Join(root, "after-dir", "child"), []byte("nested"), 0o644)
	requireContent(t, filepath.Join(root, "after-dir", "child"), []byte("nested"), "child created through a renamed graft directory")

	mustWrite(t, filepath.Join(root, "source"), []byte("linked"), 0o644)
	if err := os.Link(filepath.Join(root, "source"), filepath.Join(root, "alias")); err != nil {
		t.Fatalf("hard link inside graft: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "source")); err != nil {
		t.Fatalf("unlink hardlink source: %v", err)
	}
	requireContent(t, filepath.Join(root, "alias"), []byte("linked"), "surviving graft hardlink")

	if err := os.Remove(filepath.Join(root, "after.js")); err != nil {
		t.Fatalf("unlink renamed grafted file: %v", err)
	}
	mustWrite(t, filepath.Join(root, "after.js"), []byte("replacement"), 0o644)
	requireContent(t, filepath.Join(root, "after.js"), []byte("replacement"), "recreated grafted name")
}

func TestCreateAtAnUncreatedRouteRootIsEISDIR(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	_, err := os.OpenFile(f.join(0, "node_modules"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err == nil {
		t.Fatal("a file was created at a route root; a rule is a directory rule and the root can only ever be a directory")
	}
	requireErrno(t, err, syscall.EISDIR, "create at a route root")
	requireErrno(t, os.Symlink("elsewhere", f.join(0, "node_modules")), syscall.EISDIR, "symlink at a route root")
}

func TestARouteRootShadowsTheVolumeSubtreeOfTheSameName(t *testing.T) {
	// The volume already holds a directory the rule owns the name of. Nothing
	// is deleted; the volume's copy is simply not what this mount serves.
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	mustMkdir(t, f.join(0, "node_modules"))
	mustWrite(t, f.join(0, "node_modules", "shared.js"), []byte("from the volume"), 0o644)
	f.shutdown()

	routed := newRoutedFixture(t, integrationConfig{Mounts: 1})
	// The volume's node_modules is shadowed unconditionally, whether or not
	// this machine has created its own.
	requireAbsent(t, routed.join(0, "node_modules"), "the volume subtree the rule owns the name of")
	names := directoryNames(t, routed.mountPath(0))
	if slices.Contains(names, "node_modules") {
		t.Fatalf("listing %v still shows the volume's node_modules; the rule owns the name unconditionally", names)
	}
	mustMkdir(t, routed.join(0, "node_modules"))
	requireAbsent(t, routed.join(0, "node_modules", "shared.js"), "volume content under a graft")
	// The route root appears exactly once, and it is the machine-local one.
	// (.portablefs is the volume's own protected namespace, which holds the
	// routing declaration itself and is not a graft concern.)
	after := directoryNames(t, routed.mountPath(0))
	if count := slices.Index(after, "node_modules"); count < 0 {
		t.Fatalf("listing %v does not show the instantiated route root", after)
	}
	if slices.Contains(after[slices.Index(after, "node_modules")+1:], "node_modules") {
		t.Fatalf("listing %v shows the route root twice", after)
	}
}

func TestSharedPathsKeepTheirCoherenceWithRoutesConfigured(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 2})
	// Machine-local routes must not weaken anything about the shared volume.
	// Each mount also builds its own graft, so the barrier is running with
	// grafted work in flight alongside the shared work it is coordinating.
	for i := range 2 {
		mustMkdir(t, f.join(i, "node_modules"))
		mustWrite(t, f.join(i, "node_modules", "local.js"), []byte("machine only"), 0o644)
	}
	mustMkdir(t, f.join(0, "src"))
	mustWrite(t, f.join(0, "src", "main.go"), []byte("package main"), 0o644)
	// Every one of these is the repaired-before-return guarantee: the mutating
	// syscall on mount 0 has already returned, so mount 1 must not be able to
	// observe the previous state.
	requireContent(t, f.join(1, "src", "main.go"), []byte("package main"), "cross-mount content with routes configured")
	mustWrite(t, f.join(0, "src", "main.go"), []byte("package main // v2"), 0o644)
	requireContent(t, f.join(1, "src", "main.go"), []byte("package main // v2"), "cross-mount rewrite with routes configured")
	if err := os.Remove(f.join(0, "src", "main.go")); err != nil {
		t.Fatalf("remove on mount 0: %v", err)
	}
	requireAbsent(t, f.join(1, "src", "main.go"), "cross-mount unlink with routes configured")
	requireDirectoryNames(t, f.join(1, "src"), nil, "cross-mount listing with routes configured")
	// And the grafts stayed machine-local throughout.
	requireContent(t, f.join(0, "node_modules", "local.js"), []byte("machine only"), "graft on mount 0")
	requireContent(t, f.join(1, "node_modules", "local.js"), []byte("machine only"), "graft on mount 1")
}

// A route change is committed only at clean mount absence. LOCAL graft cache
// has no authority TTL, so no acknowledgment and no fencing can prove that a
// kernel on the old revision stopped serving it; the only proof is that no
// mount exists. Route declarations are therefore installed before mounts, and
// a change attempted underneath live mounts is refused without disturbing them.
func TestARoutingChangeIsRefusedWhileAnyMountIsLive(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 2})
	mustMkdir(t, f.join(0, "node_modules"))
	mustWrite(t, f.join(0, "node_modules", "installed"), []byte("yes"), 0o644)

	current := f.cfg.rules.Revision()
	changed, err := ActivateRoutes([]byte(integrationRouteDeclaration + "vendor/\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A mount cannot change routing; only the authority's own operator path can,
	// which is exactly the asymmetry that makes the revision meaningful.
	if _, err := f.clients[0].ApplyRoutes(t.Context(), changed.Canonical(), current); err == nil {
		t.Fatal("a mount session was allowed to change the volume's routing topology")
	}
	// The operator path is refused too, and for a different reason: the mounts
	// are live. The refusal names clean mount absence, and it is an ordinary
	// retryable answer rather than a half-applied topology.
	if _, err := f.routes.Apply(t.Context(), changed.Canonical(), current); !errors.Is(err, volumeserver.ErrLeaseRoutesLive) {
		t.Fatalf("ApplyRoutes with live mounts = %v, want %v", err, volumeserver.ErrLeaseRoutesLive)
	}
	if active, err := f.routes.Revision(); err != nil {
		t.Fatal(err)
	} else if active != current {
		t.Fatal("a refused routing change moved the volume's active revision")
	}

	// A refused change is not a disturbance: both mounts keep serving, on the
	// revision they agreed to at attach.
	requireContent(t, f.join(0, "node_modules", "installed"), []byte("yes"), "graft after a refused routing change")
	mustWrite(t, f.join(0, "shared.txt"), []byte("still serving"), 0o644)
	requireContent(t, f.join(1, "shared.txt"), []byte("still serving"), "cross-mount write after a refused routing change")
	for i := range 2 {
		if cause := f.mounts[i].fatalError(); cause != nil {
			t.Fatalf("mount %d died on a refused routing change: %v", i, cause)
		}
	}

	// At clean absence the same change commits, and the next mount serves the
	// new topology: vendor/ becomes machine-local, so it costs the authority
	// nothing and cannot be seen from the other machine.
	f.unmountAll()
	if _, err := f.routes.Apply(t.Context(), changed.Canonical(), current); err != nil {
		t.Fatalf("apply a routing change at clean mount absence: %v", err)
	}
	f.cfg.rules = changed
	f.mountAll()

	mustMkdir(t, f.join(0, "vendor"))
	warmVolumePath(t, f.mountPath(0), f.join(0, "vendor"))
	count, kinds := f.authorityRequests(func() {
		mustWrite(t, f.join(0, "vendor", "local.js"), []byte("machine only"), 0o644)
	})
	if count != 0 {
		t.Fatalf("writing under the newly routed root cost %d authority requests %s, want 0", count, kinds)
	}
	requireAbsent(t, f.join(1, "vendor", "local.js"), "the newly routed root on the other machine")
}

func TestGraftedFileDescriptorsSurviveTheRootBeingRebuilt(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	root := f.join(0, "node_modules")
	mustMkdir(t, root)
	mustWrite(t, filepath.Join(root, "pinned.js"), []byte("still here"), 0o644)
	file := mustOpenFile(t, filepath.Join(root, "pinned.js"), os.O_RDONLY, 0)

	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("rm -rf the graft root: %v", err)
	}
	mustMkdir(t, root)
	// Exactly what an open descriptor on a local filesystem does: the file is
	// unlinked, the descriptor still reads it.
	if got := readExactlyAt(t, file, 0, len("still here"), "descriptor into a rebuilt graft"); string(got) != "still here" {
		t.Fatalf("descriptor into a rebuilt graft read %q", got)
	}
}

func TestGraftsCarryARealWorkloadWithoutTheAuthority(t *testing.T) {
	f := newRoutedFixture(t, integrationConfig{Mounts: 1})
	requireWorkloadEnvironment(t)
	mustMkdir(t, f.join(0, "node_modules"))
	warmVolumePath(t, f.mountPath(0), f.join(0, "node_modules"))
	// tar is a metadata-heavy real tool: it creates directories, writes files,
	// sets modification times, and reads the tree back.
	source := t.TempDir()
	mustMkdir(t, filepath.Join(source, "pkg"))
	mustWrite(t, filepath.Join(source, "pkg", "a.js"), []byte("a"), 0o644)
	mustWrite(t, filepath.Join(source, "pkg", "b.js"), []byte("b"), 0o644)
	archive := filepath.Join(t.TempDir(), "pkg.tar")
	f.runWorkload("tar", "-cf", archive, "-C", source, "pkg")

	count, kinds := f.authorityRequests(func() {
		f.runWorkload("tar", "-xf", archive, "-C", f.join(0, "node_modules"))
	})
	if count != 0 {
		t.Fatalf("extracting an archive into a graft cost %d authority requests %s, want 0", count, kinds)
	}
	requireContent(t, f.join(0, "node_modules", "pkg", "a.js"), []byte("a"), "extracted graft content")
	if _, err := exec.LookPath("tar"); err != nil {
		t.Fatal(err)
	}
}
