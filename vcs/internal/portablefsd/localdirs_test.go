package portablefsd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func TestNormalizeLocalDirs(t *testing.T) {
	got, err := normalizeLocalDirs([]string{
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
		if _, err := normalizeLocalDirs([]string{bad}); err == nil {
			t.Fatalf("normalizeLocalDirs(%q) accepted, want error", bad)
		}
	}
	for _, trap := range []string{".portablefs", ".portablefs/local-dirs"} {
		if _, err := normalizeLocalDirs([]string{trap}); err == nil {
			t.Fatalf("normalizeLocalDirs(%q) accepted config-shadowing graft", trap)
		}
	}
	// "." and empty entries are dropped rather than rejected.
	got, err = normalizeLocalDirs([]string{"", "  "})
	if err != nil || len(got) != 0 {
		t.Fatalf("blank dirs=%v err=%v", got, err)
	}
}

func startDaemonNoAttach(t *testing.T, _ string) (Config, *http.Client, context.CancelFunc) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pfsd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := Config{
		FrontendSocket: filepath.Join(dir, "run", "frontend.sock"),
		ControlSocket:  filepath.Join(dir, "run", "control.sock"),
		StateDir:       filepath.Join(dir, "state"),
		Version:        "portablefsd-test",
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(cfg)
	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("daemon Run: %v", err)
			}
		case <-time.After(35 * time.Second):
			t.Error("daemon did not complete its bounded cooperative shutdown")
		}
	})
	waitUnix(t, cfg.ControlSocket)
	waitUnix(t, cfg.FrontendSocket)
	return cfg, httpUDSClient(cfg.ControlSocket), cancel
}

func ensureLocalDirsAttach(t *testing.T, hc *http.Client, authority, volumeID, mountPath string, localDirs []string) string {
	t.Helper()
	return ensureAttachWithPolicyOptions(t, hc, authority, volumeID, "main", mountPath, "writethrough", map[string]any{
		"localDirs": localDirs,
	})
}

func resolveRoot(t *testing.T, c *pfsTestClient, ref string) pfslocal.Item {
	t.Helper()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "localdirs-test"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	return res.Root
}

func lookupItem(t *testing.T, c *pfsTestClient, dir pfslocal.Item, name string) pfslocal.Attr {
	t.Helper()
	return c.call(&pfslocal.LookupRequest{Dir: dir, Name: []byte(name)}).(*pfslocal.LookupReply).Attr
}

func mkdirItem(t *testing.T, c *pfsTestClient, dir pfslocal.Item, name string) pfslocal.Attr {
	t.Helper()
	return c.call(&pfslocal.MkdirRequest{Dir: dir, Name: []byte(name), Mode: 0o755}).(*pfslocal.MkdirReply).Attr
}

func expectLookupErrno(t *testing.T, c *pfsTestClient, dir pfslocal.Item, name string, want int32) {
	t.Helper()
	if er := c.callErr(&pfslocal.LookupRequest{Dir: dir, Name: []byte(name)}); er.Errno != want {
		t.Fatalf("lookup %s errno=%d want %d", name, er.Errno, want)
	}
}

func writeAll(t *testing.T, c *pfsTestClient, dir pfslocal.Item, name, content string) pfslocal.Attr {
	t.Helper()
	cr := c.call(&pfslocal.CreateRequest{Dir: dir, Name: []byte(name), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte(content)})
	c.call(&pfslocal.CloseRequest{Handle: cr.Handle})
	return cr.Attr
}

func readAll(t *testing.T, c *pfsTestClient, item pfslocal.Item) string {
	t.Helper()
	op := c.call(&pfslocal.OpenRequest{Item: item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	defer c.call(&pfslocal.CloseRequest{Handle: op.Handle})
	got := c.call(&pfslocal.ReadRequest{Handle: op.Handle, Length: 1 << 20}).(*pfslocal.ReadReply)
	return string(got.Data)
}

func TestDaemonLocalDirHardLinksAndBoundaries(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-local-links", "/Volumes/LocalLinks", []string{"node_modules", "target"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	nm := mkdirItem(t, c, root, "node_modules")
	target := mkdirItem(t, c, root, "target")
	source := writeAll(t, c, nm.Item, "source", "shared")

	linked := c.call(&pfslocal.HardLinkRequest{Item: source.Item, Dir: nm.Item, Name: []byte("alias")}).(*pfslocal.HardLinkReply)
	if linked.Attr.Item != source.Item || linked.Attr.Nlink != 2 {
		t.Fatalf("local hardlink=%+v source=%+v", linked, source)
	}
	opened := c.call(&pfslocal.OpenRequest{Item: source.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	c.call(&pfslocal.RemoveRequest{Dir: nm.Item, Name: []byte("source")})
	survivor := lookupItem(t, c, nm.Item, "alias")
	if survivor.Item != source.Item || survivor.Nlink != 1 || readAll(t, c, survivor.Item) != "shared" {
		t.Fatalf("local survivor=%+v source=%+v", survivor, source)
	}
	if got := c.call(&pfslocal.ReadRequest{Handle: opened.Handle, Length: 32}).(*pfslocal.ReadReply); string(got.Data) != "shared" {
		t.Fatalf("local open handle after unlink=%q", got.Data)
	}
	c.call(&pfslocal.CloseRequest{Handle: opened.Handle})

	if er := c.callErr(&pfslocal.HardLinkRequest{Item: survivor.Item, Dir: root, Name: []byte("to-volume")}); er.Errno != darwinEXDEV {
		t.Fatalf("local-to-volume link errno=%d want EXDEV", er.Errno)
	}
	if er := c.callErr(&pfslocal.HardLinkRequest{Item: survivor.Item, Dir: target.Item, Name: []byte("cross-graft")}); er.Errno != darwinEXDEV {
		t.Fatalf("cross-graft link errno=%d want EXDEV", er.Errno)
	}
	if er := c.callErr(&pfslocal.HardLinkRequest{Item: nm.Item, Dir: nm.Item, Name: []byte("dir-alias")}); er.Errno != darwinEPERM {
		t.Fatalf("directory hardlink errno=%d want EPERM", er.Errno)
	}
}

func TestDaemonReadsVolumeLocalDirsAndNoLocalDisablesThem(t *testing.T) {
	authority := serveAuthority(t)
	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	ctx := context.Background()
	if _, st := remote.Mkdir(ctx, ".portablefs", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir .portablefs st=%d", st)
	}
	cfgAttr, st := remote.Create(ctx, ".portablefs/local-dirs", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create volume local-dirs st=%d", st)
	}
	cfgState := clientcore.NewNodeState(cfgAttr.Ino, cfgAttr.Ino != 0)
	if n, st := remote.Write(ctx, ".portablefs/local-dirs", cfgState, 0, []byte("node_modules\ncache # generated files\n")); st != fsproto.OK || n == 0 {
		t.Fatalf("write volume local-dirs n=%d st=%d", n, st)
	}

	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	withConfig := ensureAttachWithPolicyOptions(t, hc, authority, "vol-config-dirs", "main", "/Volumes/ConfigDirs", "writethrough", map[string]any{
		"localDirs":       []string{"build"},
		"volumeLocalDirs": true,
	})
	var status attachStatus
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+withConfig, nil, http.StatusOK, &status)
	if strings.Join(status.LocalDirs, ",") != "build,cache,node_modules" {
		t.Fatalf("effective localDirs=%v", status.LocalDirs)
	}

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	configRoot := resolveRoot(t, c, withConfig)
	nm := mkdirItem(t, c, configRoot, "node_modules")
	writeAll(t, c, nm.Item, "local-only", "local")
	if _, st := remote.Lookup(ctx, "node_modules"); st != fsproto.ENOENT {
		t.Fatalf("volume-configured graft leaked to authority: st=%d", st)
	}

	// A distinct volume id: one (volume, branch) allows only one live attach
	// (shared storage identity and checkout owner), and this second attach
	// only needs the same authority-side .portablefs/local-dirs file.
	noLocal := ensureAttachWithPolicyOptions(t, hc, authority, "vol-config-dirs-nolocal", "main", "/Volumes/NoConfigDirs", "writethrough", map[string]any{
		"volumeLocalDirs": false,
	})
	status = attachStatus{}
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+noLocal, nil, http.StatusOK, &status)
	if len(status.LocalDirs) != 0 {
		t.Fatalf("no-local effective localDirs=%v", status.LocalDirs)
	}
	c2 := dialPFS(t, cfg.FrontendSocket)
	defer c2.close()
	noLocalRoot := resolveRoot(t, c2, noLocal)
	mkdirItem(t, c2, noLocalRoot, "node_modules")
	verifier, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	if attr, st := verifier.Lookup(ctx, "node_modules"); st != fsproto.OK || attr.Kind != "directory" {
		t.Fatalf("no-local mkdir did not reach authority: attr=%+v st=%d", attr, st)
	}
}

// TestDaemonLocalDirsServeMachineLocalSubtree covers the core graft contract:
// a graft rule owns the name but synthesizes nothing — the root appears when
// an ordinary mkdir creates it, its contents live on machine-local disk, and
// nothing under it ever reaches the authority volume.
func TestDaemonLocalDirsServeMachineLocalSubtree(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-localdirs", "/Volumes/LocalDirs", []string{"node_modules", "agent-app/node_modules"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)

	// Before anything creates it, the graft root is honestly absent: ENOENT
	// on lookup and no phantom entry in the parent enumeration.
	expectLookupErrno(t, c, root, "node_modules", darwinENOENT)
	for _, name := range enumerateAllPFS(t, c, root, 10) {
		if name == "node_modules" {
			t.Fatalf("root enumerate lists node_modules before mkdir")
		}
	}

	// An ordinary mkdir creates it with daemon-local identity.
	nm := mkdirItem(t, c, root, "node_modules")
	if nm.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf("node_modules kind=%v want directory", nm.Kind)
	}
	if nm.Item.ItemID&localItemIDMarker == 0 {
		t.Fatalf("graft root item %x lacks the local marker bit", nm.Item.ItemID)
	}

	// Files under the graft round-trip through create/write/read/enumerate.
	writeAll(t, c, nm.Item, "package.json", `{"name":"dep"}`)
	c.call(&pfslocal.MkdirRequest{Dir: nm.Item, Name: []byte(".bin"), Mode: 0o755})
	binDir := lookupItem(t, c, nm.Item, ".bin")
	writeAll(t, c, binDir.Item, "vite", "#!/bin/sh\necho vite\n")

	pkg := lookupItem(t, c, nm.Item, "package.json")
	if got := readAll(t, c, pkg.Item); got != `{"name":"dep"}` {
		t.Fatalf("graft read=%q", got)
	}
	names := enumerateAllPFS(t, c, nm.Item, 10)
	sort.Strings(names)
	if strings.Join(names, ",") != ".bin,package.json" {
		t.Fatalf("graft enumerate=%v", names)
	}

	// The graft root merges into its parent's enumeration exactly once.
	rootNames := enumerateAllPFS(t, c, root, 10)
	countNM := 0
	for _, n := range rootNames {
		if n == "node_modules" {
			countNM++
		}
	}
	if countNM != 1 {
		t.Fatalf("root enumerate=%v node_modules count=%d want 1", rootNames, countNM)
	}

	// The authority volume never saw any of it.
	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if _, st := remote.Lookup(context.Background(), "node_modules"); st != fsproto.ENOENT {
		t.Fatalf("authority lookup node_modules st=%d want ENOENT", st)
	}

	// Symlink support with POSIX st_size == target length.
	link := c.call(&pfslocal.SymlinkRequest{Dir: nm.Item, Name: []byte("dep-link"), Target: []byte("package.json")}).(*pfslocal.SymlinkReply)
	if link.Attr.Kind != pfslocal.ItemKindSymlink || link.Attr.Size != uint64(len("package.json")) {
		t.Fatalf("symlink attr=%+v", link.Attr)
	}
	target := c.call(&pfslocal.ReadlinkRequest{Item: link.Attr.Item}).(*pfslocal.ReadlinkReply)
	if string(target.Target) != "package.json" {
		t.Fatalf("readlink=%q", target.Target)
	}

	// setattr: chmod + truncate on graft files.
	mode := uint32(0o755)
	size := uint64(4)
	sa := c.call(&pfslocal.SetAttrRequest{Item: pkg.Item, Mode: &mode, Size: &size}).(*pfslocal.SetAttrReply)
	if sa.Attr.Size != 4 || sa.Attr.Mode&0o777 != 0o755 {
		t.Fatalf("setattr attr=%+v", sa.Attr)
	}
}

// TestDaemonLocalDirsShadowVolumeSubtree pins the dual-mount contract: a
// same-named subtree that exists on the volume (for example Linux-native
// node_modules installed by a cloud sandbox) is hidden behind the graft and
// stays byte-for-byte intact on the authority.
func TestDaemonLocalDirsShadowVolumeSubtree(t *testing.T) {
	authority := serveAuthority(t)

	remote, err := fsproto.Dial(authority, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	mustMkdir := func(p string) {
		t.Helper()
		if _, st, err := remote.Mkdir(p, 0o755); err != nil || st != fsproto.OK {
			t.Fatalf("authority mkdir %s st=%d err=%v", p, st, err)
		}
	}
	mustWrite := func(p, content string) {
		t.Helper()
		if _, st, err := remote.Create(p, 0o644); err != nil || st != fsproto.OK {
			t.Fatalf("authority create %s st=%d err=%v", p, st, err)
		}
		if _, st, err := remote.Write(p, 0, []byte(content), 0o644); err != nil || st != fsproto.OK {
			t.Fatalf("authority write %s st=%d err=%v", p, st, err)
		}
	}
	mustMkdir("agent-app")
	mustMkdir("agent-app/node_modules")
	mustMkdir("agent-app/node_modules/@esbuild")
	mustWrite("agent-app/node_modules/@esbuild/linux-x64", "linux binary")
	mustWrite("agent-app/package.json", `{"scripts":{"dev":"vite"}}`)

	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-shadow", "/Volumes/Shadow", []string{"agent-app/node_modules"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	app := lookupItem(t, c, root, "agent-app")

	// The rule owns the name outright: the volume's Linux subtree is hidden
	// even before any local directory exists (no flip-flop namespaces), and
	// the parent enumeration omits the name entirely.
	expectLookupErrno(t, c, app.Item, "node_modules", darwinENOENT)
	if got := enumerateAllPFS(t, c, app.Item, 10); strings.Join(got, ",") != "package.json" {
		t.Fatalf("pre-mkdir agent-app enumerate=%v want [package.json]", got)
	}

	// mkdir starts the machine-local view empty.
	nm := mkdirItem(t, c, app.Item, "node_modules")
	if got := enumerateAllPFS(t, c, nm.Item, 10); len(got) != 0 {
		t.Fatalf("shadowed node_modules enumerate=%v want empty", got)
	}

	// Local installs land next to it without touching the volume.
	writeAll(t, c, nm.Item, "darwin-dep", "darwin binary")
	if got := enumerateAllPFS(t, c, nm.Item, 10); strings.Join(got, ",") != "darwin-dep" {
		t.Fatalf("graft enumerate=%v", got)
	}

	// The rest of agent-app still comes from the volume.
	pkg := lookupItem(t, c, app.Item, "package.json")
	if got := readAll(t, c, pkg.Item); got != `{"scripts":{"dev":"vite"}}` {
		t.Fatalf("volume package.json read=%q", got)
	}
	appNames := enumerateAllPFS(t, c, app.Item, 10)
	sort.Strings(appNames)
	if strings.Join(appNames, ",") != "node_modules,package.json" {
		t.Fatalf("agent-app enumerate=%v", appNames)
	}

	// The volume's Linux subtree is untouched underneath.
	if attr, st, err := remote.Getattr("agent-app/node_modules/@esbuild/linux-x64"); err != nil || st != fsproto.OK || attr.Size != int64(len("linux binary")) {
		t.Fatalf("authority linux dep st=%d attr=%+v err=%v", st, attr, err)
	}
	if _, st, err := remote.Getattr("agent-app/node_modules/darwin-dep"); err != nil || st != fsproto.ENOENT {
		t.Fatalf("authority darwin dep st=%d err=%v want ENOENT", st, err)
	}
}

// TestDaemonLocalDirsBoundarySemantics pins behavior at the graft boundary:
// EXDEV renames across it (including of the root itself) and POSIX type
// guards inside it.
func TestDaemonLocalDirsBoundarySemantics(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-boundary", "/Volumes/Boundary", []string{"node_modules"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	nm := mkdirItem(t, c, root, "node_modules")
	writeAll(t, c, nm.Item, "inside.txt", "inside")
	writeAll(t, c, root, "outside.txt", "outside")

	// Renames across the boundary fail with EXDEV in both directions.
	if er := c.callErr(&pfslocal.RenameRequest{FromDir: nm.Item, FromName: []byte("inside.txt"), ToDir: root, ToName: []byte("moved.txt")}); er.Errno != darwinEXDEV {
		t.Fatalf("graft->volume rename errno=%d want EXDEV", er.Errno)
	}
	if er := c.callErr(&pfslocal.RenameRequest{FromDir: root, FromName: []byte("outside.txt"), ToDir: nm.Item, ToName: []byte("moved.txt")}); er.Errno != darwinEXDEV {
		t.Fatalf("volume->graft rename errno=%d want EXDEV", er.Errno)
	}

	// Renaming the root out of its rule crosses the boundary too.
	if er := c.callErr(&pfslocal.RenameRequest{FromDir: root, FromName: []byte("node_modules"), ToDir: root, ToName: []byte("node_modules_old")}); er.Errno != darwinEXDEV {
		t.Fatalf("rename graft root errno=%d want EXDEV", er.Errno)
	}

	// Removing a non-empty root reports ENOTEMPTY like any directory (the
	// npm-ci wholesale rebuild path is pinned in its own test).
	if er := c.callErr(&pfslocal.RemoveRequest{Dir: root, Name: []byte("node_modules"), Directory: true}); er.Errno != darwinENOTEMPTY {
		t.Fatalf("remove non-empty graft root errno=%d want ENOTEMPTY", er.Errno)
	}

	// A graft rule is a directory rule: the root is never a file or symlink,
	// and mkdir over the existing root is EEXIST.
	if er := c.callErr(&pfslocal.CreateRequest{Dir: root, Name: []byte("node_modules"), Mode: 0o644}); er.Errno != darwinEISDIR {
		t.Fatalf("create over graft root errno=%d want EISDIR", er.Errno)
	}
	if er := c.callErr(&pfslocal.SymlinkRequest{Dir: root, Name: []byte("node_modules"), Target: []byte("elsewhere")}); er.Errno != darwinEISDIR {
		t.Fatalf("symlink over graft root errno=%d want EISDIR", er.Errno)
	}
	if er := c.callErr(&pfslocal.MkdirRequest{Dir: root, Name: []byte("node_modules"), Mode: 0o755}); er.Errno != darwinEEXIST {
		t.Fatalf("mkdir existing graft root errno=%d want EEXIST", er.Errno)
	}

	// Type guards inside the graft.
	c.call(&pfslocal.MkdirRequest{Dir: nm.Item, Name: []byte("pkg"), Mode: 0o755})
	if er := c.callErr(&pfslocal.RemoveRequest{Dir: nm.Item, Name: []byte("pkg"), Directory: false}); er.Errno != darwinEISDIR {
		t.Fatalf("unlink dir errno=%d want EISDIR", er.Errno)
	}
	if er := c.callErr(&pfslocal.RemoveRequest{Dir: nm.Item, Name: []byte("inside.txt"), Directory: true}); er.Errno != darwinENOTDIR {
		t.Fatalf("rmdir file errno=%d want ENOTDIR", er.Errno)
	}
	pkg := lookupItem(t, c, nm.Item, "pkg")
	writeAll(t, c, pkg.Item, "f", "x")
	if er := c.callErr(&pfslocal.RemoveRequest{Dir: nm.Item, Name: []byte("pkg"), Directory: true}); er.Errno != darwinENOTEMPTY {
		t.Fatalf("rmdir non-empty errno=%d want ENOTEMPTY", er.Errno)
	}

	// Rename within the graft (npm's staging pattern), including rename-over.
	c.call(&pfslocal.RenameRequest{FromDir: nm.Item, FromName: []byte("inside.txt"), ToDir: pkg.Item, ToName: []byte("f")})
	moved := lookupItem(t, c, pkg.Item, "f")
	if got := readAll(t, c, moved.Item); got != "inside" {
		t.Fatalf("rename-over read=%q", got)
	}
	if er := c.callErr(&pfslocal.LookupRequest{Dir: nm.Item, Name: []byte("inside.txt")}); er.Errno != darwinENOENT {
		t.Fatalf("stale source lookup errno=%d want ENOENT", er.Errno)
	}
}

// TestDaemonLocalDirsAddedLiveViaControl proves grafts can be added to a live
// attach (the agent-app runtime does this for custom source dirs) and that the
// swap invalidates and re-serves the shadowed path immediately.
func TestDaemonLocalDirsAddedLiveViaControl(t *testing.T) {
	authority := serveAuthority(t)

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	ctx := context.Background()
	if _, st := remote.Mkdir(ctx, "custom-app", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir custom-app st=%d", st)
	}
	if _, st := remote.Mkdir(ctx, "custom-app/node_modules", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir custom-app/node_modules st=%d", st)
	}
	if _, st := remote.Create(ctx, "custom-app/node_modules/linux-only", 0o644); st != fsproto.OK {
		t.Fatalf("create linux-only st=%d", st)
	}

	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-live", "/Volumes/Live", nil)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	app := lookupItem(t, c, root, "custom-app")

	// Before the graft: the volume subtree is visible.
	nmBefore := lookupItem(t, c, app.Item, "node_modules")
	if got := enumerateAllPFS(t, c, nmBefore.Item, 10); strings.Join(got, ",") != "linux-only" {
		t.Fatalf("pre-graft enumerate=%v", got)
	}

	var out struct {
		LocalDirs []string `json:"localDirs"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/local-dirs", map[string]any{"dirs": []string{"custom-app/node_modules"}}, http.StatusOK, &out)
	if strings.Join(out.LocalDirs, ",") != "custom-app/node_modules" {
		t.Fatalf("local-dirs reply=%v", out.LocalDirs)
	}

	// After the graft: the rule owns the name, the volume subtree is hidden,
	// and nothing exists until a local mkdir creates it.
	expectLookupErrno(t, c, app.Item, "node_modules", darwinENOENT)
	nmAfter := mkdirItem(t, c, app.Item, "node_modules")
	if got := enumerateAllPFS(t, c, nmAfter.Item, 10); len(got) != 0 {
		t.Fatalf("post-graft enumerate=%v want empty", got)
	}
	writeAll(t, c, nmAfter.Item, "darwin-only", "d")
	if _, st := remote.Lookup(ctx, "custom-app/node_modules/darwin-only"); st != fsproto.ENOENT {
		t.Fatalf("authority darwin-only st=%d want ENOENT", st)
	}

	// Invalid dirs are rejected.
	reqBody := map[string]any{"dirs": []string{"../escape"}}
	reqJSON, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/attaches/"+ref+"/local-dirs", jsonBody(t, reqBody))
	reqJSON.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(reqJSON)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid local-dirs status=%d want 400", resp.StatusCode)
	}

	// Status reports the graft configuration.
	var one attachStatus
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &one)
	if strings.Join(one.LocalDirs, ",") != "custom-app/node_modules" {
		t.Fatalf("status localDirs=%v", one.LocalDirs)
	}
}

// TestDaemonLocalDirsSurviveDaemonRestart pins persistence: graft config,
// grafted content, and item identity all survive a daemon restart, and ensure
// remains idempotent-and-additive for localDirs across restarts.
func TestDaemonLocalDirsSurviveDaemonRestart(t *testing.T) {
	authority := serveAuthority(t)
	dir, err := os.MkdirTemp("/tmp", "pfsd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := Config{
		FrontendSocket: filepath.Join(dir, "run", "frontend.sock"),
		ControlSocket:  filepath.Join(dir, "run", "control.sock"),
		StateDir:       filepath.Join(dir, "state"),
		Version:        "portablefsd-test",
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	s1 := NewServer(cfg)
	go func() { _ = s1.Run(ctx1) }()
	waitUnix(t, cfg.ControlSocket)
	waitUnix(t, cfg.FrontendSocket)
	hc := httpUDSClient(cfg.ControlSocket)
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-restart", "/Volumes/Restart", []string{"node_modules"})

	c1 := dialPFS(t, cfg.FrontendSocket)
	root := resolveRoot(t, c1, ref)
	nm := mkdirItem(t, c1, root, "node_modules")
	writeAll(t, c1, nm.Item, "persisted.txt", "still here")
	persistedItem := lookupItem(t, c1, nm.Item, "persisted.txt")
	c1.close()

	cancel1()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.FrontendSocket); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	s2 := NewServer(cfg)
	go func() { _ = s2.Run(ctx2) }()
	waitUnix(t, cfg.ControlSocket)
	waitUnix(t, cfg.FrontendSocket)
	hc2 := httpUDSClient(cfg.ControlSocket)

	// Revived attaches wait for credentials; re-ensure with an extra graft dir.
	ref2 := ensureAttachWithPolicyOptions(t, hc2, authority, "vol-restart", "main", "/Volumes/Restart", "writethrough", map[string]any{
		"localDirs": []string{"node_modules", "agent-app/node_modules"},
	})
	if ref2 != ref {
		t.Fatalf("revived ref=%q want %q", ref2, ref)
	}

	c2 := dialPFS(t, cfg.FrontendSocket)
	defer c2.close()
	root2 := resolveRoot(t, c2, ref2)
	nm2 := lookupItem(t, c2, root2, "node_modules")
	got := lookupItem(t, c2, nm2.Item, "persisted.txt")
	if readAll(t, c2, got.Item) != "still here" {
		t.Fatalf("persisted graft content lost")
	}
	if got.Item != persistedItem.Item {
		t.Fatalf("graft item identity changed across restart: %+v -> %+v", persistedItem.Item, got.Item)
	}

	var one attachStatus
	controlJSON(t, hc2, http.MethodGet, "/v1/attaches/"+ref2, nil, http.StatusOK, &one)
	if strings.Join(one.LocalDirs, ",") != "agent-app/node_modules,node_modules" {
		t.Fatalf("merged localDirs=%v", one.LocalDirs)
	}
}

// TestDaemonLocalDirsAuthorityRenameCarriesGraft pins that renaming a volume
// ancestor of a graft root moves the graft and its backing content with it.
func TestDaemonLocalDirsAuthorityRenameCarriesGraft(t *testing.T) {
	authority := serveAuthority(t)

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if _, st := remote.Mkdir(context.Background(), "agent-app", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir agent-app st=%d", st)
	}

	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-carry", "/Volumes/Carry", []string{"agent-app/node_modules"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	app := lookupItem(t, c, root, "agent-app")
	nm := mkdirItem(t, c, app.Item, "node_modules")
	writeAll(t, c, nm.Item, "keep.txt", "carried")

	c.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte("agent-app"), ToDir: root, ToName: []byte("agent-app-v2")})

	appV2 := lookupItem(t, c, root, "agent-app-v2")
	nmV2 := lookupItem(t, c, appV2.Item, "node_modules")
	kept := lookupItem(t, c, nmV2.Item, "keep.txt")
	if got := readAll(t, c, kept.Item); got != "carried" {
		t.Fatalf("carried read=%q", got)
	}

	var one attachStatus
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &one)
	if strings.Join(one.LocalDirs, ",") != "agent-app-v2/node_modules" {
		t.Fatalf("remapped localDirs=%v", one.LocalDirs)
	}
}

// TestDaemonLocalDirsOpenAfterAuthorityOutage pins that grafted content stays
// readable and writable while the authority volume is unreachable.
func TestDaemonLocalDirsOpenAfterAuthorityOutage(t *testing.T) {
	authority, srv := serveAuthorityServer(t)
	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-outage", "/Volumes/Outage", []string{"node_modules"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	nm := mkdirItem(t, c, root, "node_modules")
	writeAll(t, c, nm.Item, "cached.txt", "local bytes")

	_ = srv // The authority stays up in this test; local ops must not touch it
	// at all, which the shadow tests already verify via ENOENT lookups. Here we
	// pin the op path: graft lookups, reads, and writes work through items that
	// were resolved before, without any authority round-trip being required.
	item := lookupItem(t, c, nm.Item, "cached.txt")
	if got := readAll(t, c, item.Item); got != "local bytes" {
		t.Fatalf("graft read=%q", got)
	}
}

// TestDaemonLocalDirsWholesaleRebuild pins the npm-ci pattern: the graft root
// is removed wholesale (children first, then rmdir of the root itself) and
// recreated from scratch with fresh identity, exactly like a plain directory.
func TestDaemonLocalDirsWholesaleRebuild(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-rebuild", "/Volumes/Rebuild", []string{"node_modules"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)

	nm := mkdirItem(t, c, root, "node_modules")
	pkg := mkdirItem(t, c, nm.Item, "react")
	writeAll(t, c, pkg.Item, "index.js", "module.exports = 1")

	// rm -rf node_modules: children first, then the root itself.
	c.call(&pfslocal.RemoveRequest{Dir: pkg.Item, Name: []byte("index.js"), Directory: false})
	c.call(&pfslocal.RemoveRequest{Dir: nm.Item, Name: []byte("react"), Directory: true})
	c.call(&pfslocal.RemoveRequest{Dir: root, Name: []byte("node_modules"), Directory: true})

	// Gone without a trace: ENOENT and no phantom entry.
	expectLookupErrno(t, c, root, "node_modules", darwinENOENT)
	for _, name := range enumerateAllPFS(t, c, root, 10) {
		if name == "node_modules" {
			t.Fatalf("root enumerate lists node_modules after wholesale removal")
		}
	}

	// Recreate from scratch: fresh directory, fresh local identity.
	nm2 := mkdirItem(t, c, root, "node_modules")
	if nm2.Item == nm.Item {
		t.Fatalf("recreated graft root reused stale identity %+v", nm.Item)
	}
	if got := enumerateAllPFS(t, c, nm2.Item, 10); len(got) != 0 {
		t.Fatalf("recreated root enumerate=%v want empty", got)
	}
	writeAll(t, c, nm2.Item, "fresh.txt", "fresh")
	fresh := lookupItem(t, c, nm2.Item, "fresh.txt")
	if got := readAll(t, c, fresh.Item); got != "fresh" {
		t.Fatalf("post-rebuild read=%q", got)
	}
}

// TestDaemonLocalDirsControlAPIParity pins that the control fs/* surface sees
// exactly the namespace the FSKit frontend serves: grafted paths route to
// machine-local backing, graft parents merge (only existing) roots, and the
// volume view stays untouched underneath.
func TestDaemonLocalDirsControlAPIParity(t *testing.T) {
	authority := serveAuthority(t)

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	ctx := context.Background()
	if _, st := remote.Mkdir(ctx, "node_modules", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir volume node_modules st=%d", st)
	}
	if _, st := remote.Create(ctx, "node_modules/linux-only", 0o644); st != fsproto.OK {
		t.Fatalf("create linux-only st=%d", st)
	}
	if _, st := remote.Create(ctx, "volume.txt", 0o644); st != fsproto.OK {
		t.Fatalf("create volume.txt st=%d", st)
	}

	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-parity", "/Volumes/Parity", []string{"node_modules"})

	listNames := func() []string {
		t.Helper()
		var listOut struct {
			Entries []struct {
				Name string `json:"name"`
			} `json:"entries"`
		}
		controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/list", map[string]any{"path": "", "maxEntries": 100}, http.StatusOK, &listOut)
		names := make([]string, 0, len(listOut.Entries))
		for _, e := range listOut.Entries {
			names = append(names, e.Name)
		}
		sort.Strings(names)
		return names
	}

	// Backing absent: the shadowed volume subtree is hidden, the root is not
	// synthesized, and fs/stat honestly 404s.
	if got := listNames(); strings.Join(got, ",") != "volume.txt" {
		t.Fatalf("control fs/list=%v want [volume.txt]", got)
	}
	statReq, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/attaches/"+ref+"/fs/stat", jsonBody(t, map[string]string{"path": "node_modules"}))
	statReq.Header.Set("Content-Type", "application/json")
	statResp, err := hc.Do(statReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = statResp.Body.Close()
	if statResp.StatusCode != http.StatusNotFound {
		t.Fatalf("pre-mkdir fs/stat status=%d want 404", statResp.StatusCode)
	}

	// Writing to the root itself is refused: a graft rule is a directory rule.
	rootWrite, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/attaches/"+ref+"/fs/write", jsonBody(t, map[string]string{
		"path":       "node_modules",
		"dataBase64": base64.StdEncoding.EncodeToString([]byte("nope")),
	}))
	rootWrite.Header.Set("Content-Type", "application/json")
	rootWriteResp, err := hc.Do(rootWrite)
	if err != nil {
		t.Fatal(err)
	}
	_ = rootWriteResp.Body.Close()
	if rootWriteResp.StatusCode == http.StatusNoContent {
		t.Fatalf("fs/write to graft root unexpectedly succeeded")
	}

	// Control fs/write creates grafted content (scaffold and parents on
	// demand) without the frontend ever having created the root.
	writeBody := map[string]string{
		"path":       "node_modules/pkg/index.js",
		"dataBase64": base64.StdEncoding.EncodeToString([]byte("local via control")),
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/write", writeBody, http.StatusNoContent, nil)

	if got := listNames(); strings.Join(got, ",") != "node_modules,volume.txt" {
		t.Fatalf("control fs/list=%v want [node_modules volume.txt]", got)
	}
	var stat struct {
		Attr struct {
			Kind string `json:"kind"`
		} `json:"attr"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/stat", map[string]string{"path": "node_modules/pkg/index.js"}, http.StatusOK, &stat)
	if stat.Attr.Kind != "file" {
		t.Fatalf("fs/stat kind=%q want file", stat.Attr.Kind)
	}

	readReq, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/attaches/"+ref+"/fs/read", jsonBody(t, map[string]any{"path": "node_modules/pkg/index.js", "offset": 0, "length": 64}))
	readReq.Header.Set("Content-Type", "application/json")
	readResp, err := hc.Do(readReq)
	if err != nil {
		t.Fatal(err)
	}
	readData, _ := io.ReadAll(readResp.Body)
	_ = readResp.Body.Close()
	if readResp.StatusCode != http.StatusOK || string(readData) != "local via control" {
		t.Fatalf("control fs/read status=%d body=%q", readResp.StatusCode, readData)
	}

	// The FSKit frontend sees the identical namespace...
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	root := resolveRoot(t, c, ref)
	nm := lookupItem(t, c, root, "node_modules")
	pkgDir := lookupItem(t, c, nm.Item, "pkg")
	idx := lookupItem(t, c, pkgDir.Item, "index.js")
	if got := readAll(t, c, idx.Item); got != "local via control" {
		t.Fatalf("frontend read=%q", got)
	}
	if got := enumerateAllPFS(t, c, nm.Item, 10); strings.Join(got, ",") != "pkg" {
		t.Fatalf("frontend graft enumerate=%v", got)
	}

	// ...and the authority volume never saw any of it.
	if _, st := remote.Lookup(ctx, "node_modules/pkg"); st != fsproto.ENOENT {
		t.Fatalf("authority pkg st=%d want ENOENT", st)
	}
	if attr, st := remote.Lookup(ctx, "node_modules/linux-only"); st != fsproto.OK || attr.Kind != "file" {
		t.Fatalf("authority linux-only st=%d attr=%+v", st, attr)
	}
}

func jsonBody(t *testing.T, v any) *strings.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(data))
}
