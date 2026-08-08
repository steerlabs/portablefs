//go:build linux

package fusev3

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// mustRoutes compiles a rule set from the same declaration syntax a volume
// carries. The pattern language belongs to localroutes; using the real compiler
// here is deliberate, because what these tests are about is what this frontend
// does with the routing it is given.
func mustRoutes(t *testing.T, declaration string) localroutes.RuleSet {
	t.Helper()
	rules, err := localroutes.Parse([]byte(declaration))
	if err != nil {
		t.Fatalf("compile route declaration %q: %v", declaration, err)
	}
	if rules.Empty() {
		t.Fatalf("route declaration %q compiled to nothing", declaration)
	}
	return rules
}

// graftFixture is a frontend with machine-local routes and no kernel: the raw
// filesystem, the backing directory the routes are served from, and a
// programmable authority that counts every request that reaches it.
type graftFixture struct {
	raw     *rawFileSystem
	mount   *Mount
	rpc     *fakeRPC
	backing string
}

func newGraftFixture(t *testing.T, routes localroutes.RuleSet, strict bool) *graftFixture {
	t.Helper()
	backing := filepath.Join(t.TempDir(), "local")
	rpc := newFakeRPC()
	rpc.session = testSelfSession
	// Every authority lookup in this fixture answers with a DISTINCT directory,
	// so a volume path of several elements can be walked to reach a route root
	// and the frontend's own path bookkeeping is genuinely under test.
	rpc.item = testItem(9, authoritypb.Attr_DIRECTORY, 9)
	rpc.byName = map[string]*authoritypb.Item{}
	cfg := testConfig(8)
	if strict {
		cfg.Coherence, cfg.CachedNameCapacity, cfg.RepairBudget = CoherenceStrict, 32, 5*time.Second
	}
	mount := newMount(context.Background(), rpc, cfg)
	t.Cleanup(mount.cancel)
	grafts, err := localdirs.New(localdirs.Config{BackingRoot: backing, Rules: routes})
	if err != nil {
		t.Fatalf("build machine-local routes: %v", err)
	}
	t.Cleanup(func() { _ = grafts.Close() })
	mount.grafts, mount.backing = grafts, backing
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 0), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	return &graftFixture{raw: newRawFileSystem(mount, root), mount: mount, rpc: rpc, backing: backing}
}

func (f *graftFixture) calls() int {
	count := 0
	f.rpc.snapshot(func(rpc *fakeRPC) { count = rpc.calls })
	return count
}

// authorityCalls reports how many requests reached the authority while fn ran.
// It is the measurement the whole machine-local mechanism exists to move: an
// operation under a graft must not produce a single one.
func (f *graftFixture) authorityCalls(fn func()) int {
	before := f.calls()
	fn()
	return f.calls() - before
}

func (f *graftFixture) mkdir(t *testing.T, parent uint64, name string) *fuse.EntryOut {
	t.Helper()
	out := &fuse.EntryOut{}
	if status := f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{NodeId: parent}, Mode: 0o755}, name, out); !status.Ok() {
		t.Fatalf("MKDIR %q = %v", name, status)
	}
	return out
}

func (f *graftFixture) lookup(t *testing.T, parent uint64, name string) (*fuse.EntryOut, fuse.Status) {
	t.Helper()
	out := &fuse.EntryOut{}
	return out, f.raw.Lookup(nil, &fuse.InHeader{NodeId: parent}, name, out)
}

func (f *graftFixture) mustLookup(t *testing.T, parent uint64, name string) *fuse.EntryOut {
	t.Helper()
	out, status := f.lookup(t, parent, name)
	if !status.Ok() {
		t.Fatalf("LOOKUP %q = %v", name, status)
	}
	return out
}

func (f *graftFixture) createFile(t *testing.T, parent uint64, name string, data []byte) *fuse.CreateOut {
	t.Helper()
	out := &fuse.CreateOut{}
	input := &fuse.CreateIn{InHeader: fuse.InHeader{NodeId: parent}, Flags: uint32(os.O_RDWR), Mode: 0o644}
	if status := f.raw.Create(nil, input, name, out); !status.Ok() {
		t.Fatalf("CREATE %q = %v", name, status)
	}
	if len(data) != 0 {
		written, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{NodeId: out.NodeId}, Fh: out.Fh, Size: uint32(len(data))}, data)
		if !status.Ok() || int(written) != len(data) {
			t.Fatalf("WRITE %q = (%d, %v), want (%d, OK)", name, written, status, len(data))
		}
	}
	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: out.NodeId}, Fh: out.Fh})
	return out
}

func (f *graftFixture) readNode(t *testing.T, nodeID uint64, size int) ([]byte, fuse.Status) {
	t.Helper()
	opened := &fuse.OpenOut{}
	status := f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: nodeID}, Flags: uint32(os.O_RDONLY)}, opened)
	if !status.Ok() {
		return nil, status
	}
	defer f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: nodeID}, Fh: opened.Fh})
	buffer := make([]byte, size)
	result, status := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{NodeId: nodeID}, Fh: opened.Fh, Size: uint32(size)}, buffer)
	if !status.Ok() {
		return nil, status
	}
	data, _ := result.Bytes(buffer)
	return append([]byte(nil), data...), fuse.OK
}

// floatingRoutes is the shape that matters most: a rule that owns a directory
// NAME at any depth, which is what makes a node_modules created five levels
// down a route root without anything having enumerated that path.
func floatingRoutes(t *testing.T, names ...string) localroutes.RuleSet {
	t.Helper()
	var declaration strings.Builder
	for _, name := range names {
		declaration.WriteString(name)
		declaration.WriteString("/\n")
	}
	return mustRoutes(t, declaration.String())
}

// --- a graft serves locally, and the authority never hears about it ---

func TestARouteRootIsCreatedAndServedWithoutOneAuthorityRequest(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	var root *fuse.EntryOut
	if calls := f.authorityCalls(func() { root = f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules") }); calls != 0 {
		t.Fatalf("creating a route root cost %d authority requests, want 0", calls)
	}
	if info, err := os.Stat(filepath.Join(f.backing, "node_modules")); err != nil || !info.IsDir() {
		t.Fatalf("route root backing: %v (dir=%v)", err, err == nil && info.IsDir())
	}
	calls := f.authorityCalls(func() {
		create := &fuse.CreateIn{InHeader: fuse.InHeader{NodeId: root.NodeId}, Flags: uint32(os.O_RDWR), Mode: 0o644}
		out := &fuse.CreateOut{}
		if status := f.raw.Create(nil, create, "index.js", out); !status.Ok() {
			t.Fatalf("CREATE inside the graft = %v", status)
		}
		written, status := f.raw.Write(nil, &fuse.WriteIn{Fh: out.Fh, Size: 5}, []byte("hello"))
		if !status.Ok() || written != 5 {
			t.Fatalf("WRITE inside the graft = (%d, %v)", written, status)
		}
		buffer := make([]byte, 5)
		result, status := f.raw.Read(nil, &fuse.ReadIn{Fh: out.Fh, Size: 5}, buffer)
		if !status.Ok() {
			t.Fatalf("READ inside the graft = %v", status)
		}
		data, _ := result.Bytes(buffer)
		if string(data) != "hello" {
			t.Fatalf("READ inside the graft = %q, want %q", data, "hello")
		}
		f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: out.NodeId}, Fh: out.Fh})
	})
	if calls != 0 {
		t.Fatalf("create, write and read under a graft cost %d authority requests, want 0", calls)
	}
	if data, err := os.ReadFile(filepath.Join(f.backing, "node_modules", "index.js")); err != nil || string(data) != "hello" {
		t.Fatalf("graft content in backing = (%q, %v), want %q", data, err, "hello")
	}
}

func TestARouteRootWithNoBackingIsAbsentRatherThanSynthesized(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	var status fuse.Status
	calls := f.authorityCalls(func() { _, status = f.lookup(t, fuse.FUSE_ROOT_ID, "node_modules") })
	if status != fuse.Status(syscall.ENOENT) {
		t.Fatalf("LOOKUP of an uncreated route root = %v, want ENOENT", status)
	}
	if calls != 0 {
		t.Fatalf("resolving an owned name cost %d authority requests, want 0; the rule shadows the volume unconditionally", calls)
	}
	if active, errno := f.raw.grafts.ActiveRootsUnder(""); errno != 0 || len(active) != 0 {
		t.Fatalf("active route roots = (%v, %v) after a lookup of a name nothing created; a rule owns a name, it never synthesizes the directory", active, errno)
	}
}

func TestAFloatingRouteInstantiatesAtDepth(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	// Walk two volume directories the authority serves, then create the route
	// root underneath them. Nothing enumerated this path at mount time.
	first := f.mustLookup(t, fuse.FUSE_ROOT_ID, "packages")
	second := f.mustLookup(t, first.NodeId, "app")
	var root *fuse.EntryOut
	if calls := f.authorityCalls(func() { root = f.mkdir(t, second.NodeId, "node_modules") }); calls != 0 {
		t.Fatalf("instantiating a route root at depth cost %d authority requests, want 0", calls)
	}
	if info, err := os.Stat(filepath.Join(f.backing, "packages", "app", "node_modules")); err != nil || !info.IsDir() {
		t.Fatalf("backing for the depth-instantiated root: %v", err)
	}
	if calls := f.authorityCalls(func() { f.mkdir(t, root.NodeId, "lodash") }); calls != 0 {
		t.Fatalf("mkdir under the instantiated root cost %d authority requests, want 0", calls)
	}
}

// --- the wholesale rebuild shape: rm -rf node_modules && mkdir node_modules ---

func TestARouteRootIsRemovedAndRecreatedLikeAnyDirectory(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	f.mkdir(t, root.NodeId, "lodash")
	if status := f.raw.Rmdir(nil, &fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, "node_modules"); status != fuse.Status(syscall.ENOTEMPTY) {
		t.Fatalf("RMDIR of a populated route root = %v, want ENOTEMPTY", status)
	}
	if status := f.raw.Rmdir(nil, &fuse.InHeader{NodeId: root.NodeId}, "lodash"); !status.Ok() {
		t.Fatalf("RMDIR inside the graft = %v", status)
	}
	if status := f.raw.Rmdir(nil, &fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, "node_modules"); !status.Ok() {
		t.Fatalf("RMDIR of the emptied route root = %v", status)
	}
	if _, status := f.lookup(t, fuse.FUSE_ROOT_ID, "node_modules"); status != fuse.Status(syscall.ENOENT) {
		t.Fatalf("LOOKUP after removing the route root = %v, want ENOENT", status)
	}
	if calls := f.authorityCalls(func() { f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules") }); calls != 0 {
		t.Fatalf("recreating the route root cost %d authority requests, want 0", calls)
	}
}

func TestGraftNodeIDFollowsFileAndDirectoryRenames(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	file := f.createFile(t, root.NodeId, "before.js", []byte("renamed"))
	rename := &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: root.NodeId}, Newdir: root.NodeId}
	if status := f.raw.Rename(nil, rename, "before.js", "after.js"); !status.Ok() {
		t.Fatalf("RENAME file = %v", status)
	}
	if data, status := f.readNode(t, file.NodeId, len("renamed")); !status.Ok() || string(data) != "renamed" {
		t.Fatalf("OPEN through the file's pre-rename NodeID = (%q, %v), want renamed content", data, status)
	}

	directory := f.mkdir(t, root.NodeId, "before-dir")
	if status := f.raw.Rename(nil, rename, "before-dir", "after-dir"); !status.Ok() {
		t.Fatalf("RENAME directory = %v", status)
	}
	child := f.createFile(t, directory.NodeId, "child", []byte("nested"))
	if data, status := f.readNode(t, child.NodeId, len("nested")); !status.Ok() || string(data) != "nested" {
		t.Fatalf("operation through the directory's pre-rename NodeID = (%q, %v), want nested content", data, status)
	}
}

func TestUnlinkedGraftNodeIDNeverRetargetsARecreatedName(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	old := f.createFile(t, root.NodeId, "same.js", []byte("old"))
	if status := f.raw.Unlink(nil, &fuse.InHeader{NodeId: root.NodeId}, "same.js"); !status.Ok() {
		t.Fatalf("UNLINK old file = %v", status)
	}
	if _, status := f.readNode(t, old.NodeId, len("new")); status != fuse.Status(syscall.ESTALE) {
		t.Fatalf("OPEN of an unlinked NodeID = %v, want ESTALE", status)
	}
	created := f.createFile(t, root.NodeId, "same.js", []byte("new"))
	if created.NodeId == old.NodeId {
		t.Fatalf("recreated name reused stale NodeID %d", old.NodeId)
	}
	if _, status := f.readNode(t, old.NodeId, len("new")); status != fuse.Status(syscall.ESTALE) {
		t.Fatalf("old NodeID after recreation = %v, want ESTALE rather than the replacement's content", status)
	}
	if data, status := f.readNode(t, created.NodeId, len("new")); !status.Ok() || string(data) != "new" {
		t.Fatalf("new NodeID after recreation = (%q, %v), want new content", data, status)
	}
}

func TestGraftHardlinkNodeIDKeepsEveryLiveAlias(t *testing.T) {
	for _, remove := range []string{"source", "linked"} {
		t.Run("remove "+remove, func(t *testing.T) {
			f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
			root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
			source := f.createFile(t, root.NodeId, "source", []byte("shared"))
			linked := &fuse.EntryOut{}
			if status := f.raw.Link(nil, &fuse.LinkIn{InHeader: fuse.InHeader{NodeId: root.NodeId}, Oldnodeid: source.NodeId}, "linked", linked); !status.Ok() {
				t.Fatalf("LINK = %v", status)
			}
			if linked.NodeId != source.NodeId {
				t.Fatalf("hard links received NodeIDs %d and %d, want one interned object", source.NodeId, linked.NodeId)
			}
			if status := f.raw.Unlink(nil, &fuse.InHeader{NodeId: root.NodeId}, remove); !status.Ok() {
				t.Fatalf("UNLINK %q = %v", remove, status)
			}
			if data, status := f.readNode(t, source.NodeId, len("shared")); !status.Ok() || string(data) != "shared" {
				t.Fatalf("shared NodeID after unlinking %q = (%q, %v), want surviving alias content", remove, data, status)
			}
		})
	}
}

// --- boundaries ---

func TestCreateAndSymlinkAtARouteRootAreEISDIR(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	out := &fuse.CreateOut{}
	status := f.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Flags: uint32(os.O_RDWR), Mode: 0o644}, "node_modules", out)
	if status != fuse.Status(syscall.EISDIR) {
		t.Fatalf("CREATE at a route root = %v, want EISDIR", status)
	}
	entry := &fuse.EntryOut{}
	status = f.raw.Symlink(nil, &fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, "somewhere", "node_modules", entry)
	if status != fuse.Status(syscall.EISDIR) {
		t.Fatalf("SYMLINK at a route root = %v, want EISDIR", status)
	}
}

func TestRenamingAcrossTheGraftBoundaryIsEXDEV(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules", "vendor"), false)
	local := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	f.mkdir(t, local.NodeId, "lodash")
	f.mkdir(t, fuse.FUSE_ROOT_ID, "vendor")

	rename := &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: local.NodeId}, Newdir: fuse.FUSE_ROOT_ID}
	if status := f.raw.Rename(nil, rename, "lodash", "escaped"); status != fuse.Status(syscall.EXDEV) {
		t.Fatalf("rename out of a graft = %v, want EXDEV", status)
	}
	intoGraft := &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Newdir: local.NodeId}
	if status := f.raw.Rename(nil, intoGraft, "somefile", "lodash2"); status != fuse.Status(syscall.EXDEV) {
		t.Fatalf("rename into a graft = %v, want EXDEV", status)
	}
	betweenRoots := &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Newdir: fuse.FUSE_ROOT_ID}
	if status := f.raw.Rename(nil, betweenRoots, "node_modules", "vendor"); status != fuse.Status(syscall.EXDEV) {
		t.Fatalf("rename between two route roots = %v, want EXDEV", status)
	}
}

func TestRenamingAnAncestorOfAnActiveGraftIsEBUSYNotEXDEV(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	packages := f.mustLookup(t, fuse.FUSE_ROOT_ID, "packages")
	f.mkdir(t, packages.NodeId, "node_modules")

	rename := &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Newdir: fuse.FUSE_ROOT_ID}
	status := f.raw.Rename(nil, rename, "packages", "modules")
	if status == fuse.Status(syscall.EXDEV) {
		t.Fatal("renaming a shared ancestor of an active graft answered EXDEV; that invites a recursive copy that would move machine-local content into shared storage")
	}
	if status != fuse.Status(syscall.EBUSY) {
		t.Fatalf("renaming a shared ancestor of an active graft = %v, want EBUSY", status)
	}
}

func TestRenamingAnAncestorOfAnUncreatedRouteRootIsAnOrdinaryRename(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	packages := f.mustLookup(t, fuse.FUSE_ROOT_ID, "packages")
	// Resolve the owned name so the topology knows about it, without creating
	// any machine-local content behind it.
	if _, status := f.lookup(t, packages.NodeId, "node_modules"); status != fuse.Status(syscall.ENOENT) {
		t.Fatalf("LOOKUP of an uncreated route root = %v, want ENOENT", status)
	}
	rename := &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Newdir: fuse.FUSE_ROOT_ID}
	if status := f.raw.Rename(nil, rename, "packages", "modules"); !status.Ok() {
		t.Fatalf("renaming an ancestor with no machine-local content = %v, want success", status)
	}
}

func TestLinkingAcrossTheGraftBoundaryIsEXDEV(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	out := &fuse.CreateOut{}
	if status := f.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{NodeId: root.NodeId}, Flags: uint32(os.O_RDWR), Mode: 0o644}, "a.js", out); !status.Ok() {
		t.Fatalf("CREATE inside the graft = %v", status)
	}
	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: out.NodeId}, Fh: out.Fh})
	entry := &fuse.EntryOut{}
	status := f.raw.Link(nil, &fuse.LinkIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Oldnodeid: out.NodeId}, "escaped.js", entry)
	if status != fuse.Status(syscall.EXDEV) {
		t.Fatalf("hard link out of a graft = %v, want EXDEV", status)
	}
	inside := &fuse.EntryOut{}
	if status := f.raw.Link(nil, &fuse.LinkIn{InHeader: fuse.InHeader{NodeId: root.NodeId}, Oldnodeid: out.NodeId}, "b.js", inside); !status.Ok() {
		t.Fatalf("hard link inside one graft = %v, want success", status)
	}
}

// --- listings ---

func TestAVolumeListingMergesRouteRootsAndShadowsTheVolumeName(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	// The volume also holds a directory of the same name plus an unrelated one.
	f.rpc.dirPages = []*authoritypb.ReadDirReply{{
		Verifier: testToken(5), Eof: true,
		Entries: []*authoritypb.Dirent{
			{Name: []byte("src"), Attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 11}, NextCookie: encodeCookie(1)},
			{Name: []byte("node_modules"), Attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 12}, NextCookie: encodeCookie(2)},
		},
	}}
	names, inodes := f.list(t, fuse.FUSE_ROOT_ID)
	if !slices.Equal(names, []string{"src", "node_modules"}) {
		t.Fatalf("listing = %v, want the volume entry shadowed and the route root merged exactly once", names)
	}
	if inodes["node_modules"] == 12 {
		t.Fatal("the listing reported the VOLUME's node_modules inode; the rule owns the name unconditionally")
	}
	if inodes["node_modules"]&(uint64(1)<<63) == 0 {
		t.Fatalf("merged route root inode %#x is not in the machine-local range", inodes["node_modules"])
	}
}

// list drives OPENDIR/READDIR/RELEASEDIR exactly as the kernel would.
func (f *graftFixture) list(t *testing.T, nodeID uint64) ([]string, map[string]uint64) {
	t.Helper()
	open := &fuse.OpenOut{}
	if status := f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: nodeID}}, open); !status.Ok() {
		t.Fatalf("OPENDIR = %v", status)
	}
	defer f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: nodeID}, Fh: open.Fh})
	var names []string
	inodes := make(map[string]uint64)
	offset := uint64(0)
	for range 32 {
		buffer := make([]byte, 4096)
		list := fuse.NewDirEntryList(buffer, offset)
		if status := f.raw.ReadDir(nil, &fuse.ReadIn{InHeader: fuse.InHeader{NodeId: nodeID}, Fh: open.Fh, Offset: offset}, list); !status.Ok() {
			t.Fatalf("READDIR = %v", status)
		}
		produced := false
		for _, entry := range decodeDirEntries(t, buffer) {
			names = append(names, entry.Name)
			inodes[entry.Name] = entry.Ino
			offset = entry.Off
			produced = true
		}
		if !produced {
			break
		}
	}
	return names, inodes
}

// decodeDirEntries reads back what the frontend wrote into a READDIR reply
// buffer. NewDirEntryList reslices the caller's buffer, so these are the exact
// bytes the kernel would parse; asserting on them rather than on an internal
// structure is what makes a listing test about the listing. The buffer starts
// zeroed, so a zero name length is the end of what was written.
func decodeDirEntries(t *testing.T, buffer []byte) []fuse.DirEntry {
	t.Helper()
	const header = 24
	var entries []fuse.DirEntry
	for len(buffer) >= header {
		ino := binary.LittleEndian.Uint64(buffer[0:8])
		off := binary.LittleEndian.Uint64(buffer[8:16])
		nameLen := int(binary.LittleEndian.Uint32(buffer[16:20]))
		typ := binary.LittleEndian.Uint32(buffer[20:24])
		if nameLen == 0 || header+nameLen > len(buffer) {
			break
		}
		entries = append(entries, fuse.DirEntry{
			Ino: ino, Off: off, Name: string(buffer[header : header+nameLen]), Mode: typ << 12,
		})
		total := (header + nameLen + 7) &^ 7
		if total > len(buffer) {
			break
		}
		buffer = buffer[total:]
	}
	return entries
}

// --- the strict cache contract is not extended to grafted names ---

func TestGraftedNamesNeverEnterTheCachedNameRegistry(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), true)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	f.mkdir(t, root.NodeId, "lodash")
	f.mustLookup(t, root.NodeId, "lodash")
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if len(f.raw.cachedNames) != 0 {
		t.Fatalf("cachedNames holds %d machine-local bindings; the registry is the exact set of names this mount owes the AUTHORITY a repair for, and a graft can never be one", len(f.raw.cachedNames))
	}
	for key, record := range f.raw.nodesByKey {
		if record.graft {
			t.Fatalf("machine-local object %v is interned in the authority identity table; a visibility target could resolve to it", key)
		}
	}
	if len(f.raw.graftsByKey) == 0 {
		t.Fatal("machine-local objects were not interned at all")
	}
}

func TestGraftedEntriesArePublishedWithTheLocalLifetime(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), true)
	out := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	if time.Duration(out.EntryValid)*time.Second != graftEntryTimeout {
		t.Fatalf("graft entry lifetime = %ds, want %s", out.EntryValid, graftEntryTimeout)
	}
	if out.Attr.Ino&(uint64(1)<<63) == 0 {
		t.Fatalf("graft inode %#x is not in the machine-local range", out.Attr.Ino)
	}
	if out.Attr.Uid != f.mount.uid || out.Attr.Gid != f.mount.gid {
		t.Fatalf("graft owner = (%d, %d), want the identity this mount presents (%d, %d)", out.Attr.Uid, out.Attr.Gid, f.mount.uid, f.mount.gid)
	}
}

// --- a route root a previous mount left behind serves immediately ---

func TestARootLeftBehindByAPreviousMountServesImmediately(t *testing.T) {
	backing := filepath.Join(t.TempDir(), "local")
	if err := os.MkdirAll(filepath.Join(backing, "packages", "app", "node_modules", "lodash"), 0o755); err != nil {
		t.Fatal(err)
	}
	grafts, err := localdirs.New(localdirs.Config{BackingRoot: backing, Rules: floatingRoutes(t, "node_modules")})
	if err != nil {
		t.Fatalf("build machine-local routes: %v", err)
	}
	defer func() { _ = grafts.Close() }()
	active, errno := grafts.ActiveRootsUnder("")
	if errno != 0 || !slices.Equal(active, []string{"packages/app/node_modules"}) {
		t.Fatalf("active roots = (%v, %v), want the root a previous mount created", active, errno)
	}
	if _, errno := grafts.Lstat("packages/app/node_modules/lodash"); errno != 0 {
		t.Fatalf("content under a restored root = %v, want it served", errno)
	}
}
