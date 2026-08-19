//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"golang.org/x/sys/unix"
)

func kernelBeforeTmpfileLinkCredentialRelaxation(t *testing.T) (string, bool) {
	t.Helper()
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "unknown", false
	}
	release := string(bytes.TrimRight(name.Release[:], "\x00"))
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return release, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil {
		return release, false
	}
	return release, major < 6 || major == 6 && minor < 12
}

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
	base := t.TempDir()
	if tmpfileBase := os.Getenv("PFS_TMPFILE_TEST_ROOT"); tmpfileBase != "" {
		var err error
		base, err = os.MkdirTemp(tmpfileBase, "fusev3-graft-")
		if err != nil {
			t.Fatalf("create graft test root: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(base) })
	}
	backing := filepath.Join(base, "local")
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

func TestEveryGraftAttrIsExplicitlyLocal(t *testing.T) {
	for _, mode := range []uint32{syscall.S_IFREG | 0o600, syscall.S_IFDIR | 0o700, syscall.S_IFLNK | 0o777} {
		var out fuse.Attr
		fillGraftAttr(&syscall.Stat_t{Mode: mode, Ino: 7}, &out, 1, 2)
		if out.Flags != 0 {
			t.Fatalf("mode %#o attr flags = %#x, want exactly PFS_LOCAL", mode, out.Flags)
		}
	}
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
	status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
		return f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{Unique: unique, NodeId: parent}, Mode: 0o755}, name, out)
	})
	if !status.Ok() {
		t.Fatalf("MKDIR %q = %v", name, status)
	}
	return out
}

func (f *graftFixture) lookup(t *testing.T, parent uint64, name string) (*fuse.EntryOut, fuse.Status) {
	t.Helper()
	out := &fuse.EntryOut{}
	status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
		return f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: parent}, name, out)
	})
	return out, status
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
	if out.Attr.Flags != 0 || out.OpenFlags != fuse.FOPEN_KEEP_CACHE {
		t.Fatalf("local CREATE classification attr=%#x open=%#x", out.Attr.Flags, out.OpenFlags)
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

func TestStrictLocalTmpfileAndRangeOperationsStayDescriptorDirect(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), true)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	baseline := f.calls()

	newLocalFile := func(name string) *fuse.CreateOut {
		t.Helper()
		out := &fuse.CreateOut{}
		in := &fuse.CreateIn{
			InHeader: fuse.InHeader{NodeId: root.NodeId},
			Flags:    uint32(unix.O_RDWR), Mode: 0o600,
		}
		if status := f.raw.Create(nil, in, name, out); !status.Ok() {
			t.Fatalf("local CREATE %q = %v", name, status)
		}
		return out
	}

	source := newLocalFile("source")
	destination := newLocalFile("destination")
	defer f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: source.NodeId}, Fh: source.Fh})
	defer f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: destination.NodeId}, Fh: destination.Fh})
	if written, status := f.raw.Write(nil, &fuse.WriteIn{
		InHeader: fuse.InHeader{NodeId: source.NodeId}, Fh: source.Fh, Size: 6,
	}, []byte("direct")); !status.Ok() || written != 6 {
		t.Fatalf("local source WRITE = (%d, %v)", written, status)
	}
	if status := f.raw.Fallocate(nil, &fuse.FallocateIn{
		InHeader: fuse.InHeader{NodeId: destination.NodeId}, Fh: destination.Fh, Length: 32,
	}); !status.Ok() {
		t.Fatalf("local FALLOCATE = %v", status)
	}
	if copied, status := f.raw.CopyFileRange(nil, &fuse.CopyFileRangeIn{
		InHeader: fuse.InHeader{NodeId: source.NodeId}, FhIn: source.Fh,
		NodeIdOut: destination.NodeId, FhOut: destination.Fh, Len: 6,
	}); !status.Ok() || copied != 6 {
		t.Fatalf("local COPY_FILE_RANGE = (%d, %v)", copied, status)
	}
	buffer := make([]byte, 6)
	result, status := f.raw.Read(nil, &fuse.ReadIn{
		InHeader: fuse.InHeader{NodeId: destination.NodeId}, Fh: destination.Fh, Size: 6,
	}, buffer)
	if !status.Ok() {
		t.Fatalf("local destination READ = %v", status)
	}
	data, _ := result.Bytes(buffer)
	if string(data) != "direct" {
		t.Fatalf("local copied data = %q, want direct", data)
	}

	linkableUnique := nextTestRequestUnique()
	linkable := &fuse.CreateOut{}
	if status := f.raw.Tmpfile(nil, &fuse.CreateIn{
		InHeader: fuse.InHeader{Unique: linkableUnique, NodeId: root.NodeId},
		Flags:    uint32(unix.O_TMPFILE | unix.O_RDWR), Mode: 0o600,
	}, "/", linkable); status == fuse.Status(syscall.EOPNOTSUPP) && os.Getenv("PFS_TMPFILE_TEST_ROOT") == "" {
		t.Skip("test filesystem does not support O_TMPFILE; the required tmpfs-backed suite exercises it")
	} else if !status.Ok() {
		t.Fatalf("linkable local TMPFILE = %v", status)
	}
	if written, status := f.raw.Write(nil, &fuse.WriteIn{
		InHeader: fuse.InHeader{NodeId: linkable.NodeId}, Fh: linkable.Fh, Size: 8,
	}, []byte("linkable")); !status.Ok() || written != 8 {
		t.Fatalf("linkable local TMPFILE WRITE = (%d, %v)", written, status)
	}
	linked := &fuse.EntryOut{}
	linkUnique := nextTestRequestUnique()
	if status := f.raw.Link(nil, &fuse.LinkIn{
		InHeader: fuse.InHeader{Unique: linkUnique, NodeId: root.NodeId}, Oldnodeid: linkable.NodeId,
	}, "linked", linked); status == fuse.Status(syscall.ENOENT) {
		if release, old := kernelBeforeTmpfileLinkCredentialRelaxation(t); old {
			t.Skipf("kernel %s lacks the >=6.12 unprivileged linkat(AT_EMPTY_PATH) open-credential relaxation required by PortableFS", release)
		}
		t.Fatalf("first name for local TMPFILE on supported kernel = %v", status)
	} else if !status.Ok() {
		t.Fatalf("first name for local TMPFILE = %v", status)
	}
	if linked.NodeId != linkable.NodeId || linked.Attr.Flags != 0 || f.raw.ReplyWriteOrdered(linkUnique) {
		t.Fatalf("linked local TMPFILE output/lifecycle = %+v", linked)
	}
	if got, status := f.readNode(t, linked.NodeId, 8); !status.Ok() || string(got) != "linkable" {
		t.Fatalf("linked local TMPFILE READ = (%q, %v)", got, status)
	}
	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: linkable.NodeId}, Fh: linkable.Fh})
	f.raw.Forget(linkable.NodeId, 2) // TMPFILE entry plus the new LINK entry.

	unique := nextTestRequestUnique()
	tmp := &fuse.CreateOut{}
	if status := f.raw.Tmpfile(nil, &fuse.CreateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: root.NodeId},
		Flags:    uint32(unix.O_TMPFILE | unix.O_RDWR | unix.O_EXCL), Mode: 0o640,
	}, "/", tmp); !status.Ok() {
		t.Fatalf("local TMPFILE = %v", status)
	}
	if tmp.NodeId == 0 || tmp.Fh == 0 || tmp.Attr.Flags != 0 || tmp.Attr.Nlink != 0 ||
		tmp.OpenFlags != fuse.FOPEN_KEEP_CACHE {
		t.Fatalf("local TMPFILE output = %+v", tmp)
	}
	if f.raw.ReplyWriteOrdered(unique) {
		t.Fatal("LOCAL TMPFILE entered the SHARED post-VFS publication path")
	}
	if status := f.raw.Link(nil, &fuse.LinkIn{
		InHeader: fuse.InHeader{Unique: nextTestRequestUnique(), NodeId: root.NodeId}, Oldnodeid: tmp.NodeId,
	}, "forbidden", &fuse.EntryOut{}); status.Ok() {
		t.Fatal("O_EXCL local TMPFILE became linkable")
	}
	// The kernel may forget the anonymous lookup while its open description is
	// retained. The handle itself must remain the lifetime owner.
	f.raw.Forget(tmp.NodeId, 1)
	if written, status := f.raw.Write(nil, &fuse.WriteIn{
		InHeader: fuse.InHeader{NodeId: tmp.NodeId}, Fh: tmp.Fh, Size: 8,
	}, []byte("retained")); !status.Ok() || written != 8 {
		t.Fatalf("forgotten local TMPFILE handle WRITE = (%d, %v)", written, status)
	}
	readBuffer := make([]byte, 8)
	result, status = f.raw.Read(nil, &fuse.ReadIn{
		InHeader: fuse.InHeader{NodeId: tmp.NodeId}, Fh: tmp.Fh, Size: 8,
	}, readBuffer)
	if !status.Ok() {
		t.Fatalf("forgotten local TMPFILE handle READ = %v", status)
	}
	data, _ = result.Bytes(readBuffer)
	if string(data) != "retained" {
		t.Fatalf("forgotten local TMPFILE data = %q", data)
	}
	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: tmp.NodeId}, Fh: tmp.Fh})

	if calls := f.calls(); calls != baseline {
		t.Fatalf("LOCAL tmpfile/range operations cost %d authority calls, want 0", calls-baseline)
	}
}

func TestARouteRootWithNoBackingIsAbsentRatherThanSynthesized(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	var status fuse.Status
	var out *fuse.EntryOut
	calls := f.authorityCalls(func() { out, status = f.lookup(t, fuse.FUSE_ROOT_ID, "node_modules") })
	if !status.Ok() || out == nil || out.NodeId != 0 || out.Generation != 0 || out.EntryValid != 0 || out.AttrValid != 0 ||
		out.Attr.Flags != 0 {
		t.Fatalf("LOOKUP of an uncreated route root = (%+v, %v), want base-only LOCAL negative", out, status)
	}
	if calls != 0 {
		t.Fatalf("resolving an owned name cost %d authority requests, want 0; the rule shadows the volume unconditionally", calls)
	}
	if active, errno := f.raw.grafts.ActiveRootsUnder(""); errno != 0 || len(active) != 0 {
		t.Fatalf("active route roots = (%v, %v) after a lookup of a name nothing created; a rule owns a name, it never synthesizes the directory", active, errno)
	}
}

func TestRouteClaimedNegativeLookupIsLocalAcrossA_SHAREDParent(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)

	routeUnique := nextTestRequestUnique()
	routeOut := &fuse.EntryOut{}
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: routeUnique, NodeId: fuse.FUSE_ROOT_ID}, "node_modules", routeOut); !status.Ok() {
		t.Fatalf("missing route root LOOKUP = %v, want structured success", status)
	}
	if routeOut.NodeId != 0 || routeOut.Attr.Flags != 0 {
		t.Fatalf("missing route root = %+v, want LOCAL zero-nodeid shape", routeOut)
	}
	if f.raw.ReplyWriteOrdered(routeUnique) {
		t.Fatal("route-owned negative below SHARED parent entered SHARED publication lifecycle")
	}

	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	localUnique := nextTestRequestUnique()
	localOut := &fuse.EntryOut{}
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: localUnique, NodeId: root.NodeId}, "missing", localOut); !status.Ok() {
		t.Fatalf("missing local child LOOKUP = %v, want structured success", status)
	}
	if localOut.NodeId != 0 || localOut.Attr.Flags != 0 || f.raw.ReplyWriteOrdered(localUnique) {
		t.Fatal("negative LOOKUP below LOCAL parent entered shared publication lifecycle")
	}
}

func TestDirectoryOpenClassificationMatchesInodeOwnership(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), false)
	shared := &fuse.OpenOut{}
	if status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}}, shared)
	}); !status.Ok() {
		t.Fatalf("authority OPENDIR = %v", status)
	}
	if shared.OpenFlags != 0 {
		t.Fatalf("authority OPENDIR flags = %#x, want PFS_SHARED", shared.OpenFlags)
	}
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: nextTestRequestUnique(), NodeId: fuse.FUSE_ROOT_ID}, Fh: shared.Fh})

	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	local := &fuse.OpenOut{}
	if status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: root.NodeId}}, local)
	}); !status.Ok() {
		t.Fatalf("graft OPENDIR = %v", status)
	}
	if local.OpenFlags != 0 {
		t.Fatalf("graft OPENDIR flags = %#x, want PFS_LOCAL", local.OpenFlags)
	}
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: root.NodeId}, Fh: local.Fh})
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
	if out, status := f.lookup(t, fuse.FUSE_ROOT_ID, "node_modules"); !status.Ok() ||
		out.NodeId != 0 || out.Attr.Flags != 0 {
		t.Fatalf("LOOKUP after removing the route root = (%+v, %v), want LOCAL negative", out, status)
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
	if out, status := f.lookup(t, packages.NodeId, "node_modules"); !status.Ok() ||
		out.NodeId != 0 || out.Attr.Flags != 0 {
		t.Fatalf("LOOKUP of an uncreated route root = (%+v, %v), want LOCAL negative", out, status)
	}
	status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
		rename := &fuse.RenameIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Newdir: fuse.FUSE_ROOT_ID}
		return f.raw.Rename(nil, rename, "packages", "modules")
	})
	if !status.Ok() {
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
	status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: nodeID}}, open)
	})
	if !status.Ok() {
		t.Fatalf("OPENDIR = %v", status)
	}
	defer f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: nodeID}, Fh: open.Fh})
	var names []string
	inodes := make(map[string]uint64)
	offset := uint64(0)
	for range 32 {
		buffer := make([]byte, 4096)
		list := fuse.NewDirEntryList(buffer, offset)
		status := testRawCall(t, f.raw, func(unique uint64) fuse.Status {
			return f.raw.ReadDir(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique, NodeId: nodeID}, Fh: open.Fh, Offset: offset}, list)
		})
		if !status.Ok() {
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

func TestGraftGetattrByHandleReleasesExactlyOneOperationReference(t *testing.T) {
	f := newGraftFixture(t, floatingRoutes(t, "node_modules"), true)
	root := f.mkdir(t, fuse.FUSE_ROOT_ID, "node_modules")
	created := f.createFile(t, root.NodeId, "held", nil)
	opened := &fuse.OpenOut{}
	if status := f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: created.NodeId}, Flags: uint32(os.O_RDONLY)}, opened); !status.Ok() {
		t.Fatalf("OPEN graft file = %v", status)
	}
	input := &fuse.GetAttrIn{InHeader: fuse.InHeader{NodeId: created.NodeId}, Flags_: fuse.FUSE_GETATTR_FH, Fh_: opened.Fh}
	if status := f.raw.GetAttr(nil, input, &fuse.AttrOut{}); !status.Ok() {
		t.Fatalf("GETATTR by graft handle = %v", status)
	}
	f.raw.mu.Lock()
	handle := f.raw.handles[opened.Fh]
	inFlight := uint64(0)
	if handle != nil {
		inFlight = handle.inFlight
	}
	f.raw.mu.Unlock()
	if handle == nil || inFlight != 0 {
		t.Fatalf("graft handle after GETATTR = (%v, inFlight=%d), want one live handle with no leaked operation reference", handle != nil, inFlight)
	}
	done := make(chan struct{})
	go func() {
		f.raw.Release(nil, &fuse.ReleaseIn{Fh: opened.Fh})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("graft RELEASE blocked behind a leaked or underflowed GETATTR handle reference")
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
