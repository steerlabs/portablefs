// Command mount is the FUSE client: it mounts a PortableFS volume on this machine
// and translates kernel filesystem operations into the custom protocol served by
// a VCS (the authority/cache node). Because the FUSE client controls its own
// caching, reads go straight to the single authority — live read-after-write
// coherence across machines, not NFSv3 close-to-open.
//
//	mount -addr <vcs-host>:2050 -mount /mnt/vol
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/modebits"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
	"github.com/steerlabs/portablefs/vcs/internal/session"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// sessions is the mount's write-back manager: while it holds a checkout on a subtree,
// writes/fsync are served LOCALLY and flushed asynchronously (local-disk latency). Nil when
// PORTABLEFS_WRITEBACK=0, which falls back to the original per-op write-through path.
var sessions *session.Manager

// dbgOn enables verbose mount-op tracing (PORTABLEFS_DEBUG=1) for diagnosing FUSE-op failures.
var dbgOn = os.Getenv("PORTABLEFS_DEBUG") != ""

// dropOrphanInval, when set, makes watchInvalidations SKIP marking a peer-orphaned open node from the
// invalidation stream — a TEST seam (default off) that simulates a lost/overflowed Orphaned
// invalidation so the ino-based re-derivation fallback (redirectToOrphan) can be exercised end-to-end.
var dropOrphanInval = os.Getenv("PORTABLEFS_DROP_ORPHAN_INVAL") != ""

// noReaddirPlus disables readdir-plus attr-cache fill (each child stat falls back to its own GetattrV
// RPC). Default off (readdir-plus on). A kill-switch + an A/B measurement seam: the fill is provably
// equivalent to a per-child GetattrV under the same gen+version gate, so toggling it changes only RPC
// count, never the attrs observed.
var noReaddirPlus = os.Getenv("PORTABLEFS_NO_READDIRPLUS") != ""

// Version-gated ENOENT caching (the negative dentry cache) defaults to
// capability-auto: ON iff the connected authority advertises ParentVersion
// stamping in the protocol handshake (FeatParentVersion) — the property that
// makes a cached negative invalidation-coherent. PORTABLEFS_NEGATIVE_CACHE
// keeps working in both directions: "1" forces it on (safe even against a
// pre-stamp authority — an unstamped miss is never cached, so it degrades to
// no caching, never to staleness), "0" forces it off.
var negativeCacheEnabled, negativeCacheDisabled = negCacheEnv(os.Getenv("PORTABLEFS_NEGATIVE_CACHE"))

// negCacheEnv parses the tri-state negative-cache env: force-on, force-off,
// or (any other value, including unset) capability-auto.
func negCacheEnv(v string) (forceOn, forceOff bool) {
	return v == "1", v == "0"
}

// openRetentionEntries reads PORTABLEFS_OPEN_RETENTION_ENTRIES: the bound on
// retained (closed but still authority-registered) open registrations. Unset
// or unparseable = the clientcore default; "0" disables retention (every last
// close unmarks, the pre-retention behavior); N > 0 caps the LRU at N.
func openRetentionEntries() int {
	v := os.Getenv("PORTABLEFS_OPEN_RETENTION_ENTRIES")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	if n == 0 {
		return -1
	}
	return n
}

func dbg(format string, a ...any) {
	if dbgOn {
		log.Printf("DBG "+format, a...)
	}
}

// rootNode is the mount's root node; node.Open uses it to evict a subtree's stale cache on a
// write-intent (re)open.
var rootNode *node

// openFlags is how Open/Create report cacheability to the kernel; set in main.
var openFlags uint32

var orphanRenewInterval = 20 * time.Second

var openOrphans = clientcore.NewInodeSet()

// openFiles is the set of LIVE (still-named) inodes this mount currently holds open, registered at
// the authority via MarkOpen and renewed periodically (Stage 2). The authority parks instead of
// removing any inode with a live open holder, so a cross-mount unlink of a file this mount holds
// open becomes delete-on-last-close rather than a broken fd.
var openFiles = clientcore.NewInodeSet()

// diskCacheVolumeID scopes the persistent disk block cache keys to this authority address, so two
// mounts of different volumes sharing a cache directory never alias each other's blocks.
var diskCacheVolumeID string
var fsyncPolicy = clientcore.FsyncPolicy(os.Getenv("PORTABLEFS_FSYNC_POLICY"))

// Self-write freshness tracking, the metadata/version caches, and metadata prefetch now live in the
// clientcore Volume (v.recent / v.AttrCache / v.VersionCache / prefetchTree); the mount forwards its
// node ops through the Volume and no longer keeps redundant copies here.

// sessionTTL gates how long the kernel may cache a held subtree's lookup/getattr. Default 0:
// coherence is by version/invalidation, never by time. A non-zero value historically let a stale
// dentry — e.g. a phantom DELETE-journal cached from before a handoff — survive in the kernel past
// the invalidation that should have evicted it, so the next holder's SQLite rolled back over it
// (the handoff data-loss). Held-subtree metadata performance is recovered by the mount-side
// version-coherent attribute cache (it validates by version instead of expiring by time), not
// by a kernel time box.
//
// PORTABLEFS_SESSION_TTL_MS (default 0 = off) re-enables the kernel time box ONLY for paths under
// a subtree this mount exclusively holds (a write-back checkout/delegation): clientcore's
// AttrValidFor returns this TTL iff sessions.For(path) is non-nil, and 0 the moment the delegation
// is released, so shared paths always revalidate per-lookup. While held, no peer can mutate the
// subtree (the authority enforces the checkout), so the kernel cache cannot go stale from a peer;
// the residual hazard is the handoff race documented above — entries granted a TTL moments before
// a release can outlive it by up to the TTL if a push invalidation is missed/collapsed. That is
// why the default stays 0; see docs/performance.md before enabling.
var sessionTTL = envDurationMs("PORTABLEFS_SESSION_TTL_MS", 0)

// envDurationMs reads a millisecond env var as a duration, falling back to def (also for
// unparseable or negative values).
func envDurationMs(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms < 0 {
		return def
	}
	return time.Duration(ms) * time.Millisecond
}

// node is a path-addressed FUSE node backed by an fsproto.Client. The VCS holds
// all state; this node just forwards operations.
type node struct {
	fs.Inode
	v     *clientcore.Volume
	c     *fsproto.Client
	path  string // full path from the volume root ("" = root)
	state *clientcore.NodeState

	// Open-after-unlink (delete-on-last-close) state, guarded by mu. nopen counts the open handles on
	// THIS inode; orphanIno is non-zero once the file was unlinked (or renamed-over) while still open,
	// at which point the authority parked it under that ino and every op on this node addresses it by
	// ino instead of its (now-gone) name. The last close of a parked node reaps it at the authority.
	mu        sync.Mutex
	nopen     int
	orphanIno uint64

	// authIno is true iff the authority gave this node a REAL inode identity at construction
	// (a.Ino != 0); false when it had none and we fell back to a path-hash (an uncommitted write-back
	// session-local file, or a pre-identity/read-only authority). Set once at construction, immutable.
	// Open-registration treats a MarkOpen ENOENT as a lost open-vs-unlink race ONLY for an authIno
	// node — a node with no authority inode has nothing at the authority to race, so its ENOENT is
	// expected, not a removal. (This is stricter than "session-covered": a committed, peer-visible
	// file that a force-revoked peer removes still correctly reports the race.)
	authIno bool
}

func (n *node) core() *clientcore.Volume {
	if n.v != nil {
		return n.v
	}
	v, err := clientcore.Attach(context.Background(), n.c, clientcore.Options{
		NegativeCache:   negativeCacheEnabled,
		NoNegativeCache: negativeCacheDisabled,
		NoReaddirPlus:   noReaddirPlus,
		FsyncPolicy:     fsyncPolicy,
	})
	if err != nil {
		return nil
	}
	n.v = v
	sessions = v.Sessions()
	opens = &openTracker{OpenTracker: v.OpenTracker()}
	return v
}

func (n *node) coreState() *clientcore.NodeState {
	if n.state != nil {
		return n.state
	}
	ino := n.StableAttr().Ino
	if ino == 0 {
		ino = inoOf(n.curPath())
	}
	n.state = clientcore.NewNodeState(ino, n.authIno)
	return n.state
}

// incOpen records a new open handle on this inode (Open/Create). On the FIRST handle it eagerly +
// synchronously registers the inode as open at the authority (Stage 2), so a cross-mount unlink of
// it parks the inode instead of removing it (delete-on-last-close). The registration is ATOMIC with
// existence at the authority: it returns gone == true iff the inode was already destroyed by a peer
// unlink that won the race — in which case the caller must fail the open with ENOENT rather than
// return a handle to a dead inode. When it registers before the unlink, the unlink parks the inode
// and the fd survives. (A transient RPC error is non-fatal: the periodic RenewOpenInodes recovers
// the hold, and a remove racing that window is the documented residual, not a broken fd.)
func (n *node) incOpen() (gone bool) {
	return n.core().RegisterOpened(n.curPath(), n.coreState()) == fsproto.ENOENT
}

// closeOne drops one open handle. When this was the last LOCAL handle on an orphaned inode, this
// mount stops renewing that ino's lease (drops it from openOrphans) but deliberately does NOT Reap:
// with cross-mount holders, a mount cannot know it is the global last holder. Any surviving holder
// keeps the orphan alive by renewing the shared lease; once the true last holder anywhere closes (or
// crashes), the lease expires and the authority sweeper reaps it (P6 lease GC). The only cost is a
// bounded cleanup delay after the final close — exactly what lease GC is for.
func (n *node) closeOne() {
	n.core().CloseHandle(n.curPath(), n.coreState())
}

// markOrphanLocked records, under n.mu, that this inode was unlinked/replaced while open and is now
// parked under ino at the authority; subsequent reads/writes/truncates/stats address it by ino, and
// this mount renews its lease until the last local close. It is a no-op (returns false) when the node
// has no open handle: a redirect only matters for a live fd, and marking a not-open node would strand
// an ino that no close will ever clear. Caller holds n.mu.
func (n *node) markOrphanLocked(ino uint64) bool {
	return n.coreState().MarkOrphan(ino, n.core().OpenOrphans())
}

// markOrphan is markOrphanLocked taking n.mu itself.
func (n *node) markOrphan(ino uint64) bool {
	return n.coreState().MarkOrphan(ino, n.core().OpenOrphans())
}

// orphan returns the parked ino (non-zero ⇒ this node is an unlinked-but-open orphan), or 0.
func (n *node) orphan() uint64 {
	return n.coreState().Orphan()
}

// isOpen reports whether any handle is currently open on this inode (used by Unlink/rename-over to
// decide park-vs-remove).
func (n *node) isOpen() bool {
	return n.coreState().IsOpen()
}

// redirectToOrphan re-derives a LOST orphan redirect (F1): a peer mount detached this open inode and
// we missed the Orphaned invalidation (subscriber overflow / stream reconnect), so a path-addressed
// op just failed with ENOENT. If this node is still open and its STABLE inode (Stage-1 identity) is
// parked at the authority, adopt the redirect — markOrphan also enrolls the ino in openOrphans so the
// renewal goroutine keeps its lease alive (preventing a reap while we still hold the fd). Returns the
// adopted ino, or 0 if nothing is parked under it (e.g. the name was genuinely removed, not orphaned).
func (n *node) redirectToOrphan() uint64 {
	return n.core().RedirectToOrphan(n.coreState())
}

// lockTwo locks nodes a and b in a stable (ino) order, so an op that must hold BOTH — write-back
// rename-over-open, which blocks writes to the SOURCE and the DEST fd during the orphan transition —
// cannot deadlock against a concurrent single-node route-lock (Read/Write/Setattr take one n.mu).
// Either may be nil (lock only the other); a == b locks once. Inos are unique, so distinct nodes get
// a deterministic order.
func lockTwo(a, b *node) {
	switch {
	case a == nil:
		if b != nil {
			b.mu.Lock()
		}
	case b == nil || a == b:
		a.mu.Lock()
	case a.StableAttr().Ino <= b.StableAttr().Ino:
		a.mu.Lock()
		b.mu.Lock()
	default:
		b.mu.Lock()
		a.mu.Lock()
	}
}

func unlockTwo(a, b *node) {
	if a != nil {
		a.mu.Unlock()
	}
	if b != nil && b != a {
		b.mu.Unlock()
	}
}

// curPath returns the inode's CURRENT path from the volume root, derived from the live go-fuse
// tree so it follows renames — a fixed field goes stale because go-fuse reuses a node whenever a
// Lookup returns an existing StableAttr.Ino. Falls back to the creation-time path field only when
// the node is not in the tree: the root (stored "") and standalone unit-test nodes.
func (n *node) curPath() string {
	if p := n.Path(nil); p != "" {
		return p
	}
	return n.path
}

func (n *node) child(name string) string {
	p := n.curPath()
	if p == "" {
		return name
	}
	return p + "/" + name
}

func typeBits(kind string) uint32 {
	switch kind {
	case "directory":
		return fuse.S_IFDIR
	case "symlink":
		return fuse.S_IFLNK
	default:
		return fuse.S_IFREG
	}
}

// inoOf maps a path to a stable inode number so stat's st_ino matches readdir's
// d_ino across calls — required for getcwd, find, and tools like git to work.
func inoOf(path string) uint64 {
	if path == "" {
		return 1 // conventional root inode
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	if v := h.Sum64(); v > 1 {
		return v
	}
	return 2
}

// sessAttr builds an Attr from a session's local overlay metadata. A zero (never-set) mtime
// defaults to now so a freshly-written-but-not-utime'd file still reports a sane time; a
// locally-set mtime/uid/gid (via Chtimes/Chown) is surfaced so the change is visible before
// it flushes — without this, stat after touch -d/chown showed the old metadata.
func sessAttr(kind string, mode uint32, size, mtimeMs int64, uid, gid uint32) *fsproto.Attr {
	if mtimeMs == 0 {
		mtimeMs = time.Now().UnixMilli()
	}
	return &fsproto.Attr{Kind: kind, Mode: mode, Size: size, MtimeMs: mtimeMs, CtimeMs: mtimeMs, AtimeMs: mtimeMs, Uid: uid, Gid: gid}
}

// setattrOwner resolves the uid/gid for a session-routed chown. A partial chown (only uid or
// only gid set — the kernel passes the other as unchanged) must NOT clobber the unset field,
// so we read the current value from the authority for whichever side the kernel didn't supply.
// ok is false when no ownership change was requested. The authority read happens only on the
// rare partial chown; a full `chown user:group` stays local.
// p is the caller's path snapshot for this op, so the partial-chown authority read resolves the SAME
// path as the rest of Setattr even if the file is renamed mid-op (n.curPath() could otherwise drift).
func setattrOwner(n *node, p string, in *fuse.SetAttrIn) (uid, gid uint32, ok bool) {
	u, setU := in.GetUID()
	g, setG := in.GetGID()
	if !setU && !setG {
		return 0, 0, false
	}
	uid, gid = u, g
	if !setU || !setG {
		a, st, err := n.c.Getattr(p)
		if err != nil || st != fsproto.OK {
			// A partial chown leaves one side as the kernel's ^uint32(0) ("-1 = leave unchanged")
			// sentinel; we fill it from the file's CURRENT value. If the authority read fails we
			// cannot, so REFUSE the chown (ok=false) rather than persist 4294967295 as a literal
			// owner/group — that would silently, durably corrupt ownership (overflow/nobody).
			return 0, 0, false
		}
		if !setU {
			uid = a.Uid
		}
		if !setG {
			gid = a.Gid
		}
	}
	return uid, gid, true
}

func fillAttr(path string, a *fsproto.Attr, out *fuse.Attr) {
	// st_ino is the stable authority-assigned identity (survives rename, never aliases a recreated
	// path). Falls back to a path hash only when the authority predates inode identity or is read-only.
	out.Ino = a.Ino
	if out.Ino == 0 {
		out.Ino = inoOf(path)
	}
	out.Size = uint64(a.Size)
	out.Mode = typeBits(a.Kind) | modebits.CleanUnix(a.Mode)
	out.Nlink = a.Nlink
	if out.Nlink == 0 {
		out.Nlink = 1 // never report a live inode with zero links — that reads as "unlinked while open"
	}
	out.Mtime = uint64(a.MtimeMs / 1000)
	out.Mtimensec = uint32((a.MtimeMs % 1000) * 1e6)
	ctimeMs := a.CtimeMs
	if ctimeMs == 0 {
		ctimeMs = a.MtimeMs
	}
	out.Ctime = uint64(ctimeMs / 1000)
	out.Ctimensec = uint32((ctimeMs % 1000) * 1e6)
	atimeMs := a.AtimeMs
	if atimeMs == 0 {
		atimeMs = a.MtimeMs
	}
	out.Atime = uint64(atimeMs / 1000)
	out.Atimensec = uint32((atimeMs % 1000) * 1e6)
	out.Uid = a.Uid
	out.Gid = a.Gid
}

func (n *node) newChild(ctx context.Context, name string, a *fsproto.Attr) *fs.Inode {
	cp := n.child(name)
	ino := a.Ino
	if ino == 0 {
		ino = inoOf(cp) // pre-identity authority / read-only fs: stable path hash
	}
	return n.NewInode(ctx, &node{v: n.core(), c: n.c, path: cp, state: clientcore.NewNodeState(ino, a.Ino != 0), authIno: a.Ino != 0}, fs.StableAttr{Mode: typeBits(a.Kind), Ino: ino})
}

// newOpenChild is newChild for Create, which opens the file: it also counts the just-opened handle on
// the child so a subsequent unlink-while-open parks the inode (delete-on-last-close) instead of
// removing it. Operations() yields the child *node (the one we just constructed, or a reused inode's).
func (n *node) newOpenChild(ctx context.Context, name string, a *fsproto.Attr) *fs.Inode {
	cp := n.child(name)
	ch := n.newChild(ctx, name, a)
	if cn, ok := ch.Operations().(*node); ok {
		if cn.core().RegisterOpened(cp, cn.coreState()) == fsproto.ENOENT {
			// The brand-new name was unlinked by a peer within the open-registration window, so the
			// inode is already gone. Signal the caller (nil child) to return ENOENT rather than a
			// handle to a destroyed inode. Rare — it requires racing an exact just-created name.
			return nil
		}
	}
	return ch
}

// errno turns a protocol status into a FUSE errno.
func errno(st int32) syscall.Errno { return syscall.Errno(st) }

// sessionErrno maps a session op error to a FUSE errno: a session handed off mid-op
// (ErrReleased — a rare race after idle-release) maps to EAGAIN so the caller retries (the
// retry re-resolves to a fresh session or write-through); anything else is EIO.
func sessionErrno(err error) syscall.Errno {
	if errors.Is(err, session.ErrReleased) {
		return syscall.EAGAIN
	}
	if errors.Is(err, os.ErrNotExist) {
		return syscall.ENOENT
	}
	return syscall.EIO
}

var (
	_ fs.NodeLookuper   = (*node)(nil)
	_ fs.NodeGetattrer  = (*node)(nil)
	_ fs.NodeReaddirer  = (*node)(nil)
	_ fs.NodeOpener     = (*node)(nil)
	_ fs.NodeReader     = (*node)(nil)
	_ fs.NodeWriter     = (*node)(nil)
	_ fs.NodeCreater    = (*node)(nil)
	_ fs.NodeMkdirer    = (*node)(nil)
	_ fs.NodeUnlinker   = (*node)(nil)
	_ fs.NodeRmdirer    = (*node)(nil)
	_ fs.NodeRenamer    = (*node)(nil)
	_ fs.NodeSymlinker  = (*node)(nil)
	_ fs.NodeReadlinker = (*node)(nil)
	_ fs.NodeSetattrer  = (*node)(nil)
	_ fs.NodeFsyncer    = (*node)(nil)
	_ fs.NodeFlusher    = (*node)(nil)
	_ fs.NodeReleaser   = (*node)(nil)
	_ fs.NodeGetlker    = (*node)(nil)
	_ fs.NodeSetlker    = (*node)(nil)
	_ fs.NodeSetlkwer   = (*node)(nil)
	_ fs.NodeStatfser   = (*node)(nil)

	_ fs.NodeGetxattrer    = (*node)(nil)
	_ fs.NodeSetxattrer    = (*node)(nil)
	_ fs.NodeListxattrer   = (*node)(nil)
	_ fs.NodeRemovexattrer = (*node)(nil)
)

// xattrErrno maps a wire xattr status to the local syscall errno. The wire
// space is Linux-numbered; going through the syscall constants keeps the
// values right on every GOOS this frontend builds for.
func xattrErrno(st int32) syscall.Errno {
	switch st {
	case fsproto.ENODATA:
		return syscall.ENODATA
	case fsproto.E2BIG:
		return syscall.E2BIG
	case fsproto.ERANGE:
		return syscall.ERANGE
	case fsproto.EOPNOTSUPP:
		return syscall.ENOTSUP
	default:
		return errno(st)
	}
}

// setxattrFlagBits returns the kernel's XATTR_CREATE/XATTR_REPLACE bits for
// this platform (Linux 0x1/0x2; Darwin 0x2/0x4).
func setxattrFlagBits() (create, replace uint32) {
	if runtime.GOOS == "darwin" {
		return 0x2, 0x4
	}
	return 0x1, 0x2
}

func (n *node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	value, st := n.core().Getxattr(ctx, n.curPath(), n.coreState(), attr)
	if st != fsproto.OK {
		return 0, xattrErrno(st)
	}
	if len(dest) < len(value) {
		return uint32(len(value)), syscall.ERANGE // size probe / short buffer: report the needed size
	}
	copy(dest, value)
	return uint32(len(value)), 0
}

func (n *node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	names, st := n.core().Listxattr(ctx, n.curPath(), n.coreState())
	if st != fsproto.OK {
		return 0, xattrErrno(st)
	}
	total := 0
	for _, name := range names {
		total += len(name) + 1 // NUL-terminated concatenation (listxattr(2))
	}
	if len(dest) < total {
		return uint32(total), syscall.ERANGE
	}
	off := 0
	for _, name := range names {
		off += copy(dest[off:], name)
		dest[off] = 0
		off++
	}
	return uint32(total), 0
}

// Setxattr forwards XATTR_CREATE/XATTR_REPLACE to the authority so the
// existence predicate and mutation are one ordered, durable operation across
// every mount. There is intentionally no client-side probe/TOCTOU window.
func (n *node) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	p := n.curPath()
	createBit, replaceBit := setxattrFlagBits()
	if flags & ^(createBit|replaceBit) != 0 {
		return syscall.EINVAL
	}
	var wireFlags uint8
	if flags&createBit != 0 {
		wireFlags |= wal.XattrCreate
	}
	if flags&replaceBit != 0 {
		wireFlags |= wal.XattrReplace
	}
	return xattrErrno(n.core().SetxattrFlags(ctx, p, n.coreState(), attr, data, wireFlags))
}

func (n *node) Removexattr(ctx context.Context, attr string) syscall.Errno {
	return xattrErrno(n.core().Removexattr(ctx, n.curPath(), n.coreState(), attr))
}

// Statfs reports filesystem capacity for statfs(2)/df. The volume is object-store-backed and
// effectively unbounded, so we advertise a large fixed capacity that is mostly free rather than
// the zero-filled default (no handler ⇒ all zeros): a zero statfs makes df report "0 bytes",
// trips tools that pre-check free space (editors, git, package managers) into spurious "No space
// left", and divide-by-zeros any statvfs() consumer keyed on f_bsize/f_blocks. NameLen reflects
// the authority's actual maximum component length.
func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	st := n.core().Statfs()
	out.Blocks = st.Blocks
	out.Bfree = st.Bfree
	out.Bavail = st.Bavail
	out.Bsize = st.Bsize
	out.Frsize = st.Frsize
	out.Files = st.Files
	out.Ffree = st.Ffree
	out.NameLen = st.NameLen
	return 0
}

// Fsync forces durability. Under a write-back session it forces the session's flush log to
// LOCAL disk (survives a process crash) and returns — the backend catches up asynchronously
// (the blessed async-durable window). In write-through mode a write is already durable on
// the VCS (WAL fsync + synchronous replication) before it returns, so this is a no-op.
func (n *node) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return errno(n.core().FsyncPath(n.curPath()))
}

// Flush runs on every close(2) of a file descriptor — including a forked child's inherited fd and
// any non-final close of a shared open-file-description. It must NOT release advisory locks: flock
// locks are per-open-file-description and live until that description is fully closed (FUSE RELEASE,
// i.e. refcount 0), not on an intermediate FLUSH. Releasing here drops a held lock the instant a
// peer fd closes (e.g. flock(1) closing the parent's fd after forking the command), breaking
// exclusion. Lock release happens in Release.
func (n *node) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	return 0
}

// cachedGetattr serves a path's attributes from the version-coherent attrCache when possible (no
// authority round-trip), else fetches via GetattrV and caches the result. The kernel entry/attr
// TTL is 0, so this absorbs the round-trips while staying coherent: the cache is evicted by the
// invalidation stream (exactly when the content cache is), never by a timer. Returns (attr, status).
func (n *node) cachedGetattr(path string) (fsproto.Attr, int32) {
	return n.core().CachedGetattr(path)
}

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	if grafts.Owner(cp) != "" {
		// The name is grafted: resolve against machine-local backing and
		// shadow whatever the volume has — no authority round trip.
		return grafts.LookupChild(ctx, n.EmbeddedInode(), cp, out)
	}
	a, st := n.core().Lookup(ctx, cp)
	if st != fsproto.OK {
		out.SetEntryTimeout(n.core().AttrValidFor(cp))
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.core().AttrValidFor(cp))
	out.SetAttrTimeout(n.core().AttrValidFor(cp))
	return n.newChild(ctx, name, &a), 0
}

func (n *node) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	p := n.curPath() // snapshot once: one consistent path for the whole op, and avoid walking the parent chain per call
	a, st := n.core().Getattr(ctx, p, n.coreState())
	if st != fsproto.OK {
		return errno(st)
	}
	fillAttr(p, &a, &out.Attr)
	out.SetTimeout(n.core().AttrValidFor(p))
	return 0
}

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	dir := n.curPath() // snapshot once: the RPC, the session check, and every child path must agree even if the node is renamed mid-RPC
	ents, st := n.core().Readdir(ctx, dir)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	if grafts != nil {
		// Graft roots under this directory merge in exactly once (shadowing
		// same-named volume entries) and only when their backing exists.
		merged, eno := grafts.MergeParentListing(dir, ents)
		if eno != 0 {
			return nil, eno
		}
		ents = merged
	}
	list := make([]fuse.DirEntry, 0, len(ents))
	for _, e := range ents {
		list = append(list, fuse.DirEntry{Name: e.Name, Mode: typeBits(e.Attr.Kind), Ino: e.Ino})
	}
	return fs.NewListDirStream(list), 0
}

// Open lets the kernel cache reads (fast, local). Coherence comes from the VCS
// pushing invalidations that evict exactly the changed files on other clients.
func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	p := n.curPath()
	writeIntent := flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY)
	if st := n.core().Open(ctx, p, n.coreState(), writeIntent); st != fsproto.OK {
		return nil, 0, errno(st)
	}
	return &lockHandle{
		openPath: p,
		append:   flags&uint32(syscall.O_APPEND) != 0,
	}, openFlags, 0
}

func (n *node) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	p := n.curPath() // snapshot once: one consistent path for the whole op, and avoid walking the parent chain per call
	data, st := n.core().Read(ctx, p, n.coreState(), off, len(dest))
	if st != fsproto.OK {
		return nil, errno(st)
	}
	return fuse.ReadResultData(data), 0
}

func (n *node) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	p := n.curPath() // snapshot once: one consistent path for the whole op, and avoid walking the parent chain per call
	var cnt int
	var st clientcore.Status
	if h, ok := fh.(*lockHandle); ok && h.append {
		cnt, st = n.core().WriteAppend(ctx, p, n.coreState(), off, data)
	} else {
		cnt, st = n.core().Write(ctx, p, n.coreState(), off, data)
	}
	if st != fsproto.OK {
		return 0, errno(st)
	}
	return uint32(cnt), 0
}

func (n *node) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	cp := n.child(name)
	if grafts.Owner(cp) != "" {
		// At a volume parent this can only be the graft root itself, which is
		// a directory rule: EISDIR (CreateChild enforces it).
		return grafts.CreateChild(ctx, n.EmbeddedInode(), cp, flags, mode, out)
	}
	var a fsproto.Attr
	var st clientcore.Status
	if flags&syscall.O_EXCL != 0 {
		a, st = n.core().CreateExcl(ctx, cp, mode)
	} else {
		a, st = n.core().Create(ctx, cp, mode)
	}
	if st != fsproto.OK {
		return nil, nil, 0, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.core().AttrValidFor(cp))
	out.SetAttrTimeout(n.core().AttrValidFor(cp))
	ch := n.newOpenChild(ctx, name, &a)
	if ch == nil {
		return nil, nil, 0, syscall.ENOENT
	}
	return ch, &lockHandle{
		openPath: cp,
		append:   flags&uint32(syscall.O_APPEND) != 0,
	}, openFlags, 0
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	if grafts.Owner(cp) != "" {
		// mkdir of the graft root creates it machine-local (with scaffold);
		// this is the only way a graft root comes into existence.
		return grafts.MkdirChild(ctx, n.EmbeddedInode(), cp, mode, out)
	}
	a, st := n.core().Mkdir(ctx, cp, mode)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.core().AttrValidFor(cp))
	out.SetAttrTimeout(n.core().AttrValidFor(cp))
	return n.newChild(ctx, name, &a), 0
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	cp := n.child(name)
	if grafts.Owner(cp) != "" {
		return grafts.Remove(cp, false)
	}
	var child *clientcore.NodeState
	if cn := n.childNode(name); cn != nil {
		child = cn.coreState()
	}
	return errno(n.core().Remove(ctx, cp, child))
}

// childNode returns the live mount node for child `name` if the kernel currently has it instantiated
// (so Unlink/rename-over can see whether it is open), or nil.
func (n *node) childNode(name string) *node {
	ch := n.GetChild(name)
	if ch == nil {
		return nil
	}
	cn, _ := ch.Operations().(*node)
	return cn
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	cp := n.child(name)
	if grafts.Owner(cp) != "" {
		// rmdir of the graft root removes it like any directory (ENOTEMPTY
		// while it has contents) — the npm-ci wholesale-rebuild path.
		return grafts.Remove(cp, true)
	}
	return n.Unlink(ctx, name)
}

func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	np, ok := newParent.(*node)
	if !ok {
		return syscall.EXDEV
	}
	oldp, newp := n.child(name), np.child(newName)
	if eno, handled := grafts.VolumeRenameCheck(oldp, newp); handled {
		return eno
	}
	var src, dst *clientcore.NodeState
	if sn := n.childNode(name); sn != nil {
		src = sn.coreState()
	}
	if dn := np.childNode(newName); dn != nil {
		dst = dn.coreState()
	}
	st := n.core().Rename(ctx, oldp, newp, src, dst)
	if st == fsproto.OK {
		// A volume rename of a graft root's ancestor carries the graft and
		// its machine-local backing to the new location.
		grafts.RemapForRename(oldp, newp)
	}
	return errno(st)
}

func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	if grafts.Owner(cp) != "" {
		// At a volume parent this can only be the graft root: EISDIR.
		return grafts.SymlinkChild(ctx, n.EmbeddedInode(), target, cp, out)
	}
	a, st := n.core().Symlink(ctx, target, cp)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.core().AttrValidFor(cp))
	out.SetAttrTimeout(n.core().AttrValidFor(cp))
	return n.newChild(ctx, name, &a), 0
}

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	t, st := n.core().Readlink(ctx, n.curPath())
	if st != fsproto.OK {
		return nil, errno(st)
	}
	return []byte(t), 0
}

func (n *node) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	p := n.curPath() // snapshot once: one consistent path for the whole op, and avoid walking the parent chain per call
	var req clientcore.SetattrRequest
	if sz, ok := in.GetSize(); ok {
		req.Size = int64(sz)
		req.SetSize = true
	}
	if mode, ok := in.GetMode(); ok {
		req.Mode = mode
		req.SetMode = true
	}
	if mt, ok := in.GetMTime(); ok {
		req.MtimeMs = mt.UnixMilli()
		req.SetMTime = true
	}
	if uid, ok := in.GetUID(); ok {
		req.UID = uid
		req.SetUID = true
	}
	if gid, ok := in.GetGID(); ok {
		req.GID = gid
		req.SetGID = true
	}
	a, st := n.core().Setattr(ctx, p, n.coreState(), req)
	if st != fsproto.OK {
		return errno(st)
	}
	if a.Kind != "" {
		fillAttr(p, &a, &out.Attr)
	}
	out.SetTimeout(n.core().AttrValidFor(p))
	return 0
}

// ---- cache invalidation: drive the kernel from the VCS push stream ----

func splitPath(p string) (dir, base string) {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// walk resolves a path to its cached inode, or nil if it isn't cached (nothing to
// invalidate).
func walk(root *fs.Inode, path string) *fs.Inode {
	cur := root
	if path == "" {
		return cur
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		if cur = cur.GetChild(part); cur == nil {
			return nil
		}
	}
	return cur
}

// cachedNodeAtPath returns the live mount node currently instantiated at path (a node the kernel is
// holding because something has it open or recently looked it up), or nil if no node is instantiated
// there. Used by the invalidation stream to find a peer-orphaned path's open node for redirect.
func cachedNodeAtPath(root *fs.Inode, path string) *node {
	in := walk(root, path)
	if in == nil {
		return nil
	}
	n, _ := in.Operations().(*node)
	return n
}

// invalidatePath drops a path from the kernel cache on a remote change: the file's cached data
// (NotifyContent) and, when the NAME's binding may have changed, the parent dentry (NotifyEntry).
//
// It does NOT NotifyEntry for an IN-PLACE change (inPlace == true: write/truncate/chmod/chtimes/
// chown — the name still maps to the same inode). Dropping the dentry of a directory that a process
// holds as its CWD disconnects it, so a concurrent getcwd() — e.g. SQLite resolving a relative db
// path, or any tool that opens "." — fails with ENOENT and the app sees SQLITE_CANTOPEN. This is the
// SAME hazard that made flushAll content-only; invalidatePath is its per-path sibling. For an
// in-place change the dentry drop is also unnecessary: content/attr coherence flows via NotifyContent
// and the attr cache. A create/remove/rename (inPlace == false) still drops the dentry, so existence
// coherence holds for ANY entry-TTL config (not only the entry-timeout=0 default).
func invalidatePath(root *fs.Inode, path string, inPlace bool) {
	if path == "" {
		return
	}
	dir, base := splitPath(path)
	parent := walk(root, dir)
	if parent == nil {
		return
	}
	if child := parent.GetChild(base); child != nil {
		_ = child.NotifyContent(0, 0) // 0 length => invalidate to EOF (a dir's "content" is its listing)
	}
	if !inPlace {
		_ = parent.NotifyEntry(base)
	}
}

// flushAll evicts the entire cached subtree (used on (re)subscribe or overflow,
// when individual changes may have been missed).
// flushAll drops the kernel's CACHED CONTENT for an entire subtree (used on (re)acquire / release /
// generation change / resubscribe). It deliberately does NOT invalidate dentries (NotifyEntry):
//   - It is redundant — the entry timeout is 0, so the kernel revalidates every name lookup anyway
//     (existence changes are caught by that revalidation, not by a dentry drop).
//   - It is HARMFUL — invalidating the dentry of a directory that is in use as a process's CWD
//     (e.g. SQLite running in its database's directory) disconnects that dentry, and a concurrent
//     getcwd() then fails with ENOENT → the app sees SQLITE_CANTOPEN ("unable to open database
//     file"). This is exactly the two-mount build flake: an async flushAll racing SQLite's getcwd.
//
// Content coherence (a file's bytes changed under us) is what flushAll is for; NotifyContent gives
// that. Existence coherence is the entry-timeout=0 kernel's job.
//
// Grafted subtrees are skipped: their kernel cache is backed by machine-local
// disk that no authority event can invalidate.
func flushAll(n *fs.Inode) {
	for _, child := range n.Children() {
		if localdirs.IsLocalNode(child.Operations()) {
			continue
		}
		_ = child.NotifyContent(0, 0)
		flushAll(child)
	}
}

type mountInvalidationHandler struct {
	root *fs.Inode
}

func (h mountInvalidationHandler) FlushAll() { flushAll(h.root) }

func (h mountInvalidationHandler) InvalidatePath(path string, inPlace bool) {
	if grafts.Owner(path) != "" {
		// Volume changes under a graft are shadowed by machine-local backing;
		// surfacing them would evict valid local kernel state.
		return
	}
	invalidatePath(h.root, path, inPlace)
}

func (h mountInvalidationHandler) MarkOrphan(path string, ino uint64) {
	if grafts.Owner(path) != "" {
		return
	}
	if cn := cachedNodeAtPath(h.root, path); cn != nil {
		cn.markOrphan(ino)
	}
}

func (h mountInvalidationHandler) ReleaseSubtree(path string) {
	if sessions != nil {
		sessions.ReleaseSubtree(path)
	}
}

// unmountBarrierVolume is the volume surface the unmount barrier needs; a seam for testing it.
type unmountBarrierVolume interface {
	FlushToAuthority(context.Context) error
	// AuthorityUnreachable reports confirmed transport unreachability
	// (fail-fast): a network flush is futile until the prober recovers.
	AuthorityUnreachable() bool
	// SessionFenced reports a fenced mount session: this generation's writes
	// are permanently rejected by the authority (remount required), so a
	// network flush is equally futile — but for a DEFINITE reason, which the
	// log line must name.
	SessionFenced() bool
	// SyncLocalDurable fsyncs pending write-back mutations into the local
	// session WALs (the journal-first barrier; recovery replays them).
	SyncLocalDurable() error
}

// runUnmountFlushBarrier makes every write-back mutation durable before unmount WITHOUT ever
// depending on a live authority connection (journal-first unmount). Authority reachable: bounded
// flush to the authority, exactly as before. Authority confirmed unreachable/fenced — or the flush
// fails: fsync the session WALs instead; the un-flushed tail is replayed on the next clean start of
// this volume (the designed crash-recovery path), so the operator must NOT delete the WAL directory.
// m2: every failure is logged LOUDLY with the WAL-recovery hint, never discarded.
func runUnmountFlushBarrier(vol unmountBarrierVolume, timeout time.Duration, logf func(string, ...any)) {
	if fenced, unreachable := vol.SessionFenced(), vol.AuthorityUnreachable(); fenced || unreachable {
		cause := "authority unreachable (fail-fast)"
		if fenced {
			// The definite cause wins the log line: a fenced generation's
			// writes are rejected even by a healthy authority (m1), so the
			// operator must know remount — not connectivity — is the fix.
			cause = "session fenced (writes of this generation rejected; remount required)"
		}
		if err := vol.SyncLocalDurable(); err != nil {
			logf("unmount flush barrier: %s AND the local WAL fsync failed: %v; "+
				"un-flushed write-back mutations may not survive a machine crash — do NOT delete the WAL directory", cause, err)
			return
		}
		logf("unmount flush barrier: %s; skipped the network flush — "+
			"write-back mutations are durable in the session WAL and are recovered on the next clean start "+
			"of this volume (journal-first unmount); do NOT delete the WAL directory", cause)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := vol.FlushToAuthority(ctx); err != nil {
		// Close the machine-crash window for the un-flushed tail even though
		// the authority flush failed: local WAL durability is what the next
		// clean start's recovery replays.
		if serr := vol.SyncLocalDurable(); serr != nil {
			logf("unmount flush barrier FAILED: %v; local WAL fsync also failed: %v — do NOT delete the WAL directory", err, serr)
			return
		}
		logf("unmount flush barrier FAILED: %v; un-flushed write-back mutations remain durable in the session WAL and "+
			"are recovered on the next clean start of this volume — do NOT delete the WAL directory", err)
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:2050", "VCS filesystem-protocol authority address(es); comma-separated failover candidates")
	mountpoint := flag.String("mount", "", "directory to mount the volume on")
	pool := flag.Int("pool", 16, "connection pool size (concurrent in-flight ops)")
	direct := flag.Bool("direct", false, "mount via the mount(2) syscall (needs root/CAP_SYS_ADMIN) instead of the fusermount helper")
	flag.Parse()
	if *mountpoint == "" {
		log.Fatal("-mount is required")
	}

	clientTLS, err := secure.ClientTLS()
	if err != nil {
		log.Fatalf("TLS config: %v", err)
	}
	owner := mountOwner(*addr, *mountpoint) // checkout-owner id (stable when recovery is enabled)
	diskCacheVolumeID = hashString(*addr)
	diskCacheDir := os.Getenv("PORTABLEFS_DISK_CACHE_DIR")
	diskCacheBytes := int64(0)
	if dir := os.Getenv("PORTABLEFS_DISK_CACHE_DIR"); dir != "" {
		mb := 4096
		if v := os.Getenv("PORTABLEFS_DISK_CACHE_MB"); v != "" {
			if parsed, e := strconv.Atoi(v); e == nil && parsed > 0 {
				mb = parsed
			}
		}
		diskCacheBytes = int64(mb) << 20
		log.Printf("disk content cache enabled: %d MiB at %s", mb, dir)
	}

	walDir := os.Getenv("PORTABLEFS_WAL_DIR")
	if os.Getenv("PORTABLEFS_WRITEBACK") == "1" && walDir == "" {
		d, derr := os.MkdirTemp("", "portablefs-sess-")
		if derr != nil {
			log.Fatalf("write-back scratch dir: %v", derr)
		}
		walDir = d
	} else if walDir != "" {
		if err := os.MkdirAll(walDir, 0o700); err != nil {
			log.Fatalf("write-back wal dir %q: %v", walDir, err)
		}
	}
	idleMs := 0
	if v := os.Getenv("PORTABLEFS_IDLE_MS"); v != "" {
		if ms, e := strconv.Atoi(v); e == nil && ms >= 0 {
			idleMs = ms
		}
	}
	flushMs := 250
	if v := os.Getenv("PORTABLEFS_FLUSH_MS"); v != "" {
		if ms, e := strconv.Atoi(v); e == nil && ms > 0 {
			flushMs = ms
		}
	}
	flushMaxRecords := 0 // 0 = session default (512)
	if v := os.Getenv("PORTABLEFS_FLUSH_MAX_RECORDS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			flushMaxRecords = n
		}
	}
	flushMaxBytes := int64(0) // 0 = unbounded (today's behavior)
	if v := os.Getenv("PORTABLEFS_FLUSH_MAX_BYTES"); v != "" {
		if n, e := strconv.ParseInt(v, 10, 64); e == nil && n > 0 {
			flushMaxBytes = n
		}
	}
	prefetchTree := os.Getenv("PORTABLEFS_PREFETCH_TREE") == "1"
	prefetchMaxEntries := 20_000
	if v := os.Getenv("PORTABLEFS_PREFETCH_MAX_ENTRIES"); v != "" {
		if parsed, e := strconv.Atoi(v); e == nil && parsed > 0 {
			prefetchMaxEntries = parsed
		}
	}
	prefetchMaxDepth := 4
	if v := os.Getenv("PORTABLEFS_PREFETCH_MAX_DEPTH"); v != "" {
		if parsed, e := strconv.Atoi(v); e == nil && parsed >= 0 {
			prefetchMaxDepth = parsed
		}
	}
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr:                 *addr,
		Pool:                 *pool,
		TLSConfig:            clientTLS,
		Owner:                owner,
		WriteBack:            os.Getenv("PORTABLEFS_WRITEBACK") == "1",
		WALDir:               walDir,
		IdleInterval:         time.Duration(idleMs) * time.Millisecond,
		FlushInterval:        time.Duration(flushMs) * time.Millisecond,
		FlushMaxRecords:      flushMaxRecords,
		FlushMaxBytes:        flushMaxBytes,
		FsyncPolicy:          fsyncPolicy,
		NegativeCache:        negativeCacheEnabled,
		NoNegativeCache:      negativeCacheDisabled,
		OpenRetentionEntries: openRetentionEntries(),
		DiskCacheDir:         diskCacheDir,
		DiskCacheBytes:       diskCacheBytes,
		VolumeID:             diskCacheVolumeID,
		NoReaddirPlus:        noReaddirPlus,
		SessionTTL:           sessionTTL,
		PrefetchTree:         prefetchTree,
		PrefetchMaxEntries:   prefetchMaxEntries,
		PrefetchMaxDepth:     prefetchMaxDepth,
		OnFlushAll: func(path string) {
			if rootNode == nil {
				return
			}
			if path == "" {
				flushAll(rootNode.EmbeddedInode())
				return
			}
			if n := walk(rootNode.EmbeddedInode(), path); n != nil {
				flushAll(n)
			}
		},
		OnInvalidate: func(path string, inPlace bool) {
			if grafts.Owner(path) != "" {
				// Volume changes under a graft are shadowed by machine-local
				// backing; surfacing them would evict valid local kernel state.
				return
			}
			if rootNode != nil {
				invalidatePath(rootNode.EmbeddedInode(), path, inPlace)
			}
		},
		OnMarkOrphan: func(path string, ino uint64) {
			if grafts.Owner(path) != "" {
				return
			}
			if rootNode == nil {
				return
			}
			if cn := cachedNodeAtPath(rootNode.EmbeddedInode(), path); cn != nil {
				cn.markOrphan(ino)
			}
		},
		Debugf: dbg,
	})
	if err != nil {
		log.Fatalf("connect to VCS %s: %v", *addr, err)
	}
	cli := vol.Client()
	mreg := vol.Metrics
	sessions = vol.Sessions()
	openOrphans = vol.OpenOrphans()
	openFiles = vol.OpenFiles()
	opens = &openTracker{OpenTracker: vol.OpenTracker()}

	// Machine-local dirs (grafts): PORTABLEFS_LOCAL_DIRS plus the volume's
	// .portablefs/local-dirs file. Assigned before any invalidation goroutine
	// starts, so the filter closures above see the final value.
	g, err := setupLocalDirs(vol, *addr, *mountpoint, log.Printf)
	if err != nil {
		log.Fatalf("machine-local dirs: %v", err)
	}
	grafts = g
	defer func() { _ = grafts.Close() }()

	// Cache mode. Default: the kernel caches file DATA (fast local reads, kept
	// while mtime is unchanged) but attributes are always fresh (ttl 0), so a
	// freshly-written file never reports a stale size — read-after-write is correct
	// without relying on the (skip-originator) invalidation stream, which only
	// evicts OTHER clients. "keepcache"/"direct" are escape hatches.
	ttl := time.Duration(0)
	switch os.Getenv("PORTABLEFS_CACHE") {
	case "direct":
		openFlags = fuse.FOPEN_DIRECT_IO
	case "keepcache":
		openFlags = fuse.FOPEN_KEEP_CACHE
		ttl = 60 * time.Second
	default: // data cached (kept across opens), attrs fresh
		openFlags = fuse.FOPEN_KEEP_CACHE
	}
	if v := os.Getenv("PORTABLEFS_TTL_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			ttl = time.Duration(ms) * time.Millisecond
		}
	}
	// Existence (the name→inode dentry) is ALWAYS coherence-by-version, never time-cached — even under
	// keepcache / PORTABLEFS_TTL_MS. go-fuse only fills Options.EntryTimeout when a Lookup returns 0,
	// so &entryTTL=0 leaves the per-lookup value in charge: 0 for a SHARED path (revalidate every name
	// lookup) and the explicit sessionTTL for an EXCLUSIVELY-held path (kept, since it is non-zero).
	// A positive GLOBAL entry timeout would instead let a peer serve a deleted/renamed directory until
	// the TTL after a missed (flushAll-collapsed) invalidation — and flushAll is content-only by
	// design (it must not drop in-use CWD dentries). Only ATTRS/content are time-cached (the cache the
	// keepcache escape hatch actually wants); attr staleness is harmless, stale existence is not.
	entryTTL := time.Duration(0)
	opts := &fs.Options{
		AttrTimeout:  &ttl,
		EntryTimeout: &entryTTL,
		// We return precise permissions from Getattr/Lookup (the authority tracks them), so a
		// zero-permission mode is INTENTIONAL — `chmod 000` must stick. Without this, go-fuse's
		// default "null permissions => 0644/0755" convenience silently rewrites a legitimately
		// mode-0 file's perms to 0644 before they reach the kernel (the chmod-000 regression).
		NullPermissions: true,
		MountOptions: fuse.MountOptions{
			FsName:        "portablefs",
			Name:          "portablefs",
			DirectMount:   *direct,
			MaxWrite:      1 << 20,                                // 1 MiB reads/writes -> ~8x fewer round-trips
			MaxReadAhead:  1 << 20,                                // aggressive readahead -> reads parallelise over the pool
			MaxBackground: 256,                                    // allow many in-flight async reads so readahead can saturate the connection pool (default ~12 throttles it)
			EnableLocks:   os.Getenv("PORTABLEFS_NO_LOCKS") == "", // forward flock/fcntl locks to FUSE -> the authority, so they coordinate ACROSS mounts (a per-client kernel lock table cannot); PORTABLEFS_NO_LOCKS=1 disables (diagnostic)
		},
	}
	root := &node{v: vol, c: cli, state: clientcore.NewNodeState(1, true)}
	rootNode = root
	server, err := fs.Mount(*mountpoint, root, opts)
	if err != nil {
		log.Fatalf("mount %s: %v", *mountpoint, err)
	}
	log.Printf("mounted volume at %s via VCS %s (FUSE, cached reads + push invalidation)", *mountpoint, *addr)

	renewEvery := orphanRenewInterval
	if v := os.Getenv("PORTABLEFS_ORPHAN_RENEW_MS"); v != "" {
		if ms, e := strconv.Atoi(v); e == nil && ms > 0 {
			renewEvery = time.Duration(ms) * time.Millisecond
		}
	}
	renewCtx, stopRenew := context.WithCancel(context.Background())
	var renewWG sync.WaitGroup
	renewWG.Add(1)
	go func() {
		defer renewWG.Done()
		// The volume-owned loop feeds renewal confirmations back to the open
		// registry, which is what keeps retained registrations reusable.
		vol.RunOpenLeaseRenewal(renewCtx, renewEvery, dbg)
	}()

	if os.Getenv("PORTABLEFS_WRITEBACK") == "1" {
		log.Printf("write-back enabled (owner=%s, flush=%dms, idle=%dms, walDir=%s)", owner, flushMs, idleMs, walDir)
	}

	if os.Getenv("PORTABLEFS_INVAL") != "0" {
		go vol.StartInvalidations(renewCtx, dropOrphanInval)
	}

	if addr := os.Getenv("PORTABLEFS_METRICS_ADDR"); addr != "" {
		go serveMountMetrics(mreg, addr)
	}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Print("unmounting...")
		stopRenew()
		runUnmountFlushBarrier(vol, 30*time.Second, log.Printf)
		_ = server.Unmount()
	}()
	server.Wait()
	stopRenew()
	renewWG.Wait()
	if vol.AuthorityUnreachable() || vol.SessionFenced() {
		// Journal-first: the clean Close would re-block on the dead network
		// inside its final session drain (or, fenced, churn on definite
		// rejections). Fsync + keep the WALs (and the session lease, whose
		// grace protects the un-flushed state) for the next clean start's
		// recovery replay.
		log.Print("close: authority unreachable or session fenced; closing journal-first (session WALs kept for recovery)")
		_ = vol.CloseJournalDurable()
	} else {
		_ = vol.Close()
	}
}

func randHex(nbytes int) string {
	b := make([]byte, nbytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// mountOwner is this mount's checkout-owner id. For crash recovery the id (and thus the
// per-session WAL paths) must be STABLE across restarts: PORTABLEFS_OWNER (operator-set) wins;
// otherwise, when a persistent PORTABLEFS_WAL_DIR is configured, it's derived deterministically
// from host+addr+mountpoint (stable, and unique per mount so checkouts never collide). With
// no persistence it's random — a fresh identity each run (no recovery, the ephemeral default).
func mountOwner(addr, mountpoint string) string {
	if o := os.Getenv("PORTABLEFS_OWNER"); o != "" {
		return o
	}
	if os.Getenv("PORTABLEFS_WAL_DIR") != "" {
		host, _ := os.Hostname()
		return "own-" + hashString(host+"\x00"+addr+"\x00"+mountpoint)
	}
	return randHex(8)
}

func hashString(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 16)
}

// serveMountMetrics exposes mount observability over HTTP (PORTABLEFS_METRICS_ADDR):
//   - /stats   write-back + authority-round-trip metrics as JSON
//   - /metrics same, Prometheus text exposition format
//   - /healthz liveness (the mount process is up)
//
// The point-in-time gauges (active sessions, un-flushed backlog) are refreshed per scrape.
func serveMountMetrics(reg *metrics.Registry, addr string) {
	refresh := func() *metrics.Registry {
		if sessions != nil {
			return sessions.Metrics() // recomputes write-back gauges; returns the shared registry
		}
		return reg
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(refresh().Snapshot())
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(refresh().Prometheus()))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("mount metrics: http://%s/stats (+ /metrics, /healthz)", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("mount metrics server: %v", err)
	}
}
