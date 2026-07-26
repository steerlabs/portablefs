package clientcore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
	"github.com/trendup-ai/portablefs/vcs/internal/session"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// FsyncPolicy controls write-back fsync durability.
type FsyncPolicy string

const (
	// FsyncLocal keeps today's write-back behavior: fsync commits the local session WAL only.
	FsyncLocal FsyncPolicy = "local"
	// FsyncAuthority additionally flushes the covering write-back session to the authority.
	FsyncAuthority FsyncPolicy = "authority"
)

// Options configures a frontend-neutral clientcore volume attachment.
type Options struct {
	Addr      string
	Pool      int
	TLSConfig *tls.Config
	Owner     string

	CredentialSource func() string
	AuthToken        string

	// OnTokenRejected is invoked (single-flight, client-side coalesced) when
	// the data-plane router explicitly rejects this mount's session token on
	// a dial — the manager restarted or the lease rotated. It must re-resolve
	// the mount session so CredentialSource serves the fresh token, and
	// report whether it did; dials then retry immediately instead of waiting
	// for a timed credential refresh.
	OnTokenRejected func() bool

	WriteBack     bool
	WALDir        string
	IdleInterval  time.Duration
	FlushInterval time.Duration
	FsyncPolicy   FsyncPolicy

	// FlushMaxRecords / FlushMaxBytes bound one write-back FlushBatch RPC (records and
	// payload bytes). Zero keeps the session defaults (512 records, unbounded bytes).
	// Pure batching knobs: they change round-trip count, never apply semantics.
	FlushMaxRecords int
	FlushMaxBytes   int64

	// Negative dentry cache mode. Neither flag set (the default) is
	// capability-auto: ON iff the authority advertises FeatParentVersion in
	// the protocol handshake (every miss then carries a parent-directory
	// version stamp the cached negative is ordered against, and every name
	// mutation bumps it — the invalidation-driven coherence proof).
	// NegativeCache forces it on regardless (harmless against a pre-stamp
	// authority: a miss without ParentVersion is never cached, so it degrades
	// to no caching, never to staleness); NoNegativeCache forces it off.
	NegativeCache   bool
	NoNegativeCache bool

	// OpenRetentionEntries bounds the retained open-registration LRU (see
	// openreg.go). 0 = default (65536); negative disables retention.
	OpenRetentionEntries int

	DiskCacheDir   string
	DiskCacheBytes int64
	VolumeID       string

	PrefetchTree       bool
	PrefetchMaxEntries int
	PrefetchMaxDepth   int

	NoReaddirPlus bool
	AttrTTL       time.Duration
	SessionTTL    time.Duration
	OnInvalidate  func(path string, inPlace bool)
	OnFlushAll    func(path string)
	OnMarkOrphan  func(path string, ino uint64)
	// OnWriteBackError is called per subtree root after each write-back flush with the flush
	// error (nil clears). Lets the daemon flip a mount to degraded when flushes persistently
	// fail, so acked-but-unflushable write-back is loud instead of silently lost.
	OnWriteBackError func(root string, err error)
	Debugf           func(string, ...any)

	// ExactSlots bounds this mount's concurrent in-flight exact mutations
	// (0 = the fsproto default). Set before the first mutation.
	ExactSlots uint32
}

// PrefetchProgress is a snapshot of the asynchronous metadata prefetcher.
type PrefetchProgress struct {
	Entries int64
	Done    bool
	Err     string
}

// Volume is the shared PortableFS client brain: protocol client, versioned metadata cache,
// optional write-back sessions, credential renewal, prefetch, and flush barriers. It deliberately
// has no go-fuse types; kernel frontends translate their native op shapes into these methods.
type Volume struct {
	client *fsproto.Client
	owner  string

	AttrCache    *AttrCache
	VersionCache *VersionCache
	Metrics      *metrics.Registry
	DiskCache    *DiskBlockCache

	sessions    *session.Manager
	fsyncPolicy FsyncPolicy
	dirMu       sync.Mutex
	dirCache    map[string]dirCacheEntry
	recent      *recentWrites
	opens       *OpenTracker
	openOrphans *InodeSet
	openFiles   *InodeSet
	// hardlinks marks authority inodes with multiple names. Write-back's
	// path-keyed overlay cannot safely buffer two independently discovered
	// aliases, so mutations for these rare inodes stay on the ordered
	// write-through lane while ordinary files retain full write-back speed.
	hardlinks *hardlinkAliases
	openReg   *openRegistry

	// lockReg tracks the live advisory-lock handles so a post-failover
	// reclaim window can re-assert every held lock (see ReassertCoordination).
	lockRegMu sync.Mutex
	lockReg   map[*LockHandle]struct{}

	negativeCache bool
	noReaddirPlus bool
	attrTTL       time.Duration
	sessionTTL    time.Duration
	volumeID      string
	onInvalidate  func(path string, inPlace bool)
	onFlushAll    func(path string)
	onMarkOrphan  func(path string, ino uint64)
	debugf        func(string, ...any)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// kernelFlushGen tracks the last generation for which the Read path fired its FOPEN_KEEP_CACHE
	// kernel-flush backup. It is DELIBERATELY separate from the version cache's anchored generation
	// (P1): CachedGetattr/Readdir also RefreshAll on an unseen gen but must not flush the kernel, so a
	// getattr that observes a failover first cannot suppress a later read's content flush.
	kernelFlushMu  sync.Mutex
	kernelFlushGen uint64

	prefetchMu sync.Mutex
	prefetch   PrefetchProgress
}

// markKernelFlushed reports whether gen is being kernel-flushed for the FIRST time, recording it so
// the Read-path flush backup fires exactly once per new generation regardless of which op first
// observed the generation.
func (v *Volume) markKernelFlushed(gen uint64) bool {
	if gen == 0 {
		return false
	}
	v.kernelFlushMu.Lock()
	defer v.kernelFlushMu.Unlock()
	if v.kernelFlushGen == gen {
		return false
	}
	v.kernelFlushGen = gen
	return true
}

// Dial attaches to an authority and initializes the shared client state. Mount readiness is not
// blocked on optional prefetch; when enabled it runs in the background.
func Dial(ctx context.Context, opts Options) (*Volume, error) {
	if opts.Addr == "" {
		return nil, fmt.Errorf("clientcore: Addr is required")
	}
	auth := opts.CredentialSource
	if auth == nil && opts.AuthToken != "" {
		tok := opts.AuthToken
		auth = func() string { return tok }
	}
	cli, err := fsproto.DialTLSAuth(opts.Addr, opts.Pool, opts.TLSConfig, auth)
	if err != nil {
		return nil, err
	}
	if opts.Owner != "" {
		cli.SetOwner(opts.Owner)
	}
	if opts.CredentialSource != nil {
		cli.SetAuthTokenSource(opts.CredentialSource)
	} else if opts.AuthToken != "" {
		cli.SetAuthToken(opts.AuthToken)
	}
	if opts.OnTokenRejected != nil {
		cli.SetOnTokenRejected(opts.OnTokenRejected)
	}
	return Attach(ctx, cli, opts)
}

// Attach initializes clientcore state around an already-dialed fsproto client.
// Tests and embedders that own dialing use this; Dial is the normal production
// entry point.
func Attach(ctx context.Context, cli *fsproto.Client, opts Options) (*Volume, error) {
	if cli == nil {
		return nil, fmt.Errorf("clientcore: nil fsproto client")
	}
	reg := metrics.NewRegistry()
	cli.SetMetrics(reg)
	cctx, cancel := context.WithCancel(ctx)
	v := &Volume{
		client:        cli,
		owner:         opts.Owner,
		AttrCache:     NewAttrCache(),
		VersionCache:  NewVersionCache(),
		Metrics:       reg,
		fsyncPolicy:   opts.FsyncPolicy,
		dirCache:      map[string]dirCacheEntry{},
		recent:        newRecentWrites(),
		opens:         NewOpenTracker(),
		openOrphans:   NewInodeSet(),
		openFiles:     NewInodeSet(),
		hardlinks:     newHardlinkAliases(),
		lockReg:       map[*LockHandle]struct{}{},
		noReaddirPlus: opts.NoReaddirPlus,
		attrTTL:       opts.AttrTTL,
		sessionTTL:    opts.SessionTTL,
		volumeID:      opts.VolumeID,
		onInvalidate:  opts.OnInvalidate,
		onFlushAll:    opts.OnFlushAll,
		onMarkOrphan:  opts.OnMarkOrphan,
		debugf:        opts.Debugf,
		ctx:           cctx,
		cancel:        cancel,
	}
	if v.volumeID == "" {
		v.volumeID = opts.Addr
	}
	cli.SetOnSelfWrite(func(p string, g, ver uint64, inPlace bool) {
		v.noteSelfMutation(p, g, ver, inPlace)
	})
	if opts.DiskCacheDir != "" {
		dc, derr := NewDiskBlockCache(opts.DiskCacheDir, opts.DiskCacheBytes)
		if derr != nil {
			_ = cli.Close()
			cancel()
			return nil, derr
		}
		v.DiskCache = dc
	}
	if v.fsyncPolicy == "" {
		v.fsyncPolicy = FsyncLocal
	}
	// Exact mount session: establish at mount when the authority offers it
	// (negotiated; a legacy authority leaves the client on plain v1 behavior
	// — the graceful downgrade). The reclaim hook re-asserts coordination
	// state after a failover grants a reclaim window. A fenced identity at
	// establish (ErrSessionFenced) is surfaced by the first mutation instead
	// of failing the mount: reads are still valid.
	if opts.ExactSlots != 0 {
		cli.SetExactSlots(opts.ExactSlots)
	}
	cli.SetOnReclaim(v.ReassertCoordination)
	if _, err := cli.EnsureExactSession(); err != nil && !errors.Is(err, fsproto.ErrSessionFenced) {
		_ = cli.Close()
		cancel()
		return nil, err
	}
	// Capability-gated defaults, decided from the handshake the session
	// establish just performed (or a one-shot probe when sessions are
	// disabled). Never sniffed from response fields mid-flight.
	v.negativeCache = opts.NegativeCache
	if !v.negativeCache && !opts.NoNegativeCache {
		v.negativeCache = cli.HasFeature(fsproto.FeatParentVersion)
	}
	v.openReg = newOpenRegistry(cli, v.VersionCache.CurrentGen, v.openFiles,
		cli.SupportsOpenRegistration(), opts.OpenRetentionEntries, opts.Debugf)
	if opts.WriteBack {
		walDir := opts.WALDir
		if walDir == "" {
			d, derr := os.MkdirTemp("", "portablefs-sess-")
			if derr != nil {
				_ = cli.Close()
				cancel()
				return nil, derr
			}
			walDir = d
		} else if err := os.MkdirAll(walDir, 0o700); err != nil {
			_ = cli.Close()
			cancel()
			return nil, err
		}
		auth := selfInvalidatingAuthority{
			Authority: wbAuthority{cli: cli},
			onRecords: func(records []wal.Record) {
				for _, r := range records {
					v.noteSelfMutationRecord(r)
				}
			},
		}
		v.sessions = session.NewManager(auth, opts.Owner, walDir, opts.IdleInterval)
		v.sessions.AttachMetrics(reg)
		v.sessions.SetBusyCheck(v.opens.BusyUnder)
		v.sessions.SetFileGrainRootCheckouts(cli.ServerManaged())
		if opts.OnWriteBackError != nil {
			v.sessions.SetOnFlushHealth(opts.OnWriteBackError)
		}
		if opts.FlushMaxRecords > 0 || opts.FlushMaxBytes > 0 {
			v.sessions.SetFlushLimits(session.FlushLimits{MaxRecords: opts.FlushMaxRecords, MaxBytes: opts.FlushMaxBytes})
		}
		v.sessions.SetOnRelease(func(rp string) {
			v.AttrCache.EvictPrefix(rp)
			v.evictDirCachePrefix(rp) // a listing cached while rp was held must not outlive the release
			if v.onFlushAll != nil {
				v.onFlushAll(rp)
			}
		})
		v.sessions.SetOnAcquire(func(rp string) {
			v.AttrCache.EvictPrefix(rp)
			v.evictDirCachePrefix(rp)
			if v.onFlushAll != nil {
				go v.onFlushAll(rp)
			}
		})
		v.sessions.RecoverAll()
		flush := opts.FlushInterval
		if flush <= 0 {
			flush = 250 * time.Millisecond
		}
		v.sessions.Start(flush)
	}
	if opts.PrefetchTree {
		maxEntries := opts.PrefetchMaxEntries
		if maxEntries <= 0 {
			maxEntries = 20_000
		}
		maxDepth := opts.PrefetchMaxDepth
		if maxDepth <= 0 {
			maxDepth = 4
		}
		v.wg.Add(1)
		go func() {
			defer v.wg.Done()
			v.prefetchTree(maxEntries, maxDepth)
		}()
	}
	return v, nil
}

// wbAuthority adapts *fsproto.Client to session.Authority, routing checkout,
// checkin, and flush through the managed journaled-coordination surface when
// the authority negotiated it (ServerManaged), and through the legacy
// envelope-less methods otherwise. This is the seam that lets write-back work
// against a journal-native production authority (which rejects the legacy
// coordination ops with EPERM — the "checkout: status 1" failure); a legacy
// self-host authority keeps the exact prior behavior via the zero grant.
type wbAuthority struct{ cli *fsproto.Client }

func (a wbAuthority) Checkout(path, owner string) (bool, string, session.CheckoutGrant, error) {
	if a.cli.ServerManaged() {
		granted, heldBy, epoch, err := a.cli.CheckoutManaged(path)
		if err != nil || !granted {
			return granted, heldBy, session.CheckoutGrant{}, err
		}
		return true, "", session.CheckoutGrant{Path: path, Epoch: epoch}, nil
	}
	granted, heldBy, err := a.cli.Checkout(path, owner)
	return granted, heldBy, session.CheckoutGrant{}, err
}

func (a wbAuthority) Checkin(path, owner string, g session.CheckoutGrant) error {
	if g.Epoch != "" {
		return a.cli.CheckinManaged(g.Path, g.Epoch)
	}
	return a.cli.Checkin(path, owner)
}

func (a wbAuthority) FlushBatch(id string, epoch uint64, owner string, g session.CheckoutGrant, recs []wal.Record) (uint64, int32, error) {
	return a.cli.FlushBatchWriteBack(id, epoch, owner, g.Path, g.Epoch, recs)
}

func (a wbAuthority) Read(p string, off, n int64) ([]byte, int32, error) {
	return a.cli.Read(p, off, n)
}
func (a wbAuthority) Stat(p string) (string, uint32, int32, error) { return a.cli.Stat(p) }
func (a wbAuthority) Readlink(p string) (string, int32, error)     { return a.cli.Readlink(p) }

type selfInvalidatingAuthority struct {
	session.Authority
	onRecords func([]wal.Record)
}

func (a selfInvalidatingAuthority) FlushBatch(sessionID string, epoch uint64, owner string, grant session.CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	appliedThrough, status, err := a.Authority.FlushBatch(sessionID, epoch, owner, grant, records)
	if err == nil && status == fsproto.OK && a.onRecords != nil {
		applied := make([]wal.Record, 0, len(records))
		for _, r := range records {
			if r.Seq <= appliedThrough {
				applied = append(applied, r)
			}
		}
		if len(applied) > 0 {
			a.onRecords(applied)
		}
	}
	return appliedThrough, status, err
}

func (v *Volume) noteSelfMutation(p string, gen, version uint64, inPlace bool) {
	p = cleanVolumePath(p)
	if gen != 0 && !v.VersionCache.SeenGen(gen) {
		v.VersionCache.RefreshAll(gen)
		v.AttrCache.Clear()
		v.clearDirCache()
	}
	if gen != 0 && version != 0 {
		v.VersionCache.FillOK(gen, p, version)
	}
	v.AttrCache.Evict(p)
	if inPlace {
		return
	}
	dir, _ := splitPath(p)
	if gen != 0 && version != 0 {
		v.VersionCache.FillOK(gen, dir, version)
	}
	v.AttrCache.Evict(dir)
	v.evictDirCache(dir)
}

func (v *Volume) noteSelfMutationRecord(r wal.Record) {
	switch r.Op {
	case wal.OpCreate, wal.OpMkdir, wal.OpRemove, wal.OpSymlink, wal.OpOrphan:
		v.noteSelfMutation(r.Path, 0, 0, false)
	case wal.OpRename:
		v.noteSelfMutation(r.Path, 0, 0, false)
		v.noteSelfMutation(r.NewPath, 0, 0, false)
	case wal.OpWrite, wal.OpTruncate, wal.OpChmod, wal.OpChtimes, wal.OpChown:
		if r.Path != "" {
			v.noteSelfMutation(r.Path, 0, 0, true)
		}
	}
}

func cleanVolumePath(p string) string {
	p = strings.Trim(p, "/")
	if p == "." {
		return ""
	}
	return p
}

// Client exposes the underlying fsproto client for adapter paths that still need typed protocol
// helpers during the extraction.
func (v *Volume) Client() *fsproto.Client { return v.client }

// Sessions exposes the write-back manager while cmd/mount is still being collapsed into the core.
func (v *Volume) Sessions() *session.Manager { return v.sessions }

// LockAuth returns the advisory-lock surface bound to this volume's authority
// generation. Every lock acquire, release, and getlk must route through it —
// never the raw Client, whose legacy op a managed authority refuses with EPERM.
func (v *Volume) LockAuth() LockAuthority { return lockRouter{v.client} }

// registerLockHandle adds a handle to the reclaim registry (idempotent).
func (v *Volume) registerLockHandle(h *LockHandle) {
	if h == nil {
		return
	}
	v.lockRegMu.Lock()
	v.lockReg[h] = struct{}{}
	v.lockRegMu.Unlock()
}

// lockHandles snapshots the registry, pruning handles that no longer hold any
// lock (closed descriptions unregister themselves by draining empty).
func (v *Volume) lockHandles() []*LockHandle {
	v.lockRegMu.Lock()
	defer v.lockRegMu.Unlock()
	out := make([]*LockHandle, 0, len(v.lockReg))
	for h := range v.lockReg {
		if len(h.Snapshot()) == 0 {
			delete(v.lockReg, h)
			continue
		}
		out = append(out, h)
	}
	return out
}

// ReassertCoordination is the post-failover reclaim hook: within the granted
// window it re-asserts every piece of volatile coordination state this mount
// owns — advisory locks, open-inode pins, orphan leases, and write-back
// checkouts — then reports ReclaimDone so the authority can lift the grace
// early. Individual re-assert failures are logged, not fatal: state that
// cannot be re-asserted is simply lost to the normal conflict rules.
func (v *Volume) ReassertCoordination(window time.Duration) {
	deadline := time.Now().Add(window)
	for _, h := range v.lockHandles() {
		for _, l := range h.Snapshot() {
			if !time.Now().Before(deadline) {
				return // window elapsed: do not signal done; grace timeout owns it
			}
			if _, err := v.LockAuth().Lock(l.Path, fsproto.LkSetlk, l.Owner, l.Start, l.End, l.Write, false); err != nil {
				v.debug("reclaim lock %q [%d,%d]: %v", l.Path, l.Start, l.End, err)
			}
		}
	}
	for _, ino := range v.openFiles.Snapshot() {
		if _, err := v.client.MarkOpen(ino); err != nil {
			v.debug("reclaim open pin ino=%d: %v", ino, err)
		}
	}
	if inos := v.openOrphans.Snapshot(); len(inos) > 0 {
		if _, err := v.client.RenewOrphanLeases(inos); err != nil {
			v.debug("reclaim orphan leases: %v", err)
		}
	}
	if v.sessions != nil {
		for _, root := range v.sessions.Roots() {
			if granted, heldBy, err := v.client.Checkout(root, v.owner); err != nil || !granted {
				v.debug("reclaim checkout %q: granted=%v heldBy=%q err=%v", root, granted, heldBy, err)
			}
		}
	}
	v.client.ReclaimDone()
}

func (v *Volume) OpenTracker() *OpenTracker { return v.opens }

func (v *Volume) OpenOrphans() *InodeSet { return v.openOrphans }

func (v *Volume) OpenFiles() *InodeSet { return v.openFiles }

// RunOpenLeaseRenewal renews parked-orphan and open-inode leases until ctx is
// cancelled. It supersedes the free RenewOpenLeases for volume callers: a
// successful open-inode round is fed back to the open registry (stamped with
// the authority generation it landed on), which is what keeps retained
// registrations valid — and heals them across an authority restart, since
// renewal re-creates absent holds server-side.
func (v *Volume) RunOpenLeaseRenewal(ctx context.Context, every time.Duration, debugf func(string, ...any)) {
	if every <= 0 {
		every = 20 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if inos := v.openOrphans.Snapshot(); len(inos) > 0 {
				if st, err := v.client.RenewOrphanLeases(inos); err != nil || st != fsproto.OK {
					if debugf != nil {
						debugf("RenewOrphanLeases(%d inos): st=%d err=%v", len(inos), st, err)
					}
				}
			}
			v.renewOpenInodes(debugf)
		}
	}
}

// renewOpenInodes renews the registry's full open+retained set in bounded
// chunks and confirms each successful chunk back to the registry.
func (v *Volume) renewOpenInodes(debugf func(string, ...any)) {
	inos := v.openFiles.Snapshot()
	for start := 0; start < len(inos); start += renewChunk {
		end := start + renewChunk
		if end > len(inos) {
			end = len(inos)
		}
		chunk := inos[start:end]
		st, gen, err := v.client.RenewOpenInodesGen(chunk)
		if err != nil || st != fsproto.OK {
			if debugf != nil {
				debugf("RenewOpenInodes(%d inos): st=%d err=%v", len(chunk), st, err)
			}
			continue
		}
		v.openReg.ConfirmRenewal(chunk, gen)
	}
}

func (v *Volume) AttrValidFor(path string) time.Duration {
	if v.recent.mine(path) {
		return 0
	}
	if v.sessions != nil && v.sessions.For(path) != nil {
		return v.sessionTTL
	}
	return 0
}

func (v *Volume) Statfs() Statfs {
	const bsize = 4096
	const totalBlocks = uint64(1) << 38
	free := totalBlocks - (1 << 20)
	return Statfs{
		Blocks: totalBlocks, Bfree: free, Bavail: free,
		Bsize: bsize, Frsize: bsize, Files: 1 << 30, Ffree: 1 << 30, NameLen: 255,
	}
}

// StartInvalidations subscribes to authority invalidations and applies them to
// clientcore caches before forwarding frontend-specific notify callbacks.
func (v *Volume) StartInvalidations(ctx context.Context, dropOrphan bool) {
	WatchInvalidations(ctx, v.client, v.VersionCache, v.AttrCache, volumeInvalidationHandler{v: v}, InvalidationOptions{
		DropOrphan:  dropOrphan,
		ClearRecent: v.recent.clear,
		Debugf:      v.debugf,
	})
}

type volumeInvalidationHandler struct {
	v *Volume
}

func (h volumeInvalidationHandler) FlushAll() {
	h.v.clearDirCache()
	// Invalidations may have been missed wholesale (resubscribe / overflow /
	// generation change): retained open registrations whose names may have
	// silently changed are given up — worth at most one re-mark each.
	h.v.openReg.DropAllRetained()
	if h.v.onFlushAll != nil {
		h.v.onFlushAll("")
	}
}

func (h volumeInvalidationHandler) InvalidatePath(path string, inPlace bool) {
	if !inPlace {
		dir, _ := splitPath(path)
		h.v.evictDirCache(dir)
		// A peer changed this name's binding; a retained registration under
		// it has no trustworthy reuse value anymore.
		h.v.openReg.DropPath(path)
	}
	if h.v.onInvalidate != nil {
		h.v.onInvalidate(path, inPlace)
	}
}

func (h volumeInvalidationHandler) InvalidateRelatedInodes(inos []uint64, eventPath string) {
	for _, alias := range h.v.hardlinks.pathsForInos(inos) {
		if alias == eventPath {
			continue
		}
		h.v.AttrCache.Evict(alias)
		if h.v.onInvalidate != nil {
			// The alias keeps its name→inode binding; only content and
			// attributes changed through another name.
			h.v.onInvalidate(alias, true)
		}
	}
}

func (v *Volume) invalidateRelatedInodes(inos []uint64, eventPath string) {
	volumeInvalidationHandler{v: v}.InvalidateRelatedInodes(inos, eventPath)
}

func (h volumeInvalidationHandler) MarkOrphan(path string, ino uint64) {
	// A peer detached this inode. A zero-ref retained hold must be released
	// (else our lease renewal would pin the parked orphan against reap
	// forever); live handles keep theirs and redirect by ino as always.
	h.v.openReg.DropIno(ino)
	if h.v.onMarkOrphan != nil {
		h.v.onMarkOrphan(path, ino)
	}
}

func (h volumeInvalidationHandler) ReleaseSubtree(path string) {
	if h.v.sessions != nil {
		h.v.sessions.ReleaseSubtree(path)
	}
}

// SetAuthToken updates the static token used by future reconnect handshakes. An installed
// CredentialSource takes precedence and is left intact (see fsproto.Client.SetAuthToken).
func (v *Volume) SetAuthToken(tok string) { v.client.SetAuthToken(tok) }

// RenewCredential is the clientcore-level credential renewal entry point. Precedence (m3): when the
// volume was configured with a CredentialSource, renewal flows through that source on the next
// handshake and this static token is only a fallback — so RenewCredential can never pin a
// source-configured volume to a stale static token.
func (v *Volume) RenewCredential(tok string) { v.SetAuthToken(tok) }

// FlushToAuthority waits until every active write-back session has flushed to the authority.
func (v *Volume) FlushToAuthority(ctx context.Context) error {
	if v.sessions == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- v.sessions.FlushAll() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// Fsync applies the configured write-back fsync policy for path.
func (v *Volume) Fsync(path string) error {
	if v.sessions == nil {
		return nil
	}
	s := v.sessions.For(path)
	if s == nil {
		return nil
	}
	if err := s.Fsync(); err != nil && !errors.Is(err, session.ErrReleased) {
		return err
	}
	if v.fsyncPolicy == FsyncAuthority {
		if err := s.Flush(); err != nil {
			return err
		}
		// m1: a superseded/fenced session's Flush short-circuits to a no-op and returns nil, so its
		// records never reached the authority. fsync=authority must NOT report that as durable — surface
		// EIO. This is the documented force-revoke residual: a fenced holder's writes are rejected by the
		// generation/fencing token, so claiming authority durability here would be a false guarantee.
		if s.IsSuperseded() {
			return fmt.Errorf("clientcore: fsync=authority on superseded session: writes not durable at authority")
		}
		return nil
	}
	return nil
}

// Close cancels background work, flushes/checks in write-back sessions, and closes the protocol
// connections. A clean Close is an authority-durable detach when write-back is enabled.
func (v *Volume) Close() error {
	v.cancel()
	v.wg.Wait()
	var first error
	if v.sessions != nil {
		first = v.sessions.Stop()
	}
	// Release retained open registrations (bounded, best-effort): a clean
	// detach should not leave holds for the authority's lease sweeper.
	v.openReg.Shutdown(2 * time.Second)
	if err := v.client.Close(); first == nil {
		first = err
	}
	return first
}

func (v *Volume) setPrefetchProgress(p PrefetchProgress) {
	v.prefetchMu.Lock()
	v.prefetch = p
	v.prefetchMu.Unlock()
}

// PrefetchProgress returns the latest async prefetch progress snapshot.
func (v *Volume) PrefetchProgress() PrefetchProgress {
	v.prefetchMu.Lock()
	defer v.prefetchMu.Unlock()
	return v.prefetch
}

func (v *Volume) prefetchTree(maxEntries, maxDepth int) {
	type item struct {
		path  string
		depth int
	}
	q := []item{{path: "", depth: 0}}
	var walked int64
	var lastErr string // the most recent readdir failure; carried into the terminal Done snapshot
	for len(q) > 0 && int(walked) < maxEntries {
		select {
		case <-v.ctx.Done():
			v.setPrefetchProgress(PrefetchProgress{Entries: walked, Done: true, Err: lastErr})
			return
		default:
		}
		it := q[0]
		q = q[1:]
		ents, st := v.Readdir(v.ctx, it.path)
		if st != fsproto.OK {
			// Record the failure and keep walking siblings; do NOT log per directory (a large,
			// partially-unreadable tree would spam the log). The error is surfaced via
			// PrefetchProgress instead, including the terminal Done snapshot below.
			lastErr = fmt.Sprintf("readdir %q: status %d", it.path, st)
			v.setPrefetchProgress(PrefetchProgress{Entries: walked, Err: lastErr})
			continue
		}
		for _, e := range ents {
			if int(walked) >= maxEntries {
				break
			}
			cp := e.Name
			if it.path != "" {
				cp = it.path + "/" + e.Name
			}
			walked++
			if e.Attr.Kind == "directory" && it.depth+1 <= maxDepth {
				q = append(q, item{path: cp, depth: it.depth + 1})
			}
		}
		v.setPrefetchProgress(PrefetchProgress{Entries: walked, Err: lastErr})
		time.Sleep(5 * time.Millisecond)
	}
	// Surface a terminal error on Done rather than swallowing it (a caller polling for Done must be
	// able to tell a fully-walked tree from one that stopped early on an error).
	v.setPrefetchProgress(PrefetchProgress{Entries: walked, Done: true, Err: lastErr})
}
