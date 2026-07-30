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

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Options configures a frontend-neutral clientcore volume attachment.
type Options struct {
	Addr      string
	Pool      int
	TLSConfig *tls.Config
	Owner     string

	CredentialSource func() string
	AuthToken        string

	// WALDir is the write-back engine's durable state directory (the mount
	// stream WAL + recovery jobs live under it). Empty uses a fresh
	// temporary directory: crash recovery then belongs to the caller that
	// owns a persistent path (portablefsd keys it by (volume, branch)).
	WALDir string

	// Negative dentry cache mode. Neither flag set (the default) is
	// default ON: parent versions are baseline in
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
	Branch         string

	PrefetchTree       bool
	PrefetchMaxEntries int
	PrefetchMaxDepth   int

	NoReaddirPlus bool
	AttrTTL       time.Duration
	SessionTTL    time.Duration
	OnInvalidate  func(path string, inPlace bool)
	OnFlushAll    func(path string)
	OnMarkOrphan  func(path string, ino uint64)
	// OnWriteBackError reports the engine's sticky health verdict (nil
	// clears). Lets the daemon flip a mount to degraded when flushes stall,
	// so accepted-but-unflushable write-back is loud instead of hidden.
	OnWriteBackError func(root string, err error)
	Debugf           func(string, ...any)

	// ExactSlots bounds this mount's concurrent in-flight exact mutations
	// (0 = the fsproto default). Set before the first mutation.
	ExactSlots uint32
}

// volumeBarrierTimeout bounds one fsync/synchronize/unmount drain attempt.
// Past it the barrier fails and never degrades to a local-only success. The
// local sync stage must also have succeeded before any durability claim.
// A var so failure-shape tests compress it; production never changes it.
var volumeBarrierTimeout = 60 * time.Second

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

	// lifecycleMu is the frontend mutation gate. Every externally initiated
	// filesystem mutation holds it for the whole operation; close takes it
	// exclusively across the final drain, authority barrier, and optional
	// frontend detach. That closes the gap where a mutation could otherwise
	// fall through to the authority after write-back froze but before the
	// final volume barrier. A failed close leaves closed=false and releases
	// the gate so the still-mounted frontend can keep serving and retry.
	lifecycleMu sync.RWMutex
	closed      bool
	// A forced close is one terminal transaction. Retain its exact outcome
	// so retries cannot reinterpret a prior failure (or a successfully
	// parked non-empty tail) as an empty-tail success.
	forceCloseDone  bool
	forceCloseJobID string
	forceCloseErr   error
	// mutationFailClosed seals every mutation lane when an external durable
	// prepared marker cannot be rolled back. It is independent of wb because
	// authority-native lanes and a no-engine construction must also fail.
	mutationFailClosed error

	AttrCache    *AttrCache
	VersionCache *VersionCache
	Metrics      *metrics.Registry
	DiskCache    *DiskBlockCache

	wb          *writeback.Engine
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
	// openStateMu publishes tracker paths and registry paths as one local
	// namespace transition. It is never held across authority I/O; closes
	// remain responsive during delegation preparation.
	openStateMu sync.Mutex
	// prepareDelegationRelease is the authority two-phase handoff surface.
	// It is a field so failure-shape tests can inject a definite prepare
	// failure without weakening the production protocol.
	prepareDelegationRelease func(scope, epoch string, paths []string) ([]uint64, uint64, error)

	// lockReg tracks the live advisory-lock handles so a post-failover
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

var errVolumeClosed = errors.New("clientcore: volume is closed")

func (v *Volume) beginLifecycleOperation() error {
	v.lifecycleMu.RLock()
	if v.closed {
		v.lifecycleMu.RUnlock()
		return errVolumeClosed
	}
	return nil
}

func (v *Volume) beginMutation() error {
	if err := v.beginLifecycleOperation(); err != nil {
		return err
	}
	if v.mutationFailClosed != nil {
		err := v.mutationFailClosed
		v.lifecycleMu.RUnlock()
		return err
	}
	if v.wb != nil {
		if err := v.wb.MutationError(); err != nil {
			v.lifecycleMu.RUnlock()
			return err
		}
	}
	return nil
}

func (v *Volume) endMutation() {
	v.lifecycleMu.RUnlock()
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
	// Exact mount session: establish at mount. The handshake requires the
	// v8 protocol exactly — an older authority fails the mount with a clear
	// version-mismatch error. A fenced identity at establish
	// (ErrSessionFenced) is surfaced by the first mutation instead of
	// failing the mount: reads are still valid.
	if opts.ExactSlots != 0 {
		cli.SetExactSlots(opts.ExactSlots)
	}
	if _, err := cli.EnsureExactSession(); err != nil && !errors.Is(err, fsproto.ErrSessionFenced) {
		_ = cli.Close()
		cancel()
		return nil, err
	}
	// Version-gated negative caching is part of the v8 baseline (the
	// authority stamps every lookup miss with the parent directory version);
	// the explicit off switch remains as the only override.
	v.negativeCache = !opts.NoNegativeCache
	v.openReg = newOpenRegistry(cli, v.VersionCache.CurrentGen, v.openFiles,
		opts.OpenRetentionEntries, opts.Debugf)
	v.prepareDelegationRelease = cli.PrepareDelegationRelease
	// The write-back engine is part of every v8 mount: the authority decides
	// adaptively per scope whether to delegate; there is no mount-level
	// write mode. PORTABLEFS_DEBUG_WRITE_THROUGH=1 is the only override
	// (debug: never delegate; the engine still recovers parked streams).
	walDir := opts.WALDir
	if walDir == "" {
		d, derr := os.MkdirTemp("", "portablefs-wb-")
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
	budget := opts.DiskCacheBytes / 2
	wb, werr := openWritebackForAttach(cctx, cli, writeback.Config{
		StateDir:               walDir,
		VolumeID:               v.volumeID,
		Branch:                 opts.Branch,
		Remote:                 wbRemote{cli: cli},
		BudgetBytes:            budget,
		DisableDelegation:      os.Getenv("PORTABLEFS_DEBUG_WRITE_THROUGH") == "1",
		DisableDelegatedXattrs: cli.Features()&fsproto.FeatureDelegatedXattrs == 0,
		Busy:                   v.opens.BusyUnder,
		ProtectOpenPins:        v.protectOpenPins,
		Logf:                   opts.Debugf,
		Events: writeback.Events{
			OnGrant: func(scope string) {
				// Shared attr/negative/directory/kernel entries under the
				// scope must not shadow the authoritative delegated view.
				v.AttrCache.EvictPrefix(scope)
				v.evictDirCachePrefix(scope)
				if v.onFlushAll != nil {
					go v.onFlushAll(scope)
				}
			},
			OnRelease: func(scope string) {
				v.AttrCache.EvictPrefix(scope)
				v.evictDirCachePrefix(scope)
				if v.onFlushAll != nil {
					v.onFlushAll(scope)
				}
			},
			OnHealth: func(err error) {
				if opts.OnWriteBackError != nil {
					opts.OnWriteBackError("", err)
				}
			},
		},
	})
	if werr != nil {
		_ = cli.Close()
		cancel()
		return nil, werr
	}
	v.wb = wb
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

// openWritebackForAttach binds ONLY the attach-readiness window to terminal
// protocol teardown. Recovery ownership moves are resolved synchronously while
// writeback.Open holds the store flock; if the attach context ends, Abort
// interrupts and joins those calls before Open can return and release the
// lock. Once Open succeeds the watcher is joined and disappears, so ordinary
// Volume lifetime cancellation retains its existing shutdown semantics.
func openWritebackForAttach(ctx context.Context, cli *fsproto.Client, cfg writeback.Config) (*writeback.Engine, error) {
	openDone := make(chan struct{})
	abortDone := make(chan bool, 1)
	go func() {
		select {
		case <-ctx.Done():
			_ = cli.Abort()
			abortDone <- true
		case <-openDone:
			abortDone <- false
		}
	}()

	wb, openErr := writeback.Open(ctx, cfg)
	close(openDone)
	aborted := <-abortDone // join the watcher (and Abort, when selected)
	if aborted || ctx.Err() != nil {
		// If Open won the race with cancellation, make the same terminal
		// transition here. Abort is idempotent and joins protocol operations.
		abortErr := cli.Abort()
		var closeErr error
		if wb != nil {
			_, closeErr = wb.ForceClose("attach canceled after recovery")
		}
		return nil, errors.Join(ctx.Err(), openErr, abortErr, closeErr)
	}
	return wb, openErr
}

// wbRemote adapts *fsproto.Client to writeback.Remote: delegation
// acquisition, stream flushes, and recovery all ride the journaled
// coordination surface under exact identities. Read-like operations use
// ctxCall so their callers can stop waiting while the exact machinery
// resolves a lost reply in the background. Ownership transitions are
// different: ReleaseDelegation and Rebind do not return after they have
// started until their exact outcome is known. That keeps the engine's
// handoff barrier and recovery store lock installed for the whole transition.
type wbRemote struct{ cli *fsproto.Client }

func ctxCall[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := fn()
		ch <- res{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func (r wbRemote) DelegationAcquire(ctx context.Context, scope, writebackID string) (writeback.AcquireReply, error) {
	return ctxCall(ctx, func() (writeback.AcquireReply, error) {
		g, err := r.cli.DelegationAcquire(scope, writebackID)
		if err != nil {
			return writeback.AcquireReply{}, err
		}
		reply := writeback.AcquireReply{Granted: g.Granted, Epoch: g.Epoch, Exists: g.Exists}
		if g.Exists {
			reply.Self = entryFromAttr("", g.Self)
		}
		if g.HasChildren {
			reply.HasChildren = true
			reply.Children = make([]writeback.Entry, 0, len(g.Children))
			for _, d := range g.Children {
				reply.Children = append(reply.Children, entryFromAttr(d.Name, d.Attr))
			}
		}
		return reply, nil
	})
}

func (r wbRemote) ReleaseDelegation(ctx context.Context, scope, epoch string) error {
	// Once release begins, the handoff barrier must remain installed until
	// the exact Checkin reaches a definite durable outcome. Returning on
	// ctx cancellation while Checkin continues in a background goroutine
	// would let the engine drop the barrier before ownership actually
	// changes. CheckinManaged is itself bounded per transport attempt and
	// replay-resolves the same exact identity until success, refusal, fence,
	// or client teardown.
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.cli.CheckinManaged(scope, epoch)
}

func (r wbRemote) Flush(ctx context.Context, req writeback.FlushRequest) (writeback.FlushReply, error) {
	return ctxCall(ctx, func() (writeback.FlushReply, error) {
		scopes := make([]fsproto.WBScope, 0, len(req.ScopeRuns))
		for _, run := range req.ScopeRuns {
			scopes = append(scopes, fsproto.WBScope{Path: run.Scope, Epoch: run.Epoch, Through: run.Through})
		}
		through, status, err := r.cli.FlushWriteback(req.WritebackID, scopes, req.PrevDigest, req.EndDigest, req.Records)
		if err != nil {
			return writeback.FlushReply{}, err
		}
		return writeback.FlushReply{Through: through, Status: status}, nil
	})
}

func (r wbRemote) FlushResolved(ctx context.Context, req writeback.FlushRequest) (writeback.FlushReply, error) {
	if err := ctx.Err(); err != nil {
		return writeback.FlushReply{}, err
	}
	scopes := make([]fsproto.WBScope, 0, len(req.ScopeRuns))
	for _, run := range req.ScopeRuns {
		scopes = append(scopes, fsproto.WBScope{Path: run.Scope, Epoch: run.Epoch, Through: run.Through})
	}
	through, status, err := r.cli.FlushWritebackResolved(req.WritebackID, scopes, req.PrevDigest, req.EndDigest, req.Records)
	if err != nil {
		return writeback.FlushReply{}, err
	}
	return writeback.FlushReply{Through: through, Status: status}, nil
}

func (r wbRemote) StreamState(ctx context.Context, writebackID string) (writeback.StreamState, error) {
	return ctxCall(ctx, func() (writeback.StreamState, error) {
		exists, through, digest, err := r.cli.WritebackState(writebackID)
		if err != nil {
			return writeback.StreamState{}, err
		}
		return writeback.StreamState{Exists: exists, Through: through, Digest: digest}, nil
	})
}

func (r wbRemote) Rebind(ctx context.Context, writebackID string, scopes []writeback.RebindScope, through uint64, digest [32]byte) (writeback.RebindReply, error) {
	// Rebind is an exact ownership move. Once sent, returning on ctx
	// cancellation would release the recovery store lock while the move was
	// still resolving, allowing another attach to overlap the same stream.
	// The fsproto client bounds individual transports and resolves retries
	// under one exact identity; Client.Abort is the terminal interruption.
	if err := ctx.Err(); err != nil {
		return writeback.RebindReply{}, err
	}
	wire := make([]fsproto.WBScope, 0, len(scopes))
	for _, sc := range scopes {
		wire = append(wire, fsproto.WBScope{Path: sc.Scope, Epoch: sc.Epoch})
	}
	conflicts, err := r.cli.WritebackRebind(writebackID, wire, through, digest)
	if err != nil {
		return writeback.RebindReply{}, err
	}
	reply := writeback.RebindReply{}
	for _, c := range conflicts {
		reply.Conflicts = append(reply.Conflicts, writeback.ConflictDetail{Scope: c.Path, Epoch: c.Epoch, Kind: c.Kind})
	}
	return reply, nil
}

func (r wbRemote) Discard(ctx context.Context, writebackID string, scopes []writeback.RebindScope) error {
	// Recovery may remove the local stream immediately after this returns, so
	// a possibly-sent discard must resolve while Open still owns the flock.
	if err := ctx.Err(); err != nil {
		return err
	}
	wire := make([]fsproto.WBScope, 0, len(scopes))
	for _, sc := range scopes {
		wire = append(wire, fsproto.WBScope{Path: sc.Scope, Epoch: sc.Epoch})
	}
	return r.cli.WritebackDiscard(writebackID, wire)
}

// entryFromAttr converts a wire attr to the engine's entry shape.
func entryFromAttr(name string, a fsproto.Attr) writeback.Entry {
	return writeback.Entry{
		Name: name, Kind: a.Kind, Mode: a.Mode, Size: a.Size,
		MtimeMs: a.MtimeMs, CtimeMs: a.CtimeMs, AtimeMs: a.AtimeMs,
		UID: a.Uid, GID: a.Gid, Ino: a.Ino, Nlink: a.Nlink,
	}
}

// attrFromEntry converts an engine entry to wire attrs. Locally-born entries
// carry no authority ino; the caller substitutes a path-derived fallback.
func attrFromEntry(e writeback.Entry) fsproto.Attr {
	a := fsproto.Attr{
		Kind: e.Kind, Mode: e.Mode, Size: e.Size,
		MtimeMs: e.MtimeMs, CtimeMs: e.CtimeMs, AtimeMs: e.AtimeMs,
		Uid: e.UID, Gid: e.GID, Ino: e.Ino, Nlink: e.Nlink,
	}
	if a.MtimeMs == 0 {
		a.MtimeMs = time.Now().UnixMilli()
	}
	if a.CtimeMs == 0 {
		a.CtimeMs = a.MtimeMs
	}
	if a.AtimeMs == 0 {
		a.AtimeMs = a.MtimeMs
	}
	if a.Nlink == 0 {
		a.Nlink = 1
		if a.Kind == "directory" {
			a.Nlink = 2
		}
	}
	return a
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

// Writeback exposes the mount engine's status surface.
func (v *Volume) Writeback() *writeback.Engine { return v.wb }

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
	if v.wb != nil && v.wb.Covers(path) {
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
	// The engine's held views survive a wholesale flush: the delegation is
	// exclusive (peers recall before touching the scope, and the authority
	// never force-transfers), so its completeness proof does not depend on
	// the invalidation stream. Only shared-path caches reset.
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
		// it has no trustworthy reuse value anymore. (A held engine view
		// needs nothing: peers cannot mutate under an exclusive delegation.)
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
	if h.v.wb == nil {
		return
	}
	// The authority recalled the scope for a peer: drain and release. The
	// peer's gated operation waits on the durable release, so a failure here
	// only extends its bounded wait (and the recall re-arrives).
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := h.v.wb.Recall(ctx, path); err != nil {
		h.v.debug("recall %q: %v", path, err)
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

// protectOpenPins establishes an authority-durable open pin for every open
// handle under scope and returns the subtree handoff barrier the engine must
// retain THROUGH its durable delegation release. The tracker mutex is never
// held across authority I/O: closes stay responsive, while new opens and
// path rebindings in this subtree wait for the ownership transition.
func (v *Volume) protectOpenPins(ctx context.Context, scope, epoch string) (func(bool), error) {
	guard, err := v.opens.BeginRelease(ctx, scope)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(bool), error) {
		guard.End(false)
		return nil, err
	}
	var pending []trackedOpenSnapshot
	for _, snapshot := range guard.Snapshots() {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		node := snapshot.node
		if node != nil && node.Orphan() != 0 {
			continue // no longer a named handle in the delegated namespace
		}
		if !guard.NeedsPreparedPin(snapshot) {
			continue // every live handle is already represented by a pin
		}
		pending = append(pending, snapshot)
	}

	type prepareReply struct {
		inos []uint64
		gen  uint64
	}
	activeInos := map[uint64]bool{}
	var preparedInos []uint64
	preparedGen := map[uint64]uint64{}
	cleanupPrepared := func() {
		for _, ino := range preparedInos {
			if !activeInos[ino] {
				v.openReg.RetirePreparedPin(ino, preparedGen[ino])
			}
		}
	}
	cleanupDone := false
	defer func() {
		if !cleanupDone {
			cleanupPrepared()
		}
	}()
	for start := 0; start < len(pending); start += fsproto.MaxPrepareOpenPaths {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		end := start + fsproto.MaxPrepareOpenPaths
		if end > len(pending) {
			end = len(pending)
		}
		chunk := pending[start:end]
		paths := make([]string, len(chunk))
		for i := range chunk {
			paths[i] = chunk[i].path
		}
		// Do not abandon an in-flight prepare at context cancellation. A
		// prepared pin has durable side effects but no exact slot outcome;
		// keeping this barrier until the bounded RPC finishes prevents local
		// namespace rebindings from racing a late server decision.
		inos, gen, err := v.prepareDelegationRelease(scope, epoch, paths)
		reply := prepareReply{inos: inos, gen: gen}
		if err != nil {
			return fail(fmt.Errorf("clientcore: prepare delegation release %q: %w", scope, err))
		}
		if reply.gen == 0 || len(reply.inos) != len(chunk) {
			return fail(fmt.Errorf("clientcore: invalid prepare delegation release reply for %q", scope))
		}
		preparedInos = append(preparedInos, reply.inos...)
		for i, ino := range reply.inos {
			preparedGen[ino] = reply.gen
			active, err := guard.AdoptPreparedPin(
				chunk[i],
				ino,
				reply.gen,
				v.openReg.AdoptPreparedRefs,
			)
			if err != nil {
				return fail(err)
			}
			if active {
				activeInos[ino] = true
				continue
			}
			// The handle may have closed while the prepare RPC was in
			// flight. The prepare still proved the exact authority identity
			// of this frozen namespace binding. Publish that identity before
			// retiring its pin so the name mutation waiting behind this
			// handoff can synchronously order the final unmark before its
			// park-vs-destroy decision.
			if chunk[i].node != nil && !chunk[i].node.RecordAuthorityIno(ino) {
				return fail(fmt.Errorf(
					"clientcore: prepared closed open for %q could not bind inode %d",
					chunk[i].path,
					ino,
				))
			}
		}
	}
	cleanupPrepared()
	cleanupDone = true
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return guard.End, nil
}

// FlushToAuthority waits until the engine's acknowledged stream tail has
// flushed to the authority.
func (v *Volume) FlushToAuthority(ctx context.Context) error {
	if err := v.beginLifecycleOperation(); err != nil {
		return err
	}
	defer v.endMutation()
	return v.flushToAuthority(ctx)
}

func (v *Volume) flushToAuthority(ctx context.Context) error {
	if v.wb == nil {
		return nil
	}
	return v.wb.DrainAll(ctx)
}

// Fsync is the per-file authority-durability and subscriber-visibility
// barrier. It
// returns success only when (1) every accepted mutation up to the
// barrier is committed and applied at the authority (flush commits are
// durable-before-reply; the mount stream is globally dense, so the drain
// intentionally overflushes earlier unrelated mutations), and (2) every
// live protocol subscriber has acknowledged the covering invalidations at
// the frontend boundary it supports. Linux FUSE includes its kernel
// invalidation hook; macOS 26 FSKit cannot because its SDK exposes no such
// hook.
// If the authority is unreachable, slow past the deadline, or fenced, fsync
// returns the ERROR: there is no local-only fsync outcome, ever.
func (v *Volume) Fsync(path string) error {
	if err := v.beginLifecycleOperation(); err != nil {
		return err
	}
	defer v.endMutation()
	return v.fsync(path)
}

func (v *Volume) fsync(path string) error {
	if v.wb != nil {
		ctx, cancel := context.WithTimeout(v.ctx, volumeBarrierTimeout)
		defer cancel()
		if err := v.wb.Fsync(ctx, path); err != nil {
			return err
		}
	}
	// The authority barrier: earlier journal rows durable + applied +
	// published, and every live subscriber acked the covering invalidation
	// position at its supported frontend boundary.
	return v.boundedBarrier(v.client.Sync)
}

// boundedBarrier runs one authority-barrier RPC under volumeBarrierTimeout:
// past the bound the barrier FAILS typed (never a local-only success). An
// abandoned attempt resolves on its own transport budget without claiming
// anything.
func (v *Volume) boundedBarrier(fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(volumeBarrierTimeout):
		return fmt.Errorf("clientcore: volume barrier timed out after %v (authority unreachable or slow; no durability or visibility success is claimed)", volumeBarrierTimeout)
	}
}

// WriteBackPending reports the unshipped acknowledged backlog — the bytes a
// degraded drain verdict parks locally.
func (v *Volume) WriteBackPending() (records int, bytes int64) {
	if v.wb == nil {
		return 0, 0
	}
	return v.wb.Pending()
}

// RecoveryJobs reports parked write-back streams awaiting recovery (pending
// records from prior instances of this mount identity).
func (v *Volume) RecoveryJobs() []writeback.RecoveryJob {
	if v.wb == nil {
		return nil
	}
	return v.wb.Status().Jobs
}

// WritebackStatus reports the engine's full health snapshot.
func (v *Volume) WritebackStatus() writeback.Status {
	if v.wb == nil {
		return writeback.Status{}
	}
	return v.wb.Status()
}

// SyncVolume drains this volume's outstanding write-back state, then submits
// the authority volume barrier: the client gates new local mutations, waits
// for every earlier and parked exact identity, appends one journaled
// control-only barrier row, and returns only when that row — and therefore
// every row admitted before it — is durable, applied, its invalidations are
// published, AND every live subscriber has acknowledged them at its
// supported frontend boundary. This is the FSKit synchronize contract; fsyncing a snapshot
// of currently open handles alone is NOT a sufficient volume barrier. There
// is NO degraded local-only outcome: an unreachable, slow, or fenced
// authority fails the barrier with an error. The drain forces the local WAL
// first; if that local sync also fails, the mount remains failed closed.
func (v *Volume) SyncVolume() error {
	if err := v.beginLifecycleOperation(); err != nil {
		return err
	}
	defer v.endMutation()
	return v.syncVolume()
}

func (v *Volume) syncVolume() error {
	if v.wb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), volumeBarrierTimeout)
		defer cancel()
		if err := v.wb.DrainAll(ctx); err != nil {
			// The tail could not reach the authority: make it locally
			// durable when possible and surface the barrier failure. Exact
			// replay on a later attach never converts this into success.
			if serr := v.wb.SyncLocal(); serr != nil {
				return fmt.Errorf("clientcore: volume barrier: drain failed (%v) and local WAL fsync failed: %w", err, serr)
			}
			return err
		}
	}
	return v.boundedBarrier(v.client.SyncVolume)
}

// AuthorityUnreachable reports confirmed transport unreachability (fail-fast
// engaged past the grace window): a network flush is futile until the prober
// re-proves the peer. Status surfaces consult it; barriers do NOT — they
// simply fail when the authority cannot answer.
func (v *Volume) AuthorityUnreachable() bool {
	return v.client.FailFast()
}

// SessionFenced reports whether the mount session was fenced (stale
// generation / lease lost). A fence is a definite verdict from a (possibly
// perfectly reachable) authority: barrier paths surface it as an error.
func (v *Volume) SessionFenced() bool {
	return v.client.SessionFenced()
}

// CloseJournalDurable closes the volume for an EXPLICITLY FORCED unmount,
// with no authority round-trip anywhere on the path: the mount stream WAL
// and its recovery job are made durable OUTSIDE the attach lifetime and the
// engine closes WITHOUT releasing its delegations; the mount session lease
// is deliberately NOT expired — like after a crash, the delegations flip to
// recovery-required when it lapses, protecting the unshipped state until the
// next attach rebinds and drains the stream. The returned job ID is the
// user-visible recovery handle ("" when nothing was parked). Never called on
// a normal unmount: a normal unmount that cannot drain FAILS.
func (v *Volume) CloseJournalDurable() (string, error) {
	v.lifecycleMu.Lock()
	defer v.lifecycleMu.Unlock()
	if v.forceCloseDone {
		return v.forceCloseJobID, v.forceCloseErr
	}
	if v.closed {
		return "", nil
	}

	v.cancel()
	// Forced teardown is crash-equivalent: close local transports without
	// SessionExpire so the authority lease retains recovery ownership. This
	// also resolves any checked-out protocol call before the engine joins
	// its release workers and closes the WAL.
	closeErr := v.client.Abort()
	v.wg.Wait()
	jobID := ""
	if v.wb != nil {
		id, err := v.wb.ForceClose("forced unmount")
		jobID = id
		if closeErr == nil {
			closeErr = err
		}
	}
	// Deliberately NO openReg.Shutdown here: journal-first means no authority
	// round-trips anywhere on the path; open registrations are reclaimed by the
	// authority's lease sweeper, exactly as after a crash.
	v.forceCloseDone = true
	v.forceCloseJobID = jobID
	v.forceCloseErr = closeErr
	v.closed = true
	return v.forceCloseJobID, v.forceCloseErr
}

// Close drains + releases the write-back engine, then cancels background work
// and closes the protocol connections. A failed drain leaves the Volume
// fully alive and retryable; only CloseJournalDurable is allowed to park a
// recovery job and tear down without authority success.
func (v *Volume) Close() error {
	return v.CloseWithFinalizer(nil)
}

// CloseWithFinalizer performs the normal close while keeping filesystem
// mutations gated through finalize. A kernel frontend passes its detach
// operation here: if either the authority barrier or detach fails, write-back
// thaws, the Volume remains live, and the mutation gate reopens. Once
// finalize succeeds the frontend is gone before protocol resources close.
func (v *Volume) CloseWithFinalizer(finalize func() error) error {
	v.lifecycleMu.Lock()
	defer v.lifecycleMu.Unlock()
	if v.closed {
		return nil
	}

	barrierAndFinalize := func() error {
		if err := v.boundedBarrier(v.client.SyncVolume); err != nil {
			return err
		}
		if finalize != nil {
			return finalize()
		}
		return nil
	}
	if v.wb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), volumeBarrierTimeout)
		err := v.wb.CloseWithBarrier(ctx, barrierAndFinalize)
		cancel()
		if err != nil {
			v.latchFailFrozenFinalizer(err)
			return err
		}
	} else if err := barrierAndFinalize(); err != nil {
		v.latchFailFrozenFinalizer(err)
		return err
	}
	v.cancel()
	v.wg.Wait()
	// Release retained open registrations (bounded, best-effort): a clean
	// detach should not leave holds for the authority's lease sweeper.
	v.openReg.Shutdown(2 * time.Second)
	err := v.client.Close()
	v.closed = true
	return err
}

// latchFailFrozenFinalizer preserves the external durability contract even
// when no writeback engine exists. Normal retryable detach failures do not
// implement this policy and therefore leave mutation service live.
func (v *Volume) latchFailFrozenFinalizer(err error) {
	var keepFrozen writeback.KeepWritebackFrozenError
	if errors.As(err, &keepFrozen) && keepFrozen.KeepWritebackFrozen() && v.mutationFailClosed == nil {
		v.mutationFailClosed = fmt.Errorf("clientcore: mutations sealed after prepared-detach rollback failure: %w", err)
	}
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
