//go:build linux

// Package fusev3 is the branchless PortableFS v3 Linux mount frontend. It is
// intentionally thin: the authority owns every open file description and all
// filesystem state, while the kernel-facing process retains no dirty data.
package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	renameNoReplace = 1
	renameExchange  = 2

	// fsyncDataOnly is FUSE_FSYNC_FDATASYNC, bit 0 of FsyncIn.FsyncFlags. Every
	// other bit is reserved, so testing the whole word would silently turn a
	// future flag into an fdatasync request.
	fsyncDataOnly = 1

	// kernelMinMaxWrite mirrors fs/fuse/inode.c, which floors the negotiated
	// max_write at one page: `fc->max_write = max_t(unsigned, arg->max_write,
	// 4096)`. Accepting a smaller authority bound would make the kernel send
	// WRITEs this frontend is contractually required to reject.
	kernelMinMaxWrite = 4096

	// kernelDefaultMaxPages is FUSE_DEFAULT_MAX_PAGES_PER_REQ. Kernels that do
	// not advertise CAP_MAX_PAGES ignore InitOut.MaxPages and cap every request
	// at this many pages regardless of the negotiated max_write.
	kernelDefaultMaxPages = 32

	// reclaimLaneDivisor splits the authority's in-flight budget between bulk
	// kernel work and the cleanup lane. Cleanup demand is proportional to
	// lookup demand (the authority mints one capability per LOOKUP, and every
	// duplicate one has to be handed straight back), so the lane is sized as a
	// fixed fraction of the same budget rather than as an independent knob that
	// could be configured out of proportion with it.
	reclaimLaneDivisor = 4

	// livenessReserve is the number of authority in-flight slots that only
	// session keepalive may occupy.
	livenessReserve = 1

	// minMaxInFlight is the smallest authority in-flight budget from which a
	// cleanup lane, a liveness slot, and a usable bulk lane can all be carved.
	minMaxInFlight = 8

	// portableFuseMajor/minor are the stock-kernel semantic floor. Protocol
	// 7.31 is Linux 5.10's FUSE contract and includes every mandatory primitive
	// used by the portable client, including explicit data invalidation. Newer
	// protocol minors are accepted; no private capability bit refines this
	// profile.
	portableFuseMajor = 7
	portableFuseMinor = 31
)

// portableOpenFlags maps one authority-backed open description onto stock
// FUSE cache modes. A write-capable description never shares the kernel page
// cache, which keeps every mutation on the write-through FUSE_WRITE path.
// Read-only data may survive an open only while the daemon holds the covering
// D-R lease. Without one the description is direct-I/O, because merely
// omitting KEEP_CACHE purges old pages but still lets later reads refill them.
func portableOpenFlags(flags uint32, dataLease bool) uint32 {
	if flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY) || flags&uint32(syscall.O_TRUNC) != 0 {
		return fuse.FOPEN_DIRECT_IO
	}
	if dataLease {
		return fuse.FOPEN_KEEP_CACHE
	}
	return fuse.FOPEN_DIRECT_IO
}

// portableReadOpenFlags distinguishes a lease that existed before OPEN from a
// grant carried by the OPEN response. A pre-existing lease proves old pages
// may survive, so KEEP_CACHE is safe. A new grant returns buffered flags with
// KEEP_CACHE clear, making the kernel purge all old pages before this handle
// can refill the cache. Without either proof, reads must remain direct-I/O.
func portableReadOpenFlags(flags uint32, preexistingLease, currentLease bool) uint32 {
	if flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY) || flags&uint32(syscall.O_TRUNC) != 0 {
		return fuse.FOPEN_DIRECT_IO
	}
	if preexistingLease && currentLease {
		return fuse.FOPEN_KEEP_CACHE
	}
	if currentLease {
		return 0
	}
	return fuse.FOPEN_DIRECT_IO
}

// RPC is the exact authority contract required by the mount. Keeping this
// interface narrow makes kernel mapping independently fault-testable.
//
// Lease CONTROL and exact detach are mandatory for every protocol-6 mount.
type RPC interface {
	Root() *authoritypb.Item
	IOLimits() (uint32, uint32)
	SessionLease() time.Duration
	SessionDone() <-chan struct{}
	SessionError() error
	SessionEndPending() <-chan struct{}
	SessionEndCause() error
	FinishLocalSessionEnforcement()
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallReadRetained(context.Context, *authoritypb.Request, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
	CallIdempotent(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallIdempotentRetained(context.Context, *authoritypb.Request, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
	CallMutation(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallMutationWithIdentity(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned) (*authoritypb.Response, error)
	CallMutationWithIdentityRetained(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
	Close() error

	// SessionID is this mount's authority session identity. Lease CONTROL must
	// never direct a peer recall back to the initiating source session.
	SessionID() []byte
	InitialLeaseCursor() *authoritypb.LeaseEventCursor
	NextLeaseEvent(context.Context, *authoritypb.LeaseEventCursor) (*authoritypb.LeaseEvent, error)
	AcknowledgeLeaseEvent(context.Context, *authoritypb.LeaseEventCursor, []*authoritypb.LeaseDischarge) error
	AcknowledgeSourceLeaseDischarge(context.Context, uint64) error
	RenewLeases(context.Context, []*authoritypb.LeaseRenewal) (authorityrpc.LeaseRenewalOutcome, error)
	// DetachAfterUnmount may be called only with evidence that this frontend's
	// kernel mount is gone.
	DetachAfterUnmount(context.Context, MountAbsenceProof) error
}

type Config struct {
	// MountInstanceID is the random identity created before attach. MountVolume
	// derives the kernel source from it, so every attempt is distinguishable even
	// when several clients mount the same volume. Product supervisors persist it
	// as part of their recoverable mounting intent.
	MountInstanceID string
	RequestTimeout  time.Duration
	MaxBackground   int
	// MaxInFlight must be the same concurrent-call bound the RPC transport was
	// configured with. The frontend subtracts its liveness and cleanup lanes
	// from this number and admits bulk kernel work only against the remainder,
	// which is what makes those two lanes genuinely reserved rather than merely
	// hopeful.
	MaxInFlight  int
	ReclaimQueue int
	PresentedUID uint32
	PresentedGID uint32
	// Coherence validates the retained CLI spelling for protocol 6's one local
	// kernel-cache contract.
	Coherence CoherenceProfile
	// CachedNameCapacity bounds daemon N-lease payloads. Kernel dentry validity
	// is always zero. Zero selects defaultCachedNameCapacity.
	CachedNameCapacity int
	// RepairBudget bounds local recall repair. Zero selects defaultRepairBudget.
	RepairBudget time.Duration

	// Routes is the activated machine-local route set: the volume's
	// .portablefs/local-dirs declaration unioned with whatever the command line
	// added, compiled once (see ActivateRoutes). An empty set means every path
	// is served from the authority. Its Revision is the value this mount must
	// have declared at attach, so the two can never describe different
	// topologies.
	Routes localroutes.RuleSet
	// LocalBacking is the per-machine tree that holds grafted subtrees. It is
	// required whenever Routes is non-empty, because a route that cannot be
	// served locally is not a route.
	LocalBacking string
	// Debug enables the underlying FUSE request/reply trace. It is diagnostic
	// only and leaves the negotiated protocol and serving semantics unchanged.
	Debug bool

	// OnRevoked is called exactly once, from the teardown goroutine, when this
	// mount self-revokes and its kernel-state withdrawal has finished. It is a
	// Config field rather than a setter because a revocation can happen before
	// MountVolume even returns, and a supervisor that learned about it late
	// would have nothing to persist.
	//
	// It must not block: the same goroutine goes on to unmount and release the
	// authority session. Persisting one small state record is what it is for.
	OnRevoked func(RevocationReport)
}

// cleanStartupFailure is an error whose failed mount attempt has no remaining
// kernel mount or authority session. It is deliberately private: callers may
// inspect the verdict, but only this package owns the evidence that creates it.
type cleanStartupFailure struct {
	cause error
}

func (e *cleanStartupFailure) Error() string { return e.cause.Error() }
func (e *cleanStartupFailure) Unwrap() error { return e.cause }

// FailedStartupClean reports whether err proves that a failed mount startup
// left neither a kernel mount nor an authority session behind. Supervisors may
// use this verdict to remove their durable startup intent. Any unclassified
// error must remain recoverable and be reconciled explicitly.
func FailedStartupClean(err error) bool {
	var clean *cleanStartupFailure
	return errors.As(err, &clean)
}

func markCleanStartupFailure(cause error) error {
	return &cleanStartupFailure{cause: cause}
}

type Mount struct {
	server *fuse.Server
	// kernelConnectionDone closes only after go-fuse has stopped every request
	// loop, closed this mount's /dev/fuse descriptor, and run OnUnmount. Mount
	// table absence alone is insufficient on Linux: MNT_DETACH can hide a mount
	// while retained references keep the same FUSE connection alive.
	kernelConnectionDone    chan struct{}
	kernelConnectionStarted bool
	rpc                     RPC
	ctx                     context.Context
	cancel                  context.CancelFunc
	leaseSafetyCtx          context.Context
	leaseSafetyCancel       context.CancelFunc
	wg                      sync.WaitGroup
	mu                      sync.Mutex
	closed                  bool
	closeErr                error
	abort                   sync.Once
	fatalMu                 sync.Mutex
	fatalErr                error
	reclaim                 *reclaimQueue
	reclaimWorkers          int
	// bulk admits kernel-driven authority calls. Its capacity is strictly less
	// than the transport's own in-flight bound, so a keepalive or a reclaim can
	// never be queued behind saturated bulk I/O.
	bulk           chan struct{}
	requestTimeout time.Duration
	uid            uint32
	gid            uint32

	// The cache contract. raw is the kernel-facing table that owns the
	// cached-name registry and the publication gate; kernelMount is the
	// installed mount's identity, which is what makes both self-revocation and
	// a mount-absence proof exact rather than path-shaped guesses.
	nameCapacity int
	repairBudget time.Duration
	raw          *rawFileSystem
	kernelMount  kernelMount
	// plannedFSName is the unique source identity for this mount attempt and
	// plannedMountpoint is its validated target. They let failed startup prove
	// that this exact mount was never installed even when no kernel mount ID was
	// available to record.
	plannedFSName     string
	plannedMountpoint string
	revoked           atomic.Bool
	revokeOnce        sync.Once
	notifyMu          sync.Mutex
	notify            kernelNotifier
	// onRevoked is the supervisor's revocation observer (Config.OnRevoked) and
	// withdrawal the kernel primitives the escalation ladder drives; a zero
	// withdrawal selects the production syscalls.
	onRevoked   func(RevocationReport)
	withdrawal  kernelWithdrawal
	leases      *leaseRegistry
	leaseExpiry chan leaseKey
	// leaseHorizonAbort is the direct fusectl writer. Tests replace it to
	// prove this safety edge independently of the ordinary withdrawal ladder.
	leaseHorizonAbort func(kernelMount) error

	// grafts serves the machine-local routes, nil when the volume declares
	// none. routesRevision is the declaration this mount attached with, and is
	// what a routes-change event is judged against.
	grafts         *localdirs.Grafts
	backing        string
	routesRevision [32]byte
}

// publishAttr routes one stat answer through the cache contract. A mount with
// no kernel-facing table yet publishes no lifetime at all.
func (m *Mount) publishAttr(ctx context.Context, out *fuse.AttrOut, item *authoritypb.Item, attr *authoritypb.Attr) {
	if m.raw == nil {
		fillAttr(attr, &out.Attr, m.uid, m.gid)
		out.SetTimeout(0)
		return
	}
	identity, ok := publicationIdentityFromItem(item)
	if !ok {
		m.revoke(errors.New("fusev3: attribute publication has no stable item identity"))
		fillAttr(attr, &out.Attr, m.uid, m.gid)
		out.SetTimeout(0)
		return
	}
	m.raw.publishAttr(ctx, out, identity, attr)
}

// MountVolume mounts one authority session without a write-back cache.
//
// Names are cached only inside the daemon, with zero kernel entry validity.
// Attribute and clean-data kernel caching is admitted only by exact A-R/D-R
// leases and withdrawn before conflicting commits. Writes remain direct and
// write-through; shared writable mmap stays unavailable.
//
// What is not cached is a lifetime-based guess. Nothing here is served because
// a timeout has not expired yet; it is served because no repair has arrived,
// and a repair is guaranteed to arrive before any other machine could have
// observed the new value.
func MountVolume(parent context.Context, mountpoint string, rpc RPC, cfg Config) (*Mount, error) {
	if rpc == nil {
		return nil, errors.New("fusev3: authority session is required")
	}
	if mountpoint == "" || !mountid.ValidMountInstance(cfg.MountInstanceID) {
		rpc.FinishLocalSessionEnforcement()
		return nil, errors.Join(errors.New("fusev3: mountpoint and valid unique mount-instance identity are required"), rpc.Close())
	}
	if cfg.Coherence != CoherenceStrict {
		// Zero is the legacy uncached wire value. It must fail closed: translating
		// it would let an old sender attach with semantics it did not request.
		rpc.FinishLocalSessionEnforcement()
		return nil, errors.Join(errors.New("fusev3: strict coherence is required"), rpc.Close())
	}
	fsName := "portablefs:" + cfg.MountInstanceID
	failBeforeKernelMount := func(cause error) (*Mount, error) {
		if err := releaseUninstalledSession(rpc, fsName, mountpoint); err != nil {
			return nil, errors.Join(cause, err)
		}
		return nil, markCleanStartupFailure(cause)
	}
	if cfg.RequestTimeout <= 0 || cfg.MaxBackground <= 0 || cfg.ReclaimQueue <= 0 || cfg.MaxInFlight < minMaxInFlight {
		return failBeforeKernelMount(fmt.Errorf("fusev3: complete mount configuration is required with at least %d authority in-flight slots", minMaxInFlight))
	}
	if len(rpc.SessionID()) == 0 {
		return failBeforeKernelMount(errors.New("fusev3: strict coherence requires the authority session identity; without it this mount cannot recognise -- and would deadlock against -- its own mutations"))
	}
	rootItem := rpc.Root()
	if !validItem(rootItem) {
		return failBeforeKernelMount(errors.New("fusev3: authority omitted root identity"))
	}
	maxRead, maxWrite := rpc.IOLimits()
	lease := rpc.SessionLease()
	if maxRead == 0 || maxWrite == 0 || lease <= 0 || rpc.SessionDone() == nil || rpc.SessionEndPending() == nil {
		return failBeforeKernelMount(errors.New("fusev3: invalid negotiated authority bounds"))
	}
	if maxRead < kernelMinMaxWrite || maxWrite < kernelMinMaxWrite {
		return failBeforeKernelMount(fmt.Errorf("fusev3: authority I/O bounds (read %d, write %d) are below the %d-byte floor the Linux FUSE driver applies to max_write", maxRead, maxWrite, kernelMinMaxWrite))
	}
	options := mountOptions(cfg, maxRead, maxWrite)
	if err := verifyMountDecisions(options); err != nil {
		return failBeforeKernelMount(err)
	}
	m := newMount(parent, rpc, cfg)
	m.plannedFSName, m.plannedMountpoint = fsName, mountpoint
	// The machine-local serving state is built before the kernel mount exists.
	// A mount that cannot serve the routes it declared at attach is serving a
	// different topology than the authority admitted it with, so this fails the
	// mount rather than degrading to authority-only service.
	grafts, err := localdirs.New(localdirs.Config{BackingRoot: cfg.LocalBacking, Rules: cfg.Routes})
	if err != nil {
		m.cancel()
		return failBeforeKernelMount(fmt.Errorf("fusev3: serve machine-local routes: %w", err))
	}
	m.grafts, m.backing = grafts, cfg.LocalBacking
	root := &node{mount: m, item: cloneItem(rootItem), requestTimeout: cfg.RequestTimeout, maxRead: maxRead, maxWrite: maxWrite}
	server, err := fuse.NewServer(newRawFileSystem(m, root), mountpoint, options)
	if err != nil {
		m.cancel()
		return failBeforeKernelMount(errors.Join(fmt.Errorf("mount PortableFS v3: %w", err), grafts.Close()))
	}
	m.server = server
	m.setNotifier(server)
	if !m.raw.replyLifecycleReady() {
		// NewServer has already installed the mount and consumed INIT, but Serve
		// must run once to release go-fuse's prepared request-loop reference.
		m.cancel()
		m.startKernelConnection()
		return nil, m.abortMount(errors.New("fusev3: strict mount did not arm physical FUSE reply publication"))
	}
	// NewServer has installed the kernel mount, so it is now observable. Its
	// identity is recorded before anything can use the mount: its later absence
	// is the only thing that authorises a clean strict detach, and
	// self-revocation needs its device to abort the connection.
	installed, err := observeKernelMount(mountpoint)
	if err != nil {
		// go-fuse prepares one request-loop reference in NewServer, so even an
		// unserved mount needs Serve to consume it before Unmount can finish. The
		// canceled context makes this failure-only loop incapable of useful I/O.
		m.cancel()
		m.startKernelConnection()
		return nil, m.abortMount(err)
	}
	m.kernelMount = installed
	// Every background goroutine is registered before the request loop can run.
	// A request that fails the mount inside Serve reaches Unmount -> wg.Wait,
	// which must never observe a counter that is still being raised from zero.
	m.start(lease)
	m.startKernelConnection()
	if err := server.WaitMount(); err != nil {
		// NewServer has already installed the kernel mount. If INIT or the
		// readiness probe fails, remove it before releasing the authority
		// session so callers can never observe a mounted but unserved path.
		return nil, m.abortMount(fmt.Errorf("initialize PortableFS v3 mount: %w", err))
	}
	if err := verifyKernelGuarantees(server.KernelSettings(), maxWrite); err != nil {
		return nil, m.abortMount(err)
	}
	return m, nil
}

// releaseUninstalledSession discharges an authority session whose unique FUSE
// source is proven absent before a kernel mount ID could be recorded. Closing
// the connection alone is deliberately insufficient for strict membership:
// without this observation the authority must assume a failed startup may
// still have installed a cache-bearing kernel mount.
func releaseUninstalledSession(rpc RPC, fsName, mountpoint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), detachTimeout)
	defer cancel()
	proof, err := observePlannedKernelMountAbsent(fsName, mountpoint)
	if err != nil {
		rpc.FinishLocalSessionEnforcement()
		return errors.Join(fmt.Errorf("fusev3: establish failed-startup mount absence: %w", err), rpc.Close())
	}
	err = rpc.DetachAfterUnmount(ctx, proof)
	if err != nil {
		err = fmt.Errorf("fusev3: release failed-startup strict session: %w", err)
	}
	rpc.FinishLocalSessionEnforcement()
	return errors.Join(err, rpc.Close())
}

func newMount(parent context.Context, rpc RPC, cfg Config) *Mount {
	ctx, cancel := context.WithCancel(parent)
	leaseSafetyCtx, leaseSafetyCancel := context.WithCancel(context.Background())
	workers := reclaimLaneWidth(cfg.MaxInFlight)
	if cfg.CachedNameCapacity <= 0 {
		cfg.CachedNameCapacity = defaultCachedNameCapacity
	}
	if cfg.RepairBudget <= 0 {
		cfg.RepairBudget = defaultRepairBudget
	}
	// Lease CONTROL owns a transport slot no bulk request can take. Recall ACKs
	// release conflicting mutations on other participants.
	reserved := livenessReserve + leaseControlReserve
	mount := &Mount{
		rpc: rpc, ctx: ctx, cancel: cancel,
		leaseSafetyCtx: leaseSafetyCtx, leaseSafetyCancel: leaseSafetyCancel,
		kernelConnectionDone: make(chan struct{}),
		reclaim:              newReclaimQueue(cfg.ReclaimQueue),
		reclaimWorkers:       workers,
		bulk:                 make(chan struct{}, cfg.MaxInFlight-workers-reserved),
		requestTimeout:       cfg.RequestTimeout,
		uid:                  cfg.PresentedUID,
		gid:                  cfg.PresentedGID,
		nameCapacity:         cfg.CachedNameCapacity,
		repairBudget:         cfg.RepairBudget,
		leaseExpiry:          make(chan leaseKey, leaseExpiryQueueDepth),
		routesRevision:       cfg.Routes.Revision(),
		onRevoked:            cfg.OnRevoked,
	}
	mount.leases = newLeaseRegistry(mount)
	return mount
}

// reclaimLaneWidth is the number of concurrent reclaim calls the mount may
// have outstanding. It must be at least two: a single serial reclaimer drains
// at 1/RTT, which ordinary path walking outruns by an order of magnitude.
func reclaimLaneWidth(maxInFlight int) int {
	width := maxInFlight / reclaimLaneDivisor
	if width < 2 {
		width = 2
	}
	return width
}

func (m *Mount) start(lease time.Duration) {
	m.wg.Add(2 + m.reclaimWorkers)
	go m.keepAlive(m.ctx, lease)
	go m.watchSession(m.ctx, m.rpc.SessionEndPending())
	for range m.reclaimWorkers {
		go m.reclaimLoop(m.ctx)
	}
	m.wg.Add(4 + leaseExpiryWorkers)
	go m.runLeaseEvents(m.ctx)
	go m.runLeaseMaintenance(m.ctx)
	go m.runLeaseRenewals(m.ctx)
	go m.runLeaseHardWatchdog(m.leaseSafetyCtx)
	for range leaseExpiryWorkers {
		go m.runLeaseExpiry(m.ctx)
	}
}

// abortMount removes a kernel mount that was installed but cannot be served,
// then releases the authority session. Only exact absence plus a clean session
// close upgrades the original error to a clean-startup verdict.
func (m *Mount) abortMount(cause error) error {
	_ = m.server.Unmount()
	m.Wait()
	absenceErr := m.failedStartupKernelAbsent()
	closeErr := m.Close()
	if err := errors.Join(absenceErr, closeErr); err != nil {
		return errors.Join(cause, err)
	}
	return markCleanStartupFailure(cause)
}

func (m *Mount) failedStartupKernelAbsent() error {
	if m.kernelMount.point != "" {
		_, err := m.kernelMount.absent()
		return err
	}
	_, err := observePlannedKernelMountAbsent(m.plannedFSName, m.plannedMountpoint)
	return err
}

// mountOptions builds the kernel interface this frontend is willing to speak.
//
// MaxReadAhead is bounded by one authority read so a kernel read-ahead request
// never has to be split merely because the frontend chose a larger window.
func mountOptions(cfg Config, maxRead, maxWrite uint32) *fuse.MountOptions {
	return &fuse.MountOptions{
		FsName:        "portablefs:" + cfg.MountInstanceID,
		Name:          "portablefs",
		MaxWrite:      int(maxWrite),
		MaxReadAhead:  int(maxRead),
		MaxBackground: cfg.MaxBackground,
		Debug:         cfg.Debug,
		EnableLocks:   true,
		// Invalidation is this frontend's own act, never a kernel heuristic.
		// CAP_AUTO_INVAL_DATA would drop a coherent page cache whenever an
		// unrelated attribute refresh moved mtime, and -- because
		// fuse_cache_read_iter() consults fc->auto_inval_data -- would also put
		// a GETATTR in front of every buffered read. Requesting explicit
		// control instead is what makes the ordered DATA publication the single
		// thing that withdraws a page.
		ExplicitDataCacheControl: true,
		// Plain READDIR is the portable profile. Stock READDIRPLUS can install an
		// entry after a concurrent invalidation, and FOPEN_CACHE_DIR has a
		// position-zero-only validation hole; neither is part of the contract.
		DisableReadDirPlus: true,
		// Shared mmap is a decision of this mount, not an accident of which
		// capabilities go-fuse happens to forward. A writable shared mapping
		// would dirty pages that never travel the strict write transaction, and
		// a dirty page is also the one thing invalidate_inode_pages2() cannot
		// withdraw -- which would turn every later DATA repair on that inode
		// into a revocation. The capability is disabled for the whole mount
		// even if a future kernel or library change starts offering it by
		// default.
		// Atomic truncate is required, not an optimization. Without it Linux
		// decomposes open(O_TRUNC) into SETATTR(size=0) followed by OPEN, creating
		// two independently ordered authority mutations and an avoidable window in
		// which the truncate applied but the open failed. With it the authority's
		// OPEN mutation and its exact source gate are the single operation.
		// HANDLE_KILLPRIV_V2 is selected when the kernel advertises it. On the
		// 7.31 floor the kernel performs its documented SETATTR-based privilege
		// removal instead; absence is therefore not a mount refusal.
		ExtraCapabilities: fuse.CAP_ATOMIC_O_TRUNC | fuse.CAP_HANDLE_KILLPRIV_V2,
		DisabledCapabilities: fuse.CAP_DIRECT_IO_ALLOW_MMAP | fuse.CAP_PASSTHROUGH |
			fuse.CAP_NO_OPEN_SUPPORT | fuse.CAP_NO_OPENDIR_SUPPORT |
			fuse.CAP_AUTO_INVAL_DATA | fuse.CAP_WRITEBACK_CACHE |
			fuse.CAP_READDIRPLUS | fuse.CAP_READDIRPLUS_AUTO |
			fuse.CAP_CACHE_SYMLINKS | fuse.CAP_HAS_INODE_DAX,
		Options: []string{"default_permissions"},
	}
}

// verifyMountDecisions asserts the coherence-critical choices this frontend
// makes about the kernel interface before the mount is installed.
func verifyMountDecisions(options *fuse.MountOptions) error {
	if options.ExtraCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP != 0 ||
		options.DisabledCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP == 0 {
		return errors.New("fusev3: shared mmap must be disabled for the whole mount; a dirty page neither travels the strict write transaction nor survives a DATA repair")
	}
	if options.ExtraCapabilities&fuse.CAP_HAS_INODE_DAX != 0 || options.DisabledCapabilities&fuse.CAP_HAS_INODE_DAX == 0 {
		return errors.New("fusev3: inode DAX must be disabled; lease invalidation is defined over ordinary clean page-cache folios")
	}
	if options.DisabledCapabilities&fuse.CAP_AUTO_INVAL_DATA == 0 || !options.ExplicitDataCacheControl {
		return errors.New("fusev3: retained page cache requires explicit data-cache control; an mtime heuristic must not decide when this mount's pages are withdrawn")
	}
	if options.MaxReadAhead <= 0 {
		return errors.New("fusev3: the read-ahead window must be negotiated explicitly; leaving it at the kernel default silently unpairs it from the authority read bound")
	}
	if options.DisabledCapabilities&fuse.CAP_PASSTHROUGH == 0 ||
		options.DisabledCapabilities&fuse.CAP_NO_OPEN_SUPPORT == 0 ||
		options.DisabledCapabilities&fuse.CAP_NO_OPENDIR_SUPPORT == 0 {
		return errors.New("fusev3: passthrough and no-open shortcuts must be disabled; every strict handle requires an explicit classified OPEN/OPENDIR reply")
	}
	if !options.EnableLocks {
		return errors.New("fusev3: file locks must be forwarded to the authority; the local kernel lock manager cannot exclude another machine")
	}
	if options.ExtraCapabilities&fuse.CAP_ATOMIC_O_TRUNC == 0 {
		return errors.New("fusev3: atomic open-truncate must be requested; splitting it into SETATTR then OPEN is not one filesystem operation")
	}
	if options.ExtraCapabilities&fuse.CAP_HAS_RESEND != 0 {
		return errors.New("fusev3: HAS_RESEND is incompatible with strict publication identity ownership and must not be requested")
	}
	return nil
}

// verifyKernelGuarantees checks the capabilities the coherence and locking
// contracts depend on against what the kernel actually advertised in its INIT
// request. go-fuse ORs CAP_FLOCK_LOCKS|CAP_POSIX_LOCKS into the INIT reply
// unconditionally when EnableLocks is set, so a reply that requests them is no
// evidence at all: on a kernel that does not support forwarded locks the mount
// silently falls back to the local lock manager, two mounts on one host still
// exclude each other, and only mounts on different hosts lose exclusion.
func verifyKernelGuarantees(settings *fuse.InitIn, maxWrite uint32) error {
	if settings == nil {
		return errors.New("fusev3: kernel INIT settings are unavailable; the mount guarantees cannot be verified")
	}
	if settings.Major != portableFuseMajor || settings.Minor < portableFuseMinor {
		return fmt.Errorf("fusev3: portable coherence requires stock FUSE protocol %d.%d or newer; kernel offered %d.%d", portableFuseMajor, portableFuseMinor, settings.Major, settings.Minor)
	}
	offered := settings.Flags64()
	if offered&fuse.CAP_ATOMIC_O_TRUNC == 0 {
		return fmt.Errorf("fusev3: kernel does not support atomic open-truncate (INIT flags %#x); PortableFS will not split one O_TRUNC syscall across SETATTR and OPEN mutations", offered)
	}
	if offered&fuse.CAP_EXPLICIT_INVAL_DATA == 0 {
		return fmt.Errorf("fusev3: kernel cannot give this mount explicit data-cache control (INIT flags %#x); retained pages would be withdrawn by an mtime heuristic instead of by the ordered DATA repair", offered)
	}
	// InitIn reports what the kernel offers, not what the daemon selected.
	// Linux advertises RESEND, passthrough, and no-open support for non-strict
	// mounts even when this daemon correctly declines them in InitOut. The mount
	// options forbid selecting those capabilities, and the strict kernel rejects
	// an InitOut that selects any of them.
	if offered&fuse.CAP_POSIX_LOCKS == 0 || offered&fuse.CAP_FLOCK_LOCKS == 0 {
		return fmt.Errorf("fusev3: kernel does not forward POSIX and BSD file locks (INIT flags %#x); cross-machine lock exclusion is unavailable", offered)
	}
	// A strict mount publishes names and attributes with a lifetime, and the
	// only thing that makes that safe is being able to take them back. Both
	// notifications are protocol 7.12; a kernel that cannot receive them cannot
	// host this profile, and the mount must be refused rather than served with
	// a cache nothing can revoke.
	if !settings.SupportsNotify(fuse.NOTIFY_INVAL_ENTRY) || !settings.SupportsNotify(fuse.NOTIFY_INVAL_INODE) {
		return fmt.Errorf("fusev3: kernel FUSE protocol %d.%d cannot receive entry and inode invalidations; strict coherence has no way to revoke what it caches",
			settings.Major, settings.Minor)
	}
	if uint64(maxWrite) > uint64(kernelDefaultMaxPages)*uint64(syscall.Getpagesize()) && offered&fuse.CAP_MAX_PAGES == 0 {
		return fmt.Errorf("fusev3: kernel caps every request at %d pages and cannot carry the negotiated %d-byte write as one request", kernelDefaultMaxPages, maxWrite)
	}
	return nil
}

func (m *Mount) keepAlive(ctx context.Context, lease time.Duration) {
	defer m.wg.Done()
	interval := keepAliveInterval(lease, m.repairBudget)
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			callCtx, cancel := context.WithTimeout(ctx, interval)
			// Renewal never passes through the bulk lane: livenessReserve keeps
			// one transport slot that only this call can occupy.
			response, err := m.rpc.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
			cancel()
			if ctx.Err() != nil {
				// The mount is shutting down. A call that lost the race with
				// cancellation says nothing about the authority.
				return
			}
			if err != nil || responseErrno(response) != 0 {
				// A failed renewal is terminal. Keeping the path mounted would let
				// callers observe a long tail of unrelated per-operation failures.
				if err == nil {
					err = fmt.Errorf("keepalive refused: %w", responseErrno(response))
				}
				m.failAsync(fmt.Errorf("fusev3: authority keepalive failed: %w", err))
				return
			}
		}
	}
}

// keepAliveInterval makes the strict frontend's authority-contact failure
// bound no larger than its cache-repair contract. The authority may fence a
// participant whose lease CONTROL connection was lost; after that fence, this
// lane is how the frontend learns it must abort even though it never received
// the recall that would have started a withdrawal timer. One interval to start a renewal
// plus one interval for its deadline is at most two thirds of RepairBudget.
func keepAliveInterval(lease time.Duration, repairBudget time.Duration) time.Duration {
	interval := lease / 3
	if strict := repairBudget / 3; strict < interval {
		interval = strict
	}
	if interval <= 0 {
		// Mount admission already requires positive bounds. This floor merely
		// keeps sub-nanosecond integer division from reaching NewTicker.
		return time.Nanosecond
	}
	return interval
}

func (m *Mount) watchSession(ctx context.Context, done <-chan struct{}) {
	defer m.wg.Done()
	select {
	case <-ctx.Done():
		return
	case <-done:
		if ctx.Err() == nil {
			err := m.rpc.SessionEndCause()
			if err == nil {
				err = errors.New("authority session ended")
			}
			m.failAsync(fmt.Errorf("fusev3: %w", err))
		}
	}
}

// reclaimLoop drains forgotten capabilities. Several of these run concurrently
// and none of them passes through the bulk lane, so cleanup throughput is
// independent of how saturated ordinary filesystem I/O is.
func (m *Mount) reclaimLoop(ctx context.Context) {
	defer m.wg.Done()
	for {
		token, ok := m.reclaim.pop(ctx)
		if !ok {
			return
		}
		callCtx, cancel := context.WithTimeout(ctx, m.requestTimeout)
		request := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: token}}}
		response, consumption, err := m.rpc.CallMutationWithIdentityRetained(
			callCtx, request, nil, m.forceTerminalResponseRevocation,
		)
		cancel()
		if ctx.Err() != nil {
			if consumption != nil {
				m.revoke(errors.New("fusev3: mount ended before an authority reclaim response was consumed"))
				consumption.Consume()
			}
			return
		}
		if err != nil || responseErrno(response) != 0 {
			if err == nil {
				err = fmt.Errorf("reclaim refused: %w", responseErrno(response))
			}
			m.cleanupFailed("object reclaim", err)
			if consumption != nil {
				consumption.Consume()
			}
			return
		}
		if consumption != nil {
			consumption.Consume()
		}
	}
}

// cleanupFailed is the single policy this mount applies when the authority
// refuses to release a resource the frontend has already given up locally
// (a forgotten capability, or a file handle the kernel has closed). Both mean
// the frontend and the authority no longer agree about who owns an object; the
// session cannot continue correctly, and continuing would surface later as
// unexplained per-session admission failures on ordinary open() calls.
func (m *Mount) cleanupFailed(operation string, err error) {
	if m.ctx != nil && m.ctx.Err() != nil {
		// Teardown already released everything through Detach.
		return
	}
	m.revoke(fmt.Errorf("fusev3: authority refused %s of a frontend-owned resource: %w", operation, err))
}

// acquireBulk admits one kernel-driven authority call. The non-blocking attempt
// comes first on purpose: `select` picks uniformly at random when several cases
// are ready, so a single combined select would fail an admissible call roughly
// half the time whenever the operation deadline had already expired.
func (m *Mount) acquireBulk(ctx context.Context) syscall.Errno {
	// A revoked mount answers nothing. This is the single choke point every
	// authority-backed operation passes through, so refusing here is what makes
	// self-revocation immediate rather than eventual.
	if m.isRevoked() {
		return revokedErrno
	}
	select {
	case m.bulk <- struct{}{}:
		return 0
	default:
	}
	select {
	case m.bulk <- struct{}{}:
		return 0
	case <-ctx.Done():
		return contextErrno(ctx.Err())
	}
}

func (m *Mount) releaseBulk() { <-m.bulk }

// reclaimQueue is the frontend's forgotten-capability backlog.
//
// It is a FIFO with an admission watermark rather than a fixed channel because
// its two producers have opposite obligations. FORGET must never block: go-fuse
// deliberately spawns no replacement reader for FORGET/BATCH_FORGET, so a
// blocking Forget would stall the entire request loop. A request goroutine that
// is about to create new cleanup debt, by contrast, can and must be slowed
// down. Admission therefore happens before the debt exists, which makes
// overflow a state this type cannot enter -- there is no discard path and no
// failure return, so no ordinary workload can turn cleanup pressure into a
// destroyed mount.
//
// The backlog is bounded even though push never fails: the only tokens that can
// enter it are one per interned inode plus one per admitted duplicate lookup,
// and interning is exactly what admission throttles.
type reclaimQueue struct {
	watermark int

	mu     sync.Mutex
	tokens [][]byte
	head   int
	// wake carries "the backlog is non-empty" to the drain workers.
	wake chan struct{}
	// room is closed (and replaced) when the backlog falls back under the
	// watermark, releasing every producer waiting for admission.
	room chan struct{}
}

func newReclaimQueue(watermark int) *reclaimQueue {
	return &reclaimQueue{watermark: watermark, wake: make(chan struct{}, 1)}
}

func (q *reclaimQueue) push(token []byte) {
	q.mu.Lock()
	q.tokens = append(q.tokens, token)
	q.mu.Unlock()
	q.signal()
}

func (q *reclaimQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *reclaimQueue) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.tokens) - q.head
}

func (q *reclaimQueue) pop(ctx context.Context) ([]byte, bool) {
	for {
		q.mu.Lock()
		if q.head < len(q.tokens) {
			token := q.tokens[q.head]
			q.tokens[q.head] = nil
			q.head++
			if q.head == len(q.tokens) {
				// Reset instead of resliding so the backing array is reused
				// rather than growing without bound.
				q.tokens, q.head = q.tokens[:0], 0
			}
			remaining := len(q.tokens) - q.head
			if remaining < q.watermark && q.room != nil {
				close(q.room)
				q.room = nil
			}
			q.mu.Unlock()
			if remaining > 0 {
				q.signal()
			}
			return token, true
		}
		q.mu.Unlock()
		select {
		case <-q.wake:
		case <-ctx.Done():
			return nil, false
		}
	}
}

// admit blocks a producer that is about to create new cleanup debt until the
// backlog has room. It is never reachable from FORGET.
func (q *reclaimQueue) admit(ctx context.Context) error {
	for {
		q.mu.Lock()
		if len(q.tokens)-q.head < q.watermark {
			q.mu.Unlock()
			return nil
		}
		if q.room == nil {
			q.room = make(chan struct{})
		}
		room := q.room
		q.mu.Unlock()
		select {
		case <-room:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// deferReclaim hands one forgotten capability to the cleanup lane. It never
// blocks and never fails, which is exactly what makes it callable from FORGET.
func (m *Mount) deferReclaim(token []byte) {
	if len(token) == 0 {
		return
	}
	m.reclaim.push(cloneBytes(token))
}

// Wait returns only after the exact FUSE serving connection is terminal. This
// is deliberately stronger than waiting for the mountpoint to disappear from
// mountinfo, because a lazy unmount can do that while retained references keep
// the connection live.
func (m *Mount) Wait() { <-m.kernelConnectionDone }

func (m *Mount) startKernelConnection() {
	if m.kernelConnectionStarted {
		panic("fusev3: FUSE serving connection started twice")
	}
	m.kernelConnectionStarted = true
	go func() {
		m.server.Serve()
		close(m.kernelConnectionDone)
	}()
}

func (m *Mount) Unmount() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	if err := m.server.Unmount(); err != nil {
		return err
	}
	return m.closeLocked()
}

// Close releases the authority session after the kernel mount has already
// disappeared (for example, an administrator unmounted it externally). A
// strict close also requires the exact FUSE connection to have terminated.
func (m *Mount) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeLocked()
}

func (m *Mount) closeLocked() error {
	if m.closed {
		return m.closeErr
	}
	m.closed = true
	m.cancel()
	m.leaseSafetyCancel()
	var replyOwnershipErr error
	if m.raw != nil {
		if !m.raw.terminalizeReplyCacheOwnership(time.Now().Add(m.repairBudget)) {
			deadline := time.Now().Add(m.repairBudget)
			_, absenceErr := m.kernelMount.absent()
			if absenceErr != nil || !m.kernelConnectionAbsentBy(deadline) {
				replyOwnershipErr = errors.Join(
					fmt.Errorf("fusev3: terminal reply writer did not report inside the repair budget"),
					absenceErr,
				)
			} else {
				m.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
				m.raw.discardCachedOwnershipAfterConnectionGone()
			}
		}
	}
	m.wg.Wait()
	// Any capability still queued for reclaim is released by Detach: ending the
	// session drops every item and open this session holds.
	detachErr := m.detach()
	// Normal unmount and externally observed detach have no revocation ladder,
	// so their exact absence/connection checks above are the local enforcement
	// boundary. A terminal revocation already finished this idempotently from
	// scheduleAbort before it reached Close.
	m.rpc.FinishLocalSessionEnforcement()
	m.closeErr = errors.Join(m.fatalError(), replyOwnershipErr, detachErr, m.grafts.Close(), m.rpc.Close())
	return m.closeErr
}

func (m *Mount) fatalError() error {
	m.fatalMu.Lock()
	defer m.fatalMu.Unlock()
	return m.fatalErr
}

type node struct {
	mount          *Mount
	item           *authoritypb.Item
	requestTimeout time.Duration
	maxRead        uint32
	maxWrite       uint32
}

type fileHandle struct {
	node      *node
	token     []byte
	openFlags uint32
	buffered  bool
	once      sync.Once
}

type dirHandle struct {
	node             *node
	token            []byte
	mu               sync.Mutex
	cookie           []byte
	verifier         []byte
	page             []*authoritypb.Dirent
	pageLease        leaseStamp
	index            int
	cursorGeneration uint64
	fetching         bool
	fetchDone        chan struct{}
	// next is the kernel offset this handle will resume from. A READDIR that
	// asks for exactly this offset continues out of the buffered page instead
	// of discarding it and re-fetching from the authority.
	next uint64
	// pending is the entry produced by peek but not yet accepted by the kernel
	// buffer. Holding it here is what makes the page cache lossless: an entry
	// that does not fit in this READDIR reply is not consumed.
	pending       *fuse.DirEntry
	pendingDirent *authoritypb.Dirent
	pendingCookie []byte
	pageWantItems bool
	eof           bool
	once          sync.Once
	// plusReply serializes the directory cursor across the physical reply edge.
	// READDIRPLUS transfers authority capabilities while building a page, but
	// the kernel owns their lookup references only after /dev/fuse accepts the
	// reply. No later directory request may observe that provisional cursor.
	plusReply *dirPlusCursorTransaction
	// enumerationInvalidated forces the next kernel callback to restart from
	// the beginning rather than resume an authority cookie/verifier from a
	// recalled E(dir) lease.
	enumerationInvalidated bool

	// local is the set of machine-local route roots this directory contains and
	// shadow is the set of names they own. Both are decided once, when the
	// stream is opened, for the same reason the authority pages its own listing
	// from a verifier: a listing that recomputed them per reply could show a
	// name twice or lose it across the reply boundary. The roots are delivered
	// after the volume's own entries, in an offset space of their own, so
	// resuming from any offset the kernel was given lands exactly where it did.
	local      []fuse.DirEntry
	shadow     func(name string) bool
	localIndex int
}

type dirPlusCursorTransaction struct {
	handle *dirHandle
	start  uint64
	done   chan struct{}
	once   sync.Once
}

func (n *node) opContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, n.requestTimeout)
}

func (n *node) read(parent context.Context, request *authoritypb.Request) (*authoritypb.Response, syscall.Errno) {
	ctx, cancel := n.opContext(parent)
	defer cancel()
	if errno := n.mount.acquireBulk(ctx); errno != 0 {
		return nil, errno
	}
	defer n.mount.releaseBulk()
	requestStart := time.Now()
	response, consumption, err := n.mount.rpc.CallReadRetained(ctx, request, n.mount.forceTerminalResponseRevocation)
	if grantErr := captureLeaseGrants(n.mount, replyPublicationFromContext(parent), response, requestStart); grantErr != nil {
		if consumption != nil {
			consumption.Consume()
		}
		n.mount.revoke(grantErr)
		return response, syscall.ENOTCONN
	}
	if consumption != nil {
		if retainErr := retainAuthorityResponse(parent, consumption); retainErr != nil {
			n.mount.revoke(retainErr)
			consumption.Consume()
			return response, syscall.ENOTCONN
		}
	}
	return response, rpcErrno(response, err)
}

func (m *Mount) forceTerminalResponseRevocation(cause error) {
	if cause == nil {
		cause = authorityrpc.ErrSessionEnded
	}
	m.revoke(fmt.Errorf("fusev3: authority terminal response was not locally published within its drain bound: %w", cause))
}

// callMutation owns the source-publication transition around one transport
// mutation. The exact local gate is closed and drained before replay identity
// assignment. Once assignment occurs, any outcome the transport cannot prove
// is terminal and the gate stays closed through mount revocation.
func (m *Mount) callMutation(ctx context.Context, request *authoritypb.Request, gate *sourcePublicationGate) (*authoritypb.Response, error) {
	requiresGate := requestRequiresSourcePublication(request)
	if requiresGate != (gate != nil) {
		return nil, errors.New("fusev3: mutation source-publication ownership does not match its operation")
	}
	callback, _ := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
	if callback == nil || m.raw == nil {
		return nil, errors.New("fusev3: strict mutation escaped its raw callback publication lifecycle")
	}
	if callback.operationID == 0 {
		return nil, errors.New("fusev3: mutation carried an invalid frontend operation identity")
	}
	if !requiresGate {
		response, consumption, callErr := m.rpc.CallMutationWithIdentityRetained(
			ctx, request, nil, m.forceTerminalResponseRevocation,
		)
		if consumption != nil {
			if retainErr := retainAuthorityResponse(ctx, consumption); retainErr != nil {
				m.revoke(retainErr)
				consumption.Consume()
				return response, retainErr
			}
		}
		return response, callErr
	}
	lease, err := callback.acquireSource(ctx, m.raw, gate)
	if err != nil {
		return nil, err
	}
	assignmentFailed := false
	response, consumption, callErr := m.rpc.CallMutationWithIdentityRetained(ctx, request, func(authorityrpc.MutationIdentity) error {
		if err := lease.markAssigned(); err != nil {
			assignmentFailed = true
			lease.revoke()
			m.revoke(fmt.Errorf("fusev3: source mutation assignment callback violated its lifecycle: %w", err))
			return err
		}
		return nil
	}, m.forceTerminalResponseRevocation)
	assigned := lease.isAssigned()
	if consumption != nil {
		if retainErr := retainAuthorityResponse(ctx, consumption); retainErr != nil {
			m.revoke(retainErr)
			consumption.Consume()
			return response, retainErr
		}
	}
	if !assignmentFailed && !assigned && callErr == nil {
		assignmentFailed = true
		lease.revoke()
		lifecycleErr := errors.New("fusev3: source mutation transport returned without assigning its replay identity")
		m.revoke(lifecycleErr)
		callErr = lifecycleErr
	}
	if !assignmentFailed && assigned && (callErr != nil || response == nil || response.GetUncertain()) {
		lease.revoke()
		cause := callErr
		if cause == nil {
			cause = authorityrpc.ErrTransportUncertain
		}
		m.revoke(fmt.Errorf("fusev3: assigned source mutation outcome is uncertain: %w", cause))
	}
	definiteNoChange := response != nil && responseErrno(response) != 0 && response.GetPostState() == nil && response.GetSourceLeaseDischarge() == nil
	if !assignmentFailed && callErr == nil && response != nil && !response.GetUncertain() && definiteNoChange {
		lease.resolveAllNoBinding()
		if err := lease.markDefiniteNoChange(); err != nil {
			lease.revoke()
			m.revoke(fmt.Errorf("fusev3: source mutation could not record its definite refusal: %w", err))
		}
	} else if !assignmentFailed && !assigned && callErr != nil {
		lease.resolveAllNoBinding()
		if err := lease.markDefiniteNoChange(); err != nil {
			lease.revoke()
			m.revoke(fmt.Errorf("fusev3: source mutation could not record its pre-dispatch refusal: %w", err))
		}
	}
	return response, callErr
}

// requestRequiresSourcePublication is the Linux-side grammar boundary for
// filesystem-visible mutations. Keeping it next to callMutation makes a
// missing gate an invariant failure before replay assignment or transport,
// rather than a compatibility path which can apply without local ownership.
func requestRequiresSourcePublication(request *authoritypb.Request) bool {
	if request == nil {
		return false
	}
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Open:
		return body.Open.GetFlags().GetTruncate()
	case *authoritypb.Request_Create,
		*authoritypb.Request_Tmpfile,
		*authoritypb.Request_Mkdir,
		*authoritypb.Request_Unlink,
		*authoritypb.Request_Rename,
		*authoritypb.Request_Link,
		*authoritypb.Request_Symlink,
		*authoritypb.Request_SetAttr,
		*authoritypb.Request_SetXattr,
		*authoritypb.Request_RemoveXattr,
		*authoritypb.Request_Fallocate,
		*authoritypb.Request_CopyFileRange:
		return true
	case *authoritypb.Request_Write:
		return true
	default:
		return false
	}
}

func (m *Mount) retainMutationPostState(ctx context.Context, response *authoritypb.Response) error {
	if response == nil || response.GetPostState() == nil {
		return nil
	}
	publication := replyPublicationFromContext(ctx)
	if publication == nil || publication.postState != nil {
		err := errors.New("fusev3: mutation post-state escaped or duplicated its reply publication")
		m.revoke(err)
		return err
	}
	publication.postState = proto.Clone(response.GetPostState()).(*authoritypb.PostState)
	return nil
}

func (m *Mount) retainSourceLeaseDischarge(ctx context.Context, response *authoritypb.Response) error {
	if response == nil {
		return nil
	}
	discharge := response.GetSourceLeaseDischarge()
	publication := replyPublicationFromContext(ctx)
	if discharge == nil {
		return nil
	}
	if publication == nil || publication.source == nil || publication.sourceLeaseDischarge != nil ||
		discharge.GetSequence() == 0 || len(discharge.GetRecalls()) == 0 {
		return errors.New("fusev3: malformed source lease-discharge barrier")
	}
	for _, recall := range discharge.GetRecalls() {
		if _, err := validateLeaseRecall(recall); err != nil {
			return err
		}
	}
	publication.sourceLeaseDischarge = proto.Clone(discharge).(*authoritypb.SourceLeaseDischarge)
	if err := m.prepareSourceLeaseDischarge(publication); err != nil {
		return err
	}
	publication.sourceLeasePrepared = true
	return nil
}

func (n *node) mutate(parent context.Context, request *authoritypb.Request) (*authoritypb.Response, syscall.Errno) {
	return n.mutateWithSource(parent, request, nil)
}

func (n *node) mutateWithSource(parent context.Context, request *authoritypb.Request, gate *sourcePublicationGate) (*authoritypb.Response, syscall.Errno) {
	ctx, cancel := n.opContext(parent)
	defer cancel()
	if errno := n.mount.acquireBulk(ctx); errno != 0 {
		return nil, errno
	}
	defer n.mount.releaseBulk()
	requestStart := time.Now()
	response, err := n.mount.callMutation(ctx, request, gate)
	if grantErr := captureLeaseGrants(n.mount, replyPublicationFromContext(parent), response, requestStart); grantErr != nil {
		n.mount.revoke(grantErr)
		return response, syscall.ENOTCONN
	}
	if retainErr := n.mount.retainMutationPostState(parent, response); retainErr != nil {
		return response, syscall.ENOTCONN
	}
	if retainErr := n.mount.retainSourceLeaseDischarge(parent, response); retainErr != nil {
		n.mount.revoke(retainErr)
		return response, syscall.ENOTCONN
	}
	return response, rpcErrno(response, err)
}

func (n *node) Lookup(ctx context.Context, name string) (*authoritypb.Item, syscall.Errno) {
	// Lookup transfers a retained authority item capability. It is read-only in
	// XFS but not side-effect-free in the session, so it uses exact replay: a
	// lost response must return the same capability instead of allocating an
	// unreachable second one.
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil {
		snapshot := response.GetLookup().GetNegativeSnapshotSequence()
		publication := replyPublicationFromContext(ctx)
		if snapshot == 0 || publication == nil || publication.cacheStamp != nil {
			return nil, syscall.EIO
		}
		publication.cacheStamp = &cacheSnapshot{SnapshotSequence: snapshot}
		return nil, syscall.ENOENT
	}
	if item.GetAttr() == nil || item.GetObjectVersion() == 0 || item.GetSnapshotSequence() == 0 || item.GetObjectVersion() > item.GetSnapshotSequence() {
		return nil, syscall.EIO
	}
	publication := replyPublicationFromContext(ctx)
	if publication == nil || publication.cacheStamp != nil {
		return nil, syscall.EIO
	}
	publication.cacheStamp = &cacheSnapshot{
		SnapshotSequence: item.GetSnapshotSequence(), ObjectVersion: item.GetObjectVersion(),
		BirthTimeNS: item.GetAttr().GetBirthTimeNs(), InodeFlags: item.GetAttr().GetFlags(),
	}
	return cloneItem(item), 0
}

func (n *node) Getattr(ctx context.Context, fh *fileHandle, out *fuse.AttrOut) syscall.Errno {
	req := &authoritypb.GetAttrRequest{Item: cloneBytes(n.item.GetToken())}
	if fh != nil {
		req.Item, req.Handle = nil, cloneBytes(fh.token)
	}
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: req}})
	if errno != 0 {
		return errno
	}
	attr := response.GetGetAttr().GetAttr()
	objectVersion, snapshot := response.GetGetAttr().GetObjectVersion(), response.GetGetAttr().GetSnapshotSequence()
	if attr == nil || objectVersion == 0 || snapshot == 0 || objectVersion > snapshot {
		return syscall.EIO
	}
	publication := replyPublicationFromContext(ctx)
	if publication == nil || publication.cacheStamp != nil {
		return syscall.EIO
	}
	publication.cacheStamp = &cacheSnapshot{
		SnapshotSequence: snapshot, ObjectVersion: objectVersion,
		BirthTimeNS: attr.GetBirthTimeNs(), InodeFlags: attr.GetFlags(),
	}
	n.mount.publishAttr(ctx, out, n.item, attr)
	return 0
}

func (n *node) Open(ctx context.Context, flags uint32) (*fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 {
		return nil, 0, errno
	}
	identity, hasIdentity := publicationIdentityFromItem(n.item)
	preexistingDataLease := hasIdentity && n.mount.leases.remaining(leaseKey{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: identity,
	}, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, time.Now()) > 0
	request := &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: openFlags}}}
	var gate *sourcePublicationGate
	if openFlags.GetTruncate() {
		var err error
		gate, err = itemSourceGate(n.item, true)
		if err != nil {
			return nil, 0, syscall.EIO
		}
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return nil, 0, errno
	}
	if openFlags.GetTruncate() {
		if err := expectPostStateItem(ctx, n.item, postStateRoleTarget); err != nil {
			return nil, 0, syscall.EIO
		}
	}
	if response.GetOpen() == nil || len(response.GetOpen().GetHandle()) == 0 {
		return nil, 0, syscall.EIO
	}
	currentDataLease := hasIdentity && n.mount.leases.remaining(leaseKey{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: identity,
	}, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, time.Now()) > 0
	kernelFlags := portableReadOpenFlags(flags, preexistingDataLease, currentDataLease)
	return &fileHandle{
		node: n, token: cloneBytes(response.GetOpen().GetHandle()), openFlags: flags, buffered: kernelFlags&fuse.FOPEN_DIRECT_IO == 0,
	}, kernelFlags, 0
}

func (n *node) Read(ctx context.Context, handle *fileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if handle == nil || off < 0 {
		return nil, syscall.EBADF
	}
	written := 0
	for written < len(dest) {
		length := min(len(dest)-written, int(n.maxRead))
		response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: cloneBytes(handle.token), Offset: uint64(off) + uint64(written), Length: uint32(length)}}})
		if errno != 0 {
			return nil, errno
		}
		if response.GetRead() == nil {
			return nil, syscall.EIO
		}
		chunk := response.GetRead().GetData()
		if len(chunk) > length {
			return nil, syscall.EIO
		}
		copy(dest[written:], chunk)
		written += len(chunk)
		if len(chunk) < length {
			break
		}
	}
	return fuse.ReadResultData(dest[:written]), 0
}

func (n *node) Fsync(ctx context.Context, handle *fileHandle, flags uint32) syscall.Errno {
	if handle == nil {
		return syscall.EBADF
	}
	_, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytes(handle.token), DataOnly: flags&fsyncDataOnly != 0}}})
	return errno
}

func (n *node) Flush(ctx context.Context, handle *fileHandle, lockOwner uint64) syscall.Errno {
	if handle == nil {
		return syscall.EBADF
	}
	_, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Flush{Flush: &authoritypb.FlushRequest{Handle: cloneBytes(handle.token), LockOwner: lockOwner}}})
	return errno
}

func (n *node) Release(ctx context.Context, handle *fileHandle) syscall.Errno {
	if handle == nil {
		return syscall.EBADF
	}
	return handle.close(ctx, 0, false)
}

func (h *fileHandle) close(ctx context.Context, lockOwner uint64, flockUnlock bool) syscall.Errno {
	var errno syscall.Errno
	h.once.Do(func() {
		_, errno = h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(h.token), LockOwner: lockOwner, FlockUnlock: flockUnlock}}})
	})
	return errno
}

func (n *node) OpendirHandle(ctx context.Context, flags uint32) (*dirHandle, uint32, syscall.Errno) {
	if flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY) {
		return nil, 0, syscall.EISDIR
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: &authoritypb.OpenFlags{Read: true}}}})
	if errno != 0 {
		return nil, 0, errno
	}
	if response.GetOpen() == nil || len(response.GetOpen().GetHandle()) == 0 {
		return nil, 0, syscall.EIO
	}
	identity, ok := publicationIdentityFromItem(n.item)
	publication := replyPublicationFromContext(ctx)
	_, granted := publication.leaseGrant(
		authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION,
		authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ,
		identity, publicationIdentity{}, "", time.Now(),
	)
	if !ok || !granted {
		n.mount.revoke(errors.New("fusev3: successful directory OPEN omitted its required enumeration lease"))
		return nil, 0, syscall.ENOTCONN
	}
	return &dirHandle{node: n, token: cloneBytes(response.GetOpen().GetHandle())}, 0, 0
}

// peek returns the next directory entry without consuming it, fetching another
// authority page only when the buffered one is exhausted.
func (h *dirHandle) peek(ctx context.Context, wantItems bool) (*fuse.DirEntry, *authoritypb.Dirent, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The E lease covers the whole authority-derived stream state, not only an
	// unread entry. An exhausted EOF, verifier, or resume cookie from an older
	// epoch can otherwise suppress or skip names after a mutation. Dropping that
	// state re-reads the directory from the beginning; whether the kernel is
	// allowed to continue a stream that was dropped underneath it is decided in
	// seekdirLocked, which is the only place that knows the resume offset.
	if h.pageLease.epoch != 0 || h.pending != nil || h.index < len(h.page) || len(h.verifier) != 0 || len(h.cookie) != 0 {
		identity, ok := publicationIdentityFromItem(h.node.item)
		if !ok || !h.node.mount.leases.matches(leaseKey{
			family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, identity: identity,
		}, authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ, h.pageLease, time.Now()) {
			h.discardPageItemsLocked()
			h.page, h.index, h.pending, h.pendingDirent, h.pendingCookie = nil, 0, nil, nil, nil
			h.pageLease = leaseStamp{}
			h.cookie, h.verifier = nil, nil
			h.next, h.localIndex, h.eof = 0, 0, false
		}
	}
	if h.pending != nil && h.pageWantItems != wantItems {
		// Resume from the last consumed authority cookie. A kernel is allowed to
		// alternate READDIR and READDIRPLUS on one handle; capabilities must only
		// be minted for the PLUS page that will actually carry them.
		h.discardPageItemsLocked()
		h.page, h.index, h.pending, h.pendingDirent = nil, 0, nil, nil
	}
	if h.pending != nil {
		return h.pending, h.pendingDirent, 0
	}
	for {
		for h.index >= len(h.page) {
			if h.eof {
				return h.peekLocalLocked(), nil, 0
			}
			if h.fetching {
				done := h.fetchDone
				h.mu.Unlock()
				select {
				case <-done:
				case <-ctx.Done():
					h.mu.Lock()
					return nil, nil, contextErrno(ctx.Err())
				}
				h.mu.Lock()
				continue
			}
			generation := h.cursorGeneration
			request := &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{
				Handle: cloneBytes(h.token), Cookie: cloneBytes(h.cookie), Verifier: cloneBytes(h.verifier), MaxEntries: 256, WantItems: wantItems,
			}}}
			h.fetching = true
			h.fetchDone = make(chan struct{})
			done := h.fetchDone
			h.mu.Unlock()
			response, errno := h.node.mutate(ctx, request)
			h.mu.Lock()
			h.fetching = false
			h.fetchDone = nil
			close(done)
			if generation != h.cursorGeneration {
				for _, entry := range response.GetReadDir().GetEntries() {
					if item := entry.GetItem(); item != nil {
						h.node.mount.deferReclaim(item.GetToken())
					}
				}
				continue
			}
			if errno != 0 {
				return nil, nil, errno
			}
			page := response.GetReadDir()
			if page == nil || len(page.GetVerifier()) == 0 {
				return nil, nil, syscall.EIO
			}
			identity, ok := publicationIdentityFromItem(h.node.item)
			publication := replyPublicationFromContext(ctx)
			grant, granted := publication.leaseGrant(
				authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ,
				identity, publicationIdentity{}, "", time.Now())
			if !ok || !granted {
				for _, entry := range page.GetEntries() {
					if item := entry.GetItem(); item != nil {
						h.node.mount.deferReclaim(item.GetToken())
					}
				}
				h.node.mount.revoke(errors.New("fusev3: authority returned READDIR without its required enumeration lease"))
				return nil, nil, syscall.ENOTCONN
			}
			h.page, h.index, h.eof = page.GetEntries(), 0, page.GetEof()
			h.pageLease = leaseStamp{epoch: grant.epoch, issuedSequence: grant.issuedSequence}
			h.pageWantItems = wantItems
			h.verifier = cloneBytes(page.GetVerifier())
			if len(h.page) == 0 && !h.eof {
				return nil, nil, syscall.EIO
			}
		}
		entry := h.page[h.index]
		attr := entry.GetAttr()
		if attr == nil {
			return nil, nil, syscall.EIO
		}
		offset, ok := decodeCookie(entry.GetNextCookie())
		if !ok {
			// go-fuse substitutes `lastOffset + 1` for a zero DirEntry.Off, so a
			// short or zero authority cookie would be silently replaced by an
			// offset the authority cannot resume from, turning `ls` on a directory
			// larger than one reply into an infinite loop.
			return nil, nil, syscall.EIO
		}
		if offset&graftDirOffsetBase != 0 {
			// The top bit of the offset space belongs to merged route roots.
			// An authority cookie that carried it would alias onto one of them,
			// so it is refused rather than served as the wrong entry.
			return nil, nil, syscall.EIO
		}
		name := string(entry.GetName())
		if h.shadow != nil && h.shadow(name) {
			// A route rule owns this name unconditionally: the volume's
			// same-named entry is not merged, it is replaced. Advancing here
			// rather than emitting is what makes the name appear exactly once.
			if item := entry.GetItem(); item != nil {
				h.node.mount.deferReclaim(item.GetToken())
				entry.Item = nil
			}
			h.index++
			h.cookie = cloneBytes(entry.GetNextCookie())
			h.next = offset
			continue
		}
		h.pending = &fuse.DirEntry{Name: name, Mode: direntMode(attr.GetKind()), Ino: attr.GetInode(), Off: offset}
		h.pendingDirent = entry
		h.pendingCookie = cloneBytes(entry.GetNextCookie())
		return h.pending, h.pendingDirent, 0
	}
}

// peekLocalLocked returns the next merged route root. They are delivered after
// the volume's own entries because the volume's offsets are the authority's to
// choose and this frontend has nowhere to put an entry in front of them.
func (h *dirHandle) peekLocalLocked() *fuse.DirEntry {
	if h.localIndex >= len(h.local) {
		return nil
	}
	entry := h.local[h.localIndex]
	return &entry
}

// consume accepts the entry last returned by peek. Until it is called the entry
// stays buffered, so an entry that did not fit in a READDIR reply is delivered
// by the next one instead of being silently skipped.
func (h *dirHandle) consume() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == nil {
		if h.localIndex < len(h.local) {
			h.next = h.local[h.localIndex].Off
			h.localIndex++
		}
		return
	}
	h.index++
	h.cookie = h.pendingCookie
	h.next = h.pending.Off
	h.pending, h.pendingDirent, h.pendingCookie = nil, nil, nil
}

func (h *dirHandle) consumePlus() *authoritypb.Item {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == nil || h.pendingDirent == nil {
		return nil
	}
	item := h.pendingDirent.GetItem()
	h.pendingDirent.Item = nil
	h.index++
	h.cookie = h.pendingCookie
	h.next = h.pending.Off
	h.pending, h.pendingDirent, h.pendingCookie = nil, nil, nil
	return item
}

func (h *dirHandle) discardPageItemsLocked() {
	for index := h.index; index < len(h.page); index++ {
		if item := h.page[index].GetItem(); item != nil {
			h.node.mount.deferReclaim(item.GetToken())
			h.page[index].Item = nil
		}
	}
}

func (h *dirHandle) authorityPageExhausted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.index >= len(h.page)
}

func (h *dirHandle) seekdirLocked(off uint64) syscall.Errno {
	if h.enumerationInvalidated {
		if off != 0 {
			// A recalled E(dir) lease leaves this handle's stream state
			// describing no single directory state. Resuming it would return one
			// name twice and lose another, so a resume is refused and only a
			// restart from the beginning is accepted.
			return syscall.ESTALE
		}
		h.discardPageItemsLocked()
		h.page, h.index, h.pending, h.pendingDirent, h.pendingCookie = nil, 0, nil, nil, nil
		h.pageLease = leaseStamp{}
		h.cookie, h.verifier = nil, nil
		h.next, h.localIndex, h.eof = 0, 0, false
		h.enumerationInvalidated = false
		h.cursorGeneration++
	}
	if off == h.next {
		// The kernel is continuing from where this handle stopped. Keeping the
		// buffered page is the whole point of fetching 256 entries at a time.
		return 0
	}
	h.discardPageItemsLocked()
	h.cursorGeneration++
	h.pending, h.pendingDirent, h.pendingCookie = nil, nil, nil
	h.next = off
	if off&graftDirOffsetBase != 0 {
		// The kernel is resuming inside the merged route roots, so the volume's
		// own listing is already finished for this stream.
		index := int(off &^ graftDirOffsetBase)
		if index > len(h.local) {
			return syscall.EINVAL
		}
		h.localIndex = index
		h.page, h.index, h.eof = nil, 0, true
		h.pageLease = leaseStamp{}
		h.cookie, h.verifier = nil, nil
		return 0
	}
	h.localIndex = 0
	h.cookie = encodeCookie(off)
	if off == 0 {
		h.verifier = nil
	}
	h.page, h.index, h.eof = nil, 0, false
	return 0
}

func (h *dirHandle) invalidateEnumeration() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.discardPageItemsLocked()
	h.page, h.index, h.pending, h.pendingDirent, h.pendingCookie = nil, 0, nil, nil, nil
	h.pageLease = leaseStamp{}
	h.cookie, h.verifier = nil, nil
	h.next, h.localIndex, h.eof = 0, 0, false
	h.enumerationInvalidated = true
	h.cursorGeneration++
}

func (h *dirHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	for {
		h.mu.Lock()
		pending := h.plusReply
		if pending == nil {
			errno := h.seekdirLocked(off)
			h.mu.Unlock()
			return errno
		}
		done := pending.done
		h.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return contextErrno(ctx.Err())
		}
	}
}

func (h *dirHandle) beginDirPlus(ctx context.Context, off uint64) (*dirPlusCursorTransaction, syscall.Errno) {
	for {
		h.mu.Lock()
		pending := h.plusReply
		if pending == nil {
			if errno := h.seekdirLocked(off); errno != 0 {
				h.mu.Unlock()
				return nil, errno
			}
			tx := &dirPlusCursorTransaction{handle: h, start: off, done: make(chan struct{})}
			h.plusReply = tx
			h.mu.Unlock()
			return tx, 0
		}
		done := pending.done
		h.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, contextErrno(ctx.Err())
		}
	}
}

func (tx *dirPlusCursorTransaction) finish(commit bool) bool {
	if tx == nil || tx.handle == nil {
		return false
	}
	settled := false
	tx.once.Do(func() {
		h := tx.handle
		h.mu.Lock()
		if h.plusReply == tx {
			if !commit {
				// Force the ordinary seek reset even though the provisional
				// cursor may already equal its starting offset.
				h.next = ^tx.start
				_ = h.seekdirLocked(tx.start)
			}
			h.plusReply = nil
			close(tx.done)
			settled = true
		}
		h.mu.Unlock()
	})
	return settled
}

func (h *dirHandle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	_, errno := h.node.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytes(h.token), DataOnly: flags&fsyncDataOnly != 0}}})
	return errno
}

func (h *dirHandle) close(ctx context.Context) syscall.Errno {
	var errno syscall.Errno
	h.once.Do(func() {
		h.mu.Lock()
		h.discardPageItemsLocked()
		h.mu.Unlock()
		_, errno = h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(h.token)}}})
	})
	return errno
}

func (n *node) Create(ctx context.Context, name string, flags, mode uint32) (*authoritypb.Item, *fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777, Flags: openFlags, Exclusive: flags&uint32(syscall.O_EXCL) != 0}}}
	gate, err := namespaceSourceGate(n.item, name, openFlags.GetTruncate())
	if err != nil {
		return nil, nil, 0, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || created.GetItem().GetAttr() == nil || len(created.GetHandle()) == 0 {
		return nil, nil, 0, syscall.EIO
	}
	item := cloneItem(created.GetItem())
	roles := postStateRoles(response.GetPostState())
	if samePostStateRoles(roles, postStateRoleTarget, postStateRoleParent) {
		targetObject, targetErr := expectedPostStateItem(item, postStateRoleTarget)
		parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
		if targetErr != nil || parentErr != nil || expectPostState(ctx, targetObject, parentObject) != nil {
			return nil, nil, 0, syscall.EIO
		}
	} else {
		createdObject, createdErr := expectedPostStateItem(item, postStateRoleCreated)
		parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
		if createdErr != nil || parentErr != nil || expectPostState(ctx, createdObject, parentObject) != nil {
			return nil, nil, 0, syscall.EIO
		}
	}
	child := &node{mount: n.mount, item: item, requestTimeout: n.requestTimeout, maxRead: n.maxRead, maxWrite: n.maxWrite}
	identity, ok := publicationIdentityFromItem(item)
	dataLease := ok && n.mount.leases.remaining(leaseKey{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: identity,
	}, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, time.Now()) > 0
	kernelFlags := portableOpenFlags(flags, dataLease)
	return item, &fileHandle{node: child, token: cloneBytes(created.GetHandle()), openFlags: flags, buffered: kernelFlags&fuse.FOPEN_DIRECT_IO == 0}, kernelFlags, 0
}

func (n *node) Tmpfile(ctx context.Context, flags, mode uint32) (*authoritypb.Item, *fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 || !openFlags.GetWrite() {
		if errno == 0 {
			errno = syscall.EINVAL
		}
		return nil, nil, 0, errno
	}
	gate, err := itemSourceGate(n.item, false)
	if err != nil {
		return nil, nil, 0, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, &authoritypb.Request{Body: &authoritypb.Request_Tmpfile{Tmpfile: &authoritypb.TmpfileRequest{
		Parent: cloneBytes(n.item.GetToken()), Mode: mode & 0o7777, Flags: openFlags,
		Exclusive: flags&uint32(syscall.O_EXCL) != 0,
	}}}, gate)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	created := response.GetTmpfile()
	if created == nil || created.GetItem() == nil || created.GetItem().GetAttr() == nil || len(created.GetHandle()) == 0 {
		return nil, nil, 0, syscall.EIO
	}
	item := cloneItem(created.GetItem())
	if item.GetAttr().GetKind() != authoritypb.Attr_REGULAR {
		return nil, nil, 0, syscall.EIO
	}
	createdObject, createdErr := expectedPostStateItem(item, postStateRoleCreated)
	parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
	if createdErr != nil || parentErr != nil || expectPostState(ctx, createdObject, parentObject) != nil {
		return nil, nil, 0, syscall.EIO
	}
	child := &node{mount: n.mount, item: item, requestTimeout: n.requestTimeout, maxRead: n.maxRead, maxWrite: n.maxWrite}
	return item, &fileHandle{node: child, token: cloneBytes(created.GetHandle()), openFlags: flags}, portableOpenFlags(flags, false), 0
}

// Mknod exists so that mkfifo(3) and bind(2) on a unix domain socket inside the
// mount fail with an errno that describes reality. Without it the embedded
// default answers ENOSYS, which the kernel reports to userspace as "function
// not implemented" for an operation the caller made correctly.
func (n *node) Mknod(ctx context.Context, name string, mode, rdev uint32) (*authoritypb.Item, syscall.Errno) {
	switch mode & syscall.S_IFMT {
	case 0, syscall.S_IFREG:
		// mknod(2) with no type bits means a regular file.
	case syscall.S_IFIFO, syscall.S_IFSOCK:
		// The authority models a POSIX directory tree of regular files,
		// directories, and symlinks. FIFOs and sockets are not representable.
		return nil, syscall.EOPNOTSUPP
	default:
		// Device nodes require privilege this single-principal mount never has.
		return nil, syscall.EPERM
	}
	if rdev != 0 {
		return nil, syscall.EPERM
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777,
		Flags: &authoritypb.OpenFlags{Write: true}, Exclusive: true,
	}}}
	gate, gateErr := namespaceSourceGate(n.item, name, false)
	if gateErr != nil {
		return nil, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return nil, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || created.GetItem().GetAttr() == nil || len(created.GetHandle()) == 0 {
		return nil, syscall.EIO
	}
	item := cloneItem(created.GetItem())
	createdObject, createdErr := expectedPostStateItem(item, postStateRoleCreated)
	parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
	if createdErr != nil || parentErr != nil || expectPostState(ctx, createdObject, parentObject) != nil {
		return nil, syscall.EIO
	}
	child := &node{mount: n.mount, item: item, requestTimeout: n.requestTimeout, maxRead: n.maxRead, maxWrite: n.maxWrite}
	// mknod(2) does not hand an open file description to the caller, so the one
	// the authority just created is this frontend's to release immediately.
	handle := &fileHandle{node: child, token: cloneBytes(created.GetHandle())}
	if errno := handle.close(ctx, 0, false); errno != 0 {
		n.mount.cleanupFailed("open-file close after mknod", errno)
		return nil, errno
	}
	return item, 0
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32) (*authoritypb.Item, syscall.Errno) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777}}}
	gate, err := namespaceSourceGate(n.item, name, false)
	if err != nil {
		return nil, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
	}
	createdObject, createdErr := expectedPostStateItem(item, postStateRoleCreated)
	parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
	if createdErr != nil || parentErr != nil || expectPostState(ctx, createdObject, parentObject) != nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	request := &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name)}}}
	gate, err := namespaceSourceGate(n.item, name, false)
	if err != nil {
		return syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno == 0 {
		if err := n.completeRemoval(ctx, name, response); err != nil {
			return syscall.EIO
		}
	}
	return errno
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	request := &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Directory: true}}}
	gate, err := namespaceSourceGate(n.item, name, false)
	if err != nil {
		return syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno == 0 {
		if err := n.completeRemoval(ctx, name, response); err != nil {
			return syscall.EIO
		}
	}
	return errno
}

func (n *node) completeRemoval(ctx context.Context, name string, response *authoritypb.Response) error {
	parent, ok := publicationIdentityFromItem(n.item)
	if !ok {
		return errors.New("fusev3: removal source parent has an invalid stable identity")
	}
	removed, err := removedPostStateIdentity(response.GetPostState(), parent)
	if err != nil {
		return err
	}
	namespace := publicationNamespace{parent: parent, name: name}
	lease := sourceLeaseFromContext(ctx)
	if prior, known := lease.preBinding(namespace); known && prior != removed {
		return errors.New("fusev3: removal post-state disagreed with the source mount's cached pre-binding")
	}
	if err := expectPostState(ctx,
		expectedPostStateObject{identity: removed, roles: postStateRoleRemoved},
		expectedPostStateObject{identity: parent, roles: postStateRoleParent},
	); err != nil {
		return err
	}
	// Convert the unresolved namespace wildcard into the exact removed object
	// before the reply can install its final inode attributes. This retains the
	// object coordinate through the post-VFS publication receipt even when the
	// source never cached the name itself.
	return lease.attachBinding(ctx, namespace, removed)
}

func (n *node) Rename(ctx context.Context, name string, parent *node, newName string, flags uint32) (bool, syscall.Errno) {
	if parent == nil || flags&^(renameNoReplace|renameExchange) != 0 || flags == renameNoReplace|renameExchange {
		return false, syscall.EINVAL
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: cloneBytes(n.item.GetToken()), OldName: []byte(name), NewParent: cloneBytes(parent.item.GetToken()), NewName: []byte(newName), NoReplace: flags&renameNoReplace != 0, Exchange: flags&renameExchange != 0}}}
	gate, err := renameSourceGate(n.item, name, parent.item, newName)
	if err != nil {
		return false, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return false, errno
	}
	reply := response.GetRename()
	newPost, valid := publicationIdentityFromBytes(reply.GetNewPostIdentity())
	if !valid {
		return false, syscall.EIO
	}
	var oldPost *publicationIdentity
	if raw := reply.GetOldPostIdentity(); len(raw) != 0 {
		identity, valid := publicationIdentityFromBytes(raw)
		if !valid || flags&renameExchange == 0 && identity != newPost {
			return false, syscall.EIO
		}
		oldPost = &identity
	} else if flags&renameExchange != 0 {
		return false, syscall.EIO
	}
	lease := sourceLeaseFromContext(ctx)
	oldParentIdentity, oldParentValid := publicationIdentityFromItem(n.item)
	newParentIdentity, newParentValid := publicationIdentityFromItem(parent.item)
	if !oldParentValid || !newParentValid {
		return false, syscall.EIO
	}
	oldNamespace := publicationNamespace{parent: oldParentIdentity, name: name}
	newNamespace := publicationNamespace{parent: newParentIdentity, name: newName}
	overwritten, err := renamePostStateOverwrittenIdentity(response.GetPostState(), oldParentIdentity, newParentIdentity, newPost, oldPost, flags&renameExchange != 0)
	if err != nil {
		return false, syscall.EIO
	}
	if moved, known := lease.preBinding(oldNamespace); known && moved != newPost {
		return false, syscall.EIO
	}
	if replaced, known := lease.preBinding(newNamespace); known {
		switch {
		case flags&renameExchange != 0 && (oldPost == nil || replaced != *oldPost):
			return false, syscall.EIO
		case flags&renameExchange == 0 && overwritten != nil && replaced != *overwritten:
			return false, syscall.EIO
		case flags&renameExchange == 0 && overwritten == nil && replaced != newPost:
			return false, syscall.EIO
		}
	}
	expected := []expectedPostStateObject{
		{identity: newPost, roles: postStateRoleSource | postStateRoleDestination},
		{identity: oldParentIdentity, roles: postStateRoleOldParent},
		{identity: newParentIdentity, roles: postStateRoleNewParent},
	}
	if flags&renameExchange != 0 {
		expected[0].roles |= postStateRoleExchanged
		expected = append(expected, expectedPostStateObject{identity: *oldPost, roles: postStateRoleSource | postStateRoleDestination | postStateRoleExchanged})
	} else if overwritten != nil {
		expected = append(expected, expectedPostStateObject{identity: *overwritten, roles: postStateRoleOverwritten})
	}
	if expectPostState(ctx, expected...) != nil {
		return false, syscall.EIO
	}
	if err := lease.attachRename(ctx,
		oldNamespace,
		newNamespace,
		newPost, oldPost,
	); err != nil {
		n.mount.revoke(err)
		return false, syscall.ENOTCONN
	}
	return oldPost != nil, 0
}

func (n *node) Link(ctx context.Context, source *node, name string) (*authoritypb.Item, syscall.Errno) {
	if source == nil {
		return nil, syscall.EXDEV
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: cloneBytes(source.item.GetToken()), NewParent: cloneBytes(n.item.GetToken()), NewName: []byte(name)}}}
	gate, err := namespaceSourceGate(n.item, name, false, source.item)
	if err != nil {
		return nil, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLink().GetItem()
	if item == nil || item.GetAttr() == nil || !bytes.Equal(item.GetToken(), source.item.GetToken()) {
		return nil, syscall.EIO
	}
	linkedObject, linkedErr := expectedPostStateItem(source.item, postStateRoleTarget)
	parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
	if linkedErr != nil || parentErr != nil || expectPostState(ctx, linkedObject, parentObject) != nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Symlink(ctx context.Context, target, name string) (*authoritypb.Item, syscall.Errno) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Target: []byte(target)}}}
	gate, err := namespaceSourceGate(n.item, name, false)
	if err != nil {
		return nil, syscall.EIO
	}
	response, errno := n.mutateWithSource(ctx, request, gate)
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
	}
	createdObject, createdErr := expectedPostStateItem(item, postStateRoleCreated)
	parentObject, parentErr := expectedPostStateItem(n.item, postStateRoleParent)
	if createdErr != nil || parentErr != nil || expectPostState(ctx, createdObject, parentObject) != nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Readlink{Readlink: &authoritypb.ReadlinkRequest{Item: cloneBytes(n.item.GetToken())}}})
	if errno != 0 {
		return nil, errno
	}
	return cloneBytes(response.GetReadlink().GetTarget()), 0
}

func (n *node) Setattr(ctx context.Context, fh *fileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	request := &authoritypb.SetAttrRequest{Item: cloneBytes(n.item.GetToken())}
	if fh != nil {
		request.Handle = cloneBytes(fh.token)
	}
	if value, ok := in.GetMode(); ok {
		request.Mode = &value
	}
	if value, ok := in.GetUID(); ok {
		if value != n.mount.uid {
			return syscall.EPERM
		}
	}
	if value, ok := in.GetGID(); ok {
		if value != n.mount.gid {
			return syscall.EPERM
		}
	}
	if value, ok := in.GetSize(); ok {
		converted := int64(value)
		if converted < 0 {
			return syscall.EFBIG
		}
		request.Size = &converted
	}
	if in.Valid&fuse.FATTR_ATIME_NOW != 0 {
		request.AtimeNow = true
	} else if value, ok := in.GetATime(); ok {
		ns := value.UnixNano()
		request.AtimeNs = &ns
	}
	if in.Valid&fuse.FATTR_MTIME_NOW != 0 {
		request.MtimeNow = true
	} else if value, ok := in.GetMTime(); ok {
		ns := value.UnixNano()
		request.MtimeNs = &ns
	}
	if request.Mode == nil && request.Size == nil && request.AtimeNs == nil && request.MtimeNs == nil && !request.GetAtimeNow() && !request.GetMtimeNow() {
		return n.Getattr(ctx, fh, out)
	}
	gate, err := itemSourceGate(n.item, request.Size != nil)
	if err != nil {
		return syscall.EIO
	}
	wire := &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: request}}
	response, errno := n.mutateWithSource(ctx, wire, gate)
	if errno != 0 {
		return errno
	}
	if err := expectPostStateItem(ctx, n.item, postStateRoleTarget); err != nil {
		return syscall.EIO
	}
	state := response.GetPostState()
	identity := n.item.GetStableIdentity()
	if err := validateMutationPostState(state); err != nil {
		return syscall.EIO
	}
	object := postStateObject(state, identity, postStateRoleTarget)
	if object == nil {
		return syscall.EIO
	}
	fillAttr(object.GetAttr(), &out.Attr, n.mount.uid, n.mount.gid)
	out.SetTimeout(0)
	return 0
}

func (n *node) Getxattr(ctx context.Context, name string, dest []byte) (uint32, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetXattr{GetXattr: &authoritypb.GetXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	if errno != 0 {
		return 0, errno
	}
	value := response.GetGetXattr().GetValue()
	if len(dest) == 0 {
		return uint32(len(value)), 0
	}
	if len(dest) < len(value) {
		return uint32(len(value)), syscall.ERANGE
	}
	copy(dest, value)
	return uint32(len(value)), 0
}

func (n *node) Setxattr(_ context.Context, _ string, _ []byte, flags uint32) syscall.Errno {
	switch flags {
	case 0:
	case unix.XATTR_CREATE:
	case unix.XATTR_REPLACE:
	default:
		return syscall.EINVAL
	}
	// Authority protocol v4 requires user-xattr-readonly at Attach, so every
	// valid set mode has one exact result for the lifetime of this mount. Refuse
	// it before allocating a replay sequence or mutation identity. Linux VFS
	// validates the public name before invoking the FUSE callback; once the
	// callback is reached, the frozen read-only contract takes precedence just
	// as the authority's SetXattr implementation does today.
	return syscall.EOPNOTSUPP
}

func (n *node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_ListXattr{ListXattr: &authoritypb.ListXattrRequest{Item: cloneBytes(n.item.GetToken())}}})
	if errno != 0 {
		return 0, errno
	}
	total := 0
	for _, name := range response.GetListXattr().GetNames() {
		total += len(name) + 1
	}
	if len(dest) == 0 {
		return uint32(total), 0
	}
	if len(dest) < total {
		return uint32(total), syscall.ERANGE
	}
	offset := 0
	for _, name := range response.GetListXattr().GetNames() {
		offset += copy(dest[offset:], name)
		dest[offset] = 0
		offset++
	}
	return uint32(total), 0
}

func (n *node) Removexattr(ctx context.Context, name string) syscall.Errno {
	gate, err := itemSourceGate(n.item, false)
	if err != nil {
		return syscall.EIO
	}
	_, errno := n.mutateWithSource(ctx, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name)}}}, gate)
	if errno == 0 {
		if err := expectPostStateItem(ctx, n.item, postStateRoleTarget); err != nil {
			return syscall.EIO
		}
	}
	return errno
}

func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
	if errno != 0 {
		return errno
	}
	stat := response.GetStatFs()
	if stat == nil {
		return syscall.EIO
	}
	out.Blocks, out.Bfree, out.Bavail = stat.GetBlocks(), stat.GetBlocksFree(), stat.GetBlocksAvailable()
	out.Files, out.Ffree = stat.GetFiles(), stat.GetFilesFree()
	out.Bsize, out.Frsize, out.NameLen = uint32(stat.GetBlockSize()), uint32(stat.GetBlockSize()), stat.GetNameMax()
	return 0
}

func (n *node) Getlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if flags&^uint32(fuse.FUSE_LK_FLOCK) != 0 {
		return syscall.EINVAL
	}
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetLock{GetLock: &authoritypb.GetLockRequest{Lock: lockRequest(n.item.GetToken(), owner, lock, flags)}}})
	if errno != 0 {
		return errno
	}
	reply := response.GetGetLock()
	if reply == nil || !reply.GetConflict() {
		out.Typ = syscall.F_UNLCK
		return 0
	}
	held := reply.GetHeld()
	out.Start, out.End, out.Pid = held.GetRange().GetStart(), held.GetRange().GetEnd(), 0
	out.Typ = syscall.F_RDLCK
	if held.GetWrite() {
		out.Typ = syscall.F_WRLCK
	}
	return 0
}

func (n *node) Setlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setLock(ctx, owner, lock, flags, false)
}

func (n *node) Setlkw(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setLock(ctx, owner, lock, flags, true)
}

func (n *node) setLock(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32, wait bool) syscall.Errno {
	if lock.Typ != syscall.F_RDLCK && lock.Typ != syscall.F_WRLCK && lock.Typ != syscall.F_UNLCK || flags&^uint32(fuse.FUSE_LK_FLOCK) != 0 {
		return syscall.EINVAL
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Lock: lockRequest(n.item.GetToken(), owner, lock, flags), Wait: wait, Unlock: lock.Typ == syscall.F_UNLCK}}}
	if !wait {
		_, errno := n.mutate(ctx, request)
		return errno
	}
	// A blocking lock request has no operation deadline: it is defined to wait
	// for the holder. It still occupies a bulk slot, because it occupies a
	// transport slot for exactly as long.
	if errno := n.mount.acquireBulk(ctx); errno != 0 {
		return errno
	}
	defer n.mount.releaseBulk()
	response, err := n.mount.callMutation(ctx, request, nil)
	return rpcErrno(response, err)
}

func protocolOpenFlags(flags uint32) (*authoritypb.OpenFlags, syscall.Errno) {
	result := &authoritypb.OpenFlags{}
	switch flags & uint32(syscall.O_ACCMODE) {
	case uint32(syscall.O_RDONLY):
		result.Read = true
	case uint32(syscall.O_WRONLY):
		result.Write = true
	case uint32(syscall.O_RDWR):
		result.Read, result.Write = true, true
	default:
		return nil, syscall.EINVAL
	}
	// O_APPEND is meaningful only for a writable description. Every other Linux
	// filesystem accepts and ignores it on a read-only open; forwarding it
	// would make the authority reject a legal open(2) with EINVAL.
	result.Append = result.Write && flags&uint32(syscall.O_APPEND) != 0
	if result.Append {
		// Stock FUSE chooses the append offset and applies RLIMIT before the
		// request reaches userspace, but its WRITE reply can return only a byte
		// count. Relocating at the authority would therefore leave f_pos and
		// i_size describing the stale kernel offset. Refuse the operation until
		// the stock ABI has an exact result-offset mechanism.
		return nil, syscall.EOPNOTSUPP
	}
	result.Truncate = flags&uint32(syscall.O_TRUNC) != 0
	result.Sync = flags&uint32(syscall.O_SYNC) != 0
	result.DataSync = flags&uint32(unix.O_DSYNC) != 0 && !result.Sync
	return result, 0
}

func lockRequest(item []byte, owner uint64, lock *fuse.FileLock, flags uint32) *authoritypb.LockSpec {
	return &authoritypb.LockSpec{Item: cloneBytes(item), Owner: owner, Write: lock.Typ == syscall.F_WRLCK, Range: &authoritypb.LockRange{Start: lock.Start, End: lock.End}, Flock: flags&uint32(fuse.FUSE_LK_FLOCK) != 0}
}

func fillAttr(attr *authoritypb.Attr, out *fuse.Attr, uid, gid uint32) {
	out.Ino = attr.GetInode()
	out.Size = uint64(max(attr.GetSize(), 0))
	out.Blocks = attr.GetBlocks()
	out.Mode = kindMode(attr.GetKind()) | attr.GetMode()
	out.Flags = 0
	out.Nlink = attr.GetNlink()
	out.Uid, out.Gid = uid, gid
	out.Rdev = attr.GetRdev()
	out.Blksize = attr.GetBlksize()
	setTime(attr.GetAtimeNs(), &out.Atime, &out.Atimensec)
	setTime(attr.GetMtimeNs(), &out.Mtime, &out.Mtimensec)
	setTime(attr.GetCtimeNs(), &out.Ctime, &out.Ctimensec)
}

func setTime(ns int64, seconds *uint64, nanos *uint32) {
	if ns < 0 {
		return
	}
	*seconds, *nanos = uint64(ns/1e9), uint32(ns%1e9)
}

// direntMode is the readdir rendering of a kind. Unlike kindMode it passes an
// unspecified kind through as DT_UNKNOWN (mode 0): the authority lists an
// inode it never exposes — a device node or FIFO another writer placed in the
// tree — as an opaque entry, and the application's follow-up stat fails
// exactly as it does on a local directory. Defaulting it to a regular file
// here would invent a type the authority deliberately refused to state.
func direntMode(kind authoritypb.Attr_Kind) uint32 {
	if kind == authoritypb.Attr_KIND_UNSPECIFIED {
		return 0
	}
	return kindMode(kind)
}

func kindMode(kind authoritypb.Attr_Kind) uint32 {
	switch kind {
	case authoritypb.Attr_DIRECTORY:
		return fuse.S_IFDIR
	case authoritypb.Attr_SYMLINK:
		return fuse.S_IFLNK
	default:
		return fuse.S_IFREG
	}
}

func rpcErrno(response *authoritypb.Response, err error) syscall.Errno {
	if err != nil {
		if errno := contextErrno(err); errno != 0 {
			return errno
		}
		if errors.Is(err, authorityrpc.ErrAuthorityChanged) {
			return syscall.ESTALE
		}
		return syscall.EIO
	}
	return responseErrno(response)
}

// contextErrno maps the two ways an operation context can end. Neither is
// EINTR: applications retry EINTR unconditionally, so reporting a request
// timeout that way turns a hung authority into a silent infinite retry loop
// with no error ever reaching the caller. The kernel's INTERRUPT is never wired
// into an operation context (see rawFileSystem.opContext), so a cancellation
// here can only mean the mount itself is going away.
func contextErrno(err error) syscall.Errno {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return syscall.ETIMEDOUT
	case errors.Is(err, context.Canceled):
		return syscall.ENOTCONN
	default:
		return 0
	}
}

func responseErrno(response *authoritypb.Response) syscall.Errno {
	if response == nil || response.GetUncertain() {
		return syscall.EIO
	}
	if response.GetErrno() < 0 {
		return syscall.EIO
	}
	return syscall.Errno(response.GetErrno())
}

func cloneItem(item *authoritypb.Item) *authoritypb.Item {
	if item == nil {
		return nil
	}
	return proto.Clone(item).(*authoritypb.Item)
}

func cloneBytes(value []byte) []byte { return append([]byte(nil), value...) }

func encodeCookie(value uint64) []byte {
	if value == 0 {
		return nil
	}
	return []byte{byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}

// decodeCookie reports whether the authority emitted a resumable cookie. A
// cookie of any width other than eight bytes, or one that decodes to zero, is
// not a position this mount can resume from and must never reach the kernel.
func decodeCookie(value []byte) (uint64, bool) {
	if len(value) != 8 {
		return 0, false
	}
	var result uint64
	for _, part := range value {
		result = result<<8 | uint64(part)
	}
	return result, result != 0
}
