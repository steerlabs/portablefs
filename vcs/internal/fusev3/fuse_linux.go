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

	// coherentOpenFlags is the only OpenOut.OpenFlags value this frontend may
	// ever return. FOPEN_DIRECT_IO is the single load-bearing line of the whole
	// coherence claim: it keeps file data out of this kernel's page cache, and
	// (without CAP_DIRECT_IO_ALLOW_MMAP) it is also what makes the kernel
	// refuse every shared mmap. Adding FOPEN_KEEP_CACHE, or dropping
	// FOPEN_DIRECT_IO, would silently let one machine serve reads that never
	// reached the authority.
	coherentOpenFlags = fuse.FOPEN_DIRECT_IO
)

// RPC is the exact authority contract required by the mount. Keeping this
// interface narrow makes kernel mapping independently fault-testable.
//
// The last five methods are the strict cache contract. An uncached mount never
// calls them, so a transport that only implements the first seven can still
// serve CoherenceUncached, which remains a supported deployment profile.
type RPC interface {
	Root() *authoritypb.Item
	IOLimits() (uint32, uint32)
	SessionLease() time.Duration
	SessionDone() <-chan struct{}
	SessionError() error
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallMutation(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	Close() error

	// SessionID is this mount's authority session identity. It is the only way
	// a frontend can recognise a visibility event it initiated itself, and
	// therefore the only way it can avoid deadlocking against its own syscall.
	SessionID() []byte
	// InitialVisibilityCursor is the cursor the attach reply carried. Starting
	// anywhere else is a protocol violation the authority fences.
	InitialVisibilityCursor() *authoritypb.VisibilityCursor
	NextVisibility(context.Context, *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error)
	AckVisibility(context.Context, *authoritypb.VisibilityCursor) error
	// ReportVisibilityBlocked arms a nonterminal cycle break for the exact kernel
	// parents this frontend both needs to repair and already has a callback parked
	// in. The authority maps them through the pending COMPLETE to stable parent
	// identities and refuses those queued mutations pre-apply; ordinary COMPLETE
	// acknowledgment later removes the scope. Route changes use an empty parent
	// set as the terminal unable-to-serve report.
	ReportVisibilityBlocked(context.Context, *authoritypb.VisibilityCursor, []uint64) error
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
	// Coherence is the kernel-cache contract this mount declares. It must be
	// the same profile the transport attached with, because the authority sized
	// its barrier obligations from that declaration.
	Coherence CoherenceProfile
	// CachedNameCapacity bounds the directory bindings a strict mount may leave
	// resident in its kernel, and therefore also the work self-revocation has
	// to do. Zero selects defaultCachedNameCapacity.
	CachedNameCapacity int
	// RepairBudget is the per-phase deadline a strict mount commits to. Zero
	// selects defaultRepairBudget.
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

	// The strict cache contract. raw is the kernel-facing table that owns the
	// cached-name registry and the publication gate; kernelMount is the
	// installed mount's identity, which is what makes both self-revocation and
	// a mount-absence proof exact rather than path-shaped guesses.
	profile      CoherenceProfile
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
	publications      mutationPublicationLedger

	// grafts serves the machine-local routes, nil when the volume declares
	// none. routesRevision is the declaration this mount attached with, and is
	// what a routes-change event is judged against.
	grafts         *localdirs.Grafts
	backing        string
	routesRevision [32]byte
}

// publishAttr routes one stat answer through the cache contract. A mount with
// no kernel-facing table yet (or an uncached one) publishes no lifetime at all.
func (m *Mount) publishAttr(out *fuse.AttrOut, attr *authoritypb.Attr) {
	if m.raw == nil {
		fillAttr(attr, &out.Attr, m.uid, m.gid)
		out.SetTimeout(0)
		return
	}
	m.raw.publishAttr(out, attr)
}

// MountVolume mounts one authority session without a write-back cache.
//
// File data is never cached: direct I/O keeps every completed read on the wire
// to the one active volume authority, and shared mmap stays unavailable because
// no kernel primitive can revoke a mapped page coherently across machines.
// Names and attributes are a different question, and the answer depends on the
// declared profile. CoherenceUncached publishes nothing with a lifetime and
// owes the authority nothing. CoherenceStrict caches both and pays for them by
// executing the authority's two-phase visibility barrier, so a change made on
// another machine is repaired here before that machine's syscall returns.
func MountVolume(parent context.Context, mountpoint string, rpc RPC, cfg Config) (*Mount, error) {
	if rpc == nil {
		return nil, errors.New("fusev3: authority session is required")
	}
	if mountpoint == "" || !mountid.ValidMountInstance(cfg.MountInstanceID) {
		return nil, errors.Join(errors.New("fusev3: mountpoint and valid unique mount-instance identity are required"), rpc.Close())
	}
	if cfg.Coherence != CoherenceUncached && cfg.Coherence != CoherenceStrict {
		// With no valid profile, the frontend cannot know whether this session
		// joined strict membership. Close it without claiming a clean detach;
		// the authority will retain strict membership if one exists.
		return nil, errors.Join(errors.New("fusev3: unknown coherence profile"), rpc.Close())
	}
	fsName := "portablefs:" + cfg.MountInstanceID
	failBeforeKernelMount := func(cause error) (*Mount, error) {
		if err := releaseUninstalledSession(rpc, cfg.Coherence, fsName, mountpoint); err != nil {
			return nil, errors.Join(cause, err)
		}
		return nil, markCleanStartupFailure(cause)
	}
	if cfg.RequestTimeout <= 0 || cfg.MaxBackground <= 0 || cfg.ReclaimQueue <= 0 || cfg.MaxInFlight < minMaxInFlight {
		return failBeforeKernelMount(fmt.Errorf("fusev3: complete mount configuration is required with at least %d authority in-flight slots", minMaxInFlight))
	}
	if cfg.Coherence == CoherenceStrict && len(rpc.SessionID()) == 0 {
		return failBeforeKernelMount(errors.New("fusev3: strict coherence requires the authority session identity; without it this mount cannot recognise -- and would deadlock against -- its own mutations"))
	}
	rootItem := rpc.Root()
	if rootItem == nil || rootItem.GetAttr() == nil || len(rootItem.GetToken()) == 0 {
		return failBeforeKernelMount(errors.New("fusev3: authority omitted root identity"))
	}
	maxRead, maxWrite := rpc.IOLimits()
	lease := rpc.SessionLease()
	if maxRead == 0 || maxWrite == 0 || lease <= 0 || rpc.SessionDone() == nil {
		return failBeforeKernelMount(errors.New("fusev3: invalid negotiated authority bounds"))
	}
	if maxRead < kernelMinMaxWrite || maxWrite < kernelMinMaxWrite {
		return failBeforeKernelMount(fmt.Errorf("fusev3: authority I/O bounds (read %d, write %d) are below the %d-byte floor the Linux FUSE driver applies to max_write", maxRead, maxWrite, kernelMinMaxWrite))
	}
	options := mountOptions(cfg, maxWrite)
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
	if err := verifyKernelGuarantees(server.KernelSettings(), maxWrite, cfg.Coherence); err != nil {
		return nil, m.abortMount(err)
	}
	return m, nil
}

// releaseUninstalledSession discharges an authority session whose unique FUSE
// source is proven absent before a kernel mount ID could be recorded. Closing
// the connection alone is deliberately insufficient for strict membership:
// without this observation the authority must assume a failed startup may
// still have installed a cache-bearing kernel mount.
func releaseUninstalledSession(rpc RPC, profile CoherenceProfile, fsName, mountpoint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), detachTimeout)
	defer cancel()
	proof, err := observePlannedKernelMountAbsent(fsName, mountpoint)
	if err != nil {
		return errors.Join(fmt.Errorf("fusev3: establish failed-startup mount absence: %w", err), rpc.Close())
	}
	if profile != CoherenceStrict {
		_, _ = rpc.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}}})
		return rpc.Close()
	}
	err = rpc.DetachAfterUnmount(ctx, proof)
	if err != nil {
		err = fmt.Errorf("fusev3: release failed-startup strict session: %w", err)
	}
	return errors.Join(err, rpc.Close())
}

func newMount(parent context.Context, rpc RPC, cfg Config) *Mount {
	ctx, cancel := context.WithCancel(parent)
	workers := reclaimLaneWidth(cfg.MaxInFlight)
	if cfg.CachedNameCapacity <= 0 {
		cfg.CachedNameCapacity = defaultCachedNameCapacity
	}
	if cfg.RepairBudget <= 0 {
		cfg.RepairBudget = defaultRepairBudget
	}
	reserved := livenessReserve
	if cfg.Coherence == CoherenceStrict {
		// The visibility loop owns a transport slot no bulk request can take.
		// Acknowledging is what releases the mutating machine on every other
		// participant in the volume, so starving this lane behind saturated I/O
		// would convert local load into a volume-wide stall.
		reserved += visibilityReserve
	}
	return &Mount{
		rpc: rpc, ctx: ctx, cancel: cancel,
		kernelConnectionDone: make(chan struct{}),
		reclaim:              newReclaimQueue(cfg.ReclaimQueue),
		reclaimWorkers:       workers,
		bulk:                 make(chan struct{}, cfg.MaxInFlight-workers-reserved),
		requestTimeout:       cfg.RequestTimeout,
		uid:                  cfg.PresentedUID,
		gid:                  cfg.PresentedGID,
		profile:              cfg.Coherence,
		nameCapacity:         cfg.CachedNameCapacity,
		repairBudget:         cfg.RepairBudget,
		routesRevision:       cfg.Routes.Revision(),
	}
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
	go m.watchSession(m.ctx, m.rpc.SessionDone())
	for range m.reclaimWorkers {
		go m.reclaimLoop(m.ctx)
	}
	if m.profile != CoherenceStrict {
		return
	}
	m.wg.Add(1)
	go (&coherence{mount: m, session: cloneBytes(m.rpc.SessionID()), budget: m.repairBudget}).run(m.ctx)
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
// MaxReadAhead is deliberately absent: go-fuse only clamps it when nonzero, so
// setting it to 0 would express nothing at all, and read-ahead applies only to
// buffered reads, which FOPEN_DIRECT_IO already excludes.
func mountOptions(cfg Config, maxWrite uint32) *fuse.MountOptions {
	return &fuse.MountOptions{
		FsName:        "portablefs:" + cfg.MountInstanceID,
		Name:          "portablefs",
		MaxWrite:      int(maxWrite),
		MaxBackground: cfg.MaxBackground,
		EnableLocks:   true,
		// READDIRPLUS stays refused. Now that a strict mount does publish
		// nonzero entry lifetimes the old reason no longer holds, but the
		// remaining one is decisive: the authority mints one capability per
		// entry it returns, so serving READDIRPLUS means interning -- and
		// eventually reclaiming -- every name in a directory whether or not
		// anything ever looks at it. `ls` on a large tree would pay for a full
		// LOOKUP-equivalent per entry to populate a cache the caller does not
		// use. Ordinary READDIR plus cached LOOKUPs is strictly less work.
		DisableReadDirPlus: true,
		// Shared mmap over direct I/O is a decision of this mount, not an
		// accident of which capabilities go-fuse happens to forward. The mount
		// cannot revoke kernel-cached pages when another machine mutates the
		// same file, so the capability is disabled for the whole mount even if
		// a future kernel or library change starts offering it by default.
		DisabledCapabilities: fuse.CAP_DIRECT_IO_ALLOW_MMAP,
		Options:              []string{"default_permissions"},
	}
}

// verifyMountDecisions asserts the coherence-critical choices this frontend
// makes about the kernel interface before the mount is installed.
func verifyMountDecisions(options *fuse.MountOptions) error {
	if options.ExtraCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP != 0 ||
		options.DisabledCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP == 0 {
		return errors.New("fusev3: shared mmap over direct I/O must be disabled for the whole mount; cross-machine page coherence cannot be provided")
	}
	if !options.EnableLocks {
		return errors.New("fusev3: file locks must be forwarded to the authority; the local kernel lock manager cannot exclude another machine")
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
func verifyKernelGuarantees(settings *fuse.InitIn, maxWrite uint32, profile CoherenceProfile) error {
	if settings == nil {
		return errors.New("fusev3: kernel INIT settings are unavailable; the mount guarantees cannot be verified")
	}
	granted := settings.Flags64()
	if granted&fuse.CAP_POSIX_LOCKS == 0 || granted&fuse.CAP_FLOCK_LOCKS == 0 {
		return fmt.Errorf("fusev3: kernel does not forward POSIX and BSD file locks (INIT flags %#x); cross-machine lock exclusion is unavailable", granted)
	}
	// A strict mount publishes names and attributes with a lifetime, and the
	// only thing that makes that safe is being able to take them back. Both
	// notifications are protocol 7.12; a kernel that cannot receive them cannot
	// host this profile, and the mount must be refused rather than served with
	// a cache nothing can revoke.
	if profile == CoherenceStrict &&
		(!settings.SupportsNotify(fuse.NOTIFY_INVAL_ENTRY) || !settings.SupportsNotify(fuse.NOTIFY_INVAL_INODE)) {
		return fmt.Errorf("fusev3: kernel FUSE protocol %d.%d cannot receive entry and inode invalidations; strict coherence has no way to revoke what it caches",
			settings.Major, settings.Minor)
	}
	if uint64(maxWrite) > uint64(kernelDefaultMaxPages)*uint64(syscall.Getpagesize()) && granted&fuse.CAP_MAX_PAGES == 0 {
		return fmt.Errorf("fusev3: kernel caps every request at %d pages and cannot carry the negotiated %d-byte write as one request", kernelDefaultMaxPages, maxWrite)
	}
	return nil
}

func (m *Mount) keepAlive(ctx context.Context, lease time.Duration) {
	defer m.wg.Done()
	interval := keepAliveInterval(lease, m.profile, m.repairBudget)
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
// participant whose visibility reply was lost; after that fence, this lane is
// how the frontend learns it must abort even though it never received the
// event that would have started a phase timer. One interval to start a renewal
// plus one interval for its deadline is at most two thirds of RepairBudget.
func keepAliveInterval(lease time.Duration, profile CoherenceProfile, repairBudget time.Duration) time.Duration {
	interval := lease / 3
	if profile == CoherenceStrict {
		if strict := repairBudget / 3; strict < interval {
			interval = strict
		}
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
			err := m.rpc.SessionError()
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
		response, err := m.rpc.CallMutation(callCtx, request)
		cancel()
		if ctx.Err() != nil {
			return
		}
		// A reclaim runs on no raw callback, but it still occupies a replay
		// sequence on its slot, and the publication ledger must see that
		// sequence settle or the slot's watermark stops advancing forever.
		if publicationErr := m.recordMutationResponse(ctx, request, response, err); publicationErr != nil {
			m.revoke(publicationErr)
			return
		}
		if err != nil || responseErrno(response) != 0 {
			if err == nil {
				err = fmt.Errorf("reclaim refused: %w", responseErrno(response))
			}
			m.cleanupFailed("object reclaim", err)
			return
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
	m.failAsync(fmt.Errorf("fusev3: authority refused %s of a frontend-owned resource: %w", operation, err))
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
	m.wg.Wait()
	// Any capability still queued for reclaim is released by Detach: ending the
	// session drops every item and open this session holds.
	detachErr := m.detach()
	m.closeErr = errors.Join(m.fatalError(), detachErr, m.grafts.Close(), m.rpc.Close())
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
	node   *node
	token  []byte
	append bool
	once   sync.Once
}

type dirHandle struct {
	node     *node
	token    []byte
	mu       sync.Mutex
	cookie   []byte
	verifier []byte
	page     []*authoritypb.Dirent
	index    int
	// next is the kernel offset this handle will resume from. A READDIR that
	// asks for exactly this offset continues out of the buffered page instead
	// of discarding it and re-fetching from the authority.
	next uint64
	// pending is the entry produced by peek but not yet accepted by the kernel
	// buffer. Holding it here is what makes the page cache lossless: an entry
	// that does not fit in this READDIR reply is not consumed.
	pending       *fuse.DirEntry
	pendingCookie []byte
	eof           bool
	once          sync.Once

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
	response, err := n.mount.rpc.CallRead(ctx, request)
	return response, rpcErrno(response, err)
}

func (n *node) mutate(parent context.Context, request *authoritypb.Request) (*authoritypb.Response, syscall.Errno) {
	ctx, cancel := n.opContext(parent)
	defer cancel()
	if errno := n.mount.acquireBulk(ctx); errno != 0 {
		return nil, errno
	}
	defer n.mount.releaseBulk()
	response, err := n.mount.rpc.CallMutation(ctx, request)
	if publicationErr := n.mount.recordMutationResponse(parent, request, response, err); publicationErr != nil {
		n.mount.revoke(publicationErr)
		return response, syscall.EIO
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
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
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
	if attr == nil {
		return syscall.EIO
	}
	n.mount.publishAttr(out, attr)
	return 0
}

func (n *node) Open(ctx context.Context, flags uint32) (*fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 {
		return nil, 0, errno
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: openFlags}}})
	if errno != 0 {
		return nil, 0, errno
	}
	if response.GetOpen() == nil || len(response.GetOpen().GetHandle()) == 0 {
		return nil, 0, syscall.EIO
	}
	return &fileHandle{node: n, token: cloneBytes(response.GetOpen().GetHandle()), append: openFlags.GetAppend()}, coherentOpenFlags, 0
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

func (n *node) Write(ctx context.Context, handle *fileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if handle == nil || off < 0 {
		return 0, syscall.EBADF
	}
	if len(data) == 0 {
		return 0, 0
	}
	// MaxWrite is negotiated with the kernel at mount time. Splitting one
	// kernel write here would turn it into multiple independently ordered
	// authority mutations and violate the operation boundary.
	if n.maxWrite == 0 || uint64(len(data)) > uint64(n.maxWrite) {
		return 0, syscall.EIO
	}
	ctx, cancel := n.opContext(ctx)
	defer cancel()
	if errno := n.mount.acquireBulk(ctx); errno != 0 {
		return 0, errno
	}
	defer n.mount.releaseBulk()
	requestOffset := uint64(off)
	if handle.append {
		requestOffset = 0
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: cloneBytes(handle.token), Offset: requestOffset, Data: cloneBytes(data), Append: handle.append}}}
	response, err := n.mount.rpc.CallMutation(ctx, request)
	if publicationErr := n.mount.recordMutationResponse(ctx, request, response, err); publicationErr != nil {
		n.mount.revoke(publicationErr)
		return 0, syscall.EIO
	}
	if err != nil {
		return 0, rpcErrno(response, err)
	}
	errno := responseErrno(response)
	if response == nil || response.GetWrite() == nil {
		if errno != 0 {
			return 0, errno
		}
		return 0, syscall.EIO
	}
	count := response.GetWrite().GetCount()
	if count > uint32(len(data)) {
		return 0, syscall.EIO
	}
	if count > 0 {
		// Linux cannot return both positive progress and errno from write(2).
		// Preserve the committed prefix; a caller may retry the remainder.
		return count, 0
	}
	if errno != 0 {
		return 0, errno
	}
	return 0, syscall.EIO
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
	return &dirHandle{node: n, token: cloneBytes(response.GetOpen().GetHandle())}, 0, 0
}

// peek returns the next directory entry without consuming it, fetching another
// authority page only when the buffered one is exhausted.
func (h *dirHandle) peek(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending != nil {
		return h.pending, 0
	}
	for {
		for h.index >= len(h.page) {
			if h.eof {
				return h.peekLocalLocked(), 0
			}
			response, errno := h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: cloneBytes(h.token), Cookie: cloneBytes(h.cookie), Verifier: cloneBytes(h.verifier), MaxEntries: 256}}})
			if errno != 0 {
				return nil, errno
			}
			page := response.GetReadDir()
			if page == nil || len(page.GetVerifier()) == 0 {
				return nil, syscall.EIO
			}
			h.page, h.index, h.eof = page.GetEntries(), 0, page.GetEof()
			h.verifier = cloneBytes(page.GetVerifier())
			if len(h.page) == 0 && !h.eof {
				return nil, syscall.EIO
			}
		}
		entry := h.page[h.index]
		attr := entry.GetAttr()
		if attr == nil {
			return nil, syscall.EIO
		}
		offset, ok := decodeCookie(entry.GetNextCookie())
		if !ok {
			// go-fuse substitutes `lastOffset + 1` for a zero DirEntry.Off, so a
			// short or zero authority cookie would be silently replaced by an
			// offset the authority cannot resume from, turning `ls` on a directory
			// larger than one reply into an infinite loop.
			return nil, syscall.EIO
		}
		if offset&graftDirOffsetBase != 0 {
			// The top bit of the offset space belongs to merged route roots.
			// An authority cookie that carried it would alias onto one of them,
			// so it is refused rather than served as the wrong entry.
			return nil, syscall.EIO
		}
		name := string(entry.GetName())
		if h.shadow != nil && h.shadow(name) {
			// A route rule owns this name unconditionally: the volume's
			// same-named entry is not merged, it is replaced. Advancing here
			// rather than emitting is what makes the name appear exactly once.
			h.index++
			h.cookie = cloneBytes(entry.GetNextCookie())
			h.next = offset
			continue
		}
		h.pending = &fuse.DirEntry{Name: name, Mode: direntMode(attr.GetKind()), Ino: attr.GetInode(), Off: offset}
		h.pendingCookie = cloneBytes(entry.GetNextCookie())
		return h.pending, 0
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
	h.pending, h.pendingCookie = nil, nil
}

func (h *dirHandle) Seekdir(_ context.Context, off uint64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if off == h.next {
		// The kernel is continuing from where this handle stopped. Keeping the
		// buffered page is the whole point of fetching 256 entries at a time.
		return 0
	}
	h.pending, h.pendingCookie = nil, nil
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

func (h *dirHandle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	_, errno := h.node.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytes(h.token), DataOnly: flags&fsyncDataOnly != 0}}})
	return errno
}

func (h *dirHandle) close(ctx context.Context) syscall.Errno {
	var errno syscall.Errno
	h.once.Do(func() {
		_, errno = h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(h.token)}}})
	})
	return errno
}

func (n *node) Create(ctx context.Context, name string, flags, mode uint32) (*authoritypb.Item, *fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777, Flags: openFlags, Exclusive: flags&uint32(syscall.O_EXCL) != 0}}})
	if errno != 0 {
		return nil, nil, 0, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || created.GetItem().GetAttr() == nil || len(created.GetHandle()) == 0 {
		return nil, nil, 0, syscall.EIO
	}
	item := cloneItem(created.GetItem())
	child := &node{mount: n.mount, item: item, requestTimeout: n.requestTimeout, maxRead: n.maxRead, maxWrite: n.maxWrite}
	return item, &fileHandle{node: child, token: cloneBytes(created.GetHandle()), append: openFlags.GetAppend()}, coherentOpenFlags, 0
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
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777,
		Flags: &authoritypb.OpenFlags{Write: true}, Exclusive: true,
	}}})
	if errno != 0 {
		return nil, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || created.GetItem().GetAttr() == nil || len(created.GetHandle()) == 0 {
		return nil, syscall.EIO
	}
	item := cloneItem(created.GetItem())
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
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	return errno
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Directory: true}}})
	return errno
}

func (n *node) Rename(ctx context.Context, name string, parent *node, newName string, flags uint32) syscall.Errno {
	if parent == nil || flags&^(renameNoReplace|renameExchange) != 0 || flags == renameNoReplace|renameExchange {
		return syscall.EINVAL
	}
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: cloneBytes(n.item.GetToken()), OldName: []byte(name), NewParent: cloneBytes(parent.item.GetToken()), NewName: []byte(newName), NoReplace: flags&renameNoReplace != 0, Exchange: flags&renameExchange != 0}}})
	return errno
}

func (n *node) Link(ctx context.Context, source *node, name string) (*authoritypb.Item, syscall.Errno) {
	if source == nil {
		return nil, syscall.EXDEV
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: cloneBytes(source.item.GetToken()), NewParent: cloneBytes(n.item.GetToken()), NewName: []byte(name)}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLink().GetItem()
	if item == nil || item.GetAttr() == nil || !bytes.Equal(item.GetToken(), source.item.GetToken()) {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Symlink(ctx context.Context, target, name string) (*authoritypb.Item, syscall.Errno) {
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Target: []byte(target)}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
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
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: request}})
	if errno != 0 {
		return errno
	}
	if response.GetPostAttr() == nil {
		return syscall.EIO
	}
	n.mount.publishAttr(out, response.GetPostAttr())
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
	// Authority protocol v3 requires user-xattr-readonly at Attach, so every
	// valid set mode has one exact result for the lifetime of this mount. Refuse
	// it before allocating a replay sequence or visibility ticket. Linux VFS
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
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
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
	response, err := n.mount.rpc.CallMutation(ctx, request)
	if publicationErr := n.mount.recordMutationResponse(ctx, request, response, err); publicationErr != nil {
		n.mount.revoke(publicationErr)
		return syscall.EIO
	}
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
	out.Nlink = attr.GetNlink()
	out.Uid, out.Gid = uid, gid
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
