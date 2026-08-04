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
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
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
type RPC interface {
	Root() *authoritypb.Item
	IOLimits() (uint32, uint32)
	SessionLease() time.Duration
	SessionDone() <-chan struct{}
	SessionError() error
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallMutation(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	Close() error
}

type Config struct {
	FSName         string
	RequestTimeout time.Duration
	MaxBackground  int
	// MaxInFlight must be the same concurrent-call bound the RPC transport was
	// configured with. The frontend subtracts its liveness and cleanup lanes
	// from this number and admits bulk kernel work only against the remainder,
	// which is what makes those two lanes genuinely reserved rather than merely
	// hopeful.
	MaxInFlight  int
	ReclaimQueue int
	PresentedUID uint32
	PresentedGID uint32
}

type Mount struct {
	server         *fuse.Server
	rpc            RPC
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
	closed         bool
	abort          sync.Once
	fatalMu        sync.Mutex
	fatalErr       error
	reclaim        *reclaimQueue
	reclaimWorkers int
	// bulk admits kernel-driven authority calls. Its capacity is strictly less
	// than the transport's own in-flight bound, so a keepalive or a reclaim can
	// never be queued behind saturated bulk I/O.
	bulk           chan struct{}
	requestTimeout time.Duration
	uid            uint32
	gid            uint32
}

// MountVolume mounts one authority session without a write-back cache. Direct
// I/O plus zero attr/entry TTLs is the correctness-first coherence contract:
// every completed read has gone through the one active volume authority.
// Shared mmap is intentionally unavailable because the mount cannot revoke
// kernel-cached pages coherently when another machine mutates the same file.
func MountVolume(parent context.Context, mountpoint string, rpc RPC, cfg Config) (*Mount, error) {
	if mountpoint == "" || rpc == nil || cfg.FSName == "" || cfg.RequestTimeout <= 0 ||
		cfg.MaxBackground <= 0 || cfg.ReclaimQueue <= 0 || cfg.MaxInFlight < minMaxInFlight {
		return nil, fmt.Errorf("fusev3: complete mount configuration is required with at least %d authority in-flight slots", minMaxInFlight)
	}
	rootItem := rpc.Root()
	if rootItem == nil || rootItem.GetAttr() == nil || len(rootItem.GetToken()) == 0 {
		return nil, errors.New("fusev3: authority omitted root identity")
	}
	maxRead, maxWrite := rpc.IOLimits()
	lease := rpc.SessionLease()
	if maxRead == 0 || maxWrite == 0 || lease <= 0 || rpc.SessionDone() == nil {
		return nil, errors.New("fusev3: invalid negotiated authority bounds")
	}
	if maxRead < kernelMinMaxWrite || maxWrite < kernelMinMaxWrite {
		return nil, fmt.Errorf("fusev3: authority I/O bounds (read %d, write %d) are below the %d-byte floor the Linux FUSE driver applies to max_write", maxRead, maxWrite, kernelMinMaxWrite)
	}
	options := mountOptions(cfg, maxWrite)
	if err := verifyMountDecisions(options); err != nil {
		return nil, err
	}
	m := newMount(parent, rpc, cfg)
	root := &node{mount: m, item: cloneItem(rootItem), requestTimeout: cfg.RequestTimeout, maxRead: maxRead, maxWrite: maxWrite}
	server, err := fuse.NewServer(newRawFileSystem(m, root), mountpoint, options)
	if err != nil {
		m.cancel()
		_ = rpc.Close()
		return nil, fmt.Errorf("mount PortableFS v3: %w", err)
	}
	m.server = server
	// Every background goroutine is registered before the request loop can run.
	// A request that fails the mount inside Serve reaches Unmount -> wg.Wait,
	// which must never observe a counter that is still being raised from zero.
	m.start(lease)
	go server.Serve()
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

func newMount(parent context.Context, rpc RPC, cfg Config) *Mount {
	ctx, cancel := context.WithCancel(parent)
	workers := reclaimLaneWidth(cfg.MaxInFlight)
	return &Mount{
		rpc: rpc, ctx: ctx, cancel: cancel,
		reclaim:        newReclaimQueue(cfg.ReclaimQueue),
		reclaimWorkers: workers,
		bulk:           make(chan struct{}, cfg.MaxInFlight-workers-livenessReserve),
		requestTimeout: cfg.RequestTimeout,
		uid:            cfg.PresentedUID,
		gid:            cfg.PresentedGID,
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
}

// abortMount removes a kernel mount that was installed but cannot be served,
// then releases the authority session. It always reports the original cause.
func (m *Mount) abortMount(cause error) error {
	_ = m.server.Unmount()
	m.server.Wait()
	if err := m.Close(); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// mountOptions builds the kernel interface this frontend is willing to speak.
//
// MaxReadAhead is deliberately absent: go-fuse only clamps it when nonzero, so
// setting it to 0 would express nothing at all, and read-ahead applies only to
// buffered reads, which FOPEN_DIRECT_IO already excludes.
func mountOptions(cfg Config, maxWrite uint32) *fuse.MountOptions {
	return &fuse.MountOptions{
		FsName:        cfg.FSName,
		Name:          "portablefs",
		MaxWrite:      int(maxWrite),
		MaxBackground: cfg.MaxBackground,
		EnableLocks:   true,
		// READDIRPLUS is refused rather than merely unimplemented. Its whole
		// value is installing dentries with a nonzero entry timeout; with the
		// zero timeouts this mount's coherence contract requires, every entry
		// it returned would already be expired, so the kernel would re-issue
		// LOOKUP anyway while the authority minted one extra capability per
		// directory entry for this frontend to hand straight back.
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
func verifyKernelGuarantees(settings *fuse.InitIn, maxWrite uint32) error {
	if settings == nil {
		return errors.New("fusev3: kernel INIT settings are unavailable; the mount guarantees cannot be verified")
	}
	granted := settings.Flags64()
	if granted&fuse.CAP_POSIX_LOCKS == 0 || granted&fuse.CAP_FLOCK_LOCKS == 0 {
		return fmt.Errorf("fusev3: kernel does not forward POSIX and BSD file locks (INIT flags %#x); cross-machine lock exclusion is unavailable", granted)
	}
	if uint64(maxWrite) > uint64(kernelDefaultMaxPages)*uint64(syscall.Getpagesize()) && granted&fuse.CAP_MAX_PAGES == 0 {
		return fmt.Errorf("fusev3: kernel caps every request at %d pages and cannot carry the negotiated %d-byte write as one request", kernelDefaultMaxPages, maxWrite)
	}
	return nil
}

func (m *Mount) keepAlive(ctx context.Context, lease time.Duration) {
	defer m.wg.Done()
	interval := lease / 3
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
		response, err := m.rpc.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: token}}})
		cancel()
		if ctx.Err() != nil {
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

func (m *Mount) Wait() { m.server.Wait() }

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
// disappeared (for example, an administrator unmounted it externally).
func (m *Mount) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeLocked()
}

func (m *Mount) closeLocked() error {
	if m.closed {
		return m.fatalError()
	}
	m.closed = true
	m.cancel()
	m.wg.Wait()
	// Any capability still queued for reclaim is released by Detach: ending the
	// session drops every item and open this session holds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = m.rpc.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}}})
	cancel()
	return errors.Join(m.fatalError(), m.rpc.Close())
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
	return response, rpcErrno(response, err)
}

func (n *node) Lookup(ctx context.Context, name string) (*authoritypb.Item, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
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
	fillAttr(attr, &out.Attr, n.mount.uid, n.mount.gid)
	// See fillEntry: a nonzero attribute timeout would let this kernel answer
	// stat(2) from its own page-less attribute cache without the authority.
	out.SetTimeout(0)
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
	response, err := n.mount.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: cloneBytes(handle.token), Offset: requestOffset, Data: cloneBytes(data), Append: handle.append}}})
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
	for h.index >= len(h.page) {
		if h.eof {
			return nil, 0
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
	h.pending = &fuse.DirEntry{Name: string(entry.GetName()), Mode: kindMode(attr.GetKind()), Ino: attr.GetInode(), Off: offset}
	h.pendingCookie = cloneBytes(entry.GetNextCookie())
	return h.pending, 0
}

// consume accepts the entry last returned by peek. Until it is called the entry
// stays buffered, so an entry that did not fit in a READDIR reply is delivered
// by the next one instead of being silently skipped.
func (h *dirHandle) consume() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == nil {
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
	h.next = off
	h.cookie = encodeCookie(off)
	if off == 0 {
		h.verifier = nil
	}
	h.page, h.index, h.eof = nil, 0, false
	h.pending, h.pendingCookie = nil, nil
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
	fillAttr(response.GetPostAttr(), &out.Attr, n.mount.uid, n.mount.gid)
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

func (n *node) Setxattr(ctx context.Context, name string, value []byte, flags uint32) syscall.Errno {
	mode := authoritypb.SetXattrRequest_UPSERT
	switch flags {
	case 0:
	case unix.XATTR_CREATE:
		mode = authoritypb.SetXattrRequest_CREATE
	case unix.XATTR_REPLACE:
		mode = authoritypb.SetXattrRequest_REPLACE
	default:
		return syscall.EINVAL
	}
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name), Value: cloneBytes(value), Mode: mode}}})
	return errno
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
