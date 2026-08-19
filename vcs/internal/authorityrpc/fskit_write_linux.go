//go:build linux

package authorityrpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
)

const (
	fskitWriteReplyBegun     uint32 = 1 << 0
	fskitWriteReplyStaged    uint32 = 1 << 1
	fskitWriteReplyCommitted uint32 = 1 << 2
	fskitWriteReplyAborted   uint32 = 1 << 3
	fskitWriteReplyRejected  uint32 = 1 << 4
	fskitWriteReplyPostApply uint32 = 1 << 5
	fskitWriteReplyRLimit    uint32 = 1 << 6

	// These are the closed Linux FUSE write flag set. WRITE_CACHE is
	// intentionally absent: shared files never enter the stock writeback path.
	fskitWriteLockOwner   uint32 = 1 << 1
	fskitWriteKillSUIDGID uint32 = 1 << 2
)

// FskitWriteStaging creates sealed-size anonymous-memory files. Payload
// bytes therefore never enter the authority namespace, heap, or served XFS,
// and a process crash lets the kernel reclaim every incomplete transaction
// without a recovery scan.
type FskitWriteStaging struct {
	mu             sync.RWMutex
	closed         bool
	newFileForTest func(uint64) (fskitWriteStage, error)
}

type fskitWriteStage interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
}

func OpenFskitWriteStaging(path string) (*FskitWriteStaging, error) {
	// Keep validating the existing authority configuration surface, but do not
	// retain or create anything in this directory. Transaction contents live
	// exclusively in memfd-backed anonymous memory.
	dir, err := privatepath.OpenExistingDir(path)
	if err != nil {
		return nil, fmt.Errorf("open FSKit-write staging directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return nil, fmt.Errorf("close FSKit-write staging directory: %w", err)
	}
	staging := &FskitWriteStaging{}
	probe, err := staging.newFile(1)
	if err != nil {
		_ = staging.Close()
		return nil, fmt.Errorf("qualify memfd write staging: %w", err)
	}
	if err := probe.Close(); err != nil {
		_ = staging.Close()
		return nil, fmt.Errorf("close memfd write-staging probe: %w", err)
	}
	return staging, nil
}

func (s *FskitWriteStaging) newFile(size uint64) (fskitWriteStage, error) {
	if s == nil || size == 0 || size > math.MaxInt64 {
		return nil, syscall.EINVAL
	}
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, syscall.ESTALE
	}
	if hook := s.newFileForTest; hook != nil {
		s.mu.RUnlock()
		return hook(size)
	}
	defer s.mu.RUnlock()
	fd, err := unix.MemfdCreate("portablefs-fskit-write", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "portablefs-fskit-write")
	if file == nil {
		_ = unix.Close(fd)
		return nil, syscall.EIO
	}
	// ftruncate establishes and seals the logical bound without allocating or
	// dirtying served-XFS extents. The session and worker byte reservations are
	// the sole admission bound on resident staged pages. Staging was never
	// fsynced, so anonymous memory does not change write-through acknowledgement
	// or the target descriptor's later fsync durability barrier.
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s *FskitWriteStaging) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return nil
}

type fskitWriteState uint8

const (
	fskitWriteInitializing fskitWriteState = iota + 1
	fskitWriteStaging
	fskitWriteCommitting
	fskitWriteRejected
)

type fskitWriteMetadata struct {
	handle        xfsstore.Capability
	requestedSize uint64
	position      uint64
	rlimitSize    uint64
	fileMaxSize   uint64
	lockOwner     uint64
	writeFlags    uint32
	flags         uint32
	mode          xfsstore.WriteMode
	dataSync      bool
	sync          bool
}

type fskitWrite struct {
	// refs protects stage and target lifetime after the transaction is found in
	// the session ledger. The ledger mutex may add a reference only while the
	// exact pointer is still registered; removal happens under that same mutex,
	// then cleanup waits without holding it. mu serializes all work for one
	// transaction, including INITIALIZING and DATA filesystem I/O. No holder of
	// sessionResources.writeMu may wait for mu.
	mu                sync.Mutex
	refs              sync.WaitGroup
	id                uint64
	metadata          fskitWriteMetadata
	beginFingerprint  volumeserver.RequestFingerprint
	stage             fskitWriteStage
	target            xfsstore.WriteTarget
	coordinate        xfsstore.ObjectCoordinate
	state             fskitWriteState
	staged            uint64
	lastDataOffset    uint64
	lastDataSize      uint32
	lastData          volumeserver.RequestFingerprint
	progressDeadline  time.Time
	absoluteDeadline  time.Time
	initErr           error
	capacityReserved  bool
	commitFingerprint volumeserver.RequestFingerprint
	commitOwner       *fskitWriteCommitOwner
}

type fskitWriteCommitOwner struct{ marker byte }

type fskitWriteTerminalKind uint8

const (
	fskitWriteTerminalAborted fskitWriteTerminalKind = iota + 1
	fskitWriteTerminalCommitted
	fskitWriteTerminalRejected
)

// Only the newest terminal transaction is retained. BEGIN is serialized by
// the frontend and IDs are monotonic, so a legitimate lost response cannot be
// older than the newest dispatched BEGIN. Retaining one exact tombstone keeps
// cleanup bounded while altered or late reuse still fails closed.
type fskitWriteTerminal struct {
	id                uint64
	beginFingerprint  volumeserver.RequestFingerprint
	commitFingerprint volumeserver.RequestFingerprint
	metadata          fskitWriteMetadata
	staged            uint64
	kind              fskitWriteTerminalKind
	err               error
}

type fskitWriteCapacityWaiter struct {
	resources *sessionResources
	ready     chan struct{}
	previous  *fskitWriteCapacityWaiter
	next      *fskitWriteCapacityWaiter
	queued    bool
}

type fskitWriteCleanup struct {
	handler     *VolumeHandler
	resources   *sessionResources
	transaction *fskitWrite
}

func (c fskitWriteCleanup) finish() {
	if c.transaction == nil {
		return
	}
	// Removal prevents new refs before this wait begins. Existing phase work
	// drains here without holding the session ledger lock, so unrelated
	// transactions continue immediately and neither Close nor capacity reuse can
	// race a WriteAt/Pin/initialization still using these objects.
	c.transaction.refs.Wait()
	c.transaction.mu.Lock()
	stage, target := c.transaction.stage, c.transaction.target
	staged := c.transaction.staged
	c.transaction.stage, c.transaction.target = nil, nil
	c.transaction.mu.Unlock()
	if staged != 0 && c.handler != nil && c.handler.Metrics != nil {
		c.handler.Metrics.WriteStagedBytes(-int64(staged))
	}
	if stage != nil {
		_ = stage.Close()
	}
	if target != nil {
		_ = target.Close()
	}
	if c.handler != nil && c.resources != nil && c.transaction.capacityReserved {
		c.handler.releaseFskitWriteCapacity(c.resources, c.transaction.metadata.requestedSize)
	}
}

func fskitWriteMetadataFromRequest(request *authoritypb.FskitWriteRequest) (fskitWriteMetadata, error) {
	if request == nil || request.GetTransactionId() == 0 {
		return fskitWriteMetadata{}, syscall.EINVAL
	}
	return writeMetadataFromGeometry(request.GetHandle(), request.GetRequestedSize(), request.GetPosition(),
		request.GetRlimitFsize(), request.GetFileMaxSize(), request.GetLockOwner(), request.GetWriteFlags(), request.GetFlags())
}

func writeMetadataFromGeometry(handle []byte, requestedSize, position, rlimitSize, fileMaxSize, lockOwner uint64, writeFlags, flags uint32) (fskitWriteMetadata, error) {
	var metadata fskitWriteMetadata
	if len(handle) != len(metadata.handle) || requestedSize == 0 || requestedSize > math.MaxInt64 ||
		fileMaxSize == 0 || fileMaxSize > math.MaxInt64 {
		return metadata, syscall.EINVAL
	}
	copy(metadata.handle[:], handle)
	if metadata.handle == (xfsstore.Capability{}) {
		return metadata, syscall.EINVAL
	}
	metadata.requestedSize = requestedSize
	metadata.position = position
	metadata.rlimitSize = rlimitSize
	metadata.fileMaxSize = fileMaxSize
	metadata.lockOwner = lockOwner
	metadata.writeFlags = writeFlags
	metadata.flags = flags

	allowedWriteFlags := uint32(fskitWriteLockOwner | fskitWriteKillSUIDGID)
	if metadata.writeFlags&^allowedWriteFlags != 0 || metadata.writeFlags&fskitWriteLockOwner == 0 && metadata.lockOwner != 0 {
		return fskitWriteMetadata{}, syscall.EINVAL
	}
	allowedFileFlags := uint32(syscall.O_APPEND | syscall.O_DSYNC | syscall.O_SYNC)
	if metadata.flags&^allowedFileFlags != 0 {
		return fskitWriteMetadata{}, syscall.EINVAL
	}
	fullSyncBit := uint32(syscall.O_SYNC &^ syscall.O_DSYNC)
	if metadata.flags&fullSyncBit != 0 && metadata.flags&uint32(syscall.O_DSYNC) == 0 {
		return fskitWriteMetadata{}, syscall.EINVAL
	}
	metadata.sync = metadata.flags&fullSyncBit != 0
	metadata.dataSync = !metadata.sync && metadata.flags&uint32(syscall.O_DSYNC) != 0
	if metadata.flags&uint32(syscall.O_APPEND) != 0 {
		if metadata.position != 0 {
			return fskitWriteMetadata{}, syscall.EINVAL
		}
		metadata.mode = xfsstore.WriteAppend
	} else {
		if metadata.position > math.MaxInt64 {
			return fskitWriteMetadata{}, syscall.EINVAL
		}
		metadata.mode = xfsstore.WritePositioned
	}
	return metadata, nil
}

func validFskitWritePhaseShape(request *authoritypb.Request, body *authoritypb.FskitWriteRequest) bool {
	if request == nil || body == nil {
		return false
	}
	switch body.GetPhase() {
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN:
		return request.GetMutation() == nil && request.GetFskitSourcePublication() == nil &&
			body.GetFragmentOffset() == 0 && body.GetSize() == 0 && len(body.GetData()) == 0
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA:
		return request.GetMutation() == nil && request.GetFskitSourcePublication() == nil && body.GetSize() != 0 &&
			uint32(len(body.GetData())) == body.GetSize() && body.GetFragmentOffset() < body.GetRequestedSize() &&
			uint64(body.GetSize()) <= body.GetRequestedSize()-body.GetFragmentOffset()
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT:
		return request.GetMutation() != nil && request.GetFskitSourcePublication() != nil &&
			body.GetFragmentOffset() != 0 && body.GetFragmentOffset() <= body.GetRequestedSize() &&
			body.GetSize() == 0 && len(body.GetData()) == 0
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT:
		return request.GetMutation() == nil && request.GetFskitSourcePublication() == nil &&
			body.GetFragmentOffset() == 0 && body.GetSize() == 0 && len(body.GetData()) == 0
	default:
		return false
	}
}

func fskitWriteReply(transactionID uint64, flags uint32) *authoritypb.Response {
	return &authoritypb.Response{Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
		TransactionId: transactionID, Flags: flags,
	}}}
}

func fskitWriteFingerprint(h *VolumeHandler, request *authoritypb.Request) (volumeserver.RequestFingerprint, error) {
	return fskitWriteFingerprintContext(context.Background(), h, request)
}

func fskitWriteFingerprintContext(ctx context.Context, h *VolumeHandler, request *authoritypb.Request) (volumeserver.RequestFingerprint, error) {
	if h == nil || h.Runtime == nil {
		return volumeserver.RequestFingerprint{}, syscall.EIO
	}
	if body := request.GetFskitWrite(); body != nil && body.GetPhase() == authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA {
		if digest, ok := framePayloadDigest(ctx, request); ok {
			return canonicalFingerprintWithWriteDataDigest(h.Runtime, request, digest)
		}
		// DATA replay identity is epoch-local and never persisted. Hash the bulk
		// body once, then feed its fixed digest into the keyed canonical request
		// fingerprint so later canonical traversal never walks the payload again.
		// SHA-256 still covers every payload byte; the keyed fingerprint covers
		// the digest and every canonical metadata field.
		digest := sha256.Sum256(body.GetData())
		return canonicalFingerprintWithWriteDataDigest(h.Runtime, request, digest)
	}
	return canonicalFingerprint(h.Runtime, request)
}

func sameFskitWriteMetadata(left, right fskitWriteMetadata) bool { return left == right }

func fskitWriteRejection(errno int32, transactionID uint64, rlimit bool) *authoritypb.Response {
	if errno <= 0 || errno > 4095 {
		errno = int32(syscall.EIO)
	}
	flags := fskitWriteReplyRejected
	if rlimit {
		flags = fskitWriteReplyRLimit
	}
	return &authoritypb.Response{Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
		TransactionId: transactionID, Flags: flags, Error: -errno,
	}}}
}

func fskitWriteCommitReply(transactionID, committed, assigned, post, sequence uint64, postAttr xfsstore.Attr, err error) *authoritypb.Response {
	flags := fskitWriteReplyCommitted
	wireError := int32(0)
	if err != nil && errors.Is(err, xfsstore.ErrWritePostApply) {
		flags |= fskitWriteReplyPostApply
		wireError = -wireErrno(err)
		if wireError >= 0 {
			wireError = -int32(syscall.EIO)
		}
	}
	return &authoritypb.Response{
		Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
			TransactionId: transactionID, CommittedSize: committed, AssignedOffset: assigned,
			PostSize: post, VisibilitySequence: sequence, Flags: flags, Error: wireError,
		}},
	}
}

func fskitWriteResponseWithEnvelope(h *VolumeHandler, requestID uint64, response *authoritypb.Response) *authoritypb.Response {
	if response == nil {
		return h.errorResponse(requestID, syscall.EIO, true)
	}
	response.RequestId = requestID
	response.Epoch = h.Epoch()
	return response
}

func (h *VolumeHandler) fskitWriteResources(id volumeserver.SessionID) (*sessionResources, error) {
	resources, err := h.sessionResources(id)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (h *VolumeHandler) fskitWriteCapacityAvailableLocked(resources *sessionResources, bytes uint64) bool {
	return bytes <= h.MaxFskitWriteStagingBytesPerSession && bytes <= h.MaxFskitWriteStagingBytes &&
		resources.fskitWriteReservedBytes <= h.MaxFskitWriteStagingBytesPerSession-bytes &&
		h.totalFskitWriteStagingBytes <= h.MaxFskitWriteStagingBytes-bytes &&
		resources.fskitWriteCount < h.MaxFskitWritesPerSession &&
		h.totalFskitWrites < h.MaxFskitWrites
}

func (h *VolumeHandler) enqueueFskitWriteCapacityLocked(waiter *fskitWriteCapacityWaiter) {
	if waiter.queued {
		return
	}
	waiter.previous = h.fskitWriteCapacityTail
	waiter.next = nil
	if h.fskitWriteCapacityTail == nil {
		h.fskitWriteCapacityHead = waiter
	} else {
		h.fskitWriteCapacityTail.next = waiter
	}
	h.fskitWriteCapacityTail = waiter
	waiter.queued = true
}

func (h *VolumeHandler) removeFskitWriteCapacityLocked(waiter *fskitWriteCapacityWaiter) {
	if !waiter.queued {
		return
	}
	if waiter.previous == nil {
		h.fskitWriteCapacityHead = waiter.next
	} else {
		waiter.previous.next = waiter.next
	}
	if waiter.next == nil {
		h.fskitWriteCapacityTail = waiter.previous
	} else {
		waiter.next.previous = waiter.previous
	}
	waiter.previous, waiter.next, waiter.queued = nil, nil, false
}

func wakeFskitWriteCapacityWaiterLocked(waiter *fskitWriteCapacityWaiter) {
	if waiter == nil {
		return
	}
	ready := waiter.ready
	waiter.ready = make(chan struct{})
	close(ready)
}

func (h *VolumeHandler) reserveFskitWriteCapacity(ctx context.Context, terminal <-chan struct{}, resources *sessionResources, bytes uint64) error {
	waiter := &fskitWriteCapacityWaiter{resources: resources, ready: make(chan struct{})}
	waiting := false
	var waitStarted time.Time
	for {
		h.fskitWriteCapacityMu.Lock()
		if resources.fskitWriteCapacityEnded {
			h.removeFskitWriteCapacityLocked(waiter)
			wakeFskitWriteCapacityWaiterLocked(h.fskitWriteCapacityHead)
			h.fskitWriteCapacityMu.Unlock()
			if waiting && h.Metrics != nil {
				h.Metrics.WriteAdmissionFinished(time.Since(waitStarted))
			}
			return volumeserver.ErrSessionExpired
		}
		h.enqueueFskitWriteCapacityLocked(waiter)
		if h.fskitWriteCapacityHead == waiter && h.fskitWriteCapacityAvailableLocked(resources, bytes) {
			h.removeFskitWriteCapacityLocked(waiter)
			resources.fskitWriteReservedBytes += bytes
			resources.fskitWriteCount++
			h.totalFskitWriteStagingBytes += bytes
			h.totalFskitWrites++
			wakeFskitWriteCapacityWaiterLocked(h.fskitWriteCapacityHead)
			h.fskitWriteCapacityMu.Unlock()
			if h.Metrics != nil {
				h.Metrics.WriteTransactionAdmitted()
				if waiting {
					h.Metrics.WriteAdmissionFinished(time.Since(waitStarted))
				}
			}
			return nil
		}
		if !waiting {
			waiting = true
			waitStarted = time.Now()
			if h.Metrics != nil {
				h.Metrics.WriteAdmissionBlocked()
			}
		}
		ready := waiter.ready
		h.fskitWriteCapacityMu.Unlock()

		select {
		case <-ready:
			continue
		case <-terminal:
			h.fskitWriteCapacityMu.Lock()
			h.removeFskitWriteCapacityLocked(waiter)
			wakeFskitWriteCapacityWaiterLocked(h.fskitWriteCapacityHead)
			h.fskitWriteCapacityMu.Unlock()
			if h.Metrics != nil {
				h.Metrics.WriteAdmissionFinished(time.Since(waitStarted))
			}
			return volumeserver.ErrSessionExpired
		case <-ctx.Done():
			h.fskitWriteCapacityMu.Lock()
			h.removeFskitWriteCapacityLocked(waiter)
			wakeFskitWriteCapacityWaiterLocked(h.fskitWriteCapacityHead)
			ended := resources.fskitWriteCapacityEnded
			h.fskitWriteCapacityMu.Unlock()
			if h.Metrics != nil {
				h.Metrics.WriteAdmissionFinished(time.Since(waitStarted))
			}
			if ended {
				return volumeserver.ErrSessionExpired
			}
			return ctx.Err()
		}
	}
}

func (h *VolumeHandler) releaseFskitWriteCapacity(resources *sessionResources, bytes uint64) {
	h.fskitWriteCapacityMu.Lock()
	defer h.fskitWriteCapacityMu.Unlock()
	if bytes > resources.fskitWriteReservedBytes || bytes > h.totalFskitWriteStagingBytes ||
		resources.fskitWriteCount == 0 || h.totalFskitWrites == 0 {
		panic("authorityrpc: FSKit write capacity accounting underflow")
	}
	resources.fskitWriteReservedBytes -= bytes
	resources.fskitWriteCount--
	h.totalFskitWriteStagingBytes -= bytes
	h.totalFskitWrites--
	if h.Metrics != nil {
		h.Metrics.WriteTransactionReleased()
	}
	wakeFskitWriteCapacityWaiterLocked(h.fskitWriteCapacityHead)
}

func (h *VolumeHandler) endFskitWriteCapacityWaits(resources *sessionResources) {
	h.fskitWriteCapacityMu.Lock()
	resources.fskitWriteCapacityEnded = true
	for waiter := h.fskitWriteCapacityHead; waiter != nil; waiter = waiter.next {
		if waiter.resources == resources {
			wakeFskitWriteCapacityWaiterLocked(waiter)
		}
	}
	h.fskitWriteCapacityMu.Unlock()
}

// acquireFskitWrite pins the exact registered object without ever
// waiting on transaction.mu while holding the session ledger. WaitGroup.Add is
// ordered before removal by writeMu; once removal wins, no future Add can race
// cleanup's Wait.
func acquireFskitWrite(resources *sessionResources, id uint64) *fskitWrite {
	resources.fskitWriteMu.Lock()
	transaction := resources.fskitWrites[id]
	if transaction != nil {
		transaction.refs.Add(1)
	}
	resources.fskitWriteMu.Unlock()
	return transaction
}

func fskitWriteRegistered(resources *sessionResources, transaction *fskitWrite) bool {
	resources.fskitWriteMu.Lock()
	registered := resources.fskitWrites[transaction.id] == transaction
	resources.fskitWriteMu.Unlock()
	return registered
}

// removeFskitWriteLocked transfers cleanup ownership but performs no
// waiting, Close, or capacity release under writeMu. Callers must already have
// made the transaction terminal while holding transaction.mu.
func (h *VolumeHandler) removeFskitWriteLocked(resources *sessionResources, transaction *fskitWrite, terminal fskitWriteTerminalKind, terminalErr error) fskitWriteCleanup {
	if resources.fskitWrites[transaction.id] != transaction {
		return fskitWriteCleanup{}
	}
	delete(resources.fskitWrites, transaction.id)
	resources.fskitWriteTerminal = &fskitWriteTerminal{
		id: transaction.id, beginFingerprint: transaction.beginFingerprint, commitFingerprint: transaction.commitFingerprint,
		metadata: transaction.metadata, staged: transaction.staged, kind: terminal, err: terminalErr,
	}
	return fskitWriteCleanup{handler: h, resources: resources, transaction: transaction}
}

func (h *VolumeHandler) fenceFskitWriteMismatch(id volumeserver.SessionID) error {
	if h.Runtime != nil {
		h.Runtime.FenceSession(id)
	}
	if h.Metrics != nil {
		h.Metrics.Fence(authoritymetrics.FenceFskitWriteMismatch)
	}
	volume := ""
	if h.Runtime != nil {
		volume = h.Runtime.VolumeID()
	}
	log.Printf("portablefs-authority: event=fence volume=%q session=%x reason=fskit_write_mismatch", volume, id)
	return volumeserver.ErrRequestMismatch
}

func (h *VolumeHandler) beginFskitWrite(request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	return h.beginFskitWriteContext(context.Background(), request, credential, body)
}

func (h *VolumeHandler) beginFskitWriteContext(ctx context.Context, request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	metadata, err := fskitWriteMetadataFromRequest(body)
	if err != nil || !validFskitWritePhaseShape(request, body) || body.GetRequestedSize() > h.MaxFskitWriteBytes {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	fingerprint, err := fskitWriteFingerprint(h, request)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	resources, err := h.fskitWriteResources(credential.ID)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	resources.fskitWriteMu.Lock()
	if resources.fskitWrites == nil {
		resources.fskitWrites = make(map[uint64]*fskitWrite)
	}
	if existing := resources.fskitWrites[body.GetTransactionId()]; existing != nil {
		if existing.beginFingerprint != fingerprint || !sameFskitWriteMetadata(existing.metadata, metadata) {
			resources.fskitWriteMu.Unlock()
			return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
		}
		existing.refs.Add(1)
		resources.fskitWriteMu.Unlock()
		// INITIALIZING owns this mutex across allocation and target pinning. An
		// exact retry waits for that one attempt instead of duplicating either
		// resource, while every other transaction remains independent.
		existing.mu.Lock()
		var response *authoritypb.Response
		switch existing.state {
		case fskitWriteStaging, fskitWriteCommitting:
			if fskitWriteRegistered(resources, existing) {
				response = fskitWriteReply(body.GetTransactionId(), fskitWriteReplyBegun)
			}
		case fskitWriteRejected:
			if existing.initErr != nil {
				response = h.errorResponse(request.GetRequestId(), existing.initErr, false)
			}
		}
		existing.mu.Unlock()
		existing.refs.Done()
		if response == nil {
			// Removal may have won after this retry acquired its lifetime ref but
			// before it acquired transaction.mu. Preserve the same exact terminal
			// result a retry arriving one instruction later would observe.
			resources.fskitWriteMu.Lock()
			terminal := resources.fskitWriteTerminal
			if terminal != nil && terminal.id == body.GetTransactionId() && terminal.beginFingerprint == fingerprint &&
				sameFskitWriteMetadata(terminal.metadata, metadata) {
				switch terminal.kind {
				case fskitWriteTerminalAborted:
					response = fskitWriteReply(body.GetTransactionId(), fskitWriteReplyAborted)
				case fskitWriteTerminalRejected:
					if terminal.err != nil {
						response = h.errorResponse(request.GetRequestId(), terminal.err, false)
					}
				}
			}
			resources.fskitWriteMu.Unlock()
		}
		if response == nil {
			return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
		}
		if response.GetRequestId() != request.GetRequestId() {
			response = fskitWriteResponseWithEnvelope(h, request.GetRequestId(), response)
		}
		return response
	}
	if terminal := resources.fskitWriteTerminal; terminal != nil && terminal.id == body.GetTransactionId() {
		if terminal.beginFingerprint != fingerprint || !sameFskitWriteMetadata(terminal.metadata, metadata) {
			resources.fskitWriteMu.Unlock()
			return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
		}
		resources.fskitWriteMu.Unlock()
		switch terminal.kind {
		case fskitWriteTerminalAborted:
			return fskitWriteResponseWithEnvelope(h, request.GetRequestId(), fskitWriteReply(body.GetTransactionId(), fskitWriteReplyAborted))
		case fskitWriteTerminalRejected:
			if terminal.err == nil {
				return h.errorResponse(request.GetRequestId(), syscall.EIO, false)
			}
			return h.errorResponse(request.GetRequestId(), terminal.err, false)
		default:
			return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
		}
	}
	if body.GetTransactionId() != resources.fskitWriteHighWater+1 {
		resources.fskitWriteMu.Unlock()
		return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
	}
	// A syntactically valid exact next BEGIN consumes its monotonic identity
	// before waiting for resources. Its published INITIALIZING placeholder makes
	// exact retries join this attempt without allowing a later transaction to
	// reuse its number.
	resources.fskitWriteHighWater = body.GetTransactionId()
	now := time.Now()
	absoluteDeadline := now.Add(h.FskitWriteAbsoluteTimeout)
	progressDeadline := now.Add(h.FskitWriteProgressTimeout)
	if progressDeadline.After(absoluteDeadline) {
		progressDeadline = absoluteDeadline
	}
	transaction := &fskitWrite{
		id: body.GetTransactionId(), metadata: metadata, beginFingerprint: fingerprint,
		state: fskitWriteInitializing, progressDeadline: progressDeadline, absoluteDeadline: absoluteDeadline,
	}
	// Lock before publishing the placeholder so no retry can observe a partial
	// stage/target pair. The initial attempt itself is the first lifetime ref.
	transaction.mu.Lock()
	transaction.refs.Add(1)
	resources.fskitWrites[transaction.id] = transaction
	resources.fskitWriteTerminal = nil
	resources.fskitWriteMu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	terminal, initErr := h.Runtime.SessionTerminal(credential.ID)
	admissionCtx, cancelAdmission := context.WithDeadline(ctx, transaction.progressDeadline)
	if initErr == nil {
		initErr = h.reserveFskitWriteCapacity(admissionCtx, terminal, resources, metadata.requestedSize)
		transaction.capacityReserved = initErr == nil
	}
	cancelAdmission()
	if initErr == nil && !fskitWriteRegistered(resources, transaction) {
		initErr = volumeserver.ErrSessionExpired
	}
	var stage fskitWriteStage
	if initErr == nil {
		stage, initErr = h.FskitWriteStaging.newFile(metadata.requestedSize)
	}
	transaction.stage = stage
	if initErr == nil {
		store, ok := h.Store.(writeStore)
		if !ok {
			initErr = syscall.EOPNOTSUPP
		} else {
			transaction.target, initErr = store.PinWriteTarget(metadata.handle)
		}
	}
	if initErr == nil {
		transaction.coordinate = transaction.target.Coordinate()
		if transaction.coordinate.Stable == ([16]byte{}) || transaction.coordinate.Ino == 0 {
			initErr = syscall.EIO
		}
	}

	var cleanup fskitWriteCleanup
	if initErr != nil {
		transaction.state = fskitWriteRejected
		transaction.initErr = initErr
		resources.fskitWriteMu.Lock()
		cleanup = h.removeFskitWriteLocked(resources, transaction, fskitWriteTerminalRejected, initErr)
		resources.fskitWriteMu.Unlock()
	} else {
		now := time.Now()
		transaction.state = fskitWriteStaging
		transaction.progressDeadline = now.Add(h.FskitWriteProgressTimeout)
		if transaction.progressDeadline.After(transaction.absoluteDeadline) {
			transaction.progressDeadline = transaction.absoluteDeadline
		}
	}
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	if initErr != nil {
		return h.errorResponse(request.GetRequestId(), initErr, false)
	}
	if !fskitWriteRegistered(resources, transaction) {
		return h.errorResponse(request.GetRequestId(), volumeserver.ErrSessionExpired, false)
	}
	return fskitWriteResponseWithEnvelope(h, request.GetRequestId(), fskitWriteReply(transaction.id, fskitWriteReplyBegun))
}

func (h *VolumeHandler) fskitWriteForPhase(request *authoritypb.Request, body *authoritypb.FskitWriteRequest) (fskitWriteMetadata, volumeserver.RequestFingerprint, error) {
	return h.fskitWriteForPhaseContext(context.Background(), request, body)
}

func (h *VolumeHandler) fskitWriteForPhaseContext(ctx context.Context, request *authoritypb.Request, body *authoritypb.FskitWriteRequest) (fskitWriteMetadata, volumeserver.RequestFingerprint, error) {
	metadata, err := fskitWriteMetadataFromRequest(body)
	if err != nil || !validFskitWritePhaseShape(request, body) || body.GetRequestedSize() > h.MaxFskitWriteBytes {
		return fskitWriteMetadata{}, volumeserver.RequestFingerprint{}, syscall.EINVAL
	}
	fingerprint, err := fskitWriteFingerprintContext(ctx, h, request)
	if err != nil {
		return fskitWriteMetadata{}, volumeserver.RequestFingerprint{}, syscall.EINVAL
	}
	return metadata, fingerprint, nil
}

func (h *VolumeHandler) stageFskitWrite(request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	return h.stageFskitWriteContext(context.Background(), request, credential, body)
}

func (h *VolumeHandler) stageFskitWriteContext(ctx context.Context, request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	if body.GetSize() > h.MaxWrite {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	resources, err := h.fskitWriteResources(credential.ID)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	metadata, fingerprint, err := h.fskitWriteForPhaseContext(ctx, request, body)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
	}
	transaction.mu.Lock()
	var cleanup fskitWriteCleanup
	var response *authoritypb.Response
	var phaseErr error
	if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteStaging {
		phaseErr = h.fenceFskitWriteMismatch(credential.ID)
	} else if body.GetFragmentOffset() < transaction.staged {
		if body.GetFragmentOffset() != transaction.lastDataOffset || body.GetSize() != transaction.lastDataSize || transaction.lastData != fingerprint {
			phaseErr = h.fenceFskitWriteMismatch(credential.ID)
		} else {
			response = fskitWriteReply(transaction.id, fskitWriteReplyStaged)
		}
	} else if body.GetFragmentOffset() != transaction.staged {
		phaseErr = h.fenceFskitWriteMismatch(credential.ID)
	} else {
		n, writeErr := transaction.stage.WriteAt(body.GetData(), int64(transaction.staged))
		if writeErr != nil || n != len(body.GetData()) {
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			transaction.state = fskitWriteRejected
			transaction.initErr = writeErr
			resources.fskitWriteMu.Lock()
			cleanup = h.removeFskitWriteLocked(resources, transaction, fskitWriteTerminalRejected, writeErr)
			resources.fskitWriteMu.Unlock()
			phaseErr = writeErr
		} else {
			transaction.lastDataOffset = transaction.staged
			transaction.lastDataSize = body.GetSize()
			transaction.lastData = fingerprint
			transaction.staged += uint64(body.GetSize())
			if h.Metrics != nil {
				h.Metrics.WriteStagedBytes(int64(body.GetSize()))
			}
			now := time.Now()
			progress := now.Add(h.FskitWriteProgressTimeout)
			if progress.After(transaction.absoluteDeadline) {
				progress = transaction.absoluteDeadline
			}
			transaction.progressDeadline = progress
			response = fskitWriteReply(transaction.id, fskitWriteReplyStaged)
		}
	}
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	if phaseErr != nil {
		return h.errorResponse(request.GetRequestId(), phaseErr, false)
	}
	return fskitWriteResponseWithEnvelope(h, request.GetRequestId(), response)
}

func (h *VolumeHandler) abortFskitWrite(request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	metadata, err := fskitWriteMetadataFromRequest(body)
	if err != nil || !validFskitWritePhaseShape(request, body) {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	resources, err := h.fskitWriteResources(credential.ID)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	abortTerminal := func() *authoritypb.Response {
		resources.fskitWriteMu.Lock()
		terminal := resources.fskitWriteTerminal
		if body.GetTransactionId() != resources.fskitWriteHighWater || terminal == nil || terminal.id != body.GetTransactionId() ||
			!sameFskitWriteMetadata(terminal.metadata, metadata) || terminal.kind == fskitWriteTerminalCommitted {
			resources.fskitWriteMu.Unlock()
			return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
		}
		if terminal.kind == fskitWriteTerminalAborted {
			resources.fskitWriteMu.Unlock()
			return fskitWriteResponseWithEnvelope(h, request.GetRequestId(), fskitWriteReply(body.GetTransactionId(), fskitWriteReplyAborted))
		}
		// A structured BEGIN/COMMIT refusal owns no staged bytes. ABORT turns
		// that exact newest tombstone into the idempotent terminal state the
		// kernel expects after its best-effort cleanup phase.
		resources.fskitWriteTerminal = &fskitWriteTerminal{
			id: body.GetTransactionId(), beginFingerprint: terminal.beginFingerprint,
			metadata: metadata, kind: fskitWriteTerminalAborted,
		}
		resources.fskitWriteMu.Unlock()
		return fskitWriteResponseWithEnvelope(h, request.GetRequestId(), fskitWriteReply(body.GetTransactionId(), fskitWriteReplyAborted))
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil {
		return abortTerminal()
	}
	if !sameFskitWriteMetadata(transaction.metadata, metadata) {
		transaction.refs.Done()
		return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
	}
	transaction.mu.Lock()
	if !fskitWriteRegistered(resources, transaction) {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return abortTerminal()
	}
	if transaction.state != fskitWriteStaging {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return h.errorResponse(request.GetRequestId(), h.fenceFskitWriteMismatch(credential.ID), false)
	}
	resources.fskitWriteMu.Lock()
	cleanup := h.removeFskitWriteLocked(resources, transaction, fskitWriteTerminalAborted, nil)
	resources.fskitWriteMu.Unlock()
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	return fskitWriteResponseWithEnvelope(h, request.GetRequestId(), fskitWriteReply(body.GetTransactionId(), fskitWriteReplyAborted))
}

func (h *VolumeHandler) handleFskitWrite(ctx context.Context, ctxRequest *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	switch body.GetPhase() {
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN:
		return h.beginFskitWriteContext(ctx, ctxRequest, credential, body)
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA:
		return h.stageFskitWriteContext(ctx, ctxRequest, credential, body)
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT:
		return h.abortFskitWrite(ctxRequest, credential, body)
	default:
		return h.errorResponse(ctxRequest.GetRequestId(), syscall.EINVAL, false)
	}
}

// commitFskitWrite is the only phase that enters mutation replay,
// topology ordering, the source publication cut, or XFS. BEGIN/DATA are inert
// staging; this method turns exactly one staged prefix into one visible
// write-syscall outcome.
func (h *VolumeHandler) commitFskitWrite(ctx context.Context, request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	var transaction *fskitWrite
	var resources *sessionResources
	var coordinate visibilityCoordinate
	var releaseMutation func()
	prepare := func() ([]volumeserver.VisibilityTarget, error) {
		var err error
		resources, err = h.fskitWriteResources(credential.ID)
		if err != nil {
			return nil, err
		}
		metadata, err := fskitWriteMetadataFromRequest(body)
		if err != nil || !validFskitWritePhaseShape(request, body) {
			return nil, syscall.EINVAL
		}
		transaction = acquireFskitWrite(resources, body.GetTransactionId())
		if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
			if transaction != nil {
				transaction.refs.Done()
			}
			return nil, h.fenceFskitWriteMismatch(credential.ID)
		}
		transaction.mu.Lock()
		if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteCommitting ||
			transaction.staged != body.GetFragmentOffset() {
			transaction.mu.Unlock()
			transaction.refs.Done()
			return nil, h.fenceFskitWriteMismatch(credential.ID)
		}
		coordinate = visibilityCoordinate{
			identity: transaction.coordinate.Stable, ino: transaction.coordinate.Ino,
			device: uint64(transaction.coordinate.DeviceMajor)<<32 | uint64(transaction.coordinate.DeviceMinor),
		}
		transaction.mu.Unlock()
		transaction.refs.Done()
		releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
		if err != nil {
			return nil, err
		}
		return []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}, nil
	}
	response := h.mutateVisibleSequence(ctx, request, credential, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		active := acquireFskitWrite(resources, transaction.id)
		if active != transaction {
			if active != nil {
				active.refs.Done()
			}
			return h.errorResponse(0, h.fenceFskitWriteMismatch(credential.ID), false), nil
		}
		transaction.mu.Lock()
		if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteCommitting {
			transaction.mu.Unlock()
			transaction.refs.Done()
			return h.errorResponse(0, h.fenceFskitWriteMismatch(credential.ID), false), nil
		}
		stage, target, staged := transaction.stage, transaction.target, transaction.staged
		metadata := transaction.metadata

		var scratch []byte
		if metadata.mode == xfsstore.WriteAppend {
			scratchSize := int(h.MaxWrite)
			if scratchSize <= 0 {
				scratchSize = 64 << 10
			}
			if scratchSize > 1<<20 {
				scratchSize = 1 << 20
			}
			scratch = make([]byte, scratchSize)
		}
		committed, assigned, post, applyErr := target.CommitWrite(stage, xfsstore.WriteCommit{
			RequestedSize: staged, Position: metadata.position, RLimitSize: metadata.rlimitSize,
			FileMaxSize: metadata.fileMaxSize, Mode: metadata.mode,
			DataSync: metadata.dataSync, Sync: metadata.sync,
			KillPrivileges: metadata.writeFlags&fskitWriteKillSUIDGID != 0,
		}, scratch)
		terminalKind := fskitWriteTerminalCommitted
		if committed == 0 && applyErr != nil && !errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) &&
			!errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			terminalKind = fskitWriteTerminalRejected
		}
		resources.fskitWriteMu.Lock()
		cleanup := h.removeFskitWriteLocked(resources, transaction, terminalKind, nil)
		resources.fskitWriteMu.Unlock()
		transaction.mu.Unlock()
		transaction.refs.Done()
		cleanup.finish()

		zeroPostApply := committed == 0 && errors.Is(applyErr, xfsstore.ErrWritePostApply) &&
			!errors.Is(applyErr, xfsstore.ErrOutcomeUncertain)
		if committed == 0 && !zeroPostApply {
			if applyErr == nil {
				return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
			}
			if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) || errors.Is(applyErr, xfsstore.ErrWritePostApply) {
				return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
			}
			// A definite pre-apply refusal can be returned structurally, but a
			// fatal store error still fences the volume. Structured REJECTED
			// proves only that this transaction did not apply; it is not evidence
			// that the authoritative filesystem remains healthy.
			var limit *xfsstore.WriteLimitError
			response := fskitWriteRejection(wireErrno(applyErr), transaction.id, errors.As(applyErr, &limit) && limit.RLimit)
			h.deferStorageFailure(nil, applyErr)
			return response, nil
		}
		if zeroPostApply {
			if post.Kind != xfsstore.KindRegular || post.Size < 0 || sequence == 0 {
				return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
			}
			// No byte received an assigned position. The private ABI reserves zero
			// in this attr-only post-apply shape even for append, and the kernel
			// must leave every iterator/OFD position unchanged.
			response := fskitWriteCommitReply(transaction.id, 0, 0, uint64(post.Size), sequence, post, applyErr)
			response.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: post, roles: postStateRoleTarget, changed: true})
			h.deferStorageFailure(response, applyErr)
			return response, []volumeserver.VisibilityTarget{
				inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
				inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
			}
		}
		if committed > staged || assigned > math.MaxInt64 || committed > math.MaxInt64-assigned {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		end := assigned + committed
		if post.Kind != xfsstore.KindRegular || post.Size < 0 || uint64(post.Size) < end || sequence == 0 {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if metadata.mode == xfsstore.WriteAppend && uint64(post.Size) != end {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if metadata.mode == xfsstore.WritePositioned && assigned != metadata.position {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) {
			return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
		}
		if applyErr != nil && !errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			// A positive ordinary short write returns its prefix, never errno.
			// Only a post-apply obligation failure is surfaced alongside an exact
			// committed result.
			applyErr = nil
		}
		response := fskitWriteCommitReply(transaction.id, committed, assigned, uint64(post.Size), sequence, post, applyErr)
		response.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: post, roles: postStateRoleTarget, changed: true})
		if applyErr != nil {
			h.deferStorageFailure(response, applyErr)
		}
		return response, []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}
	})
	if releaseMutation != nil {
		releaseMutation()
	}
	return response
}

func (h *VolumeHandler) fskitWriteGate(id volumeserver.SessionID, body *authoritypb.FskitWriteRequest) (volumeserver.SourcePublicationGate, xfsstore.ObjectCoordinate, error) {
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, err
	}
	metadata, err := fskitWriteMetadataFromRequest(body)
	if err != nil {
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, err
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, volumeserver.ErrRequestMismatch
	}
	transaction.mu.Lock()
	if !fskitWriteRegistered(resources, transaction) ||
		(transaction.state != fskitWriteStaging && transaction.state != fskitWriteCommitting) ||
		transaction.staged != body.GetFragmentOffset() {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, volumeserver.ErrRequestMismatch
	}
	builder := sourceGateBuilder{}
	builder.addItem(transaction.coordinate.Stable, true, true)
	gate, coordinate := builder.finish(), transaction.coordinate
	transaction.mu.Unlock()
	transaction.refs.Done()
	return gate, coordinate, nil
}

func (h *VolumeHandler) rejectedFskitWriteTerminal(request *authoritypb.Request, id volumeserver.SessionID, body *authoritypb.FskitWriteRequest) (*authoritypb.Response, bool, error) {
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return nil, false, err
	}
	metadata, fingerprint, err := h.fskitWriteForPhase(request, body)
	if err != nil {
		return nil, false, err
	}
	resources.fskitWriteMu.Lock()
	terminal := resources.fskitWriteTerminal
	if terminal == nil || terminal.id != body.GetTransactionId() {
		resources.fskitWriteMu.Unlock()
		return nil, false, nil
	}
	matched := terminal.kind == fskitWriteTerminalRejected && terminal.err != nil &&
		terminal.commitFingerprint != (volumeserver.RequestFingerprint{}) && terminal.commitFingerprint == fingerprint &&
		sameFskitWriteMetadata(terminal.metadata, metadata) && terminal.staged == body.GetFragmentOffset()
	terminalErr := terminal.err
	resources.fskitWriteMu.Unlock()
	if !matched {
		return nil, false, h.fenceFskitWriteMismatch(id)
	}
	return fskitWriteRejection(wireErrno(terminalErr), body.GetTransactionId(), false), true, nil
}

func (h *VolumeHandler) markFskitWriteCommitting(id volumeserver.SessionID, request *authoritypb.Request, body *authoritypb.FskitWriteRequest) (*fskitWriteCommitOwner, error) {
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return nil, err
	}
	metadata, fingerprint, err := h.fskitWriteForPhase(request, body)
	if err != nil {
		return nil, err
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return nil, h.fenceFskitWriteMismatch(id)
	}
	transaction.mu.Lock()
	if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteStaging || transaction.staged != body.GetFragmentOffset() {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return nil, h.fenceFskitWriteMismatch(id)
	}
	// While this owner is live the transaction cannot be swept or aborted. A
	// terminal outcome consumes it through the replay slot. The one nonterminal
	// outcome is a Linux item-only visibility handoff:
	// resetFskitWriteForRetry returns these inert staged bytes to STAGING
	// before that classified reply is retained, so the frontend can retry COMMIT
	// with a fresh mutation ID.
	owner := &fskitWriteCommitOwner{}
	transaction.state = fskitWriteCommitting
	transaction.commitFingerprint = fingerprint
	transaction.commitOwner = owner
	transaction.mu.Unlock()
	transaction.refs.Done()
	return owner, nil
}

func (h *VolumeHandler) finishFskitWriteCommit(id volumeserver.SessionID, body *authoritypb.FskitWriteRequest, owner *fskitWriteCommitOwner) {
	if owner == nil {
		return
	}
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil {
		return
	}
	transaction.mu.Lock()
	if fskitWriteRegistered(resources, transaction) && transaction.state == fskitWriteCommitting && transaction.commitOwner == owner {
		transaction.commitOwner = nil
	}
	transaction.mu.Unlock()
	transaction.refs.Done()
}

// resetFskitWriteForRetry preserves inert staged bytes across the
// authority's item-only visibility handoff. No XFS callback ran, so retaining
// the memfd is both exact and avoids copying the user's write into a second
// BEGIN/DATA sequence. The transaction's absolute lifetime remains fixed; only
// its ordinary progress deadline advances, bounded by that limit.
func (h *VolumeHandler) resetFskitWriteForRetry(id volumeserver.SessionID, body *authoritypb.FskitWriteRequest) error {
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return err
	}
	metadata, err := fskitWriteMetadataFromRequest(body)
	if err != nil {
		return err
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return h.fenceFskitWriteMismatch(id)
	}
	transaction.mu.Lock()
	if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteCommitting ||
		transaction.staged != body.GetFragmentOffset() {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return h.fenceFskitWriteMismatch(id)
	}
	now := time.Now()
	progress := now.Add(h.FskitWriteProgressTimeout)
	if progress.After(transaction.absoluteDeadline) {
		progress = transaction.absoluteDeadline
	}
	transaction.state = fskitWriteStaging
	transaction.commitFingerprint = volumeserver.RequestFingerprint{}
	transaction.commitOwner = nil
	transaction.progressDeadline = progress
	transaction.mu.Unlock()
	transaction.refs.Done()
	return nil
}

// rejectPendingFskitWrite consumes a COMMIT that entered the exact
// replay/source-gate state but was refused before storage apply. It returns a
// structured REJECTED result so the patched kernel can prove no bytes landed,
// discard its staged syscall, and avoid treating an ordinary admission error
// as an ambiguous transport failure.
func (h *VolumeHandler) rejectPendingFskitWrite(id volumeserver.SessionID, body *authoritypb.FskitWriteRequest, cause error) *authoritypb.Response {
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return nil
	}
	metadata, err := fskitWriteMetadataFromRequest(body)
	if err != nil {
		return nil
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return nil
	}
	transaction.mu.Lock()
	if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteCommitting {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return nil
	}
	resources.fskitWriteMu.Lock()
	cleanup := h.removeFskitWriteLocked(resources, transaction, fskitWriteTerminalRejected, cause)
	resources.fskitWriteMu.Unlock()
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	return fskitWriteRejection(wireErrno(cause), body.GetTransactionId(), false)
}

// rejectUnadmittedFskitWrite consumes a COMMIT whose replay-cache
// reservation was refused before the mutation callback ran. The cache is a
// memory bound, so ENOMEM is the definite syscall result; a generic outer
// admission error would make Linux treat a known no-apply result as ambiguous.
func (h *VolumeHandler) rejectUnadmittedFskitWrite(request *authoritypb.Request, id volumeserver.SessionID, body *authoritypb.FskitWriteRequest) *authoritypb.Response {
	if terminal, found, err := h.rejectedFskitWriteTerminal(request, id, body); err != nil {
		return h.errorResponse(0, err, false)
	} else if found {
		return terminal
	}
	resources, err := h.fskitWriteResources(id)
	if err != nil {
		return h.errorResponse(0, err, false)
	}
	metadata, fingerprint, err := h.fskitWriteForPhase(request, body)
	if err != nil {
		return h.errorResponse(0, err, false)
	}
	declaredGate, err := decodeFskitSourcePublication(request)
	if err != nil || declaredGate == nil {
		return h.errorResponse(0, syscall.EINVAL, false)
	}
	transaction := acquireFskitWrite(resources, body.GetTransactionId())
	if transaction == nil || !sameFskitWriteMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return h.errorResponse(0, h.fenceFskitWriteMismatch(id), false)
	}
	transaction.mu.Lock()
	builder := sourceGateBuilder{}
	builder.addItem(transaction.coordinate.Stable, true, true)
	expectedGate := builder.finish()
	if !fskitWriteRegistered(resources, transaction) || transaction.state != fskitWriteStaging ||
		transaction.staged != body.GetFragmentOffset() || !sourcePublicationGatesEqual(declaredGate, &expectedGate) {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return h.errorResponse(0, h.fenceFskitWriteMismatch(id), false)
	}
	transaction.state = fskitWriteRejected
	transaction.initErr = syscall.ENOMEM
	transaction.commitFingerprint = fingerprint
	resources.fskitWriteMu.Lock()
	cleanup := h.removeFskitWriteLocked(resources, transaction, fskitWriteTerminalRejected, syscall.ENOMEM)
	resources.fskitWriteMu.Unlock()
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	return fskitWriteRejection(int32(syscall.ENOMEM), body.GetTransactionId(), false)
}

// markFskitWritePostApplyFailure preserves the exact committed prefix
// when visibility completion fails after XFS apply. The source kernel must
// install and publish that result before receiving the failure; returning a
// generic outer error would erase the only safe offset/size truth and invite a
// duplicate append on retry.
func markFskitWritePostApplyFailure(response *authoritypb.Response, cause error) bool {
	if response == nil || cause == nil {
		return false
	}
	reply := response.GetFskitWrite()
	if reply == nil || reply.GetFlags()&fskitWriteReplyCommitted == 0 {
		return false
	}
	reply.Flags |= fskitWriteReplyPostApply
	reply.Error = -wireErrno(cause)
	if reply.Error >= 0 {
		reply.Error = -int32(syscall.EIO)
	}
	response.Errno = 0
	response.Uncertain = false
	return true
}

// SweepFskitWrites releases inert staging and abandoned COMMIT attempts.
// CommitWrite removes the transaction before releasing its handler ownership,
// so a registered COMMITTING transaction with no owner is definitely pre-apply.
func (h *VolumeHandler) SweepFskitWrites(now time.Time) {
	if h == nil || now.IsZero() {
		return
	}
	h.resourcesMu.Lock()
	resources := make([]*sessionResources, 0, len(h.resources))
	for _, resource := range h.resources {
		resources = append(resources, resource)
	}
	h.resourcesMu.Unlock()
	for _, resource := range resources {
		resource.fskitWriteMu.Lock()
		transactions := make([]*fskitWrite, 0, len(resource.fskitWrites))
		for _, transaction := range resource.fskitWrites {
			transaction.refs.Add(1)
			transactions = append(transactions, transaction)
		}
		resource.fskitWriteMu.Unlock()
		for _, transaction := range transactions {
			// Wait outside the ledger for active work to publish its new progress
			// deadline. This prevents timeout cleanup from closing a live WriteAt,
			// while the session registry and every unrelated transaction remain
			// available throughout the wait.
			transaction.mu.Lock()
			var cleanup fskitWriteCleanup
			if fskitWriteRegistered(resource, transaction) {
				switch {
				case transaction.state == fskitWriteStaging &&
					(!now.Before(transaction.progressDeadline) || !now.Before(transaction.absoluteDeadline)):
					resource.fskitWriteMu.Lock()
					cleanup = h.removeFskitWriteLocked(resource, transaction, fskitWriteTerminalAborted, nil)
					resource.fskitWriteMu.Unlock()
				case transaction.state == fskitWriteCommitting && transaction.commitOwner == nil &&
					!now.Before(transaction.absoluteDeadline):
					transaction.state = fskitWriteRejected
					transaction.initErr = context.DeadlineExceeded
					resource.fskitWriteMu.Lock()
					cleanup = h.removeFskitWriteLocked(resource, transaction, fskitWriteTerminalRejected, context.DeadlineExceeded)
					resource.fskitWriteMu.Unlock()
				}
			}
			transaction.mu.Unlock()
			transaction.refs.Done()
			cleanup.finish()
		}
	}
}

func closeFskitWrites(h *VolumeHandler, resources *sessionResources) []fskitWriteCleanup {
	if h == nil || resources == nil {
		return nil
	}
	resources.fskitWriteMu.Lock()
	defer resources.fskitWriteMu.Unlock()
	cleanup := make([]fskitWriteCleanup, 0, len(resources.fskitWrites))
	for id, transaction := range resources.fskitWrites {
		// Session teardown makes the whole ledger unreachable and discards its
		// tombstone. Do not read phase-owned fields without transaction.mu merely
		// to construct a terminal value that is cleared below.
		delete(resources.fskitWrites, id)
		cleanup = append(cleanup, fskitWriteCleanup{handler: h, resources: resources, transaction: transaction})
	}
	resources.fskitWrites = nil
	resources.fskitWriteTerminal = nil
	return cleanup
}
