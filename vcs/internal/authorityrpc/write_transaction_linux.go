//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
)

const (
	writeTransactionReplyBegun     uint32 = 1 << 0
	writeTransactionReplyStaged    uint32 = 1 << 1
	writeTransactionReplyCommitted uint32 = 1 << 2
	writeTransactionReplyAborted   uint32 = 1 << 3
	writeTransactionReplyRejected  uint32 = 1 << 4
	writeTransactionReplyPostApply uint32 = 1 << 5
	writeTransactionReplyRLimit    uint32 = 1 << 6

	// These are the closed Linux FUSE write flag set. WRITE_CACHE is
	// intentionally absent: shared files never enter the stock writeback path.
	writeTransactionLockOwner   uint32 = 1 << 1
	writeTransactionKillSUIDGID uint32 = 1 << 2
)

// WriteTransactionStaging is a pinned private directory that creates only
// unnamed O_TMPFILE staging files. Payload bytes therefore never enter the
// authority namespace or heap, and a process crash lets the kernel reclaim
// every incomplete transaction without a recovery scan.
type WriteTransactionStaging struct {
	mu             sync.RWMutex
	dir            *os.File
	closed         bool
	newFileForTest func(uint64) (writeTransactionStage, error)
}

type writeTransactionStage interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
}

func OpenWriteTransactionStaging(path string) (*WriteTransactionStaging, error) {
	dir, err := privatepath.OpenExistingDir(path)
	if err != nil {
		return nil, fmt.Errorf("open write-transaction staging directory: %w", err)
	}
	staging := &WriteTransactionStaging{dir: dir}
	probe, err := staging.newFile(1)
	if err != nil {
		_ = staging.Close()
		return nil, fmt.Errorf("qualify O_TMPFILE write staging: %w", err)
	}
	if err := probe.Close(); err != nil {
		_ = staging.Close()
		return nil, fmt.Errorf("close O_TMPFILE write-staging probe: %w", err)
	}
	return staging, nil
}

func (s *WriteTransactionStaging) newFile(size uint64) (writeTransactionStage, error) {
	if s == nil || size == 0 || size > math.MaxInt64 {
		return nil, syscall.EINVAL
	}
	s.mu.RLock()
	if s.closed || s.dir == nil {
		s.mu.RUnlock()
		return nil, syscall.ESTALE
	}
	if hook := s.newFileForTest; hook != nil {
		s.mu.RUnlock()
		return hook(size)
	}
	defer s.mu.RUnlock()
	fd, err := unix.Openat(int(s.dir.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "portablefs-write-transaction")
	if file == nil {
		_ = unix.Close(fd)
		return nil, syscall.EIO
	}
	// Reserve the complete declared syscall before BEGIN succeeds. DATA is then
	// a bounded overwrite into already allocated staging rather than a delayed
	// ENOSPC surprise after the kernel has committed to this transaction.
	if err := unix.Fallocate(fd, 0, 0, int64(size)); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s *WriteTransactionStaging) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.dir == nil {
		return nil
	}
	err := s.dir.Close()
	s.dir = nil
	return err
}

type writeTransactionState uint8

const (
	writeTransactionInitializing writeTransactionState = iota + 1
	writeTransactionStaging
	writeTransactionCommitting
	writeTransactionRejected
)

type writeTransactionMetadata struct {
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

type writeTransaction struct {
	// refs protects stage and target lifetime after the transaction is found in
	// the session ledger. The ledger mutex may add a reference only while the
	// exact pointer is still registered; removal happens under that same mutex,
	// then cleanup waits without holding it. mu serializes all work for one
	// transaction, including INITIALIZING and DATA filesystem I/O. No holder of
	// sessionResources.writeMu may wait for mu.
	mu               sync.Mutex
	refs             sync.WaitGroup
	id               uint64
	metadata         writeTransactionMetadata
	beginFingerprint volumeserver.RequestFingerprint
	stage            writeTransactionStage
	target           xfsstore.WriteTarget
	coordinate       xfsstore.ObjectCoordinate
	state            writeTransactionState
	staged           uint64
	lastDataOffset   uint64
	lastDataSize     uint32
	lastData         volumeserver.RequestFingerprint
	progressDeadline time.Time
	absoluteDeadline time.Time
	initErr          error
}

type writeTransactionTerminalKind uint8

const (
	writeTransactionTerminalAborted writeTransactionTerminalKind = iota + 1
	writeTransactionTerminalCommitted
	writeTransactionTerminalRejected
)

// Only the newest terminal transaction is retained. BEGIN is serialized by
// the frontend and IDs are monotonic, so a legitimate lost response cannot be
// older than the newest dispatched BEGIN. Retaining one exact tombstone keeps
// cleanup bounded while altered or late reuse still fails closed.
type writeTransactionTerminal struct {
	id               uint64
	beginFingerprint volumeserver.RequestFingerprint
	metadata         writeTransactionMetadata
	kind             writeTransactionTerminalKind
	err              error
}

type writeTransactionCleanup struct {
	handler     *VolumeHandler
	resources   *sessionResources
	transaction *writeTransaction
}

func (c writeTransactionCleanup) finish() {
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
	c.transaction.stage, c.transaction.target = nil, nil
	c.transaction.mu.Unlock()
	if stage != nil {
		_ = stage.Close()
	}
	if target != nil {
		_ = target.Close()
	}
	if c.handler != nil && c.resources != nil {
		c.handler.releaseWriteTransactionCapacity(c.resources, c.transaction.metadata.requestedSize)
	}
}

func writeTransactionMetadataFromRequest(request *authoritypb.WriteTransactionRequest) (writeTransactionMetadata, error) {
	var metadata writeTransactionMetadata
	if request == nil || request.GetTransactionId() == 0 || len(request.GetHandle()) != len(metadata.handle) ||
		request.GetRequestedSize() == 0 || request.GetRequestedSize() > math.MaxInt64 ||
		request.GetFileMaxSize() == 0 || request.GetFileMaxSize() > math.MaxInt64 {
		return metadata, syscall.EINVAL
	}
	copy(metadata.handle[:], request.GetHandle())
	if metadata.handle == (xfsstore.Capability{}) {
		return metadata, syscall.EINVAL
	}
	metadata.requestedSize = request.GetRequestedSize()
	metadata.position = request.GetPosition()
	metadata.rlimitSize = request.GetRlimitFsize()
	metadata.fileMaxSize = request.GetFileMaxSize()
	metadata.lockOwner = request.GetLockOwner()
	metadata.writeFlags = request.GetWriteFlags()
	metadata.flags = request.GetFlags()

	allowedWriteFlags := uint32(writeTransactionLockOwner | writeTransactionKillSUIDGID)
	if metadata.writeFlags&^allowedWriteFlags != 0 || metadata.writeFlags&writeTransactionLockOwner == 0 && metadata.lockOwner != 0 {
		return writeTransactionMetadata{}, syscall.EINVAL
	}
	allowedFileFlags := uint32(syscall.O_APPEND | syscall.O_DSYNC | syscall.O_SYNC)
	if metadata.flags&^allowedFileFlags != 0 {
		return writeTransactionMetadata{}, syscall.EINVAL
	}
	fullSyncBit := uint32(syscall.O_SYNC &^ syscall.O_DSYNC)
	if metadata.flags&fullSyncBit != 0 && metadata.flags&uint32(syscall.O_DSYNC) == 0 {
		return writeTransactionMetadata{}, syscall.EINVAL
	}
	metadata.sync = metadata.flags&fullSyncBit != 0
	metadata.dataSync = !metadata.sync && metadata.flags&uint32(syscall.O_DSYNC) != 0
	if metadata.flags&uint32(syscall.O_APPEND) != 0 {
		if metadata.position != 0 {
			return writeTransactionMetadata{}, syscall.EINVAL
		}
		metadata.mode = xfsstore.WriteAppend
	} else {
		if metadata.position > math.MaxInt64 {
			return writeTransactionMetadata{}, syscall.EINVAL
		}
		metadata.mode = xfsstore.WritePositioned
	}
	return metadata, nil
}

func validWriteTransactionPhaseShape(request *authoritypb.Request, body *authoritypb.WriteTransactionRequest) bool {
	if request == nil || body == nil {
		return false
	}
	switch body.GetPhase() {
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN:
		return request.GetMutation() == nil && request.GetSourcePublicationGate() == nil &&
			body.GetFragmentOffset() == 0 && body.GetSize() == 0 && len(body.GetData()) == 0
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA:
		return request.GetMutation() == nil && request.GetSourcePublicationGate() == nil && body.GetSize() != 0 &&
			uint32(len(body.GetData())) == body.GetSize() && body.GetFragmentOffset() < body.GetRequestedSize() &&
			uint64(body.GetSize()) <= body.GetRequestedSize()-body.GetFragmentOffset()
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT:
		return request.GetMutation() != nil && request.GetSourcePublicationGate() != nil &&
			body.GetFragmentOffset() != 0 && body.GetFragmentOffset() <= body.GetRequestedSize() &&
			body.GetSize() == 0 && len(body.GetData()) == 0
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT:
		return request.GetMutation() == nil && request.GetSourcePublicationGate() == nil &&
			body.GetFragmentOffset() == 0 && body.GetSize() == 0 && len(body.GetData()) == 0
	default:
		return false
	}
}

func writeTransactionReply(transactionID uint64, flags uint32) *authoritypb.Response {
	return &authoritypb.Response{Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
		TransactionId: transactionID, Flags: flags,
	}}}
}

func writeTransactionFingerprint(h *VolumeHandler, request *authoritypb.Request) (volumeserver.RequestFingerprint, error) {
	if h == nil || h.Runtime == nil {
		return volumeserver.RequestFingerprint{}, syscall.EIO
	}
	return canonicalFingerprint(h.Runtime, request)
}

func sameWriteTransactionMetadata(left, right writeTransactionMetadata) bool { return left == right }

func writeTransactionRejection(errno int32, transactionID uint64, rlimit bool) *authoritypb.Response {
	if errno <= 0 || errno > 4095 {
		errno = int32(syscall.EIO)
	}
	flags := writeTransactionReplyRejected
	if rlimit {
		flags = writeTransactionReplyRLimit
	}
	return &authoritypb.Response{Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
		TransactionId: transactionID, Flags: flags, Error: -errno,
	}}}
}

func writeTransactionCommitReply(transactionID, committed, assigned, post, sequence uint64, postAttr xfsstore.Attr, err error) *authoritypb.Response {
	flags := writeTransactionReplyCommitted
	wireError := int32(0)
	if err != nil && errors.Is(err, xfsstore.ErrWritePostApply) {
		flags |= writeTransactionReplyPostApply
		wireError = -wireErrno(err)
		if wireError >= 0 {
			wireError = -int32(syscall.EIO)
		}
	}
	return &authoritypb.Response{
		PostAttr: attrProto(postAttr),
		Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
			TransactionId: transactionID, CommittedSize: committed, AssignedOffset: assigned,
			PostSize: post, VisibilitySequence: sequence, Flags: flags, Error: wireError,
		}},
	}
}

func writeTransactionResponseWithEnvelope(h *VolumeHandler, requestID uint64, response *authoritypb.Response) *authoritypb.Response {
	if response == nil {
		return h.errorResponse(requestID, syscall.EIO, true)
	}
	response.RequestId = requestID
	response.Epoch = h.Epoch()
	return response
}

func (h *VolumeHandler) writeTransactionResources(id volumeserver.SessionID) (*sessionResources, error) {
	resources, err := h.sessionResources(id)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (h *VolumeHandler) reserveWriteTransactionCapacity(resources *sessionResources, bytes uint64) error {
	h.writeCapacityMu.Lock()
	defer h.writeCapacityMu.Unlock()
	if bytes > h.MaxWriteStagingBytesPerSession || bytes > h.MaxWriteStagingBytes ||
		resources.writeReservedBytes > h.MaxWriteStagingBytesPerSession-bytes ||
		h.totalWriteStagingBytes > h.MaxWriteStagingBytes-bytes ||
		resources.writeTransactionCount >= h.MaxWriteTransactionsPerSession ||
		h.totalWriteTransactions >= h.MaxWriteTransactions {
		return volumeserver.ErrAdmission
	}
	resources.writeReservedBytes += bytes
	resources.writeTransactionCount++
	h.totalWriteStagingBytes += bytes
	h.totalWriteTransactions++
	return nil
}

func (h *VolumeHandler) releaseWriteTransactionCapacity(resources *sessionResources, bytes uint64) {
	h.writeCapacityMu.Lock()
	defer h.writeCapacityMu.Unlock()
	if bytes > resources.writeReservedBytes || bytes > h.totalWriteStagingBytes ||
		resources.writeTransactionCount == 0 || h.totalWriteTransactions == 0 {
		panic("authorityrpc: write transaction capacity accounting underflow")
	}
	resources.writeReservedBytes -= bytes
	resources.writeTransactionCount--
	h.totalWriteStagingBytes -= bytes
	h.totalWriteTransactions--
}

// acquireWriteTransaction pins the exact registered object without ever
// waiting on transaction.mu while holding the session ledger. WaitGroup.Add is
// ordered before removal by writeMu; once removal wins, no future Add can race
// cleanup's Wait.
func acquireWriteTransaction(resources *sessionResources, id uint64) *writeTransaction {
	resources.writeMu.Lock()
	transaction := resources.writeTransactions[id]
	if transaction != nil {
		transaction.refs.Add(1)
	}
	resources.writeMu.Unlock()
	return transaction
}

func writeTransactionRegistered(resources *sessionResources, transaction *writeTransaction) bool {
	resources.writeMu.Lock()
	registered := resources.writeTransactions[transaction.id] == transaction
	resources.writeMu.Unlock()
	return registered
}

// removeWriteTransactionLocked transfers cleanup ownership but performs no
// waiting, Close, or capacity release under writeMu. Callers must already have
// made the transaction terminal while holding transaction.mu, unless this is
// session teardown (which makes the entire ledger unreachable first).
func (h *VolumeHandler) removeWriteTransactionLocked(resources *sessionResources, transaction *writeTransaction, terminal writeTransactionTerminalKind, terminalErr error) writeTransactionCleanup {
	if resources.writeTransactions[transaction.id] != transaction {
		return writeTransactionCleanup{}
	}
	delete(resources.writeTransactions, transaction.id)
	resources.writeTerminal = &writeTransactionTerminal{
		id: transaction.id, beginFingerprint: transaction.beginFingerprint, metadata: transaction.metadata, kind: terminal, err: terminalErr,
	}
	return writeTransactionCleanup{handler: h, resources: resources, transaction: transaction}
}

func (h *VolumeHandler) fenceWriteTransactionMismatch(id volumeserver.SessionID) error {
	if h.Runtime != nil {
		h.Runtime.FenceSession(id)
	}
	return volumeserver.ErrRequestMismatch
}

func (h *VolumeHandler) beginWriteTransaction(request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.WriteTransactionRequest) *authoritypb.Response {
	metadata, err := writeTransactionMetadataFromRequest(body)
	if err != nil || !validWriteTransactionPhaseShape(request, body) || body.GetRequestedSize() > h.MaxWriteTransactionBytes {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	fingerprint, err := writeTransactionFingerprint(h, request)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	resources, err := h.writeTransactionResources(credential.ID)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	resources.writeMu.Lock()
	if resources.writeTransactions == nil {
		resources.writeTransactions = make(map[uint64]*writeTransaction)
	}
	if existing := resources.writeTransactions[body.GetTransactionId()]; existing != nil {
		if existing.beginFingerprint != fingerprint || !sameWriteTransactionMetadata(existing.metadata, metadata) {
			resources.writeMu.Unlock()
			return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
		}
		existing.refs.Add(1)
		resources.writeMu.Unlock()
		// INITIALIZING owns this mutex across allocation and target pinning. An
		// exact retry waits for that one attempt instead of duplicating either
		// resource, while every other transaction remains independent.
		existing.mu.Lock()
		var response *authoritypb.Response
		switch existing.state {
		case writeTransactionStaging, writeTransactionCommitting:
			if writeTransactionRegistered(resources, existing) {
				response = writeTransactionReply(body.GetTransactionId(), writeTransactionReplyBegun)
			}
		case writeTransactionRejected:
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
			resources.writeMu.Lock()
			terminal := resources.writeTerminal
			if terminal != nil && terminal.id == body.GetTransactionId() && terminal.beginFingerprint == fingerprint &&
				sameWriteTransactionMetadata(terminal.metadata, metadata) {
				switch terminal.kind {
				case writeTransactionTerminalAborted:
					response = writeTransactionReply(body.GetTransactionId(), writeTransactionReplyAborted)
				case writeTransactionTerminalRejected:
					if terminal.err != nil {
						response = h.errorResponse(request.GetRequestId(), terminal.err, false)
					}
				}
			}
			resources.writeMu.Unlock()
		}
		if response == nil {
			return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
		}
		if response.GetRequestId() != request.GetRequestId() {
			response = writeTransactionResponseWithEnvelope(h, request.GetRequestId(), response)
		}
		return response
	}
	if terminal := resources.writeTerminal; terminal != nil && terminal.id == body.GetTransactionId() {
		if terminal.beginFingerprint != fingerprint || !sameWriteTransactionMetadata(terminal.metadata, metadata) {
			resources.writeMu.Unlock()
			return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
		}
		resources.writeMu.Unlock()
		switch terminal.kind {
		case writeTransactionTerminalAborted:
			return writeTransactionResponseWithEnvelope(h, request.GetRequestId(), writeTransactionReply(body.GetTransactionId(), writeTransactionReplyAborted))
		case writeTransactionTerminalRejected:
			if terminal.err == nil {
				return h.errorResponse(request.GetRequestId(), syscall.EIO, false)
			}
			return h.errorResponse(request.GetRequestId(), terminal.err, false)
		default:
			return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
		}
	}
	if body.GetTransactionId() != resources.writeHighWater+1 {
		resources.writeMu.Unlock()
		return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
	}
	// A syntactically valid exact next BEGIN consumes its monotonic identity
	// before any resource decision. A refused/lost BEGIN can therefore be
	// retried or aborted without letting a later transaction reuse its number.
	resources.writeHighWater = body.GetTransactionId()
	if err := h.reserveWriteTransactionCapacity(resources, metadata.requestedSize); err != nil {
		resources.writeTerminal = &writeTransactionTerminal{id: body.GetTransactionId(), beginFingerprint: fingerprint, metadata: metadata, kind: writeTransactionTerminalRejected, err: err}
		resources.writeMu.Unlock()
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	transaction := &writeTransaction{
		id: body.GetTransactionId(), metadata: metadata, beginFingerprint: fingerprint,
		state: writeTransactionInitializing,
	}
	// Lock before publishing the placeholder so no retry can observe a partial
	// stage/target pair. The initial attempt itself is the first lifetime ref.
	transaction.mu.Lock()
	transaction.refs.Add(1)
	resources.writeTransactions[transaction.id] = transaction
	resources.writeTerminal = nil
	resources.writeMu.Unlock()

	stage, initErr := h.WriteStaging.newFile(metadata.requestedSize)
	transaction.stage = stage
	if initErr == nil {
		store, ok := h.Store.(writeTransactionStore)
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

	var cleanup writeTransactionCleanup
	if initErr != nil {
		transaction.state = writeTransactionRejected
		transaction.initErr = initErr
		resources.writeMu.Lock()
		cleanup = h.removeWriteTransactionLocked(resources, transaction, writeTransactionTerminalRejected, initErr)
		resources.writeMu.Unlock()
	} else {
		now := time.Now()
		transaction.state = writeTransactionStaging
		transaction.progressDeadline = now.Add(h.WriteTransactionProgressTimeout)
		transaction.absoluteDeadline = now.Add(h.WriteTransactionAbsoluteTimeout)
	}
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	if initErr != nil {
		return h.errorResponse(request.GetRequestId(), initErr, false)
	}
	if !writeTransactionRegistered(resources, transaction) {
		return h.errorResponse(request.GetRequestId(), volumeserver.ErrSessionExpired, false)
	}
	return writeTransactionResponseWithEnvelope(h, request.GetRequestId(), writeTransactionReply(transaction.id, writeTransactionReplyBegun))
}

func (h *VolumeHandler) writeTransactionForPhase(request *authoritypb.Request, body *authoritypb.WriteTransactionRequest) (writeTransactionMetadata, volumeserver.RequestFingerprint, error) {
	metadata, err := writeTransactionMetadataFromRequest(body)
	if err != nil || !validWriteTransactionPhaseShape(request, body) || body.GetRequestedSize() > h.MaxWriteTransactionBytes {
		return writeTransactionMetadata{}, volumeserver.RequestFingerprint{}, syscall.EINVAL
	}
	fingerprint, err := writeTransactionFingerprint(h, request)
	if err != nil {
		return writeTransactionMetadata{}, volumeserver.RequestFingerprint{}, syscall.EINVAL
	}
	return metadata, fingerprint, nil
}

func (h *VolumeHandler) stageWriteTransaction(request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.WriteTransactionRequest) *authoritypb.Response {
	if body.GetSize() > h.MaxWrite {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	resources, err := h.writeTransactionResources(credential.ID)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	metadata, fingerprint, err := h.writeTransactionForPhase(request, body)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	transaction := acquireWriteTransaction(resources, body.GetTransactionId())
	if transaction == nil || !sameWriteTransactionMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
	}
	transaction.mu.Lock()
	var cleanup writeTransactionCleanup
	var response *authoritypb.Response
	var phaseErr error
	if !writeTransactionRegistered(resources, transaction) || transaction.state != writeTransactionStaging {
		phaseErr = h.fenceWriteTransactionMismatch(credential.ID)
	} else if body.GetFragmentOffset() < transaction.staged {
		if body.GetFragmentOffset() != transaction.lastDataOffset || body.GetSize() != transaction.lastDataSize || transaction.lastData != fingerprint {
			phaseErr = h.fenceWriteTransactionMismatch(credential.ID)
		} else {
			response = writeTransactionReply(transaction.id, writeTransactionReplyStaged)
		}
	} else if body.GetFragmentOffset() != transaction.staged {
		phaseErr = h.fenceWriteTransactionMismatch(credential.ID)
	} else {
		n, writeErr := transaction.stage.WriteAt(body.GetData(), int64(transaction.staged))
		if writeErr != nil || n != len(body.GetData()) {
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			transaction.state = writeTransactionRejected
			transaction.initErr = writeErr
			resources.writeMu.Lock()
			cleanup = h.removeWriteTransactionLocked(resources, transaction, writeTransactionTerminalRejected, writeErr)
			resources.writeMu.Unlock()
			phaseErr = writeErr
		} else {
			transaction.lastDataOffset = transaction.staged
			transaction.lastDataSize = body.GetSize()
			transaction.lastData = fingerprint
			transaction.staged += uint64(body.GetSize())
			now := time.Now()
			progress := now.Add(h.WriteTransactionProgressTimeout)
			if progress.After(transaction.absoluteDeadline) {
				progress = transaction.absoluteDeadline
			}
			transaction.progressDeadline = progress
			response = writeTransactionReply(transaction.id, writeTransactionReplyStaged)
		}
	}
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	if phaseErr != nil {
		return h.errorResponse(request.GetRequestId(), phaseErr, false)
	}
	return writeTransactionResponseWithEnvelope(h, request.GetRequestId(), response)
}

func (h *VolumeHandler) abortWriteTransaction(request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.WriteTransactionRequest) *authoritypb.Response {
	metadata, err := writeTransactionMetadataFromRequest(body)
	if err != nil || !validWriteTransactionPhaseShape(request, body) {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	resources, err := h.writeTransactionResources(credential.ID)
	if err != nil {
		return h.errorResponse(request.GetRequestId(), err, false)
	}
	abortTerminal := func() *authoritypb.Response {
		resources.writeMu.Lock()
		terminal := resources.writeTerminal
		if body.GetTransactionId() != resources.writeHighWater || terminal == nil || terminal.id != body.GetTransactionId() ||
			!sameWriteTransactionMetadata(terminal.metadata, metadata) || terminal.kind == writeTransactionTerminalCommitted {
			resources.writeMu.Unlock()
			return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
		}
		if terminal.kind == writeTransactionTerminalAborted {
			resources.writeMu.Unlock()
			return writeTransactionResponseWithEnvelope(h, request.GetRequestId(), writeTransactionReply(body.GetTransactionId(), writeTransactionReplyAborted))
		}
		// A structured BEGIN/COMMIT refusal owns no staged bytes. ABORT turns
		// that exact newest tombstone into the idempotent terminal state the
		// kernel expects after its best-effort cleanup phase.
		resources.writeTerminal = &writeTransactionTerminal{
			id: body.GetTransactionId(), beginFingerprint: terminal.beginFingerprint,
			metadata: metadata, kind: writeTransactionTerminalAborted,
		}
		resources.writeMu.Unlock()
		return writeTransactionResponseWithEnvelope(h, request.GetRequestId(), writeTransactionReply(body.GetTransactionId(), writeTransactionReplyAborted))
	}
	transaction := acquireWriteTransaction(resources, body.GetTransactionId())
	if transaction == nil {
		return abortTerminal()
	}
	if !sameWriteTransactionMetadata(transaction.metadata, metadata) {
		transaction.refs.Done()
		return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
	}
	transaction.mu.Lock()
	if !writeTransactionRegistered(resources, transaction) {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return abortTerminal()
	}
	if transaction.state != writeTransactionStaging {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return h.errorResponse(request.GetRequestId(), h.fenceWriteTransactionMismatch(credential.ID), false)
	}
	resources.writeMu.Lock()
	cleanup := h.removeWriteTransactionLocked(resources, transaction, writeTransactionTerminalAborted, nil)
	resources.writeMu.Unlock()
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	return writeTransactionResponseWithEnvelope(h, request.GetRequestId(), writeTransactionReply(body.GetTransactionId(), writeTransactionReplyAborted))
}

func (h *VolumeHandler) handleWriteTransaction(ctxRequest *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.WriteTransactionRequest) *authoritypb.Response {
	switch body.GetPhase() {
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN:
		return h.beginWriteTransaction(ctxRequest, credential, body)
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA:
		return h.stageWriteTransaction(ctxRequest, credential, body)
	case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT:
		return h.abortWriteTransaction(ctxRequest, credential, body)
	default:
		return h.errorResponse(ctxRequest.GetRequestId(), syscall.EINVAL, false)
	}
}

// commitWriteTransaction is the only phase that enters mutation replay,
// topology ordering, the source publication cut, or XFS. BEGIN/DATA are inert
// staging; this method turns exactly one staged prefix into one visible
// write-syscall outcome.
func (h *VolumeHandler) commitWriteTransaction(ctx context.Context, request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.WriteTransactionRequest) *authoritypb.Response {
	var transaction *writeTransaction
	var resources *sessionResources
	var coordinate visibilityCoordinate
	prepare := func() ([]volumeserver.VisibilityTarget, error) {
		var err error
		resources, err = h.writeTransactionResources(credential.ID)
		if err != nil {
			return nil, err
		}
		metadata, err := writeTransactionMetadataFromRequest(body)
		if err != nil || !validWriteTransactionPhaseShape(request, body) {
			return nil, syscall.EINVAL
		}
		transaction = acquireWriteTransaction(resources, body.GetTransactionId())
		if transaction == nil || !sameWriteTransactionMetadata(transaction.metadata, metadata) {
			if transaction != nil {
				transaction.refs.Done()
			}
			return nil, h.fenceWriteTransactionMismatch(credential.ID)
		}
		transaction.mu.Lock()
		if !writeTransactionRegistered(resources, transaction) || transaction.state != writeTransactionCommitting ||
			transaction.staged != body.GetFragmentOffset() {
			transaction.mu.Unlock()
			transaction.refs.Done()
			return nil, h.fenceWriteTransactionMismatch(credential.ID)
		}
		coordinate = visibilityCoordinate{
			identity: transaction.coordinate.Stable, ino: transaction.coordinate.Ino,
			device: uint64(transaction.coordinate.DeviceMajor)<<32 | uint64(transaction.coordinate.DeviceMinor),
		}
		transaction.mu.Unlock()
		transaction.refs.Done()
		return []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}, nil
	}
	return h.mutateVisibleSequence(ctx, request, credential, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		active := acquireWriteTransaction(resources, transaction.id)
		if active != transaction {
			if active != nil {
				active.refs.Done()
			}
			return h.errorResponse(0, h.fenceWriteTransactionMismatch(credential.ID), false), nil
		}
		transaction.mu.Lock()
		if !writeTransactionRegistered(resources, transaction) || transaction.state != writeTransactionCommitting {
			transaction.mu.Unlock()
			transaction.refs.Done()
			return h.errorResponse(0, h.fenceWriteTransactionMismatch(credential.ID), false), nil
		}
		stage, target, staged := transaction.stage, transaction.target, transaction.staged
		metadata := transaction.metadata

		scratchSize := int(h.MaxWrite)
		if scratchSize <= 0 {
			scratchSize = 64 << 10
		}
		if scratchSize > 1<<20 {
			scratchSize = 1 << 20
		}
		committed, assigned, post, applyErr := target.CommitWrite(stage, xfsstore.WriteCommit{
			RequestedSize: staged, Position: metadata.position, RLimitSize: metadata.rlimitSize,
			FileMaxSize: metadata.fileMaxSize, Mode: metadata.mode,
			DataSync: metadata.dataSync, Sync: metadata.sync,
			KillPrivileges: metadata.writeFlags&writeTransactionKillSUIDGID != 0,
		}, make([]byte, scratchSize))
		terminalKind := writeTransactionTerminalCommitted
		if committed == 0 && applyErr != nil && !errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) &&
			!errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			terminalKind = writeTransactionTerminalRejected
		}
		resources.writeMu.Lock()
		cleanup := h.removeWriteTransactionLocked(resources, transaction, terminalKind, nil)
		resources.writeMu.Unlock()
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
			response := writeTransactionRejection(wireErrno(applyErr), transaction.id, errors.As(applyErr, &limit) && limit.RLimit)
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
			response := writeTransactionCommitReply(transaction.id, 0, 0, uint64(post.Size), sequence, post, applyErr)
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
		response := writeTransactionCommitReply(transaction.id, committed, assigned, uint64(post.Size), sequence, post, applyErr)
		if applyErr != nil {
			h.deferStorageFailure(response, applyErr)
		}
		return response, []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}
	})
}

func (h *VolumeHandler) writeTransactionGate(id volumeserver.SessionID, body *authoritypb.WriteTransactionRequest) (volumeserver.SourcePublicationGate, xfsstore.ObjectCoordinate, error) {
	resources, err := h.writeTransactionResources(id)
	if err != nil {
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, err
	}
	metadata, err := writeTransactionMetadataFromRequest(body)
	if err != nil {
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, err
	}
	transaction := acquireWriteTransaction(resources, body.GetTransactionId())
	if transaction == nil || !sameWriteTransactionMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return volumeserver.SourcePublicationGate{}, xfsstore.ObjectCoordinate{}, volumeserver.ErrRequestMismatch
	}
	transaction.mu.Lock()
	if !writeTransactionRegistered(resources, transaction) || transaction.state != writeTransactionStaging || transaction.staged != body.GetFragmentOffset() {
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

func (h *VolumeHandler) markWriteTransactionCommitting(id volumeserver.SessionID, body *authoritypb.WriteTransactionRequest) error {
	resources, err := h.writeTransactionResources(id)
	if err != nil {
		return err
	}
	metadata, err := writeTransactionMetadataFromRequest(body)
	if err != nil {
		return err
	}
	transaction := acquireWriteTransaction(resources, body.GetTransactionId())
	if transaction == nil || !sameWriteTransactionMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return h.fenceWriteTransactionMismatch(id)
	}
	transaction.mu.Lock()
	if !writeTransactionRegistered(resources, transaction) || transaction.state != writeTransactionStaging || transaction.staged != body.GetFragmentOffset() {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return h.fenceWriteTransactionMismatch(id)
	}
	// From this point the transaction cannot be swept or aborted. The replay
	// slot owns every terminal outcome, including a definite refusal while
	// waiting for visibility order.
	transaction.state = writeTransactionCommitting
	transaction.mu.Unlock()
	transaction.refs.Done()
	return nil
}

// rejectPendingWriteTransaction consumes a COMMIT that entered the exact
// replay/source-gate state but was refused before storage apply. It returns a
// structured REJECTED result so the patched kernel can prove no bytes landed,
// discard its staged syscall, and avoid treating an ordinary admission error
// as an ambiguous transport failure.
func (h *VolumeHandler) rejectPendingWriteTransaction(id volumeserver.SessionID, body *authoritypb.WriteTransactionRequest, cause error) *authoritypb.Response {
	resources, err := h.writeTransactionResources(id)
	if err != nil {
		return nil
	}
	metadata, err := writeTransactionMetadataFromRequest(body)
	if err != nil {
		return nil
	}
	transaction := acquireWriteTransaction(resources, body.GetTransactionId())
	if transaction == nil || !sameWriteTransactionMetadata(transaction.metadata, metadata) {
		if transaction != nil {
			transaction.refs.Done()
		}
		return nil
	}
	transaction.mu.Lock()
	if !writeTransactionRegistered(resources, transaction) || transaction.state != writeTransactionCommitting {
		transaction.mu.Unlock()
		transaction.refs.Done()
		return nil
	}
	resources.writeMu.Lock()
	cleanup := h.removeWriteTransactionLocked(resources, transaction, writeTransactionTerminalRejected, cause)
	resources.writeMu.Unlock()
	transaction.mu.Unlock()
	transaction.refs.Done()
	cleanup.finish()
	return writeTransactionRejection(wireErrno(cause), body.GetTransactionId(), false)
}

// markWriteTransactionPostApplyFailure preserves the exact committed prefix
// when visibility completion fails after XFS apply. The source kernel must
// install and publish that result before receiving the failure; returning a
// generic outer error would erase the only safe offset/size truth and invite a
// duplicate append on retry.
func markWriteTransactionPostApplyFailure(response *authoritypb.Response, cause error) bool {
	if response == nil || cause == nil {
		return false
	}
	reply := response.GetWriteTransaction()
	if reply == nil || reply.GetFlags()&writeTransactionReplyCommitted == 0 {
		return false
	}
	reply.Flags |= writeTransactionReplyPostApply
	reply.Error = -wireErrno(cause)
	if reply.Error >= 0 {
		reply.Error = -int32(syscall.EIO)
	}
	response.Errno = 0
	response.Uncertain = false
	return true
}

// SweepWriteTransactions releases inert staging whose progress or absolute
// deadline elapsed. COMMITTING is never swept: once mutation assignment begins,
// exact replay/fencing owns the outcome and cleanup cannot guess no-apply.
func (h *VolumeHandler) SweepWriteTransactions(now time.Time) {
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
		resource.writeMu.Lock()
		transactions := make([]*writeTransaction, 0, len(resource.writeTransactions))
		for _, transaction := range resource.writeTransactions {
			transaction.refs.Add(1)
			transactions = append(transactions, transaction)
		}
		resource.writeMu.Unlock()
		for _, transaction := range transactions {
			// Wait outside the ledger for active work to publish its new progress
			// deadline. This prevents timeout cleanup from closing a live WriteAt,
			// while the session registry and every unrelated transaction remain
			// available throughout the wait.
			transaction.mu.Lock()
			var cleanup writeTransactionCleanup
			if writeTransactionRegistered(resource, transaction) && transaction.state == writeTransactionStaging &&
				(!now.Before(transaction.progressDeadline) || !now.Before(transaction.absoluteDeadline)) {
				resource.writeMu.Lock()
				cleanup = h.removeWriteTransactionLocked(resource, transaction, writeTransactionTerminalAborted, nil)
				resource.writeMu.Unlock()
			}
			transaction.mu.Unlock()
			transaction.refs.Done()
			cleanup.finish()
		}
	}
}

func closeWriteTransactions(h *VolumeHandler, resources *sessionResources) []writeTransactionCleanup {
	if h == nil || resources == nil {
		return nil
	}
	resources.writeMu.Lock()
	defer resources.writeMu.Unlock()
	cleanup := make([]writeTransactionCleanup, 0, len(resources.writeTransactions))
	for _, transaction := range resources.writeTransactions {
		cleanup = append(cleanup, h.removeWriteTransactionLocked(resources, transaction, writeTransactionTerminalAborted, nil))
	}
	resources.writeTransactions = nil
	resources.writeTerminal = nil
	return cleanup
}
