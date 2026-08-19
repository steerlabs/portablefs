package authoritymetrics

import (
	"fmt"
	"time"
)

type Operation uint8

const (
	OperationUnknown Operation = iota
	OperationHello
	OperationAttach
	OperationResume
	OperationActivate
	OperationAbortAttach
	OperationKeepAlive
	OperationReauthorize
	OperationDetach
	OperationCancel
	OperationTerminalDeliveryReceipt
	OperationNextFskitRepair
	OperationAckFskitRepair
	OperationApplyRoutes
	OperationLookup
	OperationGetAttr
	OperationSetAttr
	OperationCreate
	OperationMkdir
	OperationUnlink
	OperationRename
	OperationLink
	OperationSymlink
	OperationReadlink
	OperationOpen
	OperationClose
	OperationRead
	OperationWrite
	OperationFskitWriteBegin
	OperationFskitWriteData
	OperationFskitWriteCommit
	OperationFskitWriteAbort
	OperationFallocate
	OperationCopyFileRange
	OperationTmpfile
	OperationFsync
	OperationReadDir
	OperationReclaim
	OperationFlush
	OperationGetXattr
	OperationSetXattr
	OperationListXattr
	OperationRemoveXattr
	OperationStatFS
	OperationSyncFS
	OperationGetLock
	OperationSetLock
	operationCount
)

var operationNames = [...]string{
	"unknown", "hello", "attach", "resume", "activate", "abort_attach", "keep_alive", "reauthorize", "detach", "cancel",
	"terminal_delivery_receipt", "next_fskit_repair", "ack_fskit_repair", "apply_routes", "lookup", "getattr", "setattr", "create",
	"mkdir", "unlink", "rename", "link", "symlink", "readlink", "open", "close", "read", "positioned_write", "fskit_write_begin",
	"fskit_write_data", "fskit_write_commit", "fskit_write_abort", "fallocate", "copy_file_range", "tmpfile",
	"fsync", "readdir", "reclaim", "flush", "getxattr", "setxattr", "listxattr", "removexattr", "statfs", "syncfs",
	"getlock", "setlock",
}

func (o Operation) String() string {
	if o >= operationCount {
		return operationNames[OperationUnknown]
	}
	return operationNames[o]
}

type Outcome uint8

const (
	OutcomeSuccess Outcome = iota
	OutcomeNotFound
	OutcomePermission
	OutcomeStale
	OutcomeInvalid
	OutcomeSaturation
	OutcomeUnsupported
	OutcomeConflict
	OutcomeCanceled
	OutcomeStorage
	OutcomeInternal
	OutcomeCoherence
	OutcomeRoutes
	OutcomeFskitRepairInterrupted
	OutcomeFskitRepairRetry
	OutcomeIO
	OutcomeOther
	outcomeCount
)

var outcomeNames = [...]string{
	"success", "not_found", "permission", "stale", "invalid", "saturation", "unsupported", "conflict", "canceled",
	"storage", "internal", "coherence", "routes", "fskit_repair_interrupted", "fskit_repair_retry", "io", "other",
}

func (o Outcome) String() string {
	if o >= outcomeCount {
		return outcomeNames[OutcomeOther]
	}
	return outcomeNames[o]
}

type FenceReason uint8

const (
	FenceFskitRepairLost FenceReason = iota
	FenceRepairDeadline
	FenceRoutesBlocked
	FenceProtocolViolation
	FenceFskitWriteMismatch
	FenceOther
	fenceReasonCount
)

var fenceReasonNames = [...]string{
	"fskit_repair_lost", "repair_deadline", "routes_blocked", "protocol_violation", "fskit_write_mismatch", "other",
}

type rpcSeries struct {
	requests *Counter
}

// Metrics is the complete bounded series inventory for one volume worker.
// Arrays make operation/outcome selection a direct index into precomputed
// handles rather than a label map lookup.
type Metrics struct {
	volume               string
	registry             *Registry
	rpc                  [operationCount][outcomeCount]rpcSeries
	rpcDuration          [operationCount]*Histogram
	activeSessions       *Gauge
	itemsHighWater       *Gauge
	writeTransactions    *Gauge
	writeWaiting         *Gauge
	writeStagedBytes     *Gauge
	writeAdmissionBlocks *Counter
	writeAdmissionWait   *Histogram
	fsyncBarrierHandles  *Counter
	fsyncStorageSyncs    *Counter
	visibilityDuration   *Histogram
	visibilityAudience   *Histogram
	fences               [fenceReasonCount]*Counter
}

var rpcDurationBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

var admissionDurationBuckets = []float64{
	0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 120,
}

var visibilityDurationBuckets = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
}

var visibilityAudienceBuckets = []float64{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}

func New(volume string) (*Metrics, error) {
	if volume == "" {
		return nil, fmt.Errorf("authoritymetrics: volume is required")
	}
	registry := NewRegistry()
	metrics := &Metrics{volume: volume, registry: registry}
	base := Label{Name: "volume", Value: volume}
	var err error
	for operation := Operation(0); operation < operationCount; operation++ {
		for outcome := Outcome(0); outcome < outcomeCount; outcome++ {
			metrics.rpc[operation][outcome].requests, err = registry.RegisterCounter(
				"portablefs_authority_rpc_requests_total",
				"Completed authority RPCs by operation and semantic errno class.",
				base, Label{Name: "opcode", Value: operation.String()}, Label{Name: "outcome", Value: outcome.String()},
			)
			if err != nil {
				return nil, err
			}
		}
		metrics.rpcDuration[operation], err = registry.RegisterHistogram(
			"portablefs_authority_rpc_duration_seconds",
			"Authority handler latency in seconds by operation.", rpcDurationBuckets,
			base, Label{Name: "opcode", Value: operation.String()},
		)
		if err != nil {
			return nil, err
		}
	}
	metrics.activeSessions, err = registry.RegisterGauge("portablefs_authority_active_sessions", "Currently active mount sessions.", base)
	if err != nil {
		return nil, err
	}
	metrics.itemsHighWater, err = registry.RegisterGauge("portablefs_authority_session_items_high_water", "Largest descriptor-backed item table observed for one session since process start.", base)
	if err != nil {
		return nil, err
	}
	metrics.writeTransactions, err = registry.RegisterGauge("portablefs_authority_write_transactions_active", "Currently admitted staged FSKit writes.", base)
	if err != nil {
		return nil, err
	}
	metrics.writeWaiting, err = registry.RegisterGauge("portablefs_authority_write_transactions_waiting", "FSKit writes currently waiting in FIFO staging admission.", base)
	if err != nil {
		return nil, err
	}
	metrics.writeStagedBytes, err = registry.RegisterGauge("portablefs_authority_write_staged_bytes", "Payload bytes currently written into inert transaction staging.", base)
	if err != nil {
		return nil, err
	}
	metrics.writeAdmissionBlocks, err = registry.RegisterCounter("portablefs_authority_write_admission_blocks_total", "FSKit writes that had to wait for staging capacity.", base)
	if err != nil {
		return nil, err
	}
	metrics.writeAdmissionWait, err = registry.RegisterHistogram("portablefs_authority_write_admission_wait_seconds", "Time spent waiting in FIFO FSKit-write staging admission.", admissionDurationBuckets, base)
	if err != nil {
		return nil, err
	}
	metrics.fsyncBarrierHandles, err = registry.RegisterCounter("portablefs_authority_fsync_barrier_handles_total", "Fsync barrier requests assigned to completed storage-sync batches.", base)
	if err != nil {
		return nil, err
	}
	metrics.fsyncStorageSyncs, err = registry.RegisterCounter("portablefs_authority_fsync_storage_syncs_total", "Completed storage sync syscalls serving fsync barrier batches.", base)
	if err != nil {
		return nil, err
	}
	metrics.visibilityDuration, err = registry.RegisterHistogram("portablefs_authority_visibility_barrier_duration_seconds", "Time from visibility PREPARE dispatch through COMPLETE acknowledgments.", visibilityDurationBuckets, base)
	if err != nil {
		return nil, err
	}
	metrics.visibilityAudience, err = registry.RegisterHistogram("portablefs_authority_visibility_barrier_audience", "Number of peer sessions selected for one visibility barrier.", visibilityAudienceBuckets, base)
	if err != nil {
		return nil, err
	}
	for reason := FenceReason(0); reason < fenceReasonCount; reason++ {
		metrics.fences[reason], err = registry.RegisterCounter(
			"portablefs_authority_fence_events_total", "Participant fence or revocation events by bounded reason.",
			base, Label{Name: "reason", Value: fenceReasonNames[reason]},
		)
		if err != nil {
			return nil, err
		}
	}
	return metrics, nil
}

func (m *Metrics) Registry() *Registry {
	if m == nil {
		return nil
	}
	return m.registry
}

func (m *Metrics) Volume() string {
	if m == nil {
		return ""
	}
	return m.volume
}

func (m *Metrics) ObserveRPC(operation Operation, outcome Outcome, elapsed time.Duration) {
	if m == nil {
		return
	}
	if operation >= operationCount {
		operation = OperationUnknown
	}
	if outcome >= outcomeCount {
		outcome = OutcomeOther
	}
	m.rpc[operation][outcome].requests.Inc()
	m.rpcDuration[operation].Observe(elapsed.Seconds())
}

func (m *Metrics) SessionActivated() {
	if m != nil {
		m.activeSessions.Inc()
	}
}
func (m *Metrics) SessionEnded() {
	if m != nil {
		m.activeSessions.Dec()
	}
}
func (m *Metrics) ObserveSessionItems(items int) {
	if m != nil {
		m.itemsHighWater.SetMax(int64(items))
	}
}
func (m *Metrics) WriteTransactionAdmitted() {
	if m != nil {
		m.writeTransactions.Inc()
	}
}
func (m *Metrics) WriteTransactionReleased() {
	if m != nil {
		m.writeTransactions.Dec()
	}
}
func (m *Metrics) WriteStagedBytes(delta int64) {
	if m != nil {
		m.writeStagedBytes.Add(delta)
	}
}

func (m *Metrics) WriteAdmissionBlocked() {
	if m == nil {
		return
	}
	m.writeAdmissionBlocks.Inc()
	m.writeWaiting.Inc()
}

func (m *Metrics) WriteAdmissionFinished(elapsed time.Duration) {
	if m == nil {
		return
	}
	m.writeWaiting.Dec()
	m.writeAdmissionWait.Observe(elapsed.Seconds())
}

// ObserveFsyncBatch records the two counters whose ratio is the group-commit
// effectiveness: barrier handles per real storage sync.
func (m *Metrics) ObserveFsyncBatch(handles int) {
	if m == nil || handles <= 0 {
		return
	}
	m.fsyncBarrierHandles.Add(uint64(handles))
	m.fsyncStorageSyncs.Inc()
}

func (m *Metrics) ObserveVisibilityBarrier(elapsed time.Duration, audience int) {
	if m == nil {
		return
	}
	m.visibilityDuration.Observe(elapsed.Seconds())
	m.visibilityAudience.Observe(float64(audience))
}

func (m *Metrics) Fence(reason FenceReason) {
	if m == nil {
		return
	}
	if reason >= fenceReasonCount {
		reason = FenceOther
	}
	m.fences[reason].Inc()
}
