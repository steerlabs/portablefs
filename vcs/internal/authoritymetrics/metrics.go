package authoritymetrics

import (
	"fmt"
	"sync/atomic"
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
	OperationSubscribe
	OperationRenewSubscription
	OperationNextControlEvent
	OperationChangeAck
	OperationDelegationRecallAck
	OperationDelegationBreakAck
	OperationDelegationModeChangeAck
	OperationDelegationRelease
	OperationBarrier
	OperationWaitVisibility
	operationCount
)

var operationNames = [...]string{
	"unknown", "hello", "attach", "resume", "activate", "abort_attach", "keep_alive", "reauthorize", "detach", "cancel",
	"terminal_delivery_receipt", "apply_routes", "lookup", "getattr", "setattr", "create",
	"mkdir", "unlink", "rename", "link", "symlink", "readlink", "open", "close", "read", "positioned_write", "fskit_write_begin",
	"fallocate", "copy_file_range", "tmpfile",
	"fsync", "readdir", "reclaim", "flush", "getxattr", "setxattr", "listxattr", "removexattr", "statfs", "syncfs",
	"getlock", "setlock",
	"subscribe", "renew_subscription", "next_control_event", "change_ack", "delegation_recall_ack", "delegation_break_ack", "delegation_mode_change_ack", "delegation_release", "barrier", "wait_visibility",
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
	OutcomeIO
	OutcomeOther
	outcomeCount
)

var outcomeNames = [...]string{
	"success", "not_found", "permission", "stale", "invalid", "saturation", "unsupported", "conflict", "canceled",
	"storage", "internal", "coherence", "routes", "io", "other",
}

func (o Outcome) String() string {
	if o >= outcomeCount {
		return outcomeNames[OutcomeOther]
	}
	return outcomeNames[o]
}

type FenceReason uint8

const (
	FenceProtocolViolation FenceReason = iota
	FenceOther
	fenceReasonCount
)

var fenceReasonNames = [...]string{
	"protocol_violation", "other",
}

type rpcSeries struct {
	requests *Counter
}

// Metrics is the complete bounded series inventory for one volume worker.
// Arrays make operation/outcome selection a direct index into precomputed
// handles rather than a label map lookup.
type Metrics struct {
	coherenceSource         atomic.Pointer[coherenceSource]
	volume                  string
	registry                *Registry
	rpc                     [operationCount][outcomeCount]rpcSeries
	rpcDuration             [operationCount]*Histogram
	mutations               [3]*Counter
	activeSessions          *Gauge
	itemsHighWater          *Gauge
	fsyncBarrierHandles     *Counter
	fsyncStorageSyncs       *Counter
	storageSyncs            [3]*Counter
	storageSyncDuration     [3]*Histogram
	storageSyncWaiters      [3]*Counter
	fskitDurabilitySyncs    [2]*Counter
	fskitDurabilityDuration [2]*Histogram
	fences                  [fenceReasonCount]*Counter
}

var rpcDurationBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

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
	for index, disposition := range []string{"executed", "replayed", "refused"} {
		metrics.mutations[index], err = registry.RegisterCounter("portablefs_authority_mutations_total", "Replay-tracked requests by execution disposition.", base, Label{Name: "disposition", Value: disposition})
		if err != nil {
			return nil, err
		}
	}
	metrics.itemsHighWater, err = registry.RegisterGauge("portablefs_authority_session_items_high_water", "Largest descriptor-backed item table observed for one session since process start.", base)
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
	for index, kind := range []string{"fsync", "fdatasync", "syncfs"} {
		labels := []Label{base, {Name: "syscall", Value: kind}}
		metrics.storageSyncs[index], err = registry.RegisterCounter("portablefs_authority_storage_syncs_total", "Actual persistence syscalls, including failed calls.", labels...)
		if err != nil {
			return nil, err
		}
		metrics.storageSyncWaiters[index], err = registry.RegisterCounter("portablefs_authority_storage_sync_waiters_total", "Logical requests in physical persistence batches.", labels...)
		if err != nil {
			return nil, err
		}
		metrics.storageSyncDuration[index], err = registry.RegisterHistogram("portablefs_authority_storage_sync_duration_seconds", "Actual persistence syscall latency.", rpcDurationBuckets, labels...)
		if err != nil {
			return nil, err
		}
	}
	for index, kind := range []string{"handle", "syncfs"} {
		labels := []Label{base, {Name: "target", Value: kind}}
		metrics.fskitDurabilitySyncs[index], err = registry.RegisterCounter("portablefs_authority_fskit_durability_syncs_total", "Required FSKit mutation durability barriers by target kind.", labels...)
		if err != nil {
			return nil, err
		}
		metrics.fskitDurabilityDuration[index], err = registry.RegisterHistogram("portablefs_authority_fskit_durability_duration_seconds", "FSKit mutation durability barrier latency by target kind.", rpcDurationBuckets, labels...)
		if err != nil {
			return nil, err
		}
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
	if err := metrics.registerCoherenceMetrics(base); err != nil {
		return nil, err
	}
	return metrics, nil
}

func (m *Metrics) ObserveMutation(disposition string) {
	if m == nil {
		return
	}
	index := 0
	switch disposition {
	case "executed":
	case "replayed":
		index = 1
	case "refused":
		index = 2
	default:
		return
	}
	m.mutations[index].Add(1)
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

// ObserveFsyncBatch records the two counters whose ratio is the group-commit
// effectiveness: barrier handles per real storage sync.
func (m *Metrics) ObserveFsyncBatch(handles int) {
	if m == nil || handles <= 0 {
		return
	}
	m.fsyncBarrierHandles.Add(uint64(handles))
	m.fsyncStorageSyncs.Inc()
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

// ObserveFskitDurability counts obligations, including failed barriers. The
// target vocabulary is fixed and never contains capability or inode labels.
func (m *Metrics) ObserveFskitDurability(kind string, elapsed time.Duration) {
	if m == nil {
		return
	}
	index := 0
	switch kind {
	case "handle":
		index = 0
	case "syncfs":
		index = 1
	default:
		return
	}
	m.fskitDurabilitySyncs[index].Inc()
	m.fskitDurabilityDuration[index].Observe(elapsed.Seconds())
}

// ObserveStorageSync records physical calls, distinct from logical FSKit
// durability obligations and coalesced waiter counts.
func (m *Metrics) ObserveStorageSync(kind string, elapsed time.Duration, waiters int) {
	if m == nil {
		return
	}
	var index int
	switch kind {
	case "fsync":
		index = 0
	case "fdatasync":
		index = 1
	case "syncfs":
		index = 2
	default:
		return
	}
	m.storageSyncs[index].Inc()
	if waiters > 0 {
		m.storageSyncWaiters[index].Add(uint64(waiters))
	}
	m.storageSyncDuration[index].Observe(elapsed.Seconds())
}
