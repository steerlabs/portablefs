package remotejournal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/ctlrec"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// AppendBatchBuffered reserves ONE contiguous LSN range under the log's
// serializer and stages the records in bounded memory: each record is encoded
// to PFR1 exactly once here, and those identical bytes later become the
// database row, the hash/chain input, the duplicate identity, and the retry
// body. Nothing is durable or visible yet. All-or-nothing: every record is
// encoded and bounds-checked before any state changes, so a failure consumes
// no LSN.
func (l *Log) AppendBatchBuffered(records []wal.Record) (firstSeq, endSeq uint64, err error) {
	if len(records) == 0 {
		return 0, 0, fmt.Errorf("remotejournal: empty batch")
	}
	if l.readOnly {
		return 0, 0, errReadOnly
	}
	if err := l.requireRecordLog("AppendBatchBuffered"); err != nil {
		return 0, 0, err
	}
	l.admissionMu.Lock()
	defer l.admissionMu.Unlock()

	commitLocked := false
	l.mu.Lock()
	defer func() {
		l.mu.Unlock()
		if commitLocked {
			l.commitMu.Unlock()
		}
	}()
	if l.suspending || l.suspended {
		return 0, 0, ErrFenced
	}
	if l.poisoned {
		return 0, 0, wal.ErrPoisoned
	}
	first := l.nextSeq
	if first > uint64(math.MaxInt64) || uint64(len(records)) > uint64(math.MaxInt64)-first {
		return 0, 0, fmt.Errorf("%w: reserving %d records at LSN %d exceeds PostgreSQL BIGINT",
			ErrBounds, len(records), first)
	}
	staged := make([]stagedRecord, len(records))
	startTip := l.tip
	tip := startTip
	var addBytes int64
	for i := range records {
		record := records[i]
		record.Seq = first + uint64(i)
		payload, encErr := wal.EncodePFR1(&record)
		if encErr != nil {
			return 0, 0, fmt.Errorf("remotejournal: encode record %d: %w", record.Seq, encErr)
		}
		hash := wal.ChainDigestBytes([32]byte{}, payload)
		tip = wal.ChainDigestBytes(tip, payload)
		staged[i] = stagedRecord{
			seq:      record.Seq,
			payload:  payload,
			hashHex:  hex.EncodeToString(hash[:]),
			tipAfter: tip,
		}
		addBytes += int64(len(payload))
	}
	projection, projectionErr := l.projectBacklogLocked(addBytes, int64(len(staged)))
	if projectionErr != nil {
		return 0, 0, projectionErr
	}
	if projection.stagedBytes > l.cfg.MaxStagedBytes {
		return 0, 0, fmt.Errorf("%w: staging %d bytes over %d already pending exceeds the %d-byte staging bound",
			ErrBounds, addBytes, l.stagedBytes, l.cfg.MaxStagedBytes)
	}
	// Quotas are generation-immutable database facts mirrored from the exact
	// claim/append responses. Check the projected durable+staged backlog before
	// publishing the reserved LSN range locally. The SQL append repeats this
	// under the generation row lock, so this is admission without weakening the
	// authoritative transactional check.
	if l.projectionExceedsCapacityLocked(projection, false) {
		// A different service may have landed a HistoryCut/logical trim since
		// this process last received a generation snapshot. Preserve ordinary
		// zero-RTT admission, but on the near-capacity path serialize against a
		// local commit, refresh authoritative durable facts with a zero-addition
		// bound query, then recompute DB backlog + local staging + candidate.
		// admissionMu keeps first/tip stable across the lock handoff.
		l.mu.Unlock()
		l.commitMu.Lock()
		commitLocked = true
		l.mu.Lock()
		if l.suspending || l.suspended {
			return 0, 0, ErrFenced
		}
		if l.poisoned {
			return 0, 0, wal.ErrPoisoned
		}
		if l.nextSeq != first || l.tip != startTip {
			return 0, 0, fmt.Errorf("%w: append revision changed during capacity refresh handoff", ErrConflict)
		}
		projection, projectionErr = l.projectBacklogLocked(addBytes, int64(len(staged)))
		if projectionErr != nil {
			return 0, 0, projectionErr
		}
		if l.projectionExceedsCapacityLocked(projection, false) {
			if refreshErr := l.refreshCapacityLocked(); refreshErr != nil {
				if errors.Is(refreshErr, ErrFenced) {
					l.poisonLocked(refreshErr)
				}
				return 0, 0, refreshErr
			}
			projection, projectionErr = l.projectBacklogLocked(addBytes, int64(len(staged)))
			if projectionErr != nil {
				return 0, 0, projectionErr
			}
		}
		if l.projectionExceedsCapacityLocked(projection, false) {
			return 0, 0, l.capacityErrorLocked(projection)
		}
	}
	for i := range records {
		records[i].Seq = staged[i].seq
	}
	l.staged = append(l.staged, staged...)
	l.stagedBytes = projection.stagedBytes
	l.nextSeq = first + uint64(len(records))
	l.tip = tip
	return first, l.nextSeq, nil
}

// backlogProjection is a checked view of durable DB backlog plus all local
// uncommitted staging after adding one candidate batch.
type backlogProjection struct {
	stagedBytes   int64
	stagedRecords int64
	totalBytes    int64
	totalRecords  int64
}

func (l *Log) projectBacklogLocked(addBytes, addRecords int64) (backlogProjection, error) {
	stagedBytes, ok := addNonnegativeInt64(l.stagedBytes, addBytes)
	if !ok {
		return backlogProjection{}, fmt.Errorf("%w: staged-byte accounting exceeds PostgreSQL BIGINT", ErrBounds)
	}
	stagedRecords, ok := addNonnegativeInt64(int64(len(l.staged)), addRecords)
	if !ok {
		return backlogProjection{}, fmt.Errorf("%w: staged-record accounting exceeds PostgreSQL BIGINT", ErrBounds)
	}
	totalBytes, ok := addNonnegativeInt64(l.backlogBytes, stagedBytes)
	if !ok {
		return backlogProjection{}, fmt.Errorf("%w: projected backlog-byte accounting exceeds PostgreSQL BIGINT", ErrBounds)
	}
	totalRecords, ok := addNonnegativeInt64(l.backlogRecords, stagedRecords)
	if !ok {
		return backlogProjection{}, fmt.Errorf("%w: projected backlog-record accounting exceeds PostgreSQL BIGINT", ErrBounds)
	}
	return backlogProjection{
		stagedBytes: stagedBytes, stagedRecords: stagedRecords,
		totalBytes: totalBytes, totalRecords: totalRecords,
	}, nil
}

// Control reserve: a HIDDEN bounded headroom above the data quota that only
// CONTROL-ONLY journal rows (no tree arm — durable rejection outcomes,
// session renew/terminal, lock releases, unpins, barriers) may consume. It
// exists so exactness never becomes unrecordable at data-quota exhaustion: a
// full volume can still journal the durable EDQUOT outcome, release its
// coordination state, and terminalize sessions. Statfs never reports the
// reserve as free space, and tree-bearing rows never use it. The SQL append
// enforces quota + the same reserve as defense in depth (it cannot cheaply
// distinguish row classes); the authority is the only writer and classifies
// exactly here.
const (
	ControlReserveBytes   int64 = 8 << 20
	ControlReserveRecords int64 = 8192
)

func (l *Log) projectionExceedsCapacityLocked(projection backlogProjection, controlOnly bool) bool {
	quotaBytes, quotaRecords := l.quotaBytes, l.quotaRecords
	if controlOnly {
		if quotaBytes > 0 {
			quotaBytes += ControlReserveBytes
		}
		if quotaRecords > 0 {
			quotaRecords += ControlReserveRecords
		}
	}
	return (quotaBytes > 0 && projection.totalBytes > quotaBytes) ||
		(quotaRecords > 0 && projection.totalRecords > quotaRecords) ||
		(l.advisoryCapacity > 0 && projection.totalBytes > l.advisoryCapacity && !controlOnly)
}

func (l *Log) capacityErrorLocked(projection backlogProjection) error {
	if l.advisoryCapacity > 0 && projection.totalBytes > l.advisoryCapacity {
		return fmt.Errorf("%w: projected backlog %d exceeds advisory capacity %d",
			ErrQuota, projection.totalBytes, l.advisoryCapacity)
	}
	return fmt.Errorf("%w: projected backlog is %d bytes/%d records (quota %d/%d)",
		ErrQuota, projection.totalBytes, projection.totalRecords, l.quotaBytes, l.quotaRecords)
}

type quotaRefreshJSON struct {
	Allowed             *bool          `json:"allowed"`
	GenerationID        string         `json:"generationId"`
	BranchName          string         `json:"branchName"`
	Epoch               *decimalUint64 `json:"epoch"`
	BaseCommitID        string         `json:"baseCommitId"`
	BaseSeq             *decimalUint64 `json:"baseSeq"`
	BaseDigest          string         `json:"baseDigest"`
	PhysicalTrimmedSeq  *decimalUint64 `json:"physicalTrimmedSeq"`
	Cut                 *cutJSON       `json:"cut"`
	BacklogBytes        *decimalInt64  `json:"backlogBytes"`
	BacklogRecords      *decimalInt64  `json:"backlogRecords"`
	QuotaBacklogBytes   *decimalInt64  `json:"quotaBacklogBytes"`
	QuotaBacklogRecords *decimalInt64  `json:"quotaBacklogRecords"`
	RemainingBytes      *decimalInt64  `json:"remainingBytes"`
	RemainingRecords    *decimalInt64  `json:"remainingRecords"`
}

// refreshCapacityLocked performs the uncommon zero-addition quota preflight.
// Callers hold admissionMu, commitMu, and l.mu, so the refreshed durable facts
// and local staged facts form one stable admission snapshot. External trims
// may race after this query only in the safe direction (more free capacity);
// every eventual append still repeats the authoritative check transactionally.
func (l *Log) refreshCapacityLocked() error {
	refreshRecordCodec, refreshControlCodec := l.codecPair()
	raw, err := l.callIdempotent(
		`SELECT pfj.journal_check_append_quota($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		refreshRecordCodec, refreshControlCodec,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
		int64(0), int64(0),
	)
	if err != nil {
		return fmt.Errorf("remotejournal: refresh journal capacity: %w", err)
	}
	var refreshed quotaRefreshJSON
	if err := json.Unmarshal(raw, &refreshed); err != nil {
		return fmt.Errorf("%w: decode quota refresh response: %v", ErrAccounting, err)
	}
	if refreshed.Allowed == nil || !*refreshed.Allowed || refreshed.Epoch == nil ||
		refreshed.BaseSeq == nil || refreshed.PhysicalTrimmedSeq == nil ||
		refreshed.BacklogBytes == nil || refreshed.BacklogRecords == nil ||
		refreshed.QuotaBacklogBytes == nil || refreshed.QuotaBacklogRecords == nil ||
		refreshed.RemainingBytes == nil || refreshed.RemainingRecords == nil {
		return fmt.Errorf("%w: quota refresh response is missing exact fields", ErrAccounting)
	}
	if refreshed.GenerationID != l.generationID || refreshed.BranchName != l.cfg.Branch ||
		uint64(*refreshed.Epoch) != l.epoch || refreshed.BaseCommitID == "" || len(refreshed.BaseCommitID) > 512 {
		return fmt.Errorf("%w: quota refresh returned another journal generation", ErrConflict)
	}
	baseSeq := uint64(*refreshed.BaseSeq)
	physicalTrimmedSeq := uint64(*refreshed.PhysicalTrimmedSeq)
	if baseSeq > l.durableSeq || physicalTrimmedSeq > baseSeq {
		return fmt.Errorf("%w: quota refresh returned invalid base/trim revision (%d/%d, local base/head %d/%d)",
			ErrAccounting, baseSeq, physicalTrimmedSeq, l.baseSeq, l.durableSeq)
	}
	baseDigest, err := decodeDigest(refreshed.BaseDigest)
	if err != nil || hex.EncodeToString(baseDigest[:]) != refreshed.BaseDigest ||
		(baseSeq == l.durableSeq && baseDigest != l.durableTip) {
		return fmt.Errorf("%w: quota refresh returned a non-canonical base digest", ErrAccounting)
	}
	backlogBytes := int64(*refreshed.BacklogBytes)
	backlogRecords := int64(*refreshed.BacklogRecords)
	quotaBytes := int64(*refreshed.QuotaBacklogBytes)
	quotaRecords := int64(*refreshed.QuotaBacklogRecords)
	remainingBytes := int64(*refreshed.RemainingBytes)
	remainingRecords := int64(*refreshed.RemainingRecords)
	// A backlog inside the control-reserve band above the data quota is
	// legitimate (control-only rows land there); remaining* may then be
	// negative by exactly the overshoot.
	if quotaBytes <= 0 || quotaRecords <= 0 ||
		backlogBytes > quotaBytes+ControlReserveBytes || backlogRecords > quotaRecords+ControlReserveRecords ||
		remainingBytes != quotaBytes-backlogBytes || remainingRecords != quotaRecords-backlogRecords {
		return fmt.Errorf("%w: quota refresh accounting is inconsistent", ErrAccounting)
	}
	var cut wal.CheckpointCut
	hasCut := refreshed.Cut != nil
	if hasCut {
		cut, err = validateCutJSON(refreshed.Cut, l.epoch, l.durableSeq)
		if err != nil {
			return fmt.Errorf("%w: invalid quota refresh checkpoint cut: %v", ErrAccounting, err)
		}
	}
	span := l.durableSeq - baseSeq
	if span > math.MaxInt64 || backlogRecords != int64(span) {
		return fmt.Errorf("%w: quota refresh backlog does not cover the exact retained range", ErrAccounting)
	}
	validated := validatedGeneration{
		epoch: l.epoch, baseSeq: baseSeq, baseDigest: baseDigest,
		nextSeq: l.durableSeq, tipDigest: l.durableTip,
		physicalTrimmedSeq: physicalTrimmedSeq,
		backlogBytes:       backlogBytes, backlogRecords: backlogRecords,
		quotaBytes: quotaBytes, quotaRecords: quotaRecords,
		cut: cut, hasCut: hasCut,
	}
	transitionHead := generationJSON{BaseCommitID: refreshed.BaseCommitID}
	if err := l.validateGenerationTransition(&transitionHead, validated); err != nil {
		return fmt.Errorf("remotejournal: invalid quota refresh transition: %w", err)
	}

	l.baseSeq = baseSeq
	l.physicalTrimmedSeq = physicalTrimmedSeq
	l.baseDigest = baseDigest
	l.baseCommitID = refreshed.BaseCommitID
	l.backlogBytes = backlogBytes
	l.backlogRecords = backlogRecords
	l.quotaBytes = quotaBytes
	l.quotaRecords = quotaRecords
	l.cut, l.hasCut = cut, hasCut
	return nil
}

// appendResult mirrors pfj.journal_append's response.
type appendResult struct {
	GenerationID             string         `json:"generationId"`
	Epoch                    *decimalUint64 `json:"epoch"`
	NextSeq                  *decimalUint64 `json:"nextSeq"`
	TipDigest                string         `json:"tipDigest"`
	Appended                 *decimalInt64  `json:"appended"`
	Duplicated               *decimalInt64  `json:"duplicated"`
	Replayed                 *bool          `json:"replayed"`
	CurrentBaseCommitID      string         `json:"currentBaseCommitId"`
	CurrentBaseSeq           *decimalUint64 `json:"currentBaseSeq"`
	CurrentBaseDigest        string         `json:"currentBaseDigest"`
	CurrentPhysicalTrimmed   *decimalUint64 `json:"currentPhysicalTrimmedSeq"`
	CurrentBacklogBytes      *decimalInt64  `json:"currentBacklogBytes"`
	CurrentBacklogRecords    *decimalInt64  `json:"currentBacklogRecords"`
	CurrentQuotaBytes        *decimalInt64  `json:"currentQuotaBacklogBytes"`
	CurrentQuotaRecords      *decimalInt64  `json:"currentQuotaBacklogRecords"`
	CurrentControlFloorMs    *decimalInt64  `json:"currentControlDbFloorMs"`
	CurrentCut               *cutJSON       `json:"currentCut"`
	currentBaseDigestDecoded [32]byte
	currentCutDecoded        wal.CheckpointCut
	hasCurrentCut            bool
}

// CommitThrough returns nil only when every record with LSN ≤ seq is durable
// in a committed database transaction. It flushes the WHOLE staged buffer in
// bounded groups (group commit), so one round of database transactions
// covers every concurrent caller.
//
// UNKNOWN outcomes (lost response, timeout, connection loss) are resolved by
// retrying the exact same group: the server folds byte-identical duplicates
// before quota, so the retry lands the group if it was lost or acknowledges
// it if it committed. Only a proven fence/conflict/integrity/quota failure
// poisons the log — the staged intent can never become durable, and the
// authority must fence before any visibility.
func (l *Log) CommitThrough(seq uint64) error {
	if l.readOnly {
		return errReadOnly
	}
	l.commitMu.Lock()
	defer l.commitMu.Unlock()
	for {
		l.mu.Lock()
		if l.suspending || l.suspended {
			l.mu.Unlock()
			return ErrFenced
		}
		if l.poisoned {
			cause := l.poisonCause
			l.mu.Unlock()
			if cause != nil {
				return fmt.Errorf("%w (cause: %v)", wal.ErrPoisoned, cause)
			}
			return wal.ErrPoisoned
		}
		if l.durableSeq > seq {
			l.mu.Unlock()
			return nil
		}
		if len(l.staged) == 0 {
			durable := l.durableSeq
			l.mu.Unlock()
			return fmt.Errorf("remotejournal: commit through %d with nothing staged (durable head %d)", seq, durable)
		}
		group := l.nextGroupLocked()
		l.mu.Unlock()

		res, err := l.appendGroup(group)
		if err != nil {
			return err
		}
		groupBytes := int64(0)
		for i := range group {
			groupBytes += int64(len(group[i].payload))
		}
		l.mu.Lock()
		if applyErr := l.applyAppendResultLocked(res, group, groupBytes); applyErr != nil {
			l.poisonLocked(applyErr)
			l.mu.Unlock()
			return applyErr
		}
		l.staged = l.staged[len(group):]
		if len(l.staged) == 0 {
			l.staged = nil // release the backing array once fully committed
		}
		l.stagedBytes -= groupBytes
		l.durableSeq = group[len(group)-1].seq + 1
		l.durableTip = group[len(group)-1].tipAfter
		l.mu.Unlock()
	}
}

// nextGroupLocked selects the staged prefix for one bounded commit group
// (≤ 128 records, ≤ 16 MiB, and — for PFJ3 rows — ≤ 128 total admission
// facts, matching the append transaction's consumption bound). The record
// cap costs one commit round trip per 128 records of a large flush; it still
// must match the frozen SQL backstop exactly (see wal.ProductionLogBounds),
// because a larger group is rejected server-side with PF004, which poisons
// the log. Caller holds l.mu; the returned slice aliases l.staged, which is
// safe because commitMu serializes commits and staging only ever appends.
func (l *Log) nextGroupLocked() []stagedRecord {
	bounds := wal.ProductionLogBounds()
	n := len(l.staged)
	if n > bounds.MaxGroupRecords {
		n = bounds.MaxGroupRecords
	}
	var bytes int64
	var facts int
	for i := 0; i < n; i++ {
		bytes += int64(len(l.staged[i].payload))
		facts += l.staged[i].factCount
		if (bytes > bounds.MaxGroupBytes || facts > pfj3.MaxFacts) && i > 0 {
			return l.staged[:i]
		}
	}
	return l.staged[:n]
}

// appendGroup lands one bounded group through pfj.journal_append, retrying
// identical bytes on non-typed failures until resolved or the lifecycle
// context ends. A typed pfj failure is proven (the server validated our exact
// request against durable state) and poisons the log.
func (l *Log) appendGroup(group []stagedRecord) (appendResult, error) {
	payloads := make([][]byte, len(group))
	hashes := make([]string, len(group))
	for i := range group {
		payloads[i] = group[i].payload
		hashes[i] = group[i].hashHex
	}
	firstSeq := group[0].seq
	firstSeqSQL, err := checkedSQLBigint("append first sequence", firstSeq)
	if err != nil {
		return appendResult{}, err
	}
	endTip := hex.EncodeToString(group[len(group)-1].tipAfter[:])

	// PFJ3 rows carry their admission facts INSIDE the exact bytes (the
	// manifest preamble); the append transaction parses, verifies, and
	// consumes them itself — there is deliberately no side-channel fact list
	// a caller could desynchronize from the bytes.
	appendSQL := `SELECT pfj.journal_append($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	appendArgs := []any{
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		wal.PFR1Codec, ctlrec.PFC1Codec,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
		firstSeqSQL, payloads, hashes, endTip,
	}
	if record, _ := l.codecPair(); record == pfj3RecordCodec {
		appendSQL = `SELECT pfj.journal_append_v3($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
		appendArgs = []any{
			l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
			l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
			firstSeqSQL, payloads, hashes, endTip,
		}
	}

	backoff := retryBackoffFloor
	invalidSuccesses := 0
	for {
		mustRetry := false
		raw, err := l.callJSONB(l.life, appendSQL, appendArgs...)
		if err == nil {
			var res appendResult
			if derr := json.Unmarshal(raw, &res); derr != nil {
				err = fmt.Errorf("decode append response: %w", derr)
				mustRetry = true
			} else if verr := l.validateAppendResult(&res, firstSeq, len(group), endTip); verr != nil {
				err = verr
				mustRetry = true
			} else {
				return res, nil
			}
			invalidSuccesses++
			if invalidSuccesses >= maxInvalidSuccessBodies {
				cause := fmt.Errorf("%w: append group [%d,%d) returned %d invalid success bodies (last: %v)",
					ErrProtocolIntegrity, firstSeq, firstSeq+uint64(len(group)), invalidSuccesses, err)
				l.poison(cause)
				return appendResult{}, cause
			}
		}
		if typed := typedError(err); typed != nil {
			if errors.Is(typed, ErrDurabilityUnavailable) {
				// PF015 is raised by the transaction guard before mutation. Keep
				// the already-reserved group intact and retry these exact bytes;
				// evidence may recover without losing the manager binding.
				err = typed
				mustRetry = true
			} else {
				cause := fmt.Errorf("remotejournal: append group [%d,%d): %w", firstSeq, firstSeq+uint64(len(group)), typed)
				l.poison(cause)
				return appendResult{}, cause
			}
		}
		if !mustRetry && !retryableSQLFailure(err) {
			return appendResult{}, fmt.Errorf("remotejournal: append group [%d,%d): %w",
				firstSeq, firstSeq+uint64(len(group)), err)
		}
		select {
		case <-l.life.Done():
			if errors.Is(err, ErrDurabilityUnavailable) {
				return appendResult{}, fmt.Errorf("%w: group [%d,%d) reached its lifecycle deadline: %v: %w",
					ErrUnknownOutcome, firstSeq, firstSeq+uint64(len(group)), l.life.Err(), err)
			}
			return appendResult{}, fmt.Errorf("%w: group [%d,%d): %v (last attempt: %v)",
				ErrUnknownOutcome, firstSeq, firstSeq+uint64(len(group)), l.life.Err(), err)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}

func (l *Log) validateAppendResult(
	res *appendResult,
	firstSeq uint64,
	groupSize int,
	endTip string,
) error {
	if res.GenerationID != l.generationID || res.Epoch == nil || uint64(*res.Epoch) != l.epoch ||
		res.NextSeq == nil || res.Appended == nil || res.Duplicated == nil || res.Replayed == nil ||
		res.CurrentBaseSeq == nil || res.CurrentPhysicalTrimmed == nil ||
		res.CurrentBacklogBytes == nil || res.CurrentBacklogRecords == nil ||
		res.CurrentQuotaBytes == nil || res.CurrentQuotaRecords == nil ||
		res.TipDigest == "" || res.CurrentBaseCommitID == "" || len(res.CurrentBaseCommitID) > 512 {
		return fmt.Errorf("remotejournal: append response is missing exact result fields")
	}
	if record, _ := l.codecPair(); record == pfj3RecordCodec {
		// The durable PFC2 control floor is a REQUIRED canonical decimal on
		// every PFJ3 append result and may never regress the mirror.
		if res.CurrentControlFloorMs == nil || int64(*res.CurrentControlFloorMs) < 0 {
			return fmt.Errorf("%w: PFJ3 append response is missing its canonical control floor", ErrProtocolIntegrity)
		}
		if int64(*res.CurrentControlFloorMs) < l.ControlDbFloorMs() {
			return fmt.Errorf("%w: append response regressed the control floor", ErrProtocolIntegrity)
		}
	}
	wantNext := firstSeq + uint64(groupSize)
	if uint64(*res.NextSeq) != wantNext || res.TipDigest != endTip {
		return fmt.Errorf("remotejournal: append response revision mismatch (next=%d tip=%s, want next=%d tip=%s)",
			*res.NextSeq, res.TipDigest, wantNext, endTip)
	}
	appended, duplicated := int64(*res.Appended), int64(*res.Duplicated)
	if appended > int64(groupSize) || duplicated > int64(groupSize) ||
		appended+duplicated != int64(groupSize) {
		return fmt.Errorf("remotejournal: append response accounting mismatch (appended=%d duplicated=%d group=%d)",
			appended, duplicated, groupSize)
	}
	baseSeq := uint64(*res.CurrentBaseSeq)
	physicalTrimmed := uint64(*res.CurrentPhysicalTrimmed)
	backlogBytes, backlogRecords := int64(*res.CurrentBacklogBytes), int64(*res.CurrentBacklogRecords)
	quotaBytes, quotaRecords := int64(*res.CurrentQuotaBytes), int64(*res.CurrentQuotaRecords)
	if physicalTrimmed > baseSeq || baseSeq > wantNext || wantNext-baseSeq > math.MaxInt64 ||
		backlogRecords != int64(wantNext-baseSeq) || quotaBytes <= 0 || quotaRecords <= 0 ||
		backlogBytes > quotaBytes+ControlReserveBytes || backlogRecords > quotaRecords+ControlReserveRecords {
		return fmt.Errorf("%w: append current base/backlog/quota facts are inconsistent", ErrAccounting)
	}
	baseDigest, ok := canonicalHexDigest(res.CurrentBaseDigest)
	endDigest, endOK := canonicalHexDigest(endTip)
	if !ok || !endOK || (baseSeq == wantNext && baseDigest != endDigest) {
		return fmt.Errorf("%w: append current base digest is non-canonical", ErrAccounting)
	}
	res.currentBaseDigestDecoded = baseDigest
	if res.CurrentCut != nil {
		cut, err := validateCutJSON(res.CurrentCut, l.epoch, wantNext)
		if err != nil {
			return fmt.Errorf("%w: append current cut is invalid: %v", ErrAccounting, err)
		}
		res.currentCutDecoded, res.hasCurrentCut = cut, true
	}
	return nil
}

// applyAppendResultLocked installs the response's current locked generation
// facts only after proving they describe this exact group atop the local
// durable mirror. Immutable receipt fields prove a response-lost append even
// after trim; current* fields prevent replay from restoring stale backlog.
func (l *Log) applyAppendResultLocked(res appendResult, group []stagedRecord, groupBytes int64) error {
	firstSeq := group[0].seq
	wantNext := firstSeq + uint64(len(group))
	if l.durableSeq != firstSeq || uint64(*res.NextSeq) != wantNext ||
		res.TipDigest != hex.EncodeToString(group[len(group)-1].tipAfter[:]) {
		return fmt.Errorf("%w: append result no longer extends the local durable head", ErrConflict)
	}
	baseSeq := uint64(*res.CurrentBaseSeq)
	physicalTrimmed := uint64(*res.CurrentPhysicalTrimmed)
	backlogBytes := int64(*res.CurrentBacklogBytes)
	backlogRecords := int64(*res.CurrentBacklogRecords)
	quotaBytes := int64(*res.CurrentQuotaBytes)
	quotaRecords := int64(*res.CurrentQuotaRecords)
	if baseSeq < l.baseSeq || physicalTrimmed < l.physicalTrimmedSeq ||
		quotaBytes != l.quotaBytes || quotaRecords != l.quotaRecords {
		return fmt.Errorf("%w: append response regressed base/trim or changed immutable quota", ErrConflict)
	}
	if err := l.validateCutTransition(res.currentCutDecoded, res.hasCurrentCut); err != nil {
		return err
	}
	expectedBytes, bytesOK := addNonnegativeInt64(l.backlogBytes, groupBytes)
	expectedRecords, recordsOK := addNonnegativeInt64(l.backlogRecords, int64(len(group)))
	if !bytesOK || !recordsOK {
		return fmt.Errorf("%w: append result overflows backlog accounting", ErrAccounting)
	}
	if baseSeq == l.baseSeq {
		if res.currentBaseDigestDecoded != l.baseDigest || res.CurrentBaseCommitID != l.baseCommitID ||
			backlogBytes != expectedBytes || backlogRecords != expectedRecords {
			return fmt.Errorf("%w: append result changed an unchanged base or miscounted the group", ErrAccounting)
		}
	} else {
		if backlogBytes > expectedBytes || backlogRecords >= expectedRecords {
			return fmt.Errorf("%w: append+trim result did not reduce projected backlog", ErrAccounting)
		}
		if res.CurrentBaseCommitID != l.baseCommitID {
			cut := res.currentCutDecoded
			if !res.hasCurrentCut || (cut.Status != wal.CheckpointLanded && cut.Status != wal.CheckpointFinalized) ||
				cut.Watermark != baseSeq || cut.CommitID != res.CurrentBaseCommitID {
				return fmt.Errorf("%w: append response advanced base commit without exact cut proof", ErrProofMissing)
			}
		} else if res.hasCurrentCut && res.currentCutDecoded.Status == wal.CheckpointPrepared &&
			res.currentCutDecoded.Watermark < baseSeq {
			return fmt.Errorf("%w: append response crossed a prepared checkpoint cut", ErrProofMissing)
		}
	}
	l.baseSeq = baseSeq
	l.physicalTrimmedSeq = physicalTrimmed
	l.baseDigest = res.currentBaseDigestDecoded
	l.baseCommitID = res.CurrentBaseCommitID
	l.backlogBytes = backlogBytes
	l.backlogRecords = backlogRecords
	l.quotaBytes = quotaBytes
	l.quotaRecords = quotaRecords
	if res.CurrentControlFloorMs != nil && int64(*res.CurrentControlFloorMs) > l.controlDbFloorMs {
		l.controlDbFloorMs = int64(*res.CurrentControlFloorMs)
	}
	l.cut, l.hasCut = res.currentCutDecoded, res.hasCurrentCut
	return nil
}
