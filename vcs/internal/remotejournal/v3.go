package remotejournal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/ctlrec"
	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/pfj3"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// PFJ3/PFC2 managed generation support: claim, entry append, admission-fact
// issuance, and verified entry replay. The legacy PFR1/PFC1 surface in the
// sibling files is untouched; a Log speaks exactly one immutable codec pair,
// fixed at claim.

const (
	pfj3RecordCodec  = pfj3.RecordCodec
	pfc2ControlCodec = pfj3.ControlCodec
)

// ErrMigrationRequired reports a writable branch whose live journal
// generation still speaks PFR1/PFC1: managed PFJ3 writes require the
// exceptional retire + new-generation migration, never an in-place switch.
var ErrMigrationRequired = errors.New("remotejournal: branch requires the exceptional PFJ3/PFC2 migration")

// ErrManagedCodecUnsupported reports a branch whose authoritative
// provisioning decided the legacy pfr1/pfc1 plane. Managed serving speaks
// PFJ3/PFC2 only, so OpenAuthoritative refuses BEFORE any claim: a
// base-authored branch enters journal service through journal activation
// (the 013 conversion), and claiming a legacy generation here would only
// strand an active generation that blocks that conversion.
var ErrManagedCodecUnsupported = errors.New("remotejournal: managed serving requires the PFJ3/PFC2 pair")

// provisioningJSON is pfj.branch_provisioning's response.
type provisioningJSON struct {
	BranchMode   string        `json:"branchMode"`
	RecordCodec  string        `json:"recordCodec"`
	ControlCodec string        `json:"controlCodec"`
	GenerationID string        `json:"generationId"`
	DBTimeMs     *decimalInt64 `json:"dbTimeMs"`
}

// Provisioning is the authoritative provisioning answer for one branch: the
// branch mode and the immutable codec pair the branch's live generation (or,
// for a fresh branch, its provisioned mode) dictates. It is a database
// decision — never a caller or environment choice.
type Provisioning struct {
	BranchMode   string
	RecordCodec  string
	ControlCodec string
	GenerationID string
}

// discoverProvisioning asks the fenced database what provisioning decided.
// Retiring/retired branches and contradictory states fail closed.
func discoverProvisioning(ctx context.Context, pool journalDB, cfg Config, managerEpoch, runtimeSeq int64) (Provisioning, error) {
	probe := &Log{
		pool: pool, life: ctx, cfg: cfg,
		capability:   cfg.AuthorityCapability,
		managerEpoch: managerEpoch,
		runtimeSeq:   runtimeSeq,
	}
	raw, err := probe.callJSONB(ctx,
		`SELECT pfj.branch_provisioning($1,$2,$3,$4,$5,$6,$7)`,
		cfg.TenantID, cfg.VolumeID, cfg.Branch,
		managerEpoch, runtimeSeq, cfg.AuthorityRuntimeID, cfg.AuthorityCapability,
	)
	if err != nil {
		if typed := typedError(err); typed != nil {
			return Provisioning{}, typed
		}
		return Provisioning{}, fmt.Errorf("remotejournal: branch provisioning: %w", err)
	}
	var body provisioningJSON
	if err := json.Unmarshal(raw, &body); err != nil {
		return Provisioning{}, fmt.Errorf("%w: decode branch provisioning: %v", ErrProtocolIntegrity, err)
	}
	valid := (body.RecordCodec == wal.PFR1Codec && body.ControlCodec == ctlrec.PFC1Codec) ||
		(body.RecordCodec == pfj3RecordCodec && body.ControlCodec == pfc2ControlCodec)
	if !valid || body.BranchMode == "" || body.DBTimeMs == nil {
		return Provisioning{}, fmt.Errorf("%w: branch provisioning answered an unknown codec pair %q/%q (mode %q)",
			ErrProtocolIntegrity, body.RecordCodec, body.ControlCodec, body.BranchMode)
	}
	return Provisioning{
		BranchMode:   body.BranchMode,
		RecordCodec:  body.RecordCodec,
		ControlCodec: body.ControlCodec,
		GenerationID: body.GenerationID,
	}, nil
}

// OpenAuthoritative claims the branch's PFJ3/PFC2 journal generation under
// the pair the AUTHORITATIVE provisioning/claim result dictates: it discovers
// the branch's provisioning first, refuses a legacy pfr1/pfc1 decision with
// ErrManagedCodecUnsupported BEFORE any claim (the decided facts ride along
// with the error), and otherwise claims via OpenV3 and verifies the claim
// result restates the same immutable pair and branch mode. There is
// deliberately NO caller or environment codec selection — a config typo has
// nothing to pick and nothing to downgrade.
func OpenAuthoritative(ctx context.Context, cfg Config) (*Log, Provisioning, error) {
	if err := normalize(&cfg); err != nil {
		return nil, Provisioning{}, err
	}
	managerEpoch, runtimeSeq, err := runtimeBinding(cfg)
	if err != nil {
		return nil, Provisioning{}, err
	}
	pool, err := connect(ctx, cfg)
	if err != nil {
		return nil, Provisioning{}, err
	}
	return openAuthoritative(ctx, pool, cfg, managerEpoch, runtimeSeq)
}

// openAuthoritative is OpenAuthoritative after the connection: it owns (and
// closes) the discovery pool. The legacy refusal happens HERE, before any
// claim, because a pfr1 claim on a base-authored branch would create or
// resume a legacy generation this process refuses to serve — stranding an
// active generation that blocks the branch's later journal activation (the
// 013 conversion).
func openAuthoritative(ctx context.Context, pool journalDB, cfg Config, managerEpoch, runtimeSeq int64) (*Log, Provisioning, error) {
	provisioning, err := discoverProvisioning(ctx, pool, cfg, managerEpoch, runtimeSeq)
	pool.Close()
	if err != nil {
		return nil, Provisioning{}, err
	}
	if provisioning.RecordCodec != pfj3RecordCodec || provisioning.ControlCodec != pfc2ControlCodec {
		return nil, provisioning, fmt.Errorf(
			"%w: provisioning decided %s/%s (branch mode %s); a base-authored branch enters journal service through journal activation, and claiming here would strand a legacy generation that blocks that conversion",
			ErrManagedCodecUnsupported, provisioning.RecordCodec, provisioning.ControlCodec, provisioning.BranchMode)
	}
	log, err := OpenV3(ctx, cfg)
	if err != nil {
		return nil, Provisioning{}, err
	}
	record, control := log.codecPair()
	if record != provisioning.RecordCodec || control != provisioning.ControlCodec ||
		(provisioning.GenerationID != "" && log.GenerationID() != provisioning.GenerationID) {
		log.Close()
		return nil, Provisioning{}, fmt.Errorf("%w: claim result (%s/%s, generation %s) does not restate the provisioning decision (%s/%s, generation %s)",
			ErrProtocolIntegrity, record, control, log.GenerationID(),
			provisioning.RecordCodec, provisioning.ControlCodec, provisioning.GenerationID)
	}
	return log, provisioning, nil
}

// OpenV3 claims (or resumes) the branch's PFJ3/PFC2 journal generation as the
// fenced writer. The claim REQUIRES the branch to already be provisioned
// managed_journal — it never changes the branch mode, so a base-authored
// (legacy_manifest) branch must run journal activation first. A branch whose
// live generation speaks the legacy pair fails with ErrMigrationRequired.
// Lost claim responses retry identically, exactly like Open.
func OpenV3(ctx context.Context, cfg Config) (*Log, error) {
	if err := normalize(&cfg); err != nil {
		return nil, err
	}
	if cfg.AttachSessionID == "" || cfg.LeaseID == "" || cfg.FencingToken <= 0 ||
		cfg.HolderID == "" || cfg.AuthorityInstanceID == "" {
		return nil, fmt.Errorf("remotejournal: writer claim requires session/lease/fence/holder/authority facts")
	}
	managerEpoch, runtimeSeq, err := runtimeBinding(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.ClaimOperationID == "" || len(cfg.ClaimOperationID) > 200 {
		return nil, fmt.Errorf("remotejournal: manager-issued claim operation id is required and bounded to 200 bytes")
	}
	pool, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	l := &Log{
		pool: pool, life: ctx, cfg: cfg,
		capability:   cfg.AuthorityCapability,
		managerEpoch: managerEpoch,
		runtimeSeq:   runtimeSeq,
		recordCodec:  pfj3RecordCodec,
		controlCodec: pfc2ControlCodec,
		poisonedCh:   make(chan struct{}),
	}
	var quotaBytes, quotaRecords any
	if cfg.QuotaBacklogBytes > 0 {
		quotaBytes = cfg.QuotaBacklogBytes
	}
	if cfg.QuotaBacklogRecords > 0 {
		quotaRecords = cfg.QuotaBacklogRecords
	}
	claimSQL := `SELECT pfj.journal_claim_v3($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
	claimArgs := []any{
		cfg.ClaimOperationID, cfg.TenantID, cfg.VolumeID, cfg.Branch,
		cfg.AttachSessionID, cfg.LeaseID, cfg.FencingToken, cfg.HolderID,
		cfg.AuthorityInstanceID, cfg.AuthorityCapability,
		managerEpoch, runtimeSeq, cfg.AuthorityRuntimeID,
		nullIfEmpty(cfg.ExpectedBaseCommitID), quotaBytes, quotaRecords,
	}
	invalidSuccesses := 0
	backoff := retryBackoffFloor
	for {
		raw, err := l.callIdempotent(claimSQL, claimArgs...)
		if err != nil {
			pool.Close()
			if errors.Is(err, ErrCodec) {
				// PF005 from claim_v3: the live generation speaks the legacy
				// pair. Old-generation reads stay possible via OpenReadOnly;
				// managed writes are refused until the exceptional migration.
				return nil, fmt.Errorf("%w: %v", ErrMigrationRequired, err)
			}
			return nil, fmt.Errorf("remotejournal: claim v3: %w", err)
		}
		var head generationJSON
		invalid := error(nil)
		if err := json.Unmarshal(raw, &head); err != nil {
			invalid = fmt.Errorf("decode claim response: %w", err)
		} else if head.OperationID != cfg.ClaimOperationID || head.Current == nil {
			invalid = fmt.Errorf("claim response is missing the exact operation/current fields")
		} else if !*head.Current {
			pool.Close()
			return nil, fmt.Errorf("%w: claim receipt was superseded by a newer writer", ErrFenced)
		} else if err := l.adoptHead(&head, true); err != nil {
			invalid = err
		} else {
			return l, nil
		}
		invalidSuccesses++
		if invalidSuccesses >= maxInvalidSuccessBodies {
			pool.Close()
			return nil, fmt.Errorf("%w: claim %s returned %d invalid success bodies (last: %v)",
				ErrProtocolIntegrity, cfg.ClaimOperationID, invalidSuccesses, invalid)
		}
		select {
		case <-l.life.Done():
			pool.Close()
			return nil, fmt.Errorf("%w: claim %s reached its lifecycle deadline after invalid success: %v",
				ErrUnknownOutcome, cfg.ClaimOperationID, invalid)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}

// requireEntryLog fails closed when this generation does not speak PFJ3.
func (l *Log) requireEntryLog(op string) error {
	if record, control := l.codecPair(); record != pfj3RecordCodec {
		return fmt.Errorf("%w: %s requires a PFJ3/PFC2 generation (this one speaks %s/%s)",
			ErrCodec, op, record, control)
	}
	return nil
}

// requireRecordLog fails closed when a legacy record API is used against a
// PFJ3 generation: entry APIs are the only correct surface there, and a
// silent PFR1 encode would corrupt the chain identity.
func (l *Log) requireRecordLog(op string) error {
	if record, _ := l.codecPair(); record == pfj3RecordCodec {
		return fmt.Errorf("%w: %s speaks legacy PFR1; use the JournalEntry APIs on a PFJ3/PFC2 generation",
			ErrCodec, op)
	}
	return nil
}

// AppendEntriesBuffered reserves ONE contiguous LSN range and stages whole
// PFJ3 entries: each entry is assigned its outer LSN (and its tree intent's
// inner Seq), encoded exactly once, and those identical bytes later become
// the database row, hash/chain input, duplicate identity, and retry body.
// The admission facts frozen in each entry's controls ride INSIDE those exact
// bytes as the SQL-verifiable manifest preamble; the append transaction
// parses, verifies, and consumes exactly them. All-or-nothing: every entry is
// encoded and bounds-checked before any state changes.
func (l *Log) AppendEntriesBuffered(entries []pfj3.JournalEntry) (firstSeq, endSeq uint64, err error) {
	if len(entries) == 0 {
		return 0, 0, fmt.Errorf("remotejournal: empty entry batch")
	}
	if l.readOnly {
		return 0, 0, errReadOnly
	}
	if err := l.requireEntryLog("AppendEntriesBuffered"); err != nil {
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
	if first > uint64(math.MaxInt64) || uint64(len(entries)) > uint64(math.MaxInt64)-first {
		return 0, 0, fmt.Errorf("%w: reserving %d entries at LSN %d exceeds PostgreSQL BIGINT",
			ErrBounds, len(entries), first)
	}
	staged := make([]stagedRecord, len(entries))
	startTip := l.tip
	tip := startTip
	var addBytes int64
	controlOnly := true
	for i := range entries {
		entry := entries[i]
		entry.LSN = first + uint64(i)
		if entry.Tree != nil {
			controlOnly = false
			tree := *entry.Tree
			tree.Seq = entry.LSN
			entry.Tree = &tree
		}
		payload, encErr := pfj3.Encode(&entry)
		if encErr != nil {
			return 0, 0, fmt.Errorf("remotejournal: encode entry %d: %w", entry.LSN, encErr)
		}
		manifest, mErr := entry.FactManifest()
		if mErr != nil {
			return 0, 0, fmt.Errorf("remotejournal: entry %d fact manifest: %w", entry.LSN, mErr)
		}
		hash := wal.ChainDigestBytes([32]byte{}, payload)
		tip = wal.ChainDigestBytes(tip, payload)
		staged[i] = stagedRecord{
			seq:       entry.LSN,
			payload:   payload,
			hashHex:   hex.EncodeToString(hash[:]),
			tipAfter:  tip,
			factCount: len(manifest),
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
	if l.projectionExceedsCapacityLocked(projection, controlOnly) {
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
		if l.projectionExceedsCapacityLocked(projection, controlOnly) {
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
		if l.projectionExceedsCapacityLocked(projection, controlOnly) {
			return 0, 0, l.capacityErrorLocked(projection)
		}
	}
	for i := range entries {
		entries[i].LSN = staged[i].seq
		if entries[i].Tree != nil {
			entries[i].Tree.Seq = staged[i].seq
		}
	}
	l.staged = append(l.staged, staged...)
	l.stagedBytes = projection.stagedBytes
	l.nextSeq = first + uint64(len(entries))
	l.tip = tip
	return first, l.nextSeq, nil
}

// admissionFactJSON is pfj.admission_fact_issue's response.
type admissionFactJSON struct {
	FactID           string        `json:"factId"`
	IssuedDbMs       *decimalInt64 `json:"issuedDbMs"`
	FactExpiresDbMs  *decimalInt64 `json:"factExpiresDbMs"`
	ControlDbFloorMs *decimalInt64 `json:"controlDbFloorMs"`
}

// IssueAdmissionFact mints one capability-bound short-lived admission fact
// for a PFC2 control transition, inside the same fenced database that will
// validate and consume it at append. The scope's session names the subject
// session; the scope's floor is the issuer's view of the durable control
// floor (stale views fail closed with ErrConflict). This Log's own claim
// identity supplies every other coordinate — the caller can neither invent a
// fact id nor bind a foreign scope.
//
// Issuance is NOT idempotent (each call mints a fresh fact) and is never
// retried here: an unused orphan fact simply expires. Implements
// pfc2.FactIssuer.
func (l *Log) IssueAdmissionFact(scope pfc2.FactScope) (pfc2.IssuedFact, error) {
	if l.readOnly {
		return pfc2.IssuedFact{}, errReadOnly
	}
	if err := l.requireEntryLog("IssueAdmissionFact"); err != nil {
		return pfc2.IssuedFact{}, err
	}
	if scope.TenantID != "" && scope.TenantID != l.cfg.TenantID ||
		scope.VolumeID != "" && scope.VolumeID != l.cfg.VolumeID ||
		scope.Branch != "" && scope.Branch != l.cfg.Branch ||
		scope.GenerationID != "" && scope.GenerationID != l.generationID ||
		scope.Epoch != 0 && scope.Epoch != l.epoch {
		return pfc2.IssuedFact{}, fmt.Errorf("%w: admission fact scope does not name this generation", ErrConflict)
	}
	if scope.Session.SessionID == "" || scope.Session.Generation == 0 {
		return pfc2.IssuedFact{}, fmt.Errorf("remotejournal: admission fact requires the subject session identity")
	}
	if !scope.Purpose.Valid() {
		return pfc2.IssuedFact{}, fmt.Errorf("remotejournal: admission fact requires a known operation purpose")
	}
	if scope.PriorDbTimeFloorMs < 0 {
		return pfc2.IssuedFact{}, fmt.Errorf("remotejournal: admission fact floor must be non-negative")
	}
	sessionGen, err := checkedSQLBigint("admission fact session generation", scope.Session.Generation)
	if err != nil {
		return pfc2.IssuedFact{}, err
	}
	raw, err := l.callJSONB(l.life,
		`SELECT pfj.admission_fact_issue($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
		int16(scope.Purpose), scope.Session.SessionID, sessionGen, scope.PriorDbTimeFloorMs,
	)
	if err != nil {
		if typed := typedError(err); typed != nil {
			return pfc2.IssuedFact{}, typed
		}
		return pfc2.IssuedFact{}, fmt.Errorf("remotejournal: issue admission fact: %w", err)
	}
	var body admissionFactJSON
	if err := json.Unmarshal(raw, &body); err != nil {
		return pfc2.IssuedFact{}, fmt.Errorf("%w: decode admission fact: %v", ErrProtocolIntegrity, err)
	}
	if body.IssuedDbMs == nil || body.FactExpiresDbMs == nil || len(body.FactID) != 32 {
		return pfc2.IssuedFact{}, fmt.Errorf("%w: admission fact response is missing exact fields", ErrProtocolIntegrity)
	}
	idBytes, err := hex.DecodeString(body.FactID)
	if err != nil || len(idBytes) != pfc2.FactIDBytes {
		return pfc2.IssuedFact{}, fmt.Errorf("%w: admission fact id is not 16 canonical hex bytes", ErrProtocolIntegrity)
	}
	fact := pfc2.TimeFact{Source: pfc2.TimeSourceDB, DbMs: int64(*body.IssuedDbMs)}
	copy(fact.FactID[:], idBytes)
	if err := fact.Validate(); err != nil {
		return pfc2.IssuedFact{}, fmt.Errorf("%w: issued fact is malformed: %v", ErrProtocolIntegrity, err)
	}
	issued := pfc2.IssuedFact{Fact: fact, FactExpiresDbMs: int64(*body.FactExpiresDbMs)}
	if issued.FactExpiresDbMs <= fact.DbMs {
		return pfc2.IssuedFact{}, fmt.Errorf("%w: issued fact expiry does not follow its mint time", ErrProtocolIntegrity)
	}
	return issued, nil
}

var _ pfc2.FactIssuer = (*Log)(nil)

// streamEntryRange streams durable PFJ3 rows [from, to) with the same
// one-page-ahead prefetch as streamRange (fetch overlaps verify+apply; one
// extra page of memory), verifying LSN contiguity, stored hashes, the digest
// chain, strict canonical PFJ3 decode, and the embedded outer LSN. Returns
// the chain digest at the end boundary.
func (l *Log) streamEntryRange(from, to uint64, chainStart [32]byte, fn func(pfj3.JournalEntry) error) ([32]byte, error) {
	chain := chainStart
	stream := l.startPageStream(from, to)
	defer stream.stop()
	for next := from; next < to; {
		fetched, ok := stream.next()
		if !ok {
			// Unreachable while rows verify: the producer serves at least the
			// consumer's position. Fail closed rather than spin.
			return chain, fmt.Errorf("%w: page stream ended before LSN %d (head %d)", wal.ErrJournalDiverged, next, to)
		}
		if fetched.err != nil {
			return chain, fetched.err
		}
		page := fetched.rows
		if len(page) == 0 {
			return chain, fmt.Errorf("%w: journal returned no rows at LSN %d (head %d)", wal.ErrJournalDiverged, next, to)
		}
		for _, row := range page {
			if next >= to {
				break
			}
			if row.seq != next {
				return chain, fmt.Errorf("%w: journal rows are not contiguous (want LSN %d, got %d)", wal.ErrJournalDiverged, next, row.seq)
			}
			hash := wal.ChainDigestBytes([32]byte{}, row.payload)
			if hex.EncodeToString(hash[:]) != row.recordHash {
				return chain, fmt.Errorf("%w: entry %d payload does not match its stored hash", wal.ErrJournalDiverged, row.seq)
			}
			chain = wal.ChainDigestBytes(chain, row.payload)
			if hex.EncodeToString(chain[:]) != row.chainDigest {
				return chain, fmt.Errorf("%w: entry %d breaks the digest chain", wal.ErrJournalDiverged, row.seq)
			}
			entry, derr := pfj3.Decode(row.payload)
			if derr != nil {
				return chain, fmt.Errorf("%w: entry %d is not canonical PFJ3: %v", wal.ErrJournalDiverged, row.seq, derr)
			}
			if entry.LSN != row.seq {
				return chain, fmt.Errorf("%w: entry payload carries LSN %d, row says %d", wal.ErrJournalDiverged, entry.LSN, row.seq)
			}
			if err := fn(entry); err != nil {
				return chain, err
			}
			next++
		}
	}
	return chain, nil
}

// ReplayEntriesInto streams the retained durable suffix as uniform
// JournalEntries (tree intent + ordered controls) with the same verification
// and post-replay head check as the legacy ReplayInto. Cold recovery reduces
// EVERY entry — tree then controls — into one WorkFS state before the
// authority admits anything.
func (l *Log) ReplayEntriesInto(fn func(pfj3.JournalEntry) error) error {
	if err := l.requireEntryLog("ReplayEntriesInto"); err != nil {
		return err
	}
	l.mu.Lock()
	from, to := l.baseSeq, l.durableSeq
	chainStart, wantTip := l.baseDigest, l.durableTip
	l.mu.Unlock()

	chain, err := l.streamEntryRange(from, to, chainStart, fn)
	if err != nil {
		return err
	}
	if chain != wantTip {
		return fmt.Errorf("%w: replayed chain does not end at the journal tip", wal.ErrJournalDiverged)
	}
	return l.verifyHeadAfterReplay(from, to, wantTip)
}
