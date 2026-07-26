package histworker

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/trendup-ai/portablefs/vcs/internal/historycut"
	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
)

// Repository is the exact database capability of the history worker: the
// claim-fenced pfh SECURITY DEFINER surface and nothing else (the worker
// role holds zero table privileges). Every mutating call presents the claim
// identity it acts under; a stale claim fails typed with ErrFenced. The
// production implementation is pgRepository (sql.go holds every statement);
// tests substitute an in-memory fake.
type Repository interface {
	// WorkerBeat records liveness for the given worker kinds and returns
	// database time. It doubles as the migration/capability readiness probe.
	WorkerBeat(ctx context.Context, workerID string, kinds []string, facts any) (int64, error)

	// ── materializer ────────────────────────────────────────────────────
	ClaimCuts(ctx context.Context, workerID string, limit int, leaseTTLMs int64) ([]CutClaim, error)
	HeartbeatCut(ctx context.Context, cutID string, claimEpoch int64, workerID string, leaseTTLMs int64, progress any) error
	RetryCut(ctx context.Context, cutID string, claimEpoch int64, errDoc any, backoffMs int64) error
	FailCut(ctx context.Context, cutID string, claimEpoch int64, errDoc any) error
	ReadJournalPage(ctx context.Context, cutID string, claimEpoch int64, fromSeq uint64, maxRecords int, maxBytes int64) ([]historycut.PageRecord, error)
	// IntendObjects registers upload intents and returns the incarnation
	// each object is bound to (the ABA guard the exact key embeds).
	IntendObjects(ctx context.Context, cutID string, claimEpoch int64, objects []ObjectIntent) (map[string]int64, error)
	// RecordCopyReceipt records one VERIFIED copy: written to the exact
	// key, read back from that key, size matched, plaintext re-hashed.
	RecordCopyReceipt(ctx context.Context, cutID string, claimEpoch int64, digest string, incarnation int64, failureDomain, storageKey string, size int64) error
	AddCutObjects(ctx context.Context, cutID string, claimEpoch int64, closure string, digests []string) error
	MarkCutReady(ctx context.Context, ready ReadyFacts) error
	// LocateObject returns the recorded exact keys of the CURRENT
	// incarnation's present copies (nil when unknown/tombstoned).
	LocateObject(ctx context.Context, tenantID, kind, digest string) (*ObjectLocation, error)
	// LocateLegacyBlob returns the recorded legacy blob location (nil when
	// the digest is unknown).
	LocateLegacyBlob(ctx context.Context, cutID string, claimEpoch int64, digest string) (*LegacyBlobLocation, error)

	// ── legacy conversion steps (bounded, resumable, claim-fenced) ──────
	LegacyChainPrepare(ctx context.Context, cutID string, claimEpoch int64) error
	LegacyChainApplyPage(ctx context.Context, cutID string, claimEpoch int64, maxOps int) (bool, error)
	LegacyAssignOrds(ctx context.Context, cutID string, claimEpoch int64, page int) (bool, error)
	LegacyAssignInos(ctx context.Context, cutID string, claimEpoch int64, page int) (bool, error)
	LegacyVerifyTreeHash(ctx context.Context, cutID string, claimEpoch int64, treeHash string) error
	LegacyEntriesPage(ctx context.Context, cutID string, claimEpoch int64, afterOrd int64, limit int) ([]historycut.LegacyEntry, error)
	LegacyPutImportCursor(ctx context.Context, cutID string, claimEpoch int64, cursor json.RawMessage) error
	LegacyGetImportCursor(ctx context.Context, cutID string, claimEpoch int64) (json.RawMessage, error)

	// ── scrub / repair ──────────────────────────────────────────────────
	ClaimScrubCopies(ctx context.Context, workerID string, limit int) ([]ScrubCopy, error)
	RecordScrubReceipt(ctx context.Context, workerID string, c ScrubCopy, ok bool) error
	ClaimRepairs(ctx context.Context, workerID string, limit int, leaseTTLMs int64) ([]RepairClaim, error)
	RecordRepairReceipt(ctx context.Context, workerID string, claim RepairClaim, storageKey string) error

	// ── GC sweep ────────────────────────────────────────────────────────
	ClaimSweep(ctx context.Context, workerID string, minAgeMs, leaseTTLMs int64) (*SweepClaim, error)
	// CompleteSweep returns "swept" or "resurrected".
	CompleteSweep(ctx context.Context, workerID string, claim *SweepClaim, absences []AbsenceReceipt) (string, error)
	ReleaseSweep(ctx context.Context, workerID string, claim *SweepClaim, reason string) error

	// ── cross-tenant rehome copy (ErrCapabilityMissing when absent) ─────
	RehomeLive(ctx context.Context, limit int) ([]RehomeRef, error)
	RehomeCopyPage(ctx context.Context, rehomeID string, limit int) ([]RehomeCopyItem, error)
	RehomeCopyReceipt(ctx context.Context, workerID, rehomeID, digest string, size int64, failureDomain, storageKey string) error

	Close()
}

// CutClaim is one claimed cut: the frozen facts the reducer consumes plus
// the fence identity every subsequent call presents.
type CutClaim struct {
	Facts            historycut.CutFacts
	TenantID         string
	ClaimEpoch       int64
	LeaseExpiresDbMs int64
	DbTimeMs         int64
	// AttemptCount is THIS attempt's 1-based number: pfh.cut_claim
	// increments the counter before projecting the row, so the value the
	// worker sees already includes the attempt it is running. Zero means
	// the claim predates the projection and never trips the local cap (the
	// database dead-letter remains the backstop).
	AttemptCount      int64
	ReplicationPolicy ReplicationPolicy
}

// ReplicationPolicy is the frozen policy captured on the cut row.
type ReplicationPolicy struct {
	Version                string   `json:"v"`
	RequiredFailureDomains []string `json:"requiredFailureDomains"`
	PolicyEpoch            string   `json:"policyEpoch"`
}

// Epoch parses the policy epoch.
func (p ReplicationPolicy) Epoch() (int64, error) {
	v, err := strconv.ParseInt(p.PolicyEpoch, 10, 64)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("%w: policy epoch %q", ErrPolicyMismatch, p.PolicyEpoch)
	}
	return v, nil
}

// claimEnvelope decodes the cut_claim JSON: cut_status projection plus the
// claim fields merged on top. attemptCount is the one numeric the
// projection emits as a JSON number, not TEXT.
type claimEnvelope struct {
	historycut.CutFacts
	TenantID          string            `json:"tenantId"`
	ClaimEpoch        string            `json:"claimEpoch"`
	LeaseExpiresDbMs  string            `json:"leaseExpiresDbMs"`
	DbTimeMs          string            `json:"dbTimeMs"`
	AttemptCount      int64             `json:"attemptCount"`
	ReplicationPolicy ReplicationPolicy `json:"replicationPolicy"`
}

// DecodeCutClaim parses one claim JSON document.
func DecodeCutClaim(raw []byte) (CutClaim, error) {
	var env claimEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return CutClaim{}, fmt.Errorf("histworker: claim decode: %w", err)
	}
	epoch, err := strconv.ParseInt(env.ClaimEpoch, 10, 64)
	if err != nil || epoch < 1 {
		return CutClaim{}, fmt.Errorf("histworker: claim epoch %q is invalid", env.ClaimEpoch)
	}
	lease, err := strconv.ParseInt(env.LeaseExpiresDbMs, 10, 64)
	if err != nil {
		return CutClaim{}, fmt.Errorf("histworker: claim lease %q is invalid", env.LeaseExpiresDbMs)
	}
	dbTime, err := strconv.ParseInt(env.DbTimeMs, 10, 64)
	if err != nil {
		return CutClaim{}, fmt.Errorf("histworker: claim db time %q is invalid", env.DbTimeMs)
	}
	if env.CutFacts.CutID == "" || env.TenantID == "" {
		return CutClaim{}, fmt.Errorf("histworker: claim is missing cut/tenant identity")
	}
	if env.AttemptCount < 0 {
		return CutClaim{}, fmt.Errorf("histworker: claim attempt count %d is invalid", env.AttemptCount)
	}
	return CutClaim{
		Facts:             env.CutFacts,
		TenantID:          env.TenantID,
		ClaimEpoch:        epoch,
		LeaseExpiresDbMs:  lease,
		DbTimeMs:          dbTime,
		AttemptCount:      env.AttemptCount,
		ReplicationPolicy: env.ReplicationPolicy,
	}, nil
}

// ObjectIntent is one object registration (digest is "sha256:<hex>").
type ObjectIntent struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// ReadyFacts carries every argument of the atomic ready publication.
type ReadyFacts struct {
	CutID      string
	ClaimEpoch int64

	RootDigestHex string
	RootSize      int64

	RecoveryRootDigestHex string
	RecoveryRootSize      int64

	ControlRootDigestHex string // "" when absent
	ControlRootSize      int64
	OrphanIndexDigestHex string // "" when absent
	OrphanIndexSize      int64

	InodeNamespace int64
	NextLocal      int64
	// MaxInoSeen is the branch ALLOCATOR watermark (anchor arm; also the
	// namespace row's monotone floor). RootMaxInoSeen is the USER root
	// object's own recorded high-water (user commit arm) — the value attach
	// proofs bind against the hashed ROOT. They differ whenever the fold
	// burned identities that did not survive into the tree.
	MaxInoSeen     int64
	RootMaxInoSeen int64

	UserObjectCount     int64
	UserObjectBytes     int64
	RecoveryObjectCount int64
	RecoveryObjectBytes int64
}

// ObjectLocation is the recorded location set of one object.
type ObjectLocation struct {
	TenantID    string       `json:"tenantId"`
	Kind        string       `json:"kind"`
	Digest      string       `json:"digest"`
	Size        int64        `json:"-"`
	Incarnation int64        `json:"-"`
	State       string       `json:"state"`
	Copies      []CopyRecord `json:"copies"`

	RawSize        string `json:"size"`
	RawIncarnation string `json:"incarnation"`
}

// CopyRecord is one recorded copy: the exact key in one failure domain.
type CopyRecord struct {
	FailureDomain string `json:"failureDomain"`
	StorageKey    string `json:"storageKey"`
	Size          int64  `json:"-"`
	LastVerified  int64  `json:"-"`

	RawSize         string `json:"size"`
	RawLastVerified string `json:"lastVerifiedDbMs"`
}

// DecodeObjectLocation parses pfh.object_locate output.
func DecodeObjectLocation(raw []byte) (*ObjectLocation, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var loc ObjectLocation
	if err := json.Unmarshal(raw, &loc); err != nil {
		return nil, fmt.Errorf("histworker: object location decode: %w", err)
	}
	var err error
	if loc.Size, err = strconv.ParseInt(loc.RawSize, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: object location size %q", loc.RawSize)
	}
	if loc.Incarnation, err = strconv.ParseInt(loc.RawIncarnation, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: object location incarnation %q", loc.RawIncarnation)
	}
	if err := validatePFT2ObjectSize(loc.Size); err != nil {
		return nil, err
	}
	for i := range loc.Copies {
		c := &loc.Copies[i]
		if c.Size, err = strconv.ParseInt(c.RawSize, 10, 64); err != nil {
			return nil, fmt.Errorf("histworker: copy size %q", c.RawSize)
		}
		if c.LastVerified, err = strconv.ParseInt(c.RawLastVerified, 10, 64); err != nil {
			return nil, fmt.Errorf("histworker: copy verify time %q", c.RawLastVerified)
		}
		if c.Size != loc.Size {
			return nil, fmt.Errorf("histworker: copy size %d contradicts object size %d", c.Size, loc.Size)
		}
	}
	return &loc, nil
}

// LegacyBlobLocation is the recorded location of one legacy blob.
type LegacyBlobLocation struct {
	Digest     string `json:"digest"`
	Size       int64  `json:"-"`
	StorageKey string `json:"storageKey"`

	RawSize string `json:"size"`
}

// DecodeLegacyBlobLocation parses pfh.legacy_blob_locate output.
func DecodeLegacyBlobLocation(raw []byte) (*LegacyBlobLocation, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var loc LegacyBlobLocation
	if err := json.Unmarshal(raw, &loc); err != nil {
		return nil, fmt.Errorf("histworker: legacy blob location decode: %w", err)
	}
	var err error
	if loc.Size, err = strconv.ParseInt(loc.RawSize, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: legacy blob size %q", loc.RawSize)
	}
	return &loc, nil
}

// ScrubCopy is one claimed copy verification.
type ScrubCopy struct {
	TenantID       string
	Kind           string
	Digest         string // sha256:<hex>
	Incarnation    int64
	FailureDomain  string
	StorageKey     string
	Size           int64
	LastVerifiedMs int64
	ClaimEpoch     int64
	ClaimExpiresMs int64
}

// RepairClaim is one leased missing/failed destination copy with its
// verified sources.
type RepairClaim struct {
	TenantID       string         `json:"tenantId"`
	Kind           string         `json:"kind"`
	Digest         string         `json:"digest"`
	Incarnation    int64          `json:"-"`
	Size           int64          `json:"-"`
	MissingDomain  string         `json:"missingDomain"`
	Sources        []RepairSource `json:"sources"`
	ClaimEpoch     int64          `json:"-"`
	LeaseExpiresMs int64          `json:"-"`

	RawIncarnation string `json:"incarnation"`
	RawSize        string `json:"size"`
	RawClaimEpoch  string `json:"claimEpoch"`
	RawLeaseExpiry string `json:"leaseExpiresDbMs"`
}

// RepairSource is one verified source copy (exact recorded key).
type RepairSource struct {
	FailureDomain string `json:"failureDomain"`
	StorageKey    string `json:"storageKey"`
	Size          int64  `json:"-"`

	RawSize string `json:"size"`
}

// DecodeRepairClaim parses one pfh.repair_claim row.
func DecodeRepairClaim(raw []byte) (RepairClaim, error) {
	var claim RepairClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return RepairClaim{}, fmt.Errorf("histworker: repair claim decode: %w", err)
	}
	var err error
	if claim.Incarnation, err = strconv.ParseInt(claim.RawIncarnation, 10, 64); err != nil {
		return RepairClaim{}, fmt.Errorf("histworker: repair incarnation %q", claim.RawIncarnation)
	}
	if claim.Size, err = strconv.ParseInt(claim.RawSize, 10, 64); err != nil {
		return RepairClaim{}, fmt.Errorf("histworker: repair size %q", claim.RawSize)
	}
	if err := validatePFT2ObjectSize(claim.Size); err != nil {
		return RepairClaim{}, err
	}
	if claim.ClaimEpoch, err = strconv.ParseInt(claim.RawClaimEpoch, 10, 64); err != nil || claim.ClaimEpoch < 1 {
		return RepairClaim{}, fmt.Errorf("histworker: repair claim epoch %q is invalid", claim.RawClaimEpoch)
	}
	if claim.LeaseExpiresMs, err = strconv.ParseInt(claim.RawLeaseExpiry, 10, 64); err != nil || claim.LeaseExpiresMs < 0 {
		return RepairClaim{}, fmt.Errorf("histworker: repair lease expiry %q is invalid", claim.RawLeaseExpiry)
	}
	for i := range claim.Sources {
		s := &claim.Sources[i]
		if s.Size, err = strconv.ParseInt(s.RawSize, 10, 64); err != nil {
			return RepairClaim{}, fmt.Errorf("histworker: repair source size %q", s.RawSize)
		}
		if s.Size != claim.Size {
			return RepairClaim{}, fmt.Errorf("histworker: repair source size %d contradicts object size %d", s.Size, claim.Size)
		}
	}
	return claim, nil
}

// SweepClaim is one leased deletion: the exact copies to remove plus the
// full fence tuple completion must re-present.
type SweepClaim struct {
	TenantID          string      `json:"tenantId"`
	Kind              string      `json:"kind"`
	Digest            string      `json:"digest"`
	Size              int64       `json:"-"`
	Incarnation       int64       `json:"-"`
	ReclaimGeneration int64       `json:"-"`
	ClaimEpoch        int64       `json:"-"`
	Copies            []SweepCopy `json:"copies"`

	RawSize        string `json:"size"`
	RawIncarnation string `json:"incarnation"`
	RawReclaimGen  string `json:"reclaimGeneration"`
	RawClaimEpoch  string `json:"claimEpoch"`
}

// SweepCopy is one exact copy the claim entered 'deleting'.
type SweepCopy struct {
	FailureDomain string `json:"failureDomain"`
	StorageKey    string `json:"storageKey"`
}

// AbsenceReceipt attests one copy proven absent at its exact key.
type AbsenceReceipt struct {
	FailureDomain   string `json:"failureDomain"`
	StorageKey      string `json:"storageKey"`
	ConfirmedAbsent bool   `json:"confirmedAbsent"`
}

// DecodeSweepClaim parses pfh.sweep_claim output (nil when idle).
func DecodeSweepClaim(raw []byte) (*SweepClaim, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var claim SweepClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return nil, fmt.Errorf("histworker: sweep claim decode: %w", err)
	}
	var err error
	if claim.Size, err = strconv.ParseInt(claim.RawSize, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: sweep size %q", claim.RawSize)
	}
	if err := validatePFT2ObjectSize(claim.Size); err != nil {
		return nil, err
	}
	if claim.Incarnation, err = strconv.ParseInt(claim.RawIncarnation, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: sweep incarnation %q", claim.RawIncarnation)
	}
	if claim.ReclaimGeneration, err = strconv.ParseInt(claim.RawReclaimGen, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: sweep reclaim generation %q", claim.RawReclaimGen)
	}
	if claim.ClaimEpoch, err = strconv.ParseInt(claim.RawClaimEpoch, 10, 64); err != nil {
		return nil, fmt.Errorf("histworker: sweep claim epoch %q", claim.RawClaimEpoch)
	}
	return &claim, nil
}

func validatePFT2ObjectSize(size int64) error {
	if size < 1 || size > int64(pft2.MaxPackBytes) {
		return fmt.Errorf("histworker: pft2 object size %d outside 1..%d", size, pft2.MaxPackBytes)
	}
	return nil
}
