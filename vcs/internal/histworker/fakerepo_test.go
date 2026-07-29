package histworker

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/historycut"
)

// fakeRepo is an in-memory Repository that mirrors the pfh SQL semantics
// exactly where the worker depends on them: claim epochs + DB-time leases,
// intent-bound incarnations with ABA bumps, per-domain copy receipts,
// dual-closure mark-ready verification, scrub quarantine/heal, repair
// leases, and the fenced sweep lifecycle with per-copy absence proofs. A
// virtual clock makes lease expiry deterministic; fault hooks cut the run at
// exact DB/object boundaries.
type fakeRepo struct {
	mu    sync.Mutex
	nowMs int64

	requiredDomains []string
	freshnessMs     int64

	cuts    map[string]*fakeCut
	objects map[string]*fakeObject     // tenant\x01kind\x01digest
	copies  map[string]*fakeCopy       // objectKey\x01incarnation\x01domain
	repairs map[string]fakeRepairLease // lease per objectKey\x01inc\x01domain

	legacy *fakeLegacyPipeline

	// Fault hooks (return error to inject a failure at that seam).
	beforeIntend      func() error
	beforeCopyReceipt func() error
	afterCopyReceipt  func() error
	beforeMarkReady   func() error
	heartbeatErr      func() error
	retentionRelease  func(limit int) (int64, error)

	// call counters (RPC-shape evidence for the convergence/batching tests).
	callsLocate       int64
	callsLocateBatch  int64
	callsReceipt      int64
	callsReceiptBatch int64
}

type fakeCut struct {
	facts       historycut.CutFacts
	tenant      string
	state       string
	claimEpoch  int64
	leaseExpiry int64
	attempts    int
	nextAttempt int64
	journal     []historycut.PageRecord
	consumed    bool // ready-cut root pin (consumer/pin present)

	intents    map[string]int64 // digest -> incarnation
	closures   map[string]map[string]bool
	commitID   string
	anchorID   string
	lastError  string
	opSettled  string
	readyInput *ReadyFacts
}

type fakeObject struct {
	tenant       string
	kind         string
	digest       string
	size         int64
	incarnation  int64
	reclaimGen   int64
	state        string
	sweepEpoch   int64
	sweepLease   int64
	lastUpdateMs int64
}

type fakeCopy struct {
	storageKey     string
	size           int64
	state          string
	verifyAttempts int
	nextVerify     int64
	lastVerified   int64
	verifyWorker   string
	verifyEpoch    int64
	verifyLease    int64
}

type fakeRepairLease struct {
	worker  string
	epoch   int64
	expires int64
}

type fakeLegacyPipeline struct {
	entries   []historycut.LegacyEntry
	cursor    json.RawMessage
	wantHash  string
	blobs     map[string]string // digest -> recorded storage key
	blobSizes map[string]int64
}

func objKey(tenant, kind, digest string) string {
	return tenant + "\x01" + kind + "\x01" + digest
}

func copyKey(ok string, incarnation int64, domain string) string {
	return ok + "\x01" + strconv.FormatInt(incarnation, 10) + "\x01" + domain
}

func newFakeRepo(domains []string) *fakeRepo {
	return &fakeRepo{
		nowMs:           1_000_000,
		requiredDomains: domains,
		freshnessMs:     86_400_000,
		cuts:            map[string]*fakeCut{},
		objects:         map[string]*fakeObject{},
		copies:          map[string]*fakeCopy{},
		repairs:         map[string]fakeRepairLease{},
	}
}

func (f *fakeRepo) advance(ms int64) {
	f.mu.Lock()
	f.nowMs += ms
	f.mu.Unlock()
}

func (f *fakeRepo) addCut(cut *fakeCut) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut.state = "pending"
	cut.intents = map[string]int64{}
	cut.closures = map[string]map[string]bool{"user": {}, "recovery": {}}
	f.cuts[cut.facts.CutID] = cut
}

func (f *fakeRepo) ClaimCuts(_ context.Context, workerID string, limit int, leaseTTLMs int64) ([]CutClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []CutClaim
	for _, cut := range f.cuts {
		if len(out) >= limit {
			break
		}
		claimable := (cut.state == "pending" || (cut.state == "materializing" && cut.leaseExpiry < f.nowMs)) &&
			cut.nextAttempt <= f.nowMs
		if !claimable {
			continue
		}
		if cut.attempts >= 16 {
			cut.state = "failed"
			cut.opSettled = "failed"
			cut.lastError = "dead_letter"
			continue
		}
		cut.state = "materializing"
		cut.claimEpoch++
		cut.leaseExpiry = f.nowMs + leaseTTLMs
		cut.attempts++
		claimed := CutClaim{
			Facts:            cut.facts,
			TenantID:         cut.tenant,
			ClaimEpoch:       cut.claimEpoch,
			LeaseExpiresDbMs: cut.leaseExpiry,
			DbTimeMs:         f.nowMs,
			AttemptCount:     int64(cut.attempts),
			ReplicationPolicy: ReplicationPolicy{
				Version:                "1",
				PolicyEpoch:            "1",
				RequiredFailureDomains: append([]string(nil), f.requiredDomains...),
			},
		}
		out = append(out, claimed)
	}
	return out, nil
}

func (f *fakeRepo) requireClaim(cutID string, claimEpoch int64) (*fakeCut, error) {
	cut, ok := f.cuts[cutID]
	if !ok {
		return nil, fmt.Errorf("cut %s not found", cutID)
	}
	if cut.state != "materializing" || cut.claimEpoch != claimEpoch {
		return nil, fmt.Errorf("%w: cut %s epoch %d state %s", ErrFenced, cutID, claimEpoch, cut.state)
	}
	if cut.leaseExpiry < f.nowMs {
		return nil, fmt.Errorf("%w: lease expired", ErrFenced)
	}
	return cut, nil
}

func (f *fakeRepo) HeartbeatCut(_ context.Context, cutID string, claimEpoch int64, _ string, ttlMs int64, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.heartbeatErr != nil {
		if err := f.heartbeatErr(); err != nil {
			return err
		}
	}
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return err
	}
	cut.leaseExpiry = f.nowMs + ttlMs
	return nil
}

func (f *fakeRepo) RetryCut(_ context.Context, cutID string, claimEpoch int64, errDoc any, backoffMs int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return err
	}
	cut.state = "pending"
	cut.leaseExpiry = 0
	cut.nextAttempt = f.nowMs + backoffMs
	raw, _ := json.Marshal(errDoc)
	cut.lastError = string(raw)
	return nil
}

func (f *fakeRepo) FailCut(_ context.Context, cutID string, claimEpoch int64, errDoc any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return err
	}
	cut.state = "failed"
	cut.opSettled = "failed"
	raw, _ := json.Marshal(errDoc)
	cut.lastError = string(raw)
	return nil
}

func (f *fakeRepo) ReadJournalPage(_ context.Context, cutID string, claimEpoch int64, fromSeq uint64, maxRecords int, _ int64) ([]historycut.PageRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return nil, err
	}
	var out []historycut.PageRecord
	for _, r := range cut.journal {
		if r.Seq >= fromSeq && len(out) < maxRecords {
			out = append(out, r)
		}
	}
	return out, nil
}

// ─── legacy pipeline ─────────────────────────────────────────────────────────

func (f *fakeRepo) LegacyChainPrepare(_ context.Context, cutID string, claimEpoch int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.requireClaim(cutID, claimEpoch)
	return err
}

func (f *fakeRepo) LegacyChainApplyPage(_ context.Context, cutID string, claimEpoch int64, _ int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.requireClaim(cutID, claimEpoch); err != nil {
		return false, err
	}
	return true, nil
}

func (f *fakeRepo) LegacyAssignOrds(_ context.Context, cutID string, claimEpoch int64, page int) (bool, error) {
	return f.LegacyChainApplyPage(nil, cutID, claimEpoch, page)
}

func (f *fakeRepo) LegacyAssignInos(_ context.Context, cutID string, claimEpoch int64, page int) (bool, error) {
	return f.LegacyChainApplyPage(nil, cutID, claimEpoch, page)
}

func (f *fakeRepo) LegacyEntriesPage(_ context.Context, cutID string, claimEpoch int64, afterOrd int64, limit int) ([]historycut.LegacyEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.requireClaim(cutID, claimEpoch); err != nil {
		return nil, err
	}
	if f.legacy == nil {
		return nil, nil
	}
	var out []historycut.LegacyEntry
	for _, e := range f.legacy.entries {
		if e.Ord > afterOrd && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeRepo) LegacyGetImportCursor(_ context.Context, cutID string, claimEpoch int64) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.requireClaim(cutID, claimEpoch); err != nil {
		return nil, err
	}
	if f.legacy == nil {
		return nil, nil
	}
	return f.legacy.cursor, nil
}

func (f *fakeRepo) LegacyPutImportCursor(_ context.Context, cutID string, claimEpoch int64, cursor json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.requireClaim(cutID, claimEpoch); err != nil {
		return err
	}
	if f.legacy != nil {
		f.legacy.cursor = append(json.RawMessage(nil), cursor...)
	}
	return nil
}

func (f *fakeRepo) LegacyVerifyTreeHash(_ context.Context, cutID string, claimEpoch int64, treeHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.requireClaim(cutID, claimEpoch); err != nil {
		return err
	}
	if f.legacy == nil || f.legacy.wantHash == "" {
		return nil
	}
	if f.legacy.wantHash != treeHash {
		return fmt.Errorf("%w: tree hash mismatch", historycut.ErrCorrupt)
	}
	return nil
}

func (f *fakeRepo) LocateLegacyBlob(_ context.Context, cutID string, claimEpoch int64, digest string) (*LegacyBlobLocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.requireClaim(cutID, claimEpoch); err != nil {
		return nil, err
	}
	if f.legacy == nil {
		return nil, nil
	}
	key, ok := f.legacy.blobs[digest]
	if !ok {
		return nil, nil
	}
	return &LegacyBlobLocation{
		Digest: digest, StorageKey: key, Size: f.legacy.blobSizes[digest],
	}, nil
}

// ─── objects / receipts / publication ────────────────────────────────────────

func (f *fakeRepo) IntendObjects(_ context.Context, cutID string, claimEpoch int64, objects []ObjectIntent) (map[string]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beforeIntend != nil {
		if err := f.beforeIntend(); err != nil {
			return nil, err
		}
	}
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(objects))
	for _, fact := range objects {
		key := objKey(cut.tenant, "pft2", fact.Digest)
		o, ok := f.objects[key]
		if !ok {
			o = &fakeObject{
				tenant: cut.tenant, kind: "pft2", digest: fact.Digest,
				size: fact.Size, incarnation: 1, state: "intended",
				lastUpdateMs: f.nowMs,
			}
			f.objects[key] = o
		} else {
			if o.size != fact.Size {
				return nil, fmt.Errorf("%w: size conflict for %s", historycut.ErrCorrupt, fact.Digest)
			}
			switch o.state {
			case "deleting", "tombstoned":
				o.incarnation++
				o.state = "intended"
				o.sweepLease = 0
				o.lastUpdateMs = f.nowMs
			case "reclaiming":
				o.state = "intended"
				o.lastUpdateMs = f.nowMs
			}
		}
		cut.intents[fact.Digest] = o.incarnation
		out[fact.Digest] = o.incarnation
	}
	return out, nil
}

func (f *fakeRepo) RecordCopyReceipt(_ context.Context, cutID string, claimEpoch int64, digest string, incarnation int64, failureDomain, storageKey string, size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callsReceipt++
	return f.recordCopyReceiptLocked(cutID, claimEpoch, digest, incarnation, failureDomain, storageKey, size)
}

func (f *fakeRepo) RecordCopyReceipts(_ context.Context, cutID string, claimEpoch int64, receipts []CopyReceipt) error {
	if len(receipts) < 1 || len(receipts) > 4096 {
		return fmt.Errorf("copy receipt batches are bounded to 1..4096 entries")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callsReceiptBatch++
	for _, r := range receipts {
		if err := f.recordCopyReceiptLocked(cutID, claimEpoch,
			r.Digest, r.Incarnation, r.FailureDomain, r.StorageKey, r.Size); err != nil {
			return err
		}
	}
	return nil
}

// recordCopyReceiptLocked mirrors pfh.object_copy_receipt: intent binding,
// incarnation fence, and the 025 write-quorum 'live' flip.
func (f *fakeRepo) recordCopyReceiptLocked(cutID string, claimEpoch int64, digest string, incarnation int64, failureDomain, storageKey string, size int64) error {
	if f.beforeCopyReceipt != nil {
		if err := f.beforeCopyReceipt(); err != nil {
			return err
		}
	}
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return err
	}
	intended, ok := cut.intents[digest]
	if !ok {
		return fmt.Errorf("copy receipt for %s without intent", digest)
	}
	if intended != incarnation {
		return fmt.Errorf("%w: receipt incarnation %d contradicts intent %d", historycut.ErrCorrupt, incarnation, intended)
	}
	key := objKey(cut.tenant, "pft2", digest)
	o, ok := f.objects[key]
	if !ok {
		return fmt.Errorf("object %s unregistered", digest)
	}
	if o.incarnation != incarnation || o.state == "deleting" || o.state == "tombstoned" {
		return fmt.Errorf("%w: incarnation %d superseded (current %d, %s)", ErrFenced, incarnation, o.incarnation, o.state)
	}
	ck := copyKey(key, incarnation, failureDomain)
	f.copies[ck] = &fakeCopy{
		storageKey: storageKey, size: size, state: "present", lastVerified: f.nowMs,
	}
	present := 0
	for _, domain := range f.requiredDomains {
		if c, ok := f.copies[copyKey(key, o.incarnation, domain)]; ok && c.state == "present" {
			present++
		}
	}
	if present >= writeQuorum(len(f.requiredDomains)) && (o.state == "intended" || o.state == "reclaiming") {
		o.state = "live"
		o.lastUpdateMs = f.nowMs
	}
	if f.afterCopyReceipt != nil {
		if err := f.afterCopyReceipt(); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeRepo) AddCutObjects(_ context.Context, cutID string, claimEpoch int64, closure string, digests []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return err
	}
	for _, d := range digests {
		cut.closures[closure][d] = true
	}
	return nil
}

// AddCutObjectsFromBase mirrors pfh.cut_objects_add_from_base: copy the
// adopted same-branch base cut's closure rows and answer final totals.
func (f *fakeRepo) AddCutObjectsFromBase(_ context.Context, cutID string, claimEpoch int64) (ClosureTotals, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut, err := f.requireClaim(cutID, claimEpoch)
	if err != nil {
		return ClosureTotals{}, err
	}
	base := cut.facts.BaseCommit
	if base == nil || base.CommitKind != "pft2" || base.BaseMode != "adopted" {
		return ClosureTotals{}, fmt.Errorf("cut %s base is not an adopted pft2 commit", cutID)
	}
	var baseCut *fakeCut
	for _, other := range f.cuts {
		if other.state == "ready" && other.commitID == base.CommitID {
			baseCut = other
			break
		}
	}
	if baseCut == nil {
		return ClosureTotals{}, fmt.Errorf("base commit %s has no ready cut", base.CommitID)
	}
	for closure, digests := range baseCut.closures {
		for digest := range digests {
			cut.closures[closure][digest] = true
		}
	}
	totals := ClosureTotals{}
	for digest := range cut.closures["user"] {
		totals.UserObjectCount++
		if o, ok := f.objects[objKey(cut.tenant, "pft2", digest)]; ok {
			totals.UserObjectBytes += o.size
		}
	}
	for digest := range cut.closures["recovery"] {
		totals.RecoveryObjectCount++
		if o, ok := f.objects[objKey(cut.tenant, "pft2", digest)]; ok {
			totals.RecoveryObjectBytes += o.size
		}
	}
	return totals, nil
}

func (f *fakeRepo) MarkCutReady(_ context.Context, in ReadyFacts) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beforeMarkReady != nil {
		if err := f.beforeMarkReady(); err != nil {
			return err
		}
	}
	cut, err := f.requireClaim(in.CutID, in.ClaimEpoch)
	if err != nil {
		return err
	}
	if int64(len(cut.closures["user"])) != in.UserObjectCount ||
		int64(len(cut.closures["recovery"])) != in.RecoveryObjectCount {
		return fmt.Errorf("%w: closure counts %d/%d vs %d/%d", historycut.ErrCorrupt,
			len(cut.closures["user"]), len(cut.closures["recovery"]),
			in.UserObjectCount, in.RecoveryObjectCount)
	}
	if !cut.closures["user"]["sha256:"+in.RootDigestHex] {
		return fmt.Errorf("%w: user closure misses its root", historycut.ErrCorrupt)
	}
	if !cut.closures["recovery"]["sha256:"+in.RecoveryRootDigestHex] {
		return fmt.Errorf("%w: recovery closure misses its root", historycut.ErrCorrupt)
	}
	if cut.closures["user"]["sha256:"+in.RecoveryRootDigestHex] {
		return fmt.Errorf("%w: user closure reaches the recovery root", historycut.ErrCorrupt)
	}
	// Mirrors the 025 pfh.cut_mark_ready readiness rule: W-of-N verified
	// copies per closure object; the freshness window applies only to
	// objects THIS cut produced (intent rows) — reused rows count on
	// presence, with scrub owning their cadence.
	quorum := writeQuorum(len(f.requiredDomains))
	for _, closure := range []string{"user", "recovery"} {
		for digest := range cut.closures[closure] {
			key := objKey(cut.tenant, "pft2", digest)
			o, ok := f.objects[key]
			if !ok || o.state != "live" {
				return fmt.Errorf("%w: closure object %s is not live", historycut.ErrCorrupt, digest)
			}
			_, intended := cut.intents[digest]
			counted := 0
			for _, domain := range f.requiredDomains {
				c, ok := f.copies[copyKey(key, o.incarnation, domain)]
				if !ok || c.state != "present" {
					continue
				}
				if intended && c.lastVerified < f.nowMs-f.freshnessMs {
					continue
				}
				counted++
			}
			if counted < quorum {
				return fmt.Errorf("%w: object %s holds %d of the %d-copy quorum", historycut.ErrCorrupt, digest, counted, quorum)
			}
		}
	}
	cut.state = "ready"
	cut.consumed = true
	cut.commitID = "cpft2_" + in.CutID
	cut.anchorID = "hanch_" + in.CutID
	cut.opSettled = "succeeded"
	inCopy := in
	cut.readyInput = &inCopy
	return nil
}

func (f *fakeRepo) LocateObject(_ context.Context, tenant, kind, digest string) (*ObjectLocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callsLocate++
	return f.locateLocked(tenant, kind, digest), nil
}

func (f *fakeRepo) LocateObjects(_ context.Context, tenant, kind string, digests []string) (map[string]*ObjectLocation, error) {
	if len(digests) < 1 || len(digests) > 512 {
		return nil, fmt.Errorf("object locate batches are bounded to 1..512 digests")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callsLocateBatch++
	out := make(map[string]*ObjectLocation, len(digests))
	for _, digest := range digests {
		if loc := f.locateLocked(tenant, kind, digest); loc != nil {
			out[digest] = loc
		}
	}
	return out, nil
}

func (f *fakeRepo) locateLocked(tenant, kind, digest string) *ObjectLocation {
	key := objKey(tenant, kind, digest)
	o, ok := f.objects[key]
	if !ok || o.state == "tombstoned" {
		return nil
	}
	out := &ObjectLocation{
		TenantID: tenant, Kind: kind, Digest: digest,
		Size: o.size, Incarnation: o.incarnation, State: o.state,
	}
	for domain, c := range f.copiesOf(key, o.incarnation) {
		if c.state != "present" {
			continue
		}
		out.Copies = append(out.Copies, CopyRecord{
			FailureDomain: domain, StorageKey: c.storageKey,
			Size: c.size, LastVerified: c.lastVerified,
		})
	}
	return out
}

func (f *fakeRepo) copiesOf(key string, incarnation int64) map[string]*fakeCopy {
	out := map[string]*fakeCopy{}
	prefix := key + "\x01" + strconv.FormatInt(incarnation, 10) + "\x01"
	for ck, c := range f.copies {
		if strings.HasPrefix(ck, prefix) {
			out[strings.TrimPrefix(ck, prefix)] = c
		}
	}
	return out
}

func (f *fakeRepo) WorkerBeat(context.Context, string, []string, any) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nowMs, nil
}

// ─── scrub / repair / sweep ──────────────────────────────────────────────────

func (f *fakeRepo) ClaimScrubCopies(_ context.Context, workerID string, limit int) ([]ScrubCopy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ScrubCopy
	for key, o := range f.objects {
		if len(out) >= limit {
			break
		}
		if o.state != "live" && o.state != "quarantined" && o.state != "intended" {
			continue
		}
		for domain, c := range f.copiesOf(key, o.incarnation) {
			if len(out) >= limit || c.state != "present" || c.nextVerify > f.nowMs || c.verifyLease > f.nowMs {
				continue
			}
			c.nextVerify = f.nowMs + 900000
			c.verifyWorker = workerID
			c.verifyEpoch++
			c.verifyLease = f.nowMs + 900000
			out = append(out, ScrubCopy{
				TenantID: o.tenant, Kind: o.kind, Digest: o.digest,
				Incarnation: o.incarnation, FailureDomain: domain,
				StorageKey: c.storageKey, Size: c.size,
				ClaimEpoch: c.verifyEpoch, ClaimExpiresMs: c.verifyLease,
			})
		}
	}
	return out, nil
}

func (f *fakeRepo) RecordScrubReceipt(_ context.Context, workerID string, claim ScrubCopy, ok bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := objKey(claim.TenantID, claim.Kind, claim.Digest)
	o, found := f.objects[key]
	if !found {
		return fmt.Errorf("object %s unregistered", claim.Digest)
	}
	if o.incarnation != claim.Incarnation {
		return fmt.Errorf("%w: scrub receipt for superseded incarnation", ErrFenced)
	}
	c, found := f.copies[copyKey(key, claim.Incarnation, claim.FailureDomain)]
	if !found {
		return fmt.Errorf("copy missing")
	}
	if c.verifyWorker != workerID || c.verifyEpoch != claim.ClaimEpoch || c.verifyLease <= f.nowMs {
		return fmt.Errorf("%w: stale scrub claim", ErrFenced)
	}
	if ok {
		c.lastVerified = f.nowMs
		c.verifyAttempts = 0
		c.nextVerify = f.nowMs + f.freshnessMs/2
		c.verifyWorker = ""
		c.verifyLease = 0
		if o.state == "quarantined" {
			healed := true
			for _, other := range f.copiesOf(key, o.incarnation) {
				if other.state == "present" && other.verifyAttempts > 0 {
					healed = false
				}
			}
			if healed {
				o.state = "live"
			}
		}
		return nil
	}
	c.verifyAttempts++
	c.nextVerify = f.nowMs + 60000
	c.verifyWorker = ""
	c.verifyLease = 0
	if c.verifyAttempts >= 3 && (o.state == "live" || o.state == "intended") {
		o.state = "quarantined"
	}
	return nil
}

func (f *fakeRepo) ClaimRepairs(_ context.Context, workerID string, limit int, leaseTTLMs int64) ([]RepairClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []RepairClaim
	for key, o := range f.objects {
		if len(out) >= limit {
			break
		}
		if o.state != "live" && o.state != "quarantined" && o.state != "intended" {
			continue
		}
		copies := f.copiesOf(key, o.incarnation)
		for _, domain := range f.requiredDomains {
			c, ok := copies[domain]
			healthy := ok && c.state == "present" && c.verifyAttempts == 0
			if healthy {
				continue
			}
			leaseKey := copyKey(key, o.incarnation, domain)
			prior, leased := f.repairs[leaseKey]
			if leased && prior.expires > f.nowMs {
				continue
			}
			var sources []RepairSource
			for srcDomain, src := range copies {
				if srcDomain != domain && src.state == "present" && src.verifyAttempts == 0 {
					sources = append(sources, RepairSource{
						FailureDomain: srcDomain, StorageKey: src.storageKey,
						Size: src.size,
					})
				}
			}
			if len(sources) == 0 {
				continue
			}
			epoch := prior.epoch + 1
			lease := fakeRepairLease{worker: workerID, epoch: epoch, expires: f.nowMs + leaseTTLMs}
			f.repairs[leaseKey] = lease
			out = append(out, RepairClaim{
				TenantID: o.tenant, Kind: o.kind, Digest: o.digest,
				Incarnation:    o.incarnation,
				Size:           o.size,
				MissingDomain:  domain,
				Sources:        sources,
				ClaimEpoch:     epoch,
				LeaseExpiresMs: lease.expires,
			})
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) RecordRepairReceipt(_ context.Context, workerID string, claim RepairClaim, storageKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := objKey(claim.TenantID, claim.Kind, claim.Digest)
	o, ok := f.objects[key]
	if !ok {
		return fmt.Errorf("object unregistered")
	}
	if o.incarnation != claim.Incarnation || o.state == "deleting" || o.state == "tombstoned" {
		return fmt.Errorf("%w: repair receipt for superseded incarnation", ErrFenced)
	}
	if o.size != claim.Size {
		return fmt.Errorf("%w: repair size mismatch", historycut.ErrCorrupt)
	}
	leaseKey := copyKey(key, claim.Incarnation, claim.MissingDomain)
	lease, ok := f.repairs[leaseKey]
	if !ok || lease.worker != workerID || lease.epoch != claim.ClaimEpoch || lease.expires <= f.nowMs {
		return fmt.Errorf("%w: stale repair claim", ErrFenced)
	}
	f.copies[leaseKey] = &fakeCopy{
		storageKey: storageKey, size: claim.Size, state: "present", lastVerified: f.nowMs,
	}
	delete(f.repairs, leaseKey)
	if o.state == "quarantined" {
		healed := true
		for _, c := range f.copiesOf(key, o.incarnation) {
			if c.state == "present" && c.verifyAttempts > 0 {
				healed = false
			}
		}
		if healed {
			o.state = "live"
		}
	}
	return nil
}

// isRoot mirrors pfh.object_is_root: intents of live cuts + closures of
// ready consumed cuts.
func (f *fakeRepo) isRoot(tenant, digest string) bool {
	for _, cut := range f.cuts {
		if cut.tenant != tenant {
			continue
		}
		switch cut.state {
		case "pending", "materializing":
			if _, ok := cut.intents[digest]; ok {
				return true
			}
		case "ready":
			if cut.consumed && (cut.closures["user"][digest] || cut.closures["recovery"][digest]) {
				return true
			}
		}
	}
	return false
}

func (f *fakeRepo) releaseCut(cutID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cut, ok := f.cuts[cutID]; ok {
		cut.consumed = false
	}
}

// RetentionRelease answers the injected hook; the release policy itself is
// SQL (pfh.retention_release) and covered by the Postgres harness.
func (f *fakeRepo) RetentionRelease(_ context.Context, limit int) (int64, error) {
	f.mu.Lock()
	hook := f.retentionRelease
	f.mu.Unlock()
	if hook == nil {
		return 0, ErrCapabilityMissing
	}
	return hook(limit)
}

func (f *fakeRepo) ClaimSweep(_ context.Context, workerID string, minAgeMs, leaseTTLMs int64) (*SweepClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Expired 'deleting' claims (crashed sweepers) reclaim FIRST — mirrors
	// the SQL ORDER BY (state='deleting') DESC.
	for _, phase := range []string{"reclaim", "fresh"} {
		if claim := f.claimSweepPhase(phase, minAgeMs, leaseTTLMs); claim != nil {
			return claim, nil
		}
	}
	return nil, nil
}

func (f *fakeRepo) claimSweepPhase(phase string, minAgeMs, leaseTTLMs int64) *SweepClaim {
	for key, o := range f.objects {
		reclaimable := o.state == "deleting" && o.sweepLease > 0 && o.sweepLease < f.nowMs
		sweepable := (o.state == "live" || o.state == "intended" || o.state == "reclaiming") &&
			o.lastUpdateMs < f.nowMs-minAgeMs
		if phase == "reclaim" && !reclaimable {
			continue
		}
		if phase == "fresh" && (!sweepable || reclaimable) {
			continue
		}
		if !reclaimable && !sweepable {
			continue
		}
		if o.state != "deleting" && f.isRoot(o.tenant, o.digest) {
			continue
		}
		if o.state != "deleting" {
			o.reclaimGen++
		}
		o.state = "deleting"
		o.sweepEpoch++
		o.sweepLease = f.nowMs + leaseTTLMs
		claim := &SweepClaim{
			TenantID: o.tenant, Kind: o.kind, Digest: o.digest,
			Size:              o.size,
			Incarnation:       o.incarnation,
			ReclaimGeneration: o.reclaimGen,
			ClaimEpoch:        o.sweepEpoch,
		}
		for domain, c := range f.copiesOf(key, o.incarnation) {
			if c.state == "present" || c.state == "deleting" {
				c.state = "deleting"
				claim.Copies = append(claim.Copies, SweepCopy{
					FailureDomain: domain, StorageKey: c.storageKey,
				})
			}
		}
		return claim
	}
	return nil
}

func (f *fakeRepo) CompleteSweep(_ context.Context, _ string, claim *SweepClaim, proofs []AbsenceReceipt) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := objKey(claim.TenantID, claim.Kind, claim.Digest)
	o, ok := f.objects[key]
	if !ok {
		return "", fmt.Errorf("object unregistered")
	}
	if o.incarnation != claim.Incarnation ||
		o.reclaimGen != claim.ReclaimGeneration ||
		o.sweepEpoch != claim.ClaimEpoch ||
		o.state != "deleting" {
		return "resurrected", nil
	}
	if f.isRoot(o.tenant, o.digest) {
		o.state = "live"
		for _, c := range f.copiesOf(key, o.incarnation) {
			if c.state == "deleting" {
				c.state = "present"
			}
		}
		return "resurrected", nil
	}
	// Every claimed deleting copy must carry an exact absence proof.
	for domain, c := range f.copiesOf(key, o.incarnation) {
		if c.state != "deleting" {
			continue
		}
		proven := false
		for _, p := range proofs {
			if p.FailureDomain == domain && p.StorageKey == c.storageKey && p.ConfirmedAbsent {
				proven = true
			}
		}
		if !proven {
			return "", fmt.Errorf("missing absence proof for %s", domain)
		}
		c.state = "absent"
	}
	o.state = "tombstoned"
	o.sweepLease = 0
	return "swept", nil
}

func (f *fakeRepo) ReleaseSweep(_ context.Context, _ string, claim *SweepClaim, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := objKey(claim.TenantID, claim.Kind, claim.Digest)
	o, ok := f.objects[key]
	if !ok || o.state != "deleting" || o.sweepEpoch != claim.ClaimEpoch {
		return nil
	}
	o.state = "reclaiming"
	o.sweepLease = 0
	for _, c := range f.copiesOf(key, o.incarnation) {
		if c.state == "deleting" {
			c.state = "present"
		}
	}
	return nil
}

// The fake installs no rehome plane: optional loops observe the same typed
// capability gap a database without that surface produces and idle.
func (f *fakeRepo) RehomeLive(context.Context, int) ([]RehomeRef, error) {
	return nil, ErrCapabilityMissing
}

func (f *fakeRepo) RehomeCopyPage(context.Context, string, int) ([]RehomeCopyItem, error) {
	return nil, ErrCapabilityMissing
}

func (f *fakeRepo) RehomeCopyReceipt(context.Context, string, string, string, int64, string, string) error {
	return ErrCapabilityMissing
}

func (f *fakeRepo) Close() {}
