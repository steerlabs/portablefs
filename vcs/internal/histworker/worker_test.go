package histworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/historycut"
	"github.com/steerlabs/portablefs/vcs/internal/histstore"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/treehash"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const (
	domA = "dom-a"
	domB = "dom-b"
)

type rig struct {
	repo   *fakeRepo
	stores *DomainStores
	fsA    *histstore.FSStore
	fsB    *histstore.FSStore
	worker *Worker
}

func newRig(t *testing.T) *rig {
	t.Helper()
	return newRigWith(t, io.Discard, nil, nil)
}

// newRigWith builds the standard two-domain rig with optional log capture,
// config mutation, and per-domain store wrapping (fault injection).
func newRigWith(t *testing.T, logOut io.Writer, mutate func(*Config), wrap func(histstore.Store) histstore.Store) *rig {
	t.Helper()
	repo := newFakeRepo([]string{domA, domB})
	rootA := t.TempDir()
	rootB := t.TempDir()
	fsA, err := histstore.NewFSStore(histstore.FSConfig{Domain: domA, RootDir: rootA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsA.Close() })
	fsB, err := histstore.NewFSStore(histstore.FSConfig{Domain: domB, RootDir: rootB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsB.Close() })
	storeA, storeB := histstore.Store(fsA), histstore.Store(fsB)
	if wrap != nil {
		storeA, storeB = wrap(storeA), wrap(storeB)
	}
	stores, err := NewDomainStores(storeA, storeB)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DSN:                    "postgres://test@localhost/test",
		WorkerID:               "test-worker",
		ExpectedPolicyEpoch:    1,
		Stores:                 []StoreConfig{{FailureDomain: domA, Kind: "fs", RootDir: rootA}, {FailureDomain: domB, Kind: "fs", RootDir: rootB}},
		MaterializeConcurrency: 2,
		UploadConcurrency:      4,
		ScrubBatch:             64,
		ScrubConcurrency:       4,
		RepairBatch:            16,
		RepairConcurrency:      4,
		LeaseTTL:               60 * time.Second,
		HeartbeatInterval:      15 * time.Second,
		PollInterval:           100 * time.Millisecond,
		SweepMinAge:            time.Hour,
		FreshenAge:             24 * time.Hour,
		ShutdownGrace:          time.Second,
		MaxCacheBytes:          8 << 20,
		MaxPendingUploadBytes:  8 << 20,
		MaxLegacyBlobBytes:     8 << 20,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	worker, err := New(cfg, repo, stores, logOut)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{repo: repo, stores: stores, fsA: fsA, fsB: fsB, worker: worker}
}

func hexOf(d [32]byte) string { return hex.EncodeToString(d[:]) }

func buildManagedCut(t *testing.T, tenant, cutID string) *fakeCut {
	t.Helper()
	var payloads [][]byte
	for i, rec := range []wal.Record{
		{Op: wal.OpMkdir, Path: "docs", Mode: 0o755, Inos: []uint64{0x700000002}, TsMs: 11},
		{Op: wal.OpCreate, Path: "docs/a.txt", Mode: 0o644, Ino: 0x700000003, TsMs: 22},
		{Op: wal.OpWrite, Path: "docs/a.txt", Data: bytes.Repeat([]byte("data!"), 3000), TsMs: 33},
		{Op: wal.OpCreate, Path: "docs/b.txt", Mode: 0o600, Ino: 0x700000004, TsMs: 44},
		{Op: wal.OpRemove, Path: "docs/b.txt", TsMs: 55},
	} {
		rec.Seq = uint64(i)
		entry := pfj3.JournalEntry{LSN: rec.Seq, Tree: &rec}
		payload, err := pfj3.Encode(&entry)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	var chain [32]byte
	base := chain
	var records []historycut.PageRecord
	for i, payload := range payloads {
		chain = historycut.ChainStep(chain, payload)
		records = append(records, historycut.PageRecord{
			Seq:         uint64(i),
			Payload:     payload,
			RecordHash:  hexOf(historycut.RecordHash(payload)),
			ChainDigest: hexOf(chain),
		})
	}
	return &fakeCut{
		tenant: tenant,
		facts: historycut.CutFacts{
			CutID: cutID, Kind: "recovery", SourceKind: "managed_journal",
			GenerationID: "gen_1", RecordCodec: "pfj3", ControlCodec: "pfc2",
			SourceBaseSeq: "0", SourceBaseDig: hexOf(base),
			CutSeqExclusive: strconv.Itoa(len(records)),
			CutDigest:       hexOf(chain),
			InodeNamespace:  "7", NamespaceNext: "1",
		},
		journal: records,
	}
}

func TestMaterializeManagedCutEndToEnd(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-1", "hcut_e2e")
	r.repo.addCut(cut)

	if n := r.repo.mustRunCuts(t, ctx, r.worker); n != 1 {
		t.Fatalf("claimed %d cuts", n)
	}
	if cut.state != "ready" || cut.opSettled != "succeeded" {
		t.Fatalf("cut state %s / op %s (err %s)", cut.state, cut.opSettled, cut.lastError)
	}
	in := cut.readyInput
	if in.UserObjectCount == 0 || in.RecoveryObjectCount == 0 {
		t.Fatalf("closure counts: %+v", in)
	}

	// Every closure object is live with verified copies in BOTH domains at
	// tenant/kind/digest/incarnation exact keys — proven by re-reading each
	// recorded key from each store.
	for digest := range mergedClosures(cut) {
		located, err := r.repo.LocateObject(ctx, "tenant-1", "pft2", digest)
		if err != nil || located == nil {
			t.Fatalf("locate %s: %+v %v", digest, located, err)
		}
		if located.State != "live" || len(located.Copies) != 2 {
			t.Fatalf("object %s: %+v", digest, located)
		}
		size := located.Size
		for _, c := range located.Copies {
			wantKey, _ := histstore.ObjectID{
				Tenant: "tenant-1", Kind: "pft2",
				DigestHex:   strings.TrimPrefix(digest, "sha256:"),
				Incarnation: located.Incarnation,
			}.Key()
			if c.StorageKey != wantKey {
				t.Fatalf("copy key %s, want %s", c.StorageKey, wantKey)
			}
			store, _ := r.stores.Get(c.FailureDomain)
			if err := histstore.VerifyStream(ctx, store, c.StorageKey, size, strings.TrimPrefix(digest, "sha256:")); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The user root opens through a strict PFT2 reader fed ONLY by located
	// exact-key store reads (the serving path), and the removed name is gone.
	rootRef := refOf(t, in.RootDigestHex, uint64(in.RootSize))
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{
		Fetcher: &locateFetcher{t: t, ctx: ctx, repo: r.repo, stores: r.stores, tenant: "tenant-1"},
	}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := reader.Lookup(ctx, rootView.Ref, "docs")
	if err != nil {
		t.Fatal(err)
	}
	docsView, err := reader.GetInode(ctx, docs.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Lookup(ctx, docsView.Ref, "a.txt"); err != nil {
		t.Fatalf("a.txt: %v", err)
	}
	if _, err := reader.Lookup(ctx, docsView.Ref, "b.txt"); !errors.Is(err, pft2.ErrNotFound) {
		t.Fatalf("removed b.txt still resolves: %v", err)
	}
}

// mustRunCuts runs one cut pass and returns claims (helper on fakeRepo to
// keep the worker API untouched).
func (f *fakeRepo) mustRunCuts(t *testing.T, ctx context.Context, w *Worker) int {
	t.Helper()
	busy, err := w.materializePass(ctx, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if busy {
		return 1
	}
	return 0
}

func (w *Worker) runCutsOnce(ctx context.Context) int {
	busy, _ := w.materializePass(ctx, ctx)
	if busy {
		return 1
	}
	return 0
}

func (w *Worker) runScrubOnce(ctx context.Context) int {
	n, _ := w.scrubPass(ctx)
	return n
}

func (w *Worker) runRepairOnce(ctx context.Context) int {
	n, _ := w.repairPass(ctx)
	return n
}

func (w *Worker) runSweepOnce(ctx context.Context) int {
	busy, _ := w.gcPass(ctx)
	if busy {
		return 1
	}
	return 0
}

func mergedClosures(cut *fakeCut) map[string]bool {
	out := map[string]bool{}
	for _, closure := range cut.closures {
		for d := range closure {
			out[d] = true
		}
	}
	return out
}

func refOf(t *testing.T, digestHex string, size uint64) pft2.Ref {
	t.Helper()
	raw, err := hex.DecodeString(digestHex)
	if err != nil || len(raw) != 32 {
		t.Fatalf("digest %q", digestHex)
	}
	var d [32]byte
	copy(d[:], raw)
	return pft2.Ref{Digest: d, Size: size}
}

// locateFetcher reads PFT2 objects the SERVING way: locate by identity,
// read the recorded exact key, verify.
type locateFetcher struct {
	t      *testing.T
	ctx    context.Context
	repo   *fakeRepo
	stores *DomainStores
	tenant string
}

func (l *locateFetcher) Fetch(_ context.Context, ref pft2.Ref) ([]byte, error) {
	digest := "sha256:" + ref.Hex()
	located, err := l.repo.LocateObject(l.ctx, l.tenant, "pft2", digest)
	if err != nil || located == nil {
		return nil, fmt.Errorf("locate %s: %v", digest, err)
	}
	var lastErr error
	for _, c := range located.Copies {
		store, ok := l.stores.Get(c.FailureDomain)
		if !ok {
			continue
		}
		data, err := histstore.ReadVerified(l.ctx, store, c.StorageKey, int64(ref.Size), ref.Hex())
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no verified copy of %s: %w", digest, lastErr)
}

// ─── crash seams ─────────────────────────────────────────────────────────────

func TestCrashSeamsConvergeOnRerun(t *testing.T) {
	seams := []struct {
		name string
		arm  func(r *rig, remaining *int)
	}{
		{"before-intent", func(r *rig, remaining *int) {
			r.repo.beforeIntend = func() error {
				if *remaining--; *remaining < 0 {
					return errors.New("injected crash before intent")
				}
				return nil
			}
		}},
		{"before-copy-receipt", func(r *rig, remaining *int) {
			r.repo.beforeCopyReceipt = func() error {
				if *remaining--; *remaining < 0 {
					return errors.New("injected crash before copy receipt")
				}
				return nil
			}
		}},
		{"before-mark-ready", func(r *rig, remaining *int) {
			r.repo.beforeMarkReady = func() error {
				if *remaining--; *remaining < 0 {
					return errors.New("injected crash before mark ready")
				}
				return nil
			}
		}},
	}
	for _, seam := range seams {
		t.Run(seam.name, func(t *testing.T) {
			r := newRig(t)
			ctx := context.Background()
			cut := buildManagedCut(t, "tenant-c", "hcut_"+seam.name)
			r.repo.addCut(cut)
			remaining := 0 // the first call at this seam dies
			seam.arm(r, &remaining)

			r.worker.runCutsOnce(ctx)
			if cut.state == "ready" {
				t.Fatal("cut became ready through an injected crash")
			}
			if cut.state != "pending" {
				t.Fatalf("crashed attempt left state %s", cut.state)
			}

			// Heal the seam, pass the backoff, re-claim: the deterministic
			// rerun converges; receipts and uploads are idempotent.
			remaining = 1 << 30
			r.repo.advance(31000)
			r.worker.runCutsOnce(ctx)
			if cut.state != "ready" || cut.opSettled != "succeeded" {
				t.Fatalf("rerun did not converge: %s (%s)", cut.state, cut.lastError)
			}
		})
	}
}

func TestLostCopyReceiptResponseConvergesWithoutDuplicateTruth(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-lost", "hcut_lost_receipt")
	r.repo.addCut(cut)

	armed := true
	r.repo.afterCopyReceipt = func() error {
		if armed {
			armed = false
			return errors.New("injected lost response after durable receipt")
		}
		return nil
	}
	r.worker.runCutsOnce(ctx)
	if cut.state != "pending" {
		t.Fatalf("lost response attempt left cut %s, want retryable pending", cut.state)
	}
	if len(r.repo.copies) == 0 {
		t.Fatal("lost response did not preserve the durably applied receipt")
	}

	r.repo.advance(31_000)
	r.worker.runCutsOnce(ctx)
	if cut.state != "ready" || cut.opSettled != "succeeded" {
		t.Fatalf("lost response replay did not converge: %s (%s)", cut.state, cut.lastError)
	}
	for key, copy := range r.repo.copies {
		if copy.state != "present" || copy.storageKey == "" {
			t.Fatalf("copy %s did not converge to one recorded exact key: %+v", key, copy)
		}
	}
}

func TestConcurrentWorkersClaimOneCutOnce(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-concurrent", "hcut_concurrent")
	r.repo.addCut(cut)

	other, err := New(r.worker.cfg, r.repo, r.stores, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan int, 2)
	for _, worker := range []*Worker{r.worker, other} {
		go func(worker *Worker) {
			<-start
			results <- worker.runCutsOnce(ctx)
		}(worker)
	}
	close(start)
	claimed := <-results + <-results
	if claimed != 1 {
		t.Fatalf("concurrent workers reported %d claimed passes, want exactly one", claimed)
	}
	if cut.state != "ready" || cut.claimEpoch != 1 {
		t.Fatalf("cut state=%s claimEpoch=%d, want ready/1", cut.state, cut.claimEpoch)
	}
}

func TestScrubAndRepairClaimsFenceStaleWorkers(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-fenced-maint", "hcut_fenced_maint")
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)
	if cut.state != "ready" {
		t.Fatalf("materialize: %s (%s)", cut.state, cut.lastError)
	}

	oldScrubs, err := r.repo.ClaimScrubCopies(ctx, "scrub-old", 512)
	if err != nil || len(oldScrubs) == 0 {
		t.Fatalf("old scrub claims: %d, %v", len(oldScrubs), err)
	}
	r.repo.advance(900_001)
	newScrubs, err := r.repo.ClaimScrubCopies(ctx, "scrub-new", 512)
	if err != nil || len(newScrubs) != len(oldScrubs) {
		t.Fatalf("reclaimed scrub claims: %d/%d, %v", len(newScrubs), len(oldScrubs), err)
	}
	if err := r.repo.RecordScrubReceipt(ctx, "scrub-old", oldScrubs[0], false); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale scrub receipt: %v", err)
	}
	for _, claim := range newScrubs {
		if err := r.repo.RecordScrubReceipt(ctx, "scrub-new", claim, true); err != nil {
			t.Fatalf("current scrub receipt: %v", err)
		}
	}
	if claims, err := r.repo.ClaimScrubCopies(ctx, "scrub-hot-loop", 512); err != nil || len(claims) != 0 {
		t.Fatalf("successful scrub was immediately due again: %d, %v", len(claims), err)
	}

	rootDigest := "sha256:" + cut.readyInput.RootDigestHex
	objectKey := objKey("tenant-fenced-maint", "pft2", rootDigest)
	r.repo.mu.Lock()
	object := r.repo.objects[objectKey]
	destination := r.repo.copies[copyKey(objectKey, object.incarnation, domA)]
	destination.verifyAttempts = 3
	object.state = "quarantined"
	r.repo.mu.Unlock()

	oldRepairs, err := r.repo.ClaimRepairs(ctx, "repair-old", 16, 60_000)
	if err != nil || len(oldRepairs) != 1 {
		t.Fatalf("old repair claims: %d, %v", len(oldRepairs), err)
	}
	r.repo.advance(60_001)
	newRepairs, err := r.repo.ClaimRepairs(ctx, "repair-new", 16, 60_000)
	if err != nil || len(newRepairs) != 1 {
		t.Fatalf("reclaimed repair claims: %d, %v", len(newRepairs), err)
	}
	if newRepairs[0].ClaimEpoch <= oldRepairs[0].ClaimEpoch {
		t.Fatalf("repair claim epoch did not advance: %d -> %d",
			oldRepairs[0].ClaimEpoch, newRepairs[0].ClaimEpoch)
	}
	if err := r.repo.RecordRepairReceipt(ctx, "repair-old", oldRepairs[0], "stale-key"); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale repair receipt: %v", err)
	}
	if err := r.repo.RecordRepairReceipt(ctx, "repair-new", newRepairs[0], destination.storageKey); err != nil {
		t.Fatalf("current repair receipt: %v", err)
	}
}

func TestProveClosureFreshensStaleReusedCopiesUnderTheCutClaim(t *testing.T) {
	// Incident regression (prod, 2026-07-22): an incremental cut REUSES base
	// objects it does not upload; once such an object's copies aged past the
	// freshen floor, proveOne re-verified the bytes but recorded the
	// freshness receipt through pfh.scrub_receipt — a surface that demands a
	// live scrub-loop verify claim on the copy row. The cut path holds no
	// such claim, so every receipt answered PF001 "scrub receipt claim is
	// stale", ErrFenced retried the attempt, and the cut looped
	// materializing forever. The freshness receipt must ride the CUT's own
	// claim (upload intent + object_copy_receipt) instead.
	r := newRig(t)
	ctx := context.Background()
	const tenant = "tenant-fresh"

	payload := []byte("reused base object: bytes that stay healthy while their receipts age")
	sum := sha256.Sum256(payload)
	hexDigest := hexOf(sum)
	digest := "sha256:" + hexDigest
	size := int64(len(payload))

	// The object is live with PRESENT, byte-healthy copies in both domains
	// at the exact per-incarnation keys — only their verification receipts
	// are stale (older than the 24h FreshenAge).
	id := histstore.ObjectID{Tenant: tenant, Kind: "pft2", DigestHex: hexDigest, Incarnation: 1}
	key := objKey(tenant, "pft2", digest)
	r.repo.mu.Lock()
	r.repo.objects[key] = &fakeObject{
		tenant: tenant, kind: "pft2", digest: digest,
		size: size, incarnation: 1, state: "live", lastUpdateMs: r.repo.nowMs,
	}
	r.repo.mu.Unlock()
	for _, store := range []*histstore.FSStore{r.fsA, r.fsB} {
		storageKey, err := store.ExactKey(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(ctx, storageKey, size, hexDigest, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		r.repo.mu.Lock()
		r.repo.copies[copyKey(key, 1, store.Domain())] = &fakeCopy{
			storageKey: storageKey, size: size, state: "present", lastVerified: r.repo.nowMs,
		}
		r.repo.mu.Unlock()
	}
	r.repo.advance(25 * 60 * 60 * 1000) // past FreshenAge (24h)

	cut := buildManagedCut(t, tenant, "hcut_freshen")
	r.repo.addCut(cut)
	claims, err := r.repo.ClaimCuts(ctx, "test-worker", 1, 60_000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %d, %v", len(claims), err)
	}
	claim := claims[0]
	store := newCutStore(ctx, r.repo, r.stores, claim, r.worker.cfg)

	if err := r.worker.proveClosure(ctx, claim, store, []string{digest}); err != nil {
		t.Fatalf("freshness proof over a reused stale copy fenced the cut: %v", err)
	}

	// Both copies are re-receipted FRESH at the same exact keys under the
	// same incarnation — exactly what cut_mark_ready's freshness audit needs.
	located, err := r.repo.LocateObject(ctx, tenant, "pft2", digest)
	if err != nil || located == nil {
		t.Fatalf("locate: %+v %v", located, err)
	}
	if located.Incarnation != 1 || len(located.Copies) != 2 {
		t.Fatalf("object after freshness proof: %+v", located)
	}
	freshFloor := claim.DbTimeMs - r.worker.cfg.FreshenAge.Milliseconds()
	for _, c := range located.Copies {
		if c.LastVerified < freshFloor {
			t.Fatalf("copy %s/%s still stale after proof: verified=%d floor=%d",
				digest, c.FailureDomain, c.LastVerified, freshFloor)
		}
		domainStore, ok := r.stores.Get(c.FailureDomain)
		if !ok {
			t.Fatalf("domain %s has no store", c.FailureDomain)
		}
		wantKey, err := domainStore.ExactKey(id)
		if err != nil {
			t.Fatal(err)
		}
		if c.StorageKey != wantKey {
			t.Fatalf("copy key moved during freshness proof: %s -> %s", wantKey, c.StorageKey)
		}
	}
}

func TestFenceStopsAttemptWithoutSettlement(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-f", "hcut_fence")
	r.repo.addCut(cut)
	// Fence the very first DB step after the claim.
	r.repo.beforeIntend = func() error {
		return fmt.Errorf("%w: fenced by a newer claim", ErrFenced)
	}
	r.worker.runCutsOnce(ctx)
	if cut.state == "ready" || cut.state == "failed" {
		t.Fatalf("fenced attempt must not settle the cut (state %s)", cut.state)
	}
}

func TestClaimExpiryWhileBlockedIsReclaimable(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-l", "hcut_lease")
	r.repo.addCut(cut)

	// First worker claims, then stalls past its lease (simulated: claim
	// directly, never heartbeat, advance the clock).
	claims, err := r.repo.ClaimCuts(ctx, "stalled-worker", 1, 60000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims: %v %v", claims, err)
	}
	r.repo.advance(120000)

	// The healthy worker re-claims after DB-time expiry and finishes.
	r.worker.runCutsOnce(ctx)
	if cut.state != "ready" {
		t.Fatalf("expired claim was not reclaimed: %s (%s)", cut.state, cut.lastError)
	}
	// The stalled worker's late receipts are fenced.
	stale := claims[0]
	err = r.repo.RecordCopyReceipt(ctx, stale.Facts.CutID, stale.ClaimEpoch,
		"sha256:"+hexOf(sha256.Sum256([]byte("x"))), 1, domA, "k", 1)
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("stale receipt: %v", err)
	}
}

func TestCorruptJournalDeadLettersDefinitely(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-x", "hcut_corrupt")
	cut.journal[1].Payload = append([]byte(nil), cut.journal[1].Payload...)
	cut.journal[1].Payload[0] ^= 1
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)
	if cut.state != "failed" || cut.opSettled != "failed" {
		t.Fatalf("corrupt source must fail definitively: %s / %s", cut.state, cut.opSettled)
	}
}

// ─── attempt outcomes: bounded, loud, terminal ───────────────────────────────

// gatedStore blocks every Put until the gate closes or the Put context
// dies; an optional release error simulates a store failing exactly when
// the attempt resumes. The deterministic way to hold an attempt mid-flight
// while the heartbeat / fence / shutdown / deadline machinery acts.
type gatedStore struct {
	histstore.Store
	gate       <-chan struct{}
	releaseErr error
}

func (g *gatedStore) Put(ctx context.Context, key string, size int64, digestHex string, body io.Reader) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.gate:
	}
	if g.releaseErr != nil {
		return g.releaseErr
	}
	return g.Store.Put(ctx, key, size, digestHex, body)
}

// lagReadStore answers the first misses Gets with typed absence — the
// production propagation lag between a PUT and its read-after-write GET on
// an S3-compatible store.
type lagReadStore struct {
	histstore.Store
	mu     sync.Mutex
	misses int
}

func (l *lagReadStore) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	l.mu.Lock()
	if l.misses > 0 {
		l.misses--
		l.mu.Unlock()
		return nil, 0, fmt.Errorf("%w: %s (propagation lag)", histstore.ErrNotFound, key)
	}
	l.mu.Unlock()
	return l.Store.Get(ctx, key)
}

func decodeEvents(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, entry)
	}
	return out
}

func findEvent(events []map[string]any, name string) map[string]any {
	for _, entry := range events {
		if entry["event"] == name {
			return entry
		}
	}
	return nil
}

func claimEpochOf(r *rig, cut *fakeCut) int64 {
	r.repo.mu.Lock()
	defer r.repo.mu.Unlock()
	return cut.claimEpoch
}

// TestAttemptCapTerminalFailsWithErrorDoc pins the fail-fast boundary: the
// attempt BEFORE the cap settles a retry; the attempt AT the cap settles
// the terminal FailCut whose error doc carries the last error and the
// attempt count. A terminally failed cut is never handed out again.
func TestAttemptCapTerminalFailsWithErrorDoc(t *testing.T) {
	logBuf := &bytes.Buffer{}
	r := newRigWith(t, logBuf, nil, nil)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-cap", "hcut_cap")
	r.repo.addCut(cut)
	maxAttempts := r.worker.cfg.MaxCutAttempts
	r.repo.mu.Lock()
	cut.attempts = maxAttempts - 2 // the next claim runs attempt cap-1
	r.repo.mu.Unlock()
	r.repo.beforeIntend = func() error {
		return errors.New("injected persistent transient failure")
	}

	r.worker.runCutsOnce(ctx)
	if cut.state != "pending" {
		t.Fatalf("attempt %d (below cap) settled %s, want a retry", maxAttempts-1, cut.state)
	}

	r.repo.advance(31_000)
	r.worker.runCutsOnce(ctx)
	if cut.state != "failed" || cut.opSettled != "failed" {
		t.Fatalf("attempt %d (at cap) settled %s / op %s, want terminal failure", maxAttempts, cut.state, cut.opSettled)
	}
	for _, want := range []string{"attempts_exhausted", "injected persistent transient failure", fmt.Sprintf(`"attempts":%d`, maxAttempts)} {
		if !strings.Contains(cut.lastError, want) {
			t.Fatalf("terminal error doc %q misses %q", cut.lastError, want)
		}
	}
	if findEvent(decodeEvents(t, logBuf), "cut_attempts_exhausted") == nil {
		t.Fatal("terminal failure was not logged as cut_attempts_exhausted")
	}

	// Terminal means terminal: no backoff, clock, or lease expiry makes the
	// cut claimable again.
	r.repo.advance(3_600_000)
	claims, err := r.repo.ClaimCuts(ctx, "test-worker", 8, 60_000)
	if err != nil || len(claims) != 0 {
		t.Fatalf("terminally failed cut was re-claimed: %d claims, %v", len(claims), err)
	}
}

// TestHeartbeatFenceMidflightLogsAndAssertsNothing reproduces the incident
// shape: the lease is lost while uploads are in flight. The attempt must
// die LOUDLY (cut_fenced_midflight with progress) and assert nothing on
// the row another claimer now owns.
func TestHeartbeatFenceMidflightLogsAndAssertsNothing(t *testing.T) {
	logBuf := &bytes.Buffer{}
	gate := make(chan struct{}) // never opened: the fence must release the Puts
	r := newRigWith(t, logBuf,
		func(cfg *Config) {
			cfg.LeaseTTL = 5 * time.Second
			cfg.HeartbeatInterval = 50 * time.Millisecond
		},
		func(s histstore.Store) histstore.Store { return &gatedStore{Store: s, gate: gate} })
	cut := buildManagedCut(t, "tenant-hbf", "hcut_hb_fence")
	r.repo.addCut(cut)
	r.repo.heartbeatErr = func() error {
		return fmt.Errorf("%w: lease reclaimed by another worker", ErrFenced)
	}

	r.worker.runCutsOnce(context.Background())

	r.repo.mu.Lock()
	state, nextAttempt, opSettled := cut.state, cut.nextAttempt, cut.opSettled
	r.repo.mu.Unlock()
	if state != "materializing" || nextAttempt != 0 || opSettled != "" {
		t.Fatalf("fenced attempt touched the row: state=%s nextAttempt=%d op=%q", state, nextAttempt, opSettled)
	}
	events := decodeEvents(t, logBuf)
	if findEvent(events, "cut_heartbeat_fenced") == nil {
		t.Fatal("lost lease was not logged as cut_heartbeat_fenced")
	}
	midflight := findEvent(events, "cut_fenced_midflight")
	if midflight == nil {
		t.Fatal("fenced attempt died without a cut_fenced_midflight event")
	}
	for _, field := range []string{"cutId", "claimEpoch", "phase", "uploadedObjects", "elapsedMs"} {
		if _, ok := midflight[field]; !ok {
			t.Fatalf("cut_fenced_midflight misses %s: %v", field, midflight)
		}
	}
	for _, forbidden := range []string{"cut_retry", "cut_attempt_timeout", "cut_attempts_exhausted", "cut_interrupted_shutdown"} {
		if findEvent(events, forbidden) != nil {
			t.Fatalf("fenced attempt also emitted %s", forbidden)
		}
	}
}

// TestShutdownInterruptionIsLoggedNotSettled: a worker draining at
// shutdown leaves the row to the DB-time lease (by design) but must say
// so — the interruption is an event, never silence.
func TestShutdownInterruptionIsLoggedNotSettled(t *testing.T) {
	logBuf := &bytes.Buffer{}
	gate := make(chan struct{})
	r := newRigWith(t, logBuf, nil, func(s histstore.Store) histstore.Store {
		return &gatedStore{Store: s, gate: gate, releaseErr: errors.New("injected failure during shutdown drain")}
	})
	cut := buildManagedCut(t, "tenant-shut", "hcut_shutdown")
	r.repo.addCut(cut)

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.worker.materializePass(rootCtx, context.Background())
	}()
	deadline := time.Now().Add(5 * time.Second)
	for claimEpochOf(r, cut) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("cut was never claimed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancelRoot()
	close(gate) // the drain now fails while the root context is dead
	<-done

	r.repo.mu.Lock()
	state, nextAttempt := cut.state, cut.nextAttempt
	r.repo.mu.Unlock()
	if state != "materializing" || nextAttempt != 0 {
		t.Fatalf("shutdown interruption settled the row: state=%s nextAttempt=%d", state, nextAttempt)
	}
	events := decodeEvents(t, logBuf)
	interrupted := findEvent(events, "cut_interrupted_shutdown")
	if interrupted == nil {
		t.Fatal("shutdown interruption left no cut_interrupted_shutdown event")
	}
	if _, ok := interrupted["phase"]; !ok {
		t.Fatalf("cut_interrupted_shutdown misses phase: %v", interrupted)
	}
	if findEvent(events, "cut_retry") != nil || findEvent(events, "cut_fenced_midflight") != nil {
		t.Fatal("shutdown interruption was misclassified")
	}
}

// TestOperationTimeoutSettlesLoudly is the incident regression: an attempt
// that outlives the claim-loop operation deadline used to die with no log
// line and no DB transition, leaving the row to silent lease expiry and an
// endless restart loop. It must settle a retry carrying the timeout.
func TestOperationTimeoutSettlesLoudly(t *testing.T) {
	logBuf := &bytes.Buffer{}
	gate := make(chan struct{}) // never opened: the deadline must release the Puts
	r := newRigWith(t, logBuf, nil, func(s histstore.Store) histstore.Store {
		return &gatedStore{Store: s, gate: gate}
	})
	cut := buildManagedCut(t, "tenant-to", "hcut_timeout")
	r.repo.addCut(cut)

	workCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := r.worker.materializePass(context.Background(), workCtx); err != nil {
		t.Fatal(err)
	}

	r.repo.mu.Lock()
	state, lastError := cut.state, cut.lastError
	r.repo.mu.Unlock()
	if state != "pending" {
		t.Fatalf("timed-out attempt left state %s, want a settled retry", state)
	}
	for _, want := range []string{`"kind":"timeout"`, "operation timeout"} {
		if !strings.Contains(lastError, want) {
			t.Fatalf("timeout error doc %q misses %q", lastError, want)
		}
	}
	events := decodeEvents(t, logBuf)
	timeout := findEvent(events, "cut_attempt_timeout")
	if timeout == nil {
		t.Fatal("operation timeout died silently: no cut_attempt_timeout event")
	}
	for _, field := range []string{"phase", "elapsedMs"} {
		if _, ok := timeout[field]; !ok {
			t.Fatalf("cut_attempt_timeout misses %s: %v", field, timeout)
		}
	}
	if findEvent(events, "cut_interrupted_shutdown") != nil {
		t.Fatal("operation timeout was misclassified as shutdown")
	}
}

// TestReadbackPropagationLagSucceedsWithinOneAttempt: a fresh upload whose
// readback answers 404 for a moment (S3 propagation) must be retried per
// object inside the attempt — one attempt, ready — instead of restarting
// the whole attempt.
func TestReadbackPropagationLagSucceedsWithinOneAttempt(t *testing.T) {
	logBuf := &bytes.Buffer{}
	r := newRigWith(t, logBuf, nil, func(s histstore.Store) histstore.Store {
		if s.Domain() == domA {
			return &lagReadStore{Store: s, misses: 2}
		}
		return s
	})
	cut := buildManagedCut(t, "tenant-lag", "hcut_lag")
	r.repo.addCut(cut)

	r.worker.runCutsOnce(context.Background())

	r.repo.mu.Lock()
	state, attempts := cut.state, cut.attempts
	r.repo.mu.Unlock()
	if state != "ready" || attempts != 1 {
		t.Fatalf("propagation lag cost the attempt: state=%s attempts=%d (%s)", state, attempts, cut.lastError)
	}
	if findEvent(decodeEvents(t, logBuf), "cut_retry") != nil {
		t.Fatal("propagation lag was settled as an attempt-level retry")
	}
}

// TestHeartbeatFailureRetriesPromptly: a failed lease renewal retries
// within the SAME tick window (bounded rapid train), never waiting a full
// interval per failure — and every failure is logged.
func TestHeartbeatFailureRetriesPromptly(t *testing.T) {
	logBuf := &bytes.Buffer{}
	gate := make(chan struct{})
	r := newRigWith(t, logBuf,
		func(cfg *Config) {
			cfg.LeaseTTL = 5 * time.Second
			cfg.HeartbeatInterval = time.Second
		},
		func(s histstore.Store) histstore.Store { return &gatedStore{Store: s, gate: gate} })
	cut := buildManagedCut(t, "tenant-hb", "hcut_hb_retry")
	r.repo.addCut(cut)

	var (
		beatMu    sync.Mutex
		beatTimes []time.Time
		gateOnce  sync.Once
	)
	r.repo.heartbeatErr = func() error {
		beatMu.Lock()
		defer beatMu.Unlock()
		beatTimes = append(beatTimes, time.Now())
		if len(beatTimes) <= 2 {
			return errors.New("injected heartbeat outage")
		}
		gateOnce.Do(func() { close(gate) })
		return nil
	}

	r.worker.runCutsOnce(context.Background())

	if cut.state != "ready" {
		t.Fatalf("cut did not converge past the heartbeat outage: %s (%s)", cut.state, cut.lastError)
	}
	beatMu.Lock()
	times := append([]time.Time(nil), beatTimes...)
	beatMu.Unlock()
	if len(times) < 3 {
		t.Fatalf("heartbeat retried %d times, want the rapid train", len(times)-1)
	}
	// The retry train (backoffs interval/8 + interval/4 = 375ms) must beat
	// the tick cadence (a second failure tick would land at +1s).
	if spread := times[2].Sub(times[0]); spread >= 900*time.Millisecond {
		t.Fatalf("heartbeat retries waited for regular ticks: 3 beats spread over %v", spread)
	}
	events := decodeEvents(t, logBuf)
	logged := 0
	for _, entry := range events {
		if entry["event"] == "cut_heartbeat_error" {
			logged++
		}
	}
	if logged != 2 {
		t.Fatalf("heartbeat failures logged %d times, want 2", logged)
	}
}

// TestProveClosureParallelReportsFirstErrorDeterministically: the closure
// proof runs with bounded parallelism, but the reported failure is always
// the FIRST failing digest in closure order.
func TestProveClosureParallelReportsFirstErrorDeterministically(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const tenant = "tenant-order"

	// Eight reused closure objects, healthy and fresh except the two
	// unregistered holes at indices 2 and 5.
	var digests []string
	for i := 0; i < 8; i++ {
		payload := []byte(fmt.Sprintf("closure-object-%d", i))
		sum := sha256.Sum256(payload)
		digest := "sha256:" + hexOf(sum)
		digests = append(digests, digest)
		if i == 2 || i == 5 {
			continue
		}
		key := objKey(tenant, "pft2", digest)
		r.repo.mu.Lock()
		r.repo.objects[key] = &fakeObject{
			tenant: tenant, kind: "pft2", digest: digest,
			size: int64(len(payload)), incarnation: 1, state: "live", lastUpdateMs: r.repo.nowMs,
		}
		for _, domain := range []string{domA, domB} {
			r.repo.copies[copyKey(key, 1, domain)] = &fakeCopy{
				storageKey: "key-" + domain, size: int64(len(payload)),
				state: "present", lastVerified: r.repo.nowMs,
			}
		}
		r.repo.mu.Unlock()
	}
	cut := buildManagedCut(t, tenant, "hcut_order")
	r.repo.addCut(cut)
	claims, err := r.repo.ClaimCuts(ctx, "test-worker", 1, 60_000)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim: %d, %v", len(claims), err)
	}
	for run := 0; run < 25; run++ {
		store := newCutStore(ctx, r.repo, r.stores, claims[0], r.worker.cfg)
		err := r.worker.proveClosure(ctx, claims[0], store, digests)
		if err == nil || !strings.Contains(err.Error(), digests[2]) {
			t.Fatalf("run %d reported %v, want the first failing digest %s", run, err, digests[2])
		}
	}
}

// ─── legacy conversion through the worker ────────────────────────────────────

func TestLegacyConversionThroughWorker(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	legacyRoot := t.TempDir()
	r.worker.cfg.LegacyStore = &LegacyStoreConfig{Kind: "fs", RootDir: legacyRoot}

	content := bytes.Repeat([]byte("legacy-bytes"), 500)
	sum := sha256.Sum256(content)
	digest := "sha256:" + hexOf(sum)
	// Recorded exact key (the legacy store's canonical layout).
	legacyKey := legacyRoot + "/legacy-blob"
	if err := os.WriteFile(legacyKey, content, 0o600); err != nil {
		t.Fatal(err)
	}

	ns := uint64(9) << 32
	entries := []historycut.LegacyEntry{
		{Ord: 0, Path: "dir", Kind: "directory", Mode: 0o755, AssignedIno: ns + 1, MtimeMs: 5, CtimeMs: 5, AtimeMs: 5},
		{Ord: 1, Path: "dir/file.bin", Kind: "file", Mode: 0o644, Size: uint64(len(content)),
			BlobDigest: digest, BlobSize: int64(len(content)), Compression: "none",
			AssignedIno: ns + 2, MtimeMs: 6, CtimeMs: 6, AtimeMs: 6},
	}
	var hashEntries []treehash.Entry
	for i := range entries {
		hashEntries = append(hashEntries, treehash.Entry{
			Path: entries[i].Path, Kind: entries[i].Kind, Mode: entries[i].Mode,
			Size: int64(entries[i].Size),
			Blob: blobOf(&entries[i]),
		})
	}
	cut := &fakeCut{
		tenant: "tenant-conv",
		facts: historycut.CutFacts{
			CutID: "hcut_conv", Kind: "conversion_final", SourceKind: "legacy_manifest",
			InodeNamespace: "9", NamespaceNext: "3",
		},
	}
	r.repo.legacy = &fakeLegacyPipeline{
		entries:   entries,
		wantHash:  treehash.Compute(hashEntries),
		blobs:     map[string]string{digest: "file://" + legacyKey},
		blobSizes: map[string]int64{digest: int64(len(content))},
	}
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)
	if cut.state != "ready" {
		t.Fatalf("conversion cut: %s (%s)", cut.state, cut.lastError)
	}
	// The imported file content round-trips through the serving path.
	in := cut.readyInput
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{
		Fetcher: &locateFetcher{t: t, ctx: ctx, repo: r.repo, stores: r.stores, tenant: "tenant-conv"},
	}, refOf(t, in.RootDigestHex, uint64(in.RootSize)))
	if err != nil {
		t.Fatal(err)
	}
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := reader.Lookup(ctx, rootView.Ref, "dir")
	if err != nil || dir.Ino != ns+1 {
		t.Fatalf("dir: %+v %v", dir, err)
	}
}

func blobOf(e *historycut.LegacyEntry) *treehash.Blob {
	if e.BlobDigest == "" {
		return nil
	}
	return &treehash.Blob{Digest: e.BlobDigest, Size: e.BlobSize, Compression: e.Compression, Packed: e.Packed}
}

// ─── scrub / repair ──────────────────────────────────────────────────────────

func TestScrubQuarantineRepairHeal(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-s", "hcut_scrub")
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)
	if cut.state != "ready" {
		t.Fatalf("cut: %s", cut.state)
	}

	// Corrupt ONE copy of the user root in dom-a at its exact key.
	rootDigest := "sha256:" + cut.readyInput.RootDigestHex
	located, _ := r.repo.LocateObject(ctx, "tenant-s", "pft2", rootDigest)
	var key string
	for _, c := range located.Copies {
		if c.FailureDomain == domA {
			key = c.StorageKey
		}
	}
	if err := r.fsA.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	rotten := []byte("rotten")
	rottenSum := sha256.Sum256(rotten)
	if err := r.fsA.Put(ctx, key, int64(len(rotten)), hexOf(rottenSum), bytes.NewReader(rotten)); err != nil {
		t.Fatal(err)
	}

	// Three failing scrubs quarantine the object.
	for i := 0; i < 3; i++ {
		r.worker.runScrubOnce(ctx)
		r.repo.advance(120000)
	}
	o := r.repo.objects[objKey("tenant-s", "pft2", rootDigest)]
	if o.state != "quarantined" {
		t.Fatalf("object state %s, want quarantined", o.state)
	}

	// Repair copies from the verified dom-b source, read back, receipts, and
	// the object heals to live.
	r.worker.runRepairOnce(ctx)
	if o.state != "live" {
		t.Fatalf("object state %s after repair, want live", o.state)
	}
	if err := histstore.VerifyStream(ctx, r.fsA, key, located.Size, strings.TrimPrefix(rootDigest, "sha256:")); err != nil {
		t.Fatalf("repaired bytes: %v", err)
	}
	// A follow-up scrub verifies clean.
	r.repo.advance(1_000_000)
	r.worker.runScrubOnce(ctx)
	if o.state != "live" {
		t.Fatalf("object state %s after clean scrub", o.state)
	}
}

func TestAllCopiesLostIsReportedNotHealed(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-a2", "hcut_loss")
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)

	rootDigest := "sha256:" + cut.readyInput.RootDigestHex
	located, _ := r.repo.LocateObject(ctx, "tenant-a2", "pft2", rootDigest)
	for _, c := range located.Copies {
		store, _ := r.stores.Get(c.FailureDomain)
		if err := store.Delete(ctx, c.StorageKey); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		r.worker.runScrubOnce(ctx)
		r.repo.advance(120000)
	}
	o := r.repo.objects[objKey("tenant-a2", "pft2", rootDigest)]
	if o.state != "quarantined" {
		t.Fatalf("all-loss object state %s", o.state)
	}
	// Repair finds no verified source and cannot fabricate one.
	r.worker.runRepairOnce(ctx)
	if o.state != "quarantined" {
		t.Fatalf("all-loss object healed without a source: %s", o.state)
	}
}

// ─── GC sweep ────────────────────────────────────────────────────────────────

func TestSweepDeletesWithProofsAndABASafety(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-g", "hcut_gc")
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)
	if cut.state != "ready" {
		t.Fatalf("cut: %s", cut.state)
	}
	rootDigest := "sha256:" + cut.readyInput.RootDigestHex
	key := objKey("tenant-g", "pft2", rootDigest)

	// While the ready cut is a root, nothing sweeps.
	r.repo.advance(10_000_000)
	if n := r.worker.runSweepOnce(ctx); n != 0 {
		t.Fatal("swept a rooted object")
	}

	// Release the cut: objects become sweepable after the age floor.
	r.repo.releaseCut("hcut_gc")
	r.repo.advance(10_000_000)
	swept := 0
	for i := 0; i < 200; i++ {
		if n := r.worker.runSweepOnce(ctx); n == 0 {
			break
		}
		swept++
	}
	if swept == 0 {
		t.Fatal("nothing swept after release")
	}
	o := r.repo.objects[key]
	if o.state != "tombstoned" {
		t.Fatalf("root object state %s, want tombstoned", o.state)
	}
	// Physical absence: the exact keys are gone from both stores.
	for domain, c := range r.repo.copiesOf(key, o.incarnation) {
		if c.state != "absent" {
			t.Fatalf("copy in %s state %s", domain, c.state)
		}
		store, _ := r.stores.Get(domain)
		if _, err := store.Head(ctx, c.storageKey); !errors.Is(err, histstore.ErrNotFound) {
			t.Fatalf("swept key %s still present in %s", c.storageKey, domain)
		}
	}

	// ABA: a new cut re-uploads the same digest -> NEW incarnation, NEW keys;
	// the tombstoned incarnation stays absent and untouched.
	oldIncarnation := o.incarnation
	cut2 := buildManagedCut(t, "tenant-g", "hcut_gc2")
	r.repo.addCut(cut2)
	r.worker.runCutsOnce(ctx)
	if cut2.state != "ready" {
		t.Fatalf("second cut: %s (%s)", cut2.state, cut2.lastError)
	}
	if o.incarnation != oldIncarnation+1 {
		t.Fatalf("incarnation %d, want %d", o.incarnation, oldIncarnation+1)
	}
	newKey, _ := histstore.ObjectID{Tenant: "tenant-g", Kind: "pft2", DigestHex: strings.TrimPrefix(rootDigest, "sha256:"), Incarnation: o.incarnation}.Key()
	oldKey, _ := histstore.ObjectID{Tenant: "tenant-g", Kind: "pft2", DigestHex: strings.TrimPrefix(rootDigest, "sha256:"), Incarnation: oldIncarnation}.Key()
	if newKey == oldKey {
		t.Fatal("incarnations share a key")
	}
	storeA, _ := r.stores.Get(domA)
	if _, err := storeA.Head(ctx, newKey); err != nil {
		t.Fatal("new incarnation missing")
	}
	if _, err := storeA.Head(ctx, oldKey); !errors.Is(err, histstore.ErrNotFound) {
		t.Fatal("old incarnation resurrected")
	}
}

func TestSweepCrashReclaimAndRootRaceResurrection(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cut := buildManagedCut(t, "tenant-r", "hcut_race")
	r.repo.addCut(cut)
	r.worker.runCutsOnce(ctx)
	r.repo.releaseCut("hcut_race")
	r.repo.advance(10_000_000)

	// A sweeper claims and crashes (no completion). The lease expires; a
	// second claim reclaims with a bumped epoch; the stale completion is
	// fenced (resurrected outcome, no tombstone).
	first, err := r.repo.ClaimSweep(ctx, "crashed", 3600000, 300000)
	if err != nil || first == nil {
		t.Fatalf("first sweep claim: %v %v", first, err)
	}
	r.repo.advance(600000)
	second, err := r.repo.ClaimSweep(ctx, "healthy", 3600000, 300000)
	if err != nil || second == nil {
		t.Fatalf("reclaim: %v %v", second, err)
	}
	if second.Digest != first.Digest || second.ClaimEpoch == first.ClaimEpoch {
		t.Fatalf("reclaim identity: %+v vs %+v", first, second)
	}
	outcome, err := r.repo.CompleteSweep(ctx, "crashed", first, nil)
	if err != nil || outcome != "resurrected" {
		t.Fatalf("stale completion: %s %v", outcome, err)
	}

	// A root arrives before the healthy sweeper completes: completion
	// resurrects instead of tombstoning.
	r.repo.mu.Lock()
	r.repo.cuts["hcut_race"].consumed = true
	r.repo.mu.Unlock()
	proofs := make([]AbsenceReceipt, 0, len(second.Copies))
	for _, c := range second.Copies {
		proofs = append(proofs, AbsenceReceipt{FailureDomain: c.FailureDomain, StorageKey: c.StorageKey, ConfirmedAbsent: true})
	}
	outcome, err = r.repo.CompleteSweep(ctx, "healthy", second, proofs)
	if err != nil || outcome != "resurrected" {
		t.Fatalf("root race completion: %s %v", outcome, err)
	}
	rootDigest := "sha256:" + cut.readyInput.RootDigestHex
	if o := r.repo.objects[objKey("tenant-r", "pft2", rootDigest)]; o.state == "tombstoned" {
		t.Fatal("root race tombstoned a live root")
	}
}
