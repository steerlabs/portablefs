package histworker

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/historycut"
	"github.com/steerlabs/portablefs/vcs/internal/histstore"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

// settleTimeout bounds the one DB transition (RetryCut/FailCut) that
// settles an attempt outcome. It rides its own context: when the outcome
// IS the attempt context dying (operation timeout), the settlement must
// still reach the database or the row dies silently on lease expiry.
const settleTimeout = 30 * time.Second

// heartbeatRetries bounds the rapid in-tick retry train after a failed
// lease renewal. Each retry backs off HeartbeatInterval/8, doubling, so
// the full train (1/8+1/4+1/2) always completes before the next regular
// tick and a transient miss can never quietly spend the lease.
const heartbeatRetries = 3

// materializeClaim drives ONE claimed cut end to end: policy admission,
// independent heartbeats, bounded legacy SQL steps, the shared
// deterministic reducer over the upload-as-produced store, dual-closure
// registration, per-domain readback freshness proof, and the atomic ready
// publication — or the typed retry/fail outcome. A fence at any seam stops
// the attempt without publishing.
//
// ctx is the attempt context (bounded by OperationTimeout); rootCtx is the
// worker's run context and only distinguishes real shutdown from an
// attempt that died alone. Every attempt exit logs a structured event, and
// every exit the worker still owns settles the row: only a fence (another
// claimer owns the cut) and shutdown (the DB-time lease reclaims it, by
// design) leave the row to the database.
func (w *Worker) materializeClaim(rootCtx, ctx context.Context, claim CutClaim) {
	started := time.Now()
	log := w.log.With(map[string]any{
		"cutId":      claim.Facts.CutID,
		"claimEpoch": claim.ClaimEpoch,
	})

	if err := w.stores.RequireAll(claim.ReplicationPolicy, w.cfg.ExpectedPolicyEpoch, w.cfg.MinFailureDomains); err != nil {
		// A policy this deployment cannot serve is retryable operator work,
		// never corruption; back off without burning attempts quickly.
		log.Error("cut_policy_refused", err, nil)
		w.setPolicyAdmission(err)
		if retryErr := w.repo.RetryCut(ctx, claim.Facts.CutID, claim.ClaimEpoch,
			errDoc("policy_mismatch", err), (5 * time.Minute).Milliseconds()); retryErr != nil {
			log.Error("cut_retry_error", retryErr, nil)
		}
		return
	}
	w.setPolicyAdmission(nil)

	// The heartbeat runs independently of reduction; a lost lease cancels
	// the materialization context so no further fenced call can publish.
	// fenced records WHY the cancellation happened — inferring it from
	// context state conflates a fence with the operation deadline.
	matCtx, cancelMat := context.WithCancel(ctx)
	defer cancelMat()
	var fenced atomic.Bool
	store := newCutStore(matCtx, w.repo, w.stores, claim, w.cfg)
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		ticker := time.NewTicker(w.cfg.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-matCtx.Done():
				return
			case <-ticker.C:
				if !w.heartbeatWithRetries(matCtx, log, claim, store, &fenced, cancelMat) {
					return
				}
			}
		}
	}()
	defer func() { cancelMat(); <-hbDone }()

	result, err := w.runReduction(matCtx, claim, store)
	if err == nil {
		store.SetPhase("publishing")
		err = w.publishReady(matCtx, claim, store, result)
	}
	if retries := store.StoreRetries.Load(); retries > 0 {
		w.metrics.Counter("pfh_worker_store_retries_total").Add(retries)
		log.Warn("store_throttled", map[string]any{"storeRetries": retries})
	}

	attemptFields := func() map[string]any {
		return map[string]any{
			"phase":           store.Phase(),
			"uploadedObjects": store.ObjectsUploaded.Load(),
			"uploadedBytes":   store.BytesUploaded.Load(),
			"fetchedObjects":  store.ObjectsFetched.Load(),
			"elapsedMs":       time.Since(started).Milliseconds(),
		}
	}
	switch {
	case err == nil:
		w.metrics.Counter("pfh_worker_cuts_ready_total").Inc()
		log.Info("cut_ready", map[string]any{
			"root":            result.Root.Hex(),
			"recoveryRoot":    result.RecoveryRoot.Hex(),
			"userObjects":     result.UserObjectCount,
			"recoveryObjects": result.RecoveryObjectCount,
			"uploadedObjects": store.ObjectsUploaded.Load(),
			"uploadedBytes":   store.BytesUploaded.Load(),
			"elapsedMs":       time.Since(started).Milliseconds(),
		})
	case rootCtx.Err() != nil:
		// Worker shutdown: nothing settles by local assertion on the way
		// out — the DB-time lease reclaims the cut. Loud, so a drain is
		// distinguishable from a death in the logs.
		w.metrics.Counter("pfh_worker_cuts_interrupted_total").Inc()
		log.Error("cut_interrupted_shutdown", err, attemptFields())
	case fenced.Load() || errors.Is(err, ErrFenced):
		// Fenced (heartbeat lost the lease, or a fenced DB call surfaced
		// directly): another claimer owns the cut; assert nothing.
		w.metrics.Counter("pfh_worker_cuts_fenced_total").Inc()
		log.Error("cut_fenced_midflight", err, attemptFields())
	case errors.Is(err, historycut.ErrCorrupt):
		w.metrics.Counter("pfh_worker_cuts_failed_total").Inc()
		log.Error("cut_corrupt", err, attemptFields())
		w.settleAttempt(log, "cut_fail_error", func(settleCtx context.Context) error {
			return w.repo.FailCut(settleCtx, claim.Facts.CutID, claim.ClaimEpoch, errDoc("corrupt", err))
		})
	case ctx.Err() != nil:
		// The attempt context died without a shutdown or a fence: the
		// OperationTimeout deadline. This exit used to be silent — the
		// incident signature of a big cut restarting from zero forever —
		// and now settles a bounded retry carrying the timeout.
		timeoutErr := fmt.Errorf("histworker: attempt exceeded the %v operation timeout: %w",
			w.cfg.OperationTimeout, err)
		w.retryOrExhaust(log, claim, "timeout", "cut_attempt_timeout", timeoutErr, attemptFields())
	default:
		w.retryOrExhaust(log, claim, "transient", "cut_retry", err, attemptFields())
	}
}

// heartbeatWithRetries renews the lease once per regular tick, retrying a
// failed renewal promptly (bounded train, every failure logged) instead of
// waiting a full interval: with heartbeats at leaseTTL/4, two quiet misses
// used to put the lease within one stall of expiry. Returns false when the
// heartbeat goroutine must stop (fenced or attempt over). On a fence it
// records the cause and cancels the materialization context.
func (w *Worker) heartbeatWithRetries(matCtx context.Context, log *Logger, claim CutClaim, store *cutStore, fenced *atomic.Bool, cancelMat context.CancelFunc) bool {
	backoff := w.cfg.HeartbeatInterval / 8
	for attempt := 0; ; attempt++ {
		progress := map[string]any{
			"phase":           store.Phase(),
			"uploadedObjects": store.ObjectsUploaded.Load(),
			"uploadedBytes":   store.BytesUploaded.Load(),
			"fetchedObjects":  store.ObjectsFetched.Load(),
			"storeRetries":    store.StoreRetries.Load(),
		}
		// Each renewal is individually bounded: a hung call is a failed
		// call, not a quietly spent lease.
		beatCtx, cancelBeat := context.WithTimeout(matCtx, w.cfg.HeartbeatInterval)
		err := w.repo.HeartbeatCut(beatCtx, claim.Facts.CutID, claim.ClaimEpoch,
			w.cfg.WorkerID, w.cfg.LeaseTTL.Milliseconds(), progress)
		cancelBeat()
		if err == nil {
			return true
		}
		if errors.Is(err, ErrFenced) {
			log.Error("cut_heartbeat_fenced", err, nil)
			fenced.Store(true)
			cancelMat()
			return false
		}
		if matCtx.Err() != nil {
			return false
		}
		log.Error("cut_heartbeat_error", err, map[string]any{"attempt": attempt})
		if attempt >= heartbeatRetries {
			return true // resume at the next regular tick
		}
		select {
		case <-matCtx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

// retryOrExhaust settles a retryable attempt failure: a bounded retry with
// the typed error, or — once the claim's attempt number has reached
// MaxCutAttempts — the terminal FailCut. Terminal failure is deliberate
// fail-fast: a cut that cannot make it in MaxCutAttempts tries (including
// zombies whose volume is gone) surfaces as 'failed' with its last error
// instead of burning the materializer forever.
func (w *Worker) retryOrExhaust(log *Logger, claim CutClaim, kind, event string, err error, fields map[string]any) {
	if claim.AttemptCount >= int64(w.cfg.MaxCutAttempts) {
		w.metrics.Counter("pfh_worker_cuts_failed_total").Inc()
		fields["attempts"] = claim.AttemptCount
		log.Error("cut_attempts_exhausted", err, fields)
		doc := errDoc("attempts_exhausted", err)
		doc["attempts"] = claim.AttemptCount
		w.settleAttempt(log, "cut_fail_error", func(settleCtx context.Context) error {
			return w.repo.FailCut(settleCtx, claim.Facts.CutID, claim.ClaimEpoch, doc)
		})
		return
	}
	w.metrics.Counter("pfh_worker_cuts_retried_total").Inc()
	log.Error(event, err, fields)
	w.settleAttempt(log, "cut_retry_error", func(settleCtx context.Context) error {
		return w.repo.RetryCut(settleCtx, claim.Facts.CutID, claim.ClaimEpoch,
			errDoc(kind, err), (30 * time.Second).Milliseconds())
	})
}

// settleAttempt runs one outcome transition on its own bounded context —
// the attempt context is usually already dead when settling a timeout —
// and logs the transition's own failure: the last silent path out.
func (w *Worker) settleAttempt(log *Logger, failEvent string, transition func(context.Context) error) {
	settleCtx, cancel := context.WithTimeout(context.Background(), settleTimeout)
	defer cancel()
	if err := transition(settleCtx); err != nil {
		log.Error(failEvent, err, nil)
	}
}

// runReduction drives the legacy SQL steps when the source requires them,
// then the deterministic reducer.
func (w *Worker) runReduction(ctx context.Context, claim CutClaim, store *cutStore) (*historycut.Result, error) {
	needsLegacy := claim.Facts.SourceKind == "legacy_manifest" ||
		(claim.Facts.BaseCommit != nil && claim.Facts.BaseCommit.CommitKind == "manifest_v1")
	if needsLegacy {
		if err := w.driveLegacySteps(ctx, claim); err != nil {
			return nil, err
		}
	}
	blobs, err := newLegacyBlobSource(w.repo, claim, w.cfg)
	if err != nil {
		return nil, err
	}
	defer blobs.Close()
	sources := &repoSources{repo: w.repo, claim: claim}
	m := &historycut.Materializer{
		Facts:   claim.Facts,
		Journal: sources,
		Legacy:  sources,
		Blobs:   blobs,
		Spool:   store,
	}
	result, err := m.Run(ctx)
	if err != nil {
		return nil, err
	}
	if err := store.Flush(); err != nil {
		return nil, err
	}
	return result, nil
}

// driveLegacySteps executes the resumable conversion pipeline: chain
// resolve, bounded page application, ordinal assignment, inode assignment.
// Every call is claim-fenced and idempotent; reruns resume from cursors.
func (w *Worker) driveLegacySteps(ctx context.Context, claim CutClaim) error {
	cutID, epoch := claim.Facts.CutID, claim.ClaimEpoch
	if err := w.repo.LegacyChainPrepare(ctx, cutID, epoch); err != nil {
		return err
	}
	steps := []struct {
		name string
		page int
		run  func(context.Context, string, int64, int) (bool, error)
	}{
		{"chain_apply", 2000, w.repo.LegacyChainApplyPage},
		{"assign_ords", 5000, w.repo.LegacyAssignOrds},
		{"assign_inos", 5000, w.repo.LegacyAssignInos},
	}
	const maxPages = 1 << 20 // structural runaway guard, not a tunable
	for _, step := range steps {
		for i := 0; ; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			if i >= maxPages {
				return fmt.Errorf("histworker: legacy step %s exceeded %d pages", step.name, maxPages)
			}
			done, err := step.run(ctx, cutID, epoch, step.page)
			if err != nil {
				return err
			}
			if done {
				break
			}
		}
	}
	return nil
}

// publishReady registers both closures, proves fresh verified copies in
// every required domain for every closure object (uploading or
// re-verifying as needed), and marks the cut ready atomically.
func (w *Worker) publishReady(ctx context.Context, claim CutClaim, store *cutStore, result *historycut.Result) error {
	if err := w.proveClosure(ctx, claim, store, result.UserClosure); err != nil {
		return err
	}
	if err := w.proveClosure(ctx, claim, store, result.RecoveryClosure); err != nil {
		return err
	}
	if err := w.addClosure(ctx, claim, "user", result.UserClosure); err != nil {
		return err
	}
	if err := w.addClosure(ctx, claim, "recovery", result.RecoveryClosure); err != nil {
		return err
	}

	namespace, err := strconv.ParseInt(claim.Facts.InodeNamespace, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: inode namespace %q", historycut.ErrCorrupt, claim.Facts.InodeNamespace)
	}
	ready := ReadyFacts{
		CutID:      claim.Facts.CutID,
		ClaimEpoch: claim.ClaimEpoch,

		RootDigestHex: result.Root.Hex(),
		RootSize:      int64(result.Root.Size),

		RecoveryRootDigestHex: result.RecoveryRoot.Hex(),
		RecoveryRootSize:      int64(result.RecoveryRoot.Size),

		InodeNamespace: namespace,
		NextLocal:      int64(result.NextLocal),
		MaxInoSeen:     int64(result.MaxInoSeen),
		RootMaxInoSeen: int64(result.RootMaxInoSeen),

		UserObjectCount:     int64(result.UserObjectCount),
		UserObjectBytes:     int64(result.UserObjectBytes),
		RecoveryObjectCount: int64(result.RecoveryObjectCount),
		RecoveryObjectBytes: int64(result.RecoveryObjectBytes),
	}
	if result.ControlRoot != nil {
		ready.ControlRootDigestHex = result.ControlRoot.Hex()
		ready.ControlRootSize = int64(result.ControlRoot.Size)
	}
	if result.OrphanIndex != nil {
		ready.OrphanIndexDigestHex = result.OrphanIndex.Hex()
		ready.OrphanIndexSize = int64(result.OrphanIndex.Size)
	}
	return w.repo.MarkCutReady(ctx, ready)
}

func (w *Worker) addClosure(ctx context.Context, claim CutClaim, closure string, digests []string) error {
	for start := 0; start < len(digests); start += 4096 {
		end := min(start+4096, len(digests))
		if err := w.repo.AddCutObjects(ctx, claim.Facts.CutID, claim.ClaimEpoch,
			closure, digests[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// proveClosure guarantees every closure object holds a FRESH verified copy
// at its exact recorded key in every required failure domain before
// publication: objects uploaded by this run were receipted at upload;
// reused base objects are re-verified (stale) or re-uploaded (missing /
// failed verification) — always at per-incarnation exact keys under the
// live claim. Proofs run with the upload concurrency bound (each one
// streams whole objects from both domains; a sequential walk over a large
// reused closure starves the heartbeat window) and report the FIRST failed
// digest in closure order regardless of scheduling.
func (w *Worker) proveClosure(ctx context.Context, claim CutClaim, store *cutStore, digests []string) error {
	freshFloor := claim.DbTimeMs - w.cfg.FreshenAge.Milliseconds()
	sem := make(chan struct{}, w.cfg.UploadConcurrency)
	proofErrs := make([]error, len(digests))
	var wg sync.WaitGroup
	for i, digest := range digests {
		if _, uploadedNow := store.UploadedIncarnation(digest); uploadedNow {
			continue // receipted with read-after-write proof during upload
		}
		wg.Add(1)
		go func(i int, digest string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				proofErrs[i] = err
				return
			}
			proofErrs[i] = w.proveOne(ctx, claim, store, digest, freshFloor)
		}(i, digest)
	}
	wg.Wait()
	for _, err := range proofErrs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) proveOne(ctx context.Context, claim CutClaim, store *cutStore, digest string, freshFloor int64) error {
	loc, err := w.repo.LocateObject(ctx, claim.TenantID, "pft2", digest)
	if err != nil {
		return err
	}
	if loc == nil {
		return fmt.Errorf("histworker: closure object %s has no registration", digest)
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	copies := map[string]CopyRecord{}
	for _, c := range loc.Copies {
		copies[c.FailureDomain] = c
	}

	// Every receipt below rides the CUT's own live claim (upload intent +
	// object_copy_receipt), never pfh.scrub_receipt: that surface demands a
	// live scrub-loop verify claim on the copy row, which this path does not
	// hold — presenting one anyway fences the whole cut attempt into an
	// endless retry loop the moment a reused base copy ages past the
	// freshen floor.
	var stale []string   // present, bytes re-verified at the recorded key, freshness receipt due
	var missing []string // absent, corrupt, or unreachable: heal through re-upload
	for _, domain := range claim.ReplicationPolicy.RequiredFailureDomains {
		copyRec, present := copies[domain]
		if !present {
			missing = append(missing, domain)
			continue
		}
		if copyRec.LastVerified >= freshFloor {
			continue
		}
		domainStore, ok := w.stores.Get(domain)
		if !ok {
			return fmt.Errorf("%w: required failure domain %q has no store", ErrPolicyMismatch, domain)
		}
		if verifyErr := histstore.VerifyStream(ctx, domainStore, copyRec.StorageKey, copyRec.Size, hexDigest); verifyErr != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			missing = append(missing, domain)
			continue
		}
		stale = append(stale, domain)
	}
	if len(stale) == 0 && len(missing) == 0 {
		return nil
	}

	// One intent binds the incarnation for both arms; the copy receipt
	// requires it either way.
	bindings, err := w.repo.IntendObjects(ctx, claim.Facts.CutID, claim.ClaimEpoch,
		[]ObjectIntent{{Digest: digest, Size: loc.Size}})
	if err != nil {
		return err
	}
	incarnation, ok := bindings[digest]
	if !ok {
		return fmt.Errorf("histworker: intent response is missing %s", digest)
	}
	id := histstore.ObjectID{
		Tenant: claim.TenantID, Kind: "pft2",
		DigestHex: hexDigest, Incarnation: incarnation,
	}

	// Freshness receipts for verified-but-stale copies: the streamed
	// re-verification at the DB-recorded exact key IS the reconciliation
	// proof object_copy_receipt admits. Valid only while the recorded key is
	// the bound incarnation's exact key — an intent that bumped the
	// incarnation (sweep race) moves the copy to the re-upload arm instead.
	for _, domain := range stale {
		domainStore, ok := w.stores.Get(domain)
		if !ok {
			return fmt.Errorf("%w: required failure domain %q has no store", ErrPolicyMismatch, domain)
		}
		key, err := domainStore.ExactKey(id)
		if err != nil {
			return err
		}
		if incarnation != loc.Incarnation || key != copies[domain].StorageKey {
			missing = append(missing, domain)
			continue
		}
		if err := w.repo.RecordCopyReceipt(ctx, claim.Facts.CutID, claim.ClaimEpoch,
			digest, incarnation, domain, key, loc.Size); err != nil {
			return err
		}
	}
	if len(missing) == 0 {
		return nil
	}

	// Re-upload path: verified bytes from cache or any healthy domain.
	ref, err := refFromDigest(hexDigest, loc.Size)
	if err != nil {
		return err
	}
	data, ok := store.CachedBytes(ref)
	if !ok {
		data, err = store.fetchRecorded(ctx, ref)
		if err != nil {
			return fmt.Errorf("histworker: closure object %s has no healthy source for repair: %w", digest, err)
		}
	}
	for _, domain := range missing {
		domainStore, ok := w.stores.Get(domain)
		if !ok {
			return fmt.Errorf("%w: required failure domain %q has no store", ErrPolicyMismatch, domain)
		}
		key, err := domainStore.ExactKey(id)
		if err != nil {
			return err
		}
		if err := domainStore.Put(ctx, key, loc.Size, hexDigest, bytes.NewReader(data)); err != nil {
			return err
		}
		if err := readbackVerified(ctx, domainStore, key, loc.Size, hexDigest); err != nil {
			return err
		}
		if err := w.repo.RecordCopyReceipt(ctx, claim.Facts.CutID, claim.ClaimEpoch,
			digest, incarnation, domain, key, loc.Size); err != nil {
			return err
		}
	}
	return nil
}

func refFromDigest(hexDigest string, size int64) (pft2.Ref, error) {
	raw, err := hex.DecodeString(hexDigest)
	if err != nil || len(raw) != 32 || size < 0 {
		return pft2.Ref{}, fmt.Errorf("histworker: bad object reference %q/%d", hexDigest, size)
	}
	var ref pft2.Ref
	copy(ref.Digest[:], raw)
	ref.Size = uint64(size)
	return ref, nil
}

// errDoc is the bounded structured error the database stores on a cut.
func errDoc(kind string, err error) map[string]any {
	message := err.Error()
	if len(message) > 2048 {
		message = message[:2048]
	}
	return map[string]any{"kind": kind, "message": message}
}
