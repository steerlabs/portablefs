package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authority"
	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/hapolicy"
	"github.com/steerlabs/portablefs/vcs/internal/lifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/managerlease"
	"github.com/steerlabs/portablefs/vcs/internal/opstate"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/remotejournal"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// This file is the managed-production serving path: ONE disposable fenced
// child per active branch, cold-replaying the synchronously durable remote
// PostgreSQL journal (VCS_JOURNAL_DSN) — the only write truth. The child
// never opens or creates a local WAL, opstate, transition, checkpoint-intent,
// trace, or cache file, never serves NFS, never runs a checkpoint loop, and
// never adopts prior local state: it starts in an empty ephemeral working
// directory, verifies HA evidence against the structured policy, claims the
// journal under the exact manager/runtime binding, replays, and serves the
// authenticated fsproto data plane only. Snapshots/publishing/terminal
// history belong to the EXTERNAL HistoryCut service, not this process.

// managedProtocolVersion versions the manager↔child control contract
// (bootstrap frame, lease frames, readiness identity fields).
const managedProtocolVersion = 1

// firstLeaseFrameTimeout bounds the wait for the manager's first lease frame:
// a child whose manager never speaks must not hold the writer claim forever.
const firstLeaseFrameTimeout = 30 * time.Second

func (c config) journalConfig() remotejournal.Config {
	return remotejournal.Config{
		DSN:      c.journalDSN,
		TenantID: c.tenantID,
		VolumeID: c.volumeID,
		Branch:   c.branch,
		// The exact manager/runtime binding every journal transaction presents
		// (pfm cross-checks the live rows at database time). The capability is
		// manager-issued for THIS runtime; the child never generates one.
		ManagerEpoch:        c.managerEpoch,
		AuthorityRuntimeSeq: c.authorityRuntimeSeq,
		AuthorityRuntimeID:  c.authorityRuntimeID,
		AuthorityCapability: c.authorityRuntimeCapability,
		// Deterministic per-runtime claim id: an in-process retry of a lost
		// claim response replays the exact claim instead of burning epochs.
		ClaimOperationID:  "pfjclaim-" + c.authorityRuntimeID,
		ApplicationName:   "vcs-" + c.volumeID,
		TransactionPooler: c.journalPoolerMode == "transaction",
	}
}

// runRemotePrimary is the managed writable path: writer lease → journal claim
// (exact manager/runtime binding) → HA policy verification → exact base
// manifest → verified cold replay → serve. Nothing else: no checkpoint
// reconciliation, no checkpoint loop, no opstate/quiesce-marker coupling,
// no NFS, no read-only sibling mode.
func runRemotePrimary(ctx context.Context, client *backend.Client, cfg config) error {
	setRole("primary")

	// The manager lease pipe is attached FIRST so a manager death during our
	// own startup already fences us. Required in managed production; optional
	// for a development run against a local database.
	var guard *managerlease.Guard
	if cfg.heartbeatFD >= 3 {
		leasePipe := os.NewFile(uintptr(cfg.heartbeatFD), "portablefs-manager-lease-pipe")
		if leasePipe == nil {
			log.Fatalf("VCS_HEARTBEAT_FD=%d does not name an inherited descriptor", cfg.heartbeatFD)
		}
		guard = managerlease.NewGuard(managerlease.Identity{
			ManagerEpoch:        cfg.managerEpoch,
			ManagerRuntimeID:    cfg.managerRuntimeID,
			AuthorityInstanceID: cfg.authorityInstanceID,
			AuthorityRuntimeSeq: cfg.authorityRuntimeSeq,
			AuthorityRuntimeID:  cfg.authorityRuntimeID,
		}, 0)
		go guard.Run(leasePipe)
	}

	poll := cfg.failoverPoll
	if poll <= 0 {
		poll = time.Second
	}
	holder := holderID()
	// The RECEIPTED attach is the managed write-authority admission: the only
	// attach the volume API admits on a journal-owned branch, retry-stable
	// under one operation id so an ambiguous response can never orphan the
	// exclusive lease. A legacy_manifest branch refuses HERE, typed, before
	// any journal claim could mint a generation this child would refuse to
	// serve.
	auth, err := authority.AcquireReceiptedWhenFree(ctx, client, cfg.volumeID, cfg.branch, holder, cfg.leaseTTLms, poll)
	if err != nil {
		if ctx.Err() != nil {
			return nil // clean shutdown while waiting for a busy lease
		}
		log.Fatalf("acquire write authority for %s: %v", cfg.volumeID, err)
	}
	releaseAndFatal := func(format string, args ...any) {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = auth.Release(releaseCtx)
		cancel()
		log.Fatalf(format, args...)
	}

	// NON-SERVING WRITER-LEASE KEEPER: starts immediately after the acquire —
	// BEFORE the journal claim, HA verification, and cold replay — so a slow
	// recovery can never let the freshly acquired lease lapse unrenewed. It
	// runs for the whole process life; a definitive loss (superseded/expired)
	// or a missed renewal window closes leaseLost exactly once.
	leaseLost := make(chan struct{})
	var loseOnce sync.Once
	loseLease := func() { loseOnce.Do(func() { close(leaseLost) }) }
	keeperCtx, stopKeeper := context.WithCancel(ctx)
	defer stopKeeper()
	go renewLoop(keeperCtx, auth, cfg.renewEvery(), cfg.leaseTTL(), loseLease)

	// The journal's lifecycle context must OUTLIVE SIGTERM once serving: the
	// graceful eviction drain executes the exact receipted suspension AFTER
	// the signal context is cancelled. It is cancelled explicitly once
	// serving returns.
	journalCtx, journalCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer journalCancel()
	// recoveryCtx bounds the recovery phase (claim, HA evidence, manifest,
	// replay). DURING RECOVERY every abort trigger cancels BOTH the recovery
	// and the journal lifecycle — nothing served yet, so there is no drain or
	// suspension to protect, and no detached journal context may survive the
	// cancellation and become ready:
	//   - SIGTERM/SIGINT (ctx): a DB-blackholed claim/read-page retry loop
	//     dies with the signal instead of hanging on the detached journalCtx;
	//   - definitive writer lease loss;
	//   - a manager lease-pipe fence (guard).
	// The journal claim itself verifies the exact manager/runtime/capability
	// binding server-side, so an invalidated authority runtime aborts as a
	// definitive claim error. Once recovery completes, the watcher stands
	// down: a serving-phase loss fences the data plane while the eviction
	// path still attempts (and honestly fails) its suspension.
	recoveryCtx, recoveryCancel := context.WithCancel(ctx)
	defer recoveryCancel()
	recoveryDone := make(chan struct{})
	var guardFenced <-chan struct{}
	if guard != nil {
		guardFenced = guard.Fenced()
	}
	go watchRecoveryAbort(ctx.Done(), leaseLost, guardFenced, recoveryDone, recoveryCancel, journalCancel)

	jcfg := cfg.journalConfig()
	jcfg.AttachSessionID = auth.SessionID()
	jcfg.LeaseID = auth.LeaseID()
	jcfg.FencingToken = auth.FencingToken()
	jcfg.HolderID = holder
	jcfg.AuthorityInstanceID = cfg.authorityInstanceID
	// The immutable codec pair comes from the AUTHORITATIVE provisioning and
	// claim result alone: OpenAuthoritative asks pfj.branch_provisioning what
	// provisioning decided (live generation's pair, else the provisioned
	// branch mode; retiring/retired refuse), dispatches to the matching claim
	// wrapper, and verifies the claim result restates the same pair. Nothing
	// here — no flag, no environment value — can pick or downgrade a plane.
	rlog, provisioning, err := remotejournal.OpenAuthoritative(journalCtx, jcfg)
	if err != nil {
		if errors.Is(err, remotejournal.ErrManagedCodecUnsupported) {
			// Refused BEFORE any claim: no legacy generation was minted, so
			// the branch's journal activation stays unblocked.
			releaseAndFatal("branch %s@%s speaks %s/%s (base-authoring phase); managed serving requires PFJ3/PFC2 — run journal activation (adopt does this automatically) before mounting: %v",
				cfg.volumeID, cfg.branch, provisioning.RecordCodec, provisioning.ControlCodec, err)
		}
		if errors.Is(err, remotejournal.ErrMigrationRequired) {
			releaseAndFatal("claim remote journal: branch provisioning and its live generation disagree (existing PFR1 conversion is migration 013): %v", err)
		}
		if leaseLostNow(leaseLost) {
			releaseAndFatal("writer lease lost while claiming the remote journal; recovery canceled: %v", err)
		}
		// A cancellation here came from one of the recovery abort triggers;
		// the fatal message must name WHICH ONE, or an operator sees only
		// "context canceled" and cannot tell a fenced lease pipe from a
		// delivered signal.
		if guard != nil {
			if cause := guard.Cause(); cause != nil {
				releaseAndFatal("claim remote journal: manager lease guard fenced (%v): %v", cause, err)
			}
		}
		if ctx.Err() != nil {
			releaseAndFatal("claim remote journal: shutdown signal during claim: %v", err)
		}
		releaseAndFatal("claim remote journal: %v", err)
	}
	defer rlog.Close()
	log.Printf("remote primary: provisioning decided %s (%s/%s)",
		provisioning.BranchMode, provisioning.RecordCodec, provisioning.ControlCodec)
	// The managed store speaks PFJ3/PFC2 only. OpenAuthoritative already
	// refused a legacy provisioning decision BEFORE claiming, so this is a
	// cheap defensive re-check on the pair the claim restated — definitive,
	// never a downgrade.
	if provisioning.RecordCodec != pfj3.RecordCodec || provisioning.ControlCodec != pfj3.ControlCodec {
		releaseAndFatal("remote journal generation %s speaks %s/%s; managed serving requires the PFJ3/PFC2 pair (existing-generation conversion is migration 013)",
			rlog.GenerationID(), provisioning.RecordCodec, provisioning.ControlCodec)
	}
	if guard != nil {
		// Ground every lease deadline in the CAPABILITY/RUNTIME-BOUND
		// lease-facts read on the fenced journal pool: a frame that sat in a
		// pipe can no longer overstate its window, and a manager superseded
		// BEFORE its previously reported expiry stops producing extensions
		// the moment the database says so. Frames observed before this point
		// armed only a provisional fencing deadline and never released
		// serving; the latest queued frame grounds right now.
		guard.SetProber(&journalLeaseFactsProber{log: rlog})
	}

	policyHash, err := requireJournalDurability(recoveryCtx, rlog, cfg)
	if err != nil {
		releaseAndFatal("journal durability evidence: %v", err)
	}

	// Cold recovery first proves EXACTLY the journal's base tuple through the
	// independent tenant-scoped serving surface. A positive manifest_v1 proof
	// selects the exact-commit manifest loader; a positive PFT2 proof selects
	// the immutable base reader. Absence, timeout, or unsupported provenance
	// never means "try the other format".
	baseCommit := rlog.BaseCommitID()
	resolved, err := resolveRemoteBase(recoveryCtx, client, remoteBaseIdentity{
		TenantID: cfg.tenantID, CommitID: baseCommit,
		GenerationID: rlog.GenerationID(), BaseSeq: rlog.CompactedThrough(),
		BaseDigest: rlog.BaseDigest(), RecordCodec: rlog.RecordCodec(),
		ControlCodec: rlog.ControlCodec(),
	})
	if err != nil {
		releaseAndFatal("prove journal base %s: %v", baseCommit, err)
	}
	cache := buildCache(cfg) // RAM-only: validateConfig rejects VCS_CACHE_DIR here
	wfs, err := openResolvedRemoteBase(recoveryCtx, client, rlog, cache, resolved)
	if err != nil {
		if leaseLostNow(leaseLost) {
			releaseAndFatal("writer lease lost during the cold replay; recovery canceled: %v", err)
		}
		releaseAndFatal("build working fs (verified journal replay): %v", err)
	}
	close(recoveryDone)
	if leaseLostNow(leaseLost) {
		releaseAndFatal("writer lease lost during recovery; refusing to serve")
	}
	// Set AFTER cold replay (durable history must always load, even one that
	// exceeds a lowered bound) and BEFORE the listeners bind: the managed
	// child runs no checkpoint loop, so this bound is the only thing keeping
	// resident dirty blocks — 4 MiB per partially written region, for the
	// whole generation — from outgrowing the shared container.
	dirtyMax, _ := cfg.dirtyRSSMaxBytes() // validated at startup
	wfs.SetDirtyRSSMax(dirtyMax)
	log.Printf("remote primary: proven %s base commit %s + %d journal records replayed (generation %s, epoch %d), exclusive lease (%dms) held, dirty-block bound %d MiB (%d MiB resident after replay)",
		resolved.proof.Kind, baseCommit, rlog.Watermark()-rlog.CompactedThrough(), rlog.GenerationID(), rlog.Epoch(), cfg.leaseTTLms, dirtyMax>>20, wfs.DirtyBlockBytes()>>20)
	logBindingWriteBound(dirtyMax, rlog.QuotaBytes())
	// The dirty-block fold: cut adoption now RELEASES this child's resident
	// blocks instead of only advancing the journal base underneath them.
	// Started before serving so the first adoption after readiness is folded.
	folder := &foldDriver{
		client: client, fs: wfs, rlog: rlog,
		identity: remoteBaseIdentity{
			TenantID: cfg.tenantID, GenerationID: rlog.GenerationID(),
			RecordCodec: rlog.RecordCodec(), ControlCodec: rlog.ControlCodec(),
		},
	}
	go folder.run(ctx)
	return serveRemotePrimary(ctx, cfg, wfs, auth, rlog, guard, policyHash, leaseLost)
}

// logBindingWriteBound names WHICH of the two write-admission bounds this
// generation will actually hit first, because they are bounds on different
// resources with different relief and only one of them has a driver.
//
//	journal backlog quota   durable bytes in PFJ3. RELIEVABLE: the volume-api's
//	                        history-maintenance loop scans generations past
//	                        PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT of
//	                        THIS number, creates a recovery cut, and adoption
//	                        subtracts the backlog. That loop is the only driver
//	                        of journal shrink, and this is the only quantity it
//	                        watches.
//
//	dirty-block bound       resident RAM in THIS child. As of the dirty-block
//	                        FOLD (workfs/dirtyfold.go + foldDriver) it is
//	                        relieved by the SAME event: on cut adoption the
//	                        child re-proves the adopted base and releases every
//	                        resident block that base now contains. Before the
//	                        fold existed, adoption advanced the journal base
//	                        without rebinding this child's inodes to it and the
//	                        counter was monotone for the life of the child —
//	                        a hard ceiling on CUMULATIVE writes.
//
// Both bounds are now relieved by history-cut adoption, so the remaining
// question is purely one of ORDER: the loop must cut before RAM fills. It
// triggers at PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT of the JOURNAL
// quota, and if that trigger point sits above the dirty bound the RAM bound is
// still reached first with the loop having seen nothing — the inversion that
// wedged production (2048 MiB of RAM against 4096 MiB of journal is 50%, and
// the loop's default is 70%).
//
// coordinatedBacklogPercent is the largest maintenance percentage that CANNOT
// invert, for the dominant case where journal bytes track written bytes. This
// record names it so an operator (and the volume-api's own coordination, which
// derives the same number from PORTABLEFS_DIRTY_RSS_MAX_MB) can be checked
// against reality at a glance.
//
// It is a bound on the JOURNAL-PROPORTIONAL case only, and deliberately not
// claimed for more. A write pattern that touches one byte per 4 MiB region
// materialises a whole block per ~40 journal bytes; no percentage of a journal
// quota bounds that. For that shape the fold still turns a terminal ceiling
// into a recovering one — every adoption releases the amplified blocks — and a
// burst that outruns any cadence still lands on the definite ENOSPC.
func coordinatedBacklogPercent(dirtyMax, journalQuota int64) int64 {
	if dirtyMax <= 0 || journalQuota <= 0 {
		return 0
	}
	// Half the dirty bound as the journal trigger leaves a full fold window of
	// headroom between "the loop decides to cut" and "RAM is full": the cut
	// must be created, materialised, adopted and folded while writes continue,
	// and that whole pipeline has to fit inside the remaining half.
	percent := dirtyMax * 100 / (2 * journalQuota)
	if percent < 1 {
		return 1
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func logBindingWriteBound(dirtyMax, journalQuota int64) {
	switch {
	case dirtyMax <= 0:
		log.Printf("remote primary: write-admission bound = journal backlog quota %d MiB "+
			"(resident dirty blocks unbounded: VCS_DIRTY_RSS_MAX_MB disabled)", journalQuota>>20)
	case journalQuota <= 0:
		log.Printf("remote primary: write-admission bound = resident dirty blocks %d MiB "+
			"(journal quota unknown); relief is history-cut adoption (folded) plus truncate/reap", dirtyMax>>20)
	case dirtyMax < journalQuota:
		log.Printf("remote primary: BINDING write-admission bound is RESIDENT DIRTY BLOCKS "+
			"(%d MiB), reached at %d%% of the %d MiB journal backlog quota. Cut adoption now "+
			"FOLDS this bound (resident blocks the adopted base contains are released), so the "+
			"maintenance loop must cut at or below %d%% for the fold to land in time — "+
			"PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT above that reaches RAM first.",
			dirtyMax>>20, dirtyMax*100/journalQuota, journalQuota>>20,
			coordinatedBacklogPercent(dirtyMax, journalQuota))
	default:
		log.Printf("remote primary: binding write-admission bound is the journal backlog "+
			"quota (%d MiB), reached before the %d MiB dirty-block bound; history-cut "+
			"adoption is the relief for both", journalQuota>>20, dirtyMax>>20)
	}
}

type remoteBaseIdentity struct {
	TenantID     string
	CommitID     string
	GenerationID string
	BaseSeq      uint64
	BaseDigest   string
	RecordCodec  string
	ControlCodec string
}

type remoteBaseBackend interface {
	content.BlobReader
	BaseProvenance(context.Context, backend.BaseProvenanceRequest) (*backend.BaseProvenance, error)
	ManifestAt(context.Context, string) ([]backend.Entry, error)
	HistoryObject(context.Context, string, uint64) ([]byte, error)
}

type resolvedRemoteBase struct {
	proof   *backend.BaseProvenance
	entries []backend.Entry
}

// resolveRemoteBase makes the family decision before any family-specific
// read. In particular, a PFT2 outcome never calls ManifestAt, and a manifest
// outcome never touches the history-object route.
func resolveRemoteBase(ctx context.Context, client remoteBaseBackend, id remoteBaseIdentity) (resolvedRemoteBase, error) {
	proof, err := client.BaseProvenance(ctx, backend.BaseProvenanceRequest{
		TenantID: id.TenantID, CommitID: id.CommitID, GenerationID: id.GenerationID,
		BaseSeq: id.BaseSeq, BaseDigest: id.BaseDigest,
		RecordCodec: id.RecordCodec, ControlCodec: id.ControlCodec,
	})
	if err != nil {
		return resolvedRemoteBase{}, err
	}
	if proof == nil {
		return resolvedRemoteBase{}, fmt.Errorf("remote base proof returned no positive commit family")
	}
	switch proof.Kind {
	case "pft2":
		if id.RecordCodec != pfj3.RecordCodec || id.ControlCodec != pfj3.ControlCodec {
			return resolvedRemoteBase{}, fmt.Errorf("PFT2 base is forbidden for journal codec %s/%s", id.RecordCodec, id.ControlCodec)
		}
		return resolvedRemoteBase{proof: proof}, nil
	case "manifest_v1":
		entries, err := client.ManifestAt(ctx, id.CommitID)
		if err != nil {
			return resolvedRemoteBase{}, fmt.Errorf("fetch proven journal base manifest %s: %w", id.CommitID, err)
		}
		return resolvedRemoteBase{proof: proof, entries: entries}, nil
	default:
		return resolvedRemoteBase{}, fmt.Errorf("remote base proof selected unknown commit family %q", proof.Kind)
	}
}

func openResolvedRemoteBase(
	ctx context.Context,
	client remoteBaseBackend,
	rlog *remotejournal.Log,
	cache content.Cache,
	resolved resolvedRemoteBase,
) (*workfs.FS, error) {
	if resolved.proof == nil {
		return nil, fmt.Errorf("remote base is unresolved")
	}
	// runRemotePrimary already refused a non-PFJ3 provisioning decision; keep
	// the runtime honest here so no caller can route a legacy generation into
	// the managed store.
	if rlog.RecordCodec() != pfj3.RecordCodec || rlog.ControlCodec() != pfj3.ControlCodec {
		return nil, fmt.Errorf("managed serving requires a PFJ3/PFC2 generation (this one speaks %s/%s)", rlog.RecordCodec(), rlog.ControlCodec())
	}
	if resolved.proof.Kind == "manifest_v1" {
		return workfs.NewManagedWithCache(resolved.entries, client, rlog, cache)
	}
	base, err := pft2BaseFromProof(resolved.proof, rlog.CompactedThrough())
	if err != nil {
		return nil, err
	}
	base.Fetcher = backend.NewPft2Fetcher(client)
	return workfs.NewManagedFromPft2(ctx, base, client, rlog, cache)
}

// pft2BaseFromProof maps one validated PFT2 provenance proof onto the exact
// WorkFS base contract. baseSeq is the claimed journal base sequence (the
// proof already restated it).
//
//   - A positively proven FORK starts new control/orphan state under the NEW
//     branch's DB-issued never-reused allocator namespace. It never keeps a
//     flat allocator: the reused source root carries namespaced inodes far
//     beyond the flat 2^32 cap, so a flat fork would exhaust identity space
//     on its first create. Missing anchor data never produces this shape.
//   - Conversion/adopted bases carry their allocator inside the recovery
//     anchor; WorkFS additionally binds every fact against the hashed
//     RecoveryRoot object before readiness.
func pft2BaseFromProof(proof *backend.BaseProvenance, baseSeq uint64) (workfs.Pft2Base, error) {
	root, err := proof.RootRef()
	if err != nil {
		return workfs.Pft2Base{}, err
	}
	rootMax, err := proof.RootMaxInoSeen()
	if err != nil {
		return workfs.Pft2Base{}, err
	}
	base := workfs.Pft2Base{
		Root:           root,
		BaseSeq:        baseSeq,
		RootMaxInoSeen: rootMax,
	}
	if proof.BaseMode == "fork" {
		allocMax, namespace, nextLocal, err := proof.ForkAllocatorFacts()
		if err != nil {
			return workfs.Pft2Base{}, err
		}
		base.InodeNamespace = namespace
		base.NextLocal = nextLocal
		base.AllocatorMaxInoSeen = allocMax
		return base, nil
	}
	recovery, err := proof.RecoveryRootRef()
	if err != nil {
		return workfs.Pft2Base{}, err
	}
	maxIno, namespace, nextLocal, err := proof.AnchorFacts()
	if err != nil {
		return workfs.Pft2Base{}, err
	}
	if maxIno < rootMax {
		return workfs.Pft2Base{}, fmt.Errorf("PFT2 anchor maxInoSeen %d is below root high-water %d", maxIno, rootMax)
	}
	asOf, err := proof.AnchorAsOf()
	if err != nil {
		return workfs.Pft2Base{}, err
	}
	base.RecoveryRoot = &recovery
	base.AnchorAsOfSeq = asOf
	base.InodeNamespace = namespace
	base.NextLocal = nextLocal
	base.AllocatorMaxInoSeen = maxIno
	return base, nil
}

// watchRecoveryAbort cancels the recovery phase — INCLUDING the otherwise
// signal-detached journal lifecycle — the moment a shutdown signal arrives,
// the writer lease is definitively lost, or the manager lease pipe fences
// this child. Once recovery is done it stands down without canceling
// anything (nil trigger channels block forever and are ignored).
func watchRecoveryAbort(signal, leaseLost, guardFenced, recoveryDone <-chan struct{}, cancels ...func()) {
	select {
	case <-signal:
	case <-leaseLost:
	case <-guardFenced:
	case <-recoveryDone:
		return
	}
	for _, cancel := range cancels {
		cancel()
	}
}

func leaseLostNow(leaseLost <-chan struct{}) bool {
	select {
	case <-leaseLost:
		return true
	default:
		return false
	}
}

// requireJournalDurability verifies the database's durability EVIDENCE —
// fact by fact, never by prose. It samples pfj.durability_facts() TWICE so
// identity instability (a pooler bouncing between clusters, a mid-check
// failover) is caught, enforces the same floor pfm.require_durable_primary
// applies inside every SQL transaction, and then evaluates the operator's
// structured HA policy (VCS_JOURNAL_HA_POLICY_JSON) on top. It returns the
// canonical policy hash the child reports through bootstrap/readiness.
func requireJournalDurability(ctx context.Context, rlog *remotejournal.Log, cfg config) (policyHash string, err error) {
	factsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	first, err := rlog.DurabilityFacts(factsCtx)
	if err != nil {
		return "", err
	}
	second, err := rlog.DurabilityFacts(factsCtx)
	if err != nil {
		return "", err
	}
	log.Printf("journal durability facts: server=%v database=%v system=%v fsync=%v full_page_writes=%v synchronous_commit=%v synchronous_standby_names=%q in_recovery=%v sync_standbys=%v ready=%v",
		first["serverVersion"], first["database"], first["systemIdentifier"], first["fsync"], first["fullPageWrites"],
		first["synchronousCommit"], first["synchronousStandbyNames"], first["inRecovery"], first["syncOrQuorumStandbys"], first["ready"])
	return evaluateJournalDurability(cfg, first, second)
}

// evaluateJournalDurability is the pure evidence check behind
// requireJournalDurability (unit-tested without a database).
//
// The STRUCTURAL FLOOR applies in every mode and mirrors the SQL transaction
// guard (pfm.require_durable_primary: ready OR the superuser-only test
// bypass), plus the identity facts a guard inside one SQL transaction cannot
// see across calls:
//
//   - synchronous_commit must be EXACTLY on or remote_apply — never weaker.
//     (remote_apply is stronger; pfm.require_txn_settings never downgrades it.)
//   - the database's own ready verdict must hold in BOTH samples (or the
//     test bypass must be active — impossible for production logins, which
//     are never superusers),
//   - systemIdentifier must be present and IDENTICAL across both samples (a
//     changing identifier means the two calls answered from different
//     clusters; nothing sampled here describes one durable primary),
//   - replication visibility must be positive: pg_stat_replication rows must
//     be readable when standbys exist, or provably absent.
//
// The structured policy then pins identity and minimums on top (production
// requires it; validateConfig enforces that).
func evaluateJournalDurability(cfg config, first, second map[string]any) (policyHash string, err error) {
	commit, _ := first["synchronousCommit"].(string)
	if commit != "on" && commit != "remote_apply" {
		return "", fmt.Errorf("database reports synchronous_commit=%q; the journal requires exactly on or remote_apply, never weaker", commit)
	}
	systemID, _ := first["systemIdentifier"].(string)
	if systemID == "" {
		return "", fmt.Errorf("database did not report its system identifier; the journal refuses evidence that cannot name the exact cluster")
	}
	secondSystemID, _ := second["systemIdentifier"].(string)
	if secondSystemID != systemID {
		return "", fmt.Errorf("database system identifier changed between evidence samples (%q then %q); the connection does not describe one stable cluster", systemID, secondSystemID)
	}
	visible, _ := first["replicationVisible"].(bool)
	if !visible {
		return "", fmt.Errorf("pg_stat_replication is not visible to the journal role; standby liveness cannot be verified")
	}
	bypass, _ := first["testBypassActive"].(bool)
	firstReady, _ := first["ready"].(bool)
	secondReady, _ := second["ready"].(bool)
	if !(firstReady && secondReady) && !bypass {
		return "", fmt.Errorf("database durability evidence is not ready (ready=%v then %v): the same guard fences every journal transaction (pfm.require_durable_primary), so serving would only defer the failure", firstReady, secondReady)
	}

	if cfg.journalHAPolicyJSON != "" {
		policy, parseErr := hapolicy.ParsePolicy(cfg.journalHAPolicyJSON)
		if parseErr != nil {
			return "", parseErr
		}
		secondBypass, _ := second["testBypassActive"].(bool)
		if bypass && secondBypass {
			// The SUPERUSER-ONLY test bypass (portablefs.test_allow_unsafe_
			// durability, impossible for production logins — they are never
			// superusers) short-circuits the policy's replication MINIMUMS
			// exactly the way pfm.require_durable_primary short-circuits the
			// durability gate inside every journal transaction. The policy's
			// IDENTITY pins still bind: a bypassed child must still be
			// talking to the exact pinned cluster and database.
			database, _ := first["database"].(string)
			if systemID != policy.ExpectedSystemIdentifier {
				return "", fmt.Errorf("test bypass is active but the system identifier is %q, policy pins %q", systemID, policy.ExpectedSystemIdentifier)
			}
			if database != policy.ExpectedDatabase {
				return "", fmt.Errorf("test bypass is active but the database is %q, policy pins %q", database, policy.ExpectedDatabase)
			}
			log.Printf("journal HA policy minimums BYPASSED by the superuser-only durability test bypass (v%d, hash %s): single-node test topology, identity pins verified", policy.V, policy.Hash())
			return policy.Hash(), nil
		}
		summary, evalErr := hapolicy.Evaluate(policy, first)
		if evalErr != nil {
			return "", evalErr
		}
		if _, evalErr := hapolicy.Evaluate(policy, second); evalErr != nil {
			return "", fmt.Errorf("second evidence sample violated the HA policy: %w", evalErr)
		}
		log.Printf("journal HA policy satisfied (v%d, hash %s): %s", policy.V, policy.Hash(), summary)
		return policy.Hash(), nil
	}
	if cfg.production {
		// validateConfig already refuses this shape; keep the runtime honest.
		return "", fmt.Errorf("VCS_PRODUCTION=1 requires VCS_JOURNAL_HA_POLICY_JSON")
	}
	log.Print("journal HA: NOT policy-verified (non-production run without VCS_JOURNAL_HA_POLICY_JSON)")
	return "", nil
}

// serveRemotePrimary runs the managed serving loop: fsproto + metrics on
// self-bound loopback listeners, readiness only after every startup proof,
// and ordinary eviction (seal → drain → exact journal suspension) on the way
// out. There is deliberately NO checkpoint loop, NO NFS listener, and NO
// quiesce path here — Checkpoint/Quiesce answer VCS_HISTORY_CUT_UNAVAILABLE.
func serveRemotePrimary(
	ctx context.Context,
	cfg config,
	wfs *workfs.FS,
	auth *authority.Authority,
	rlog *remotejournal.Log,
	guard *managerlease.Guard,
	policyHash string,
	leaseLost <-chan struct{},
) (shutdownErr error) {
	// serveCtx fences the data plane: backend lease loss (signalled by the
	// process-wide lease keeper started before recovery), journal poison, or
	// a manager lease-pipe fence all cancel it, so the node steps down before
	// anything can serve past its authority.
	serveCtx, fence := context.WithCancel(ctx)
	defer fence()
	go func() {
		select {
		case <-leaseLost:
			log.Print("writer lease lost (superseded, expired, or unrenewable): fencing data plane and stepping down")
			fence()
		case <-serveCtx.Done():
		}
	}()
	go func() {
		select {
		case <-wfs.PoisonedCh():
			// Name the proof that failed. Without it this line reported a
			// CATEGORY ("durability/fence failure") for an event that always
			// has one specific, enumerated cause, and every diagnosis of a
			// fenced child had to start by guessing which one.
			cause := "cause unrecorded"
			if rlog != nil {
				if c := rlog.PoisonCause(); c != nil {
					cause = c.Error()
				}
			}
			log.Printf("journal poisoned (durability/fence failure): fencing data plane and stepping down: %s", cause)
			fence()
		case <-serveCtx.Done():
		}
	}()
	if guard != nil {
		go func() {
			select {
			case <-guard.Fenced():
				log.Printf("manager lease pipe fenced this child: %v", guard.Cause())
				fence()
			case <-serveCtx.Done():
			}
		}()
		if err := waitForInitialManagerLease(ctx, guard, leaseLost); err != nil {
			return err
		}
	}
	wfs.StartOrphanSweeper(serveCtx)

	// dataCtx scopes the mount data plane separately: eviction closes it while
	// the process keeps renewing and answering fenced admin retries until the
	// manager terminates it.
	dataCtx, stopData := context.WithCancel(serveCtx)
	defer stopData()
	controller := lifecycle.NewController(lifecycle.Deps{
		FS:            wfs,
		StopDataPlane: stopData,
		// Process-local receipts: durable lifecycle idempotency across child
		// death is the manager's pfm receipts plus the journal's pfj suspend
		// receipt. A disposable child persists nothing locally.
		Store:    opstate.NewMemory(),
		Identity: cfg.identity(),
		Lease:    auth,
		Journal: &journalStepDown{
			log: rlog,
			// Deterministic per-runtime suspend id: every caller (manager
			// evict, SIGTERM) converges on ONE receipted suspension.
			operationID: "pfjsd-" + cfg.authorityRuntimeID,
		},
		// Bounded suspension inside every eviction attempt: an unresolved
		// suspension fails the eviction closed and this process exits
		// non-zero with the writer lease UNRELEASED (DB-time expiry fences).
		SuspendDeadline: cfg.suspendDeadline(),
	})
	adminLifecycle.Set(controller)

	// FRESH DB-TIME LEASE VALIDATION immediately before the listeners bind:
	// a slow cold replay (or a long wait for the first manager frame) must
	// never roll into readiness on an expired or lapsed writer lease. The
	// renewed window is projected CONSERVATIVELY from the PRE-CALL monotonic
	// instant, so a delayed response can only shrink the proof, never
	// stretch it.
	if err := renewLeaseBeforeReady(ctx, auth, cfg.leaseTTL(), cfg.renewEvery()); err != nil {
		return err
	}
	if leaseLostNow(leaseLost) {
		return fmt.Errorf("writer lease lost before readiness; refusing to serve")
	}

	// Self-bound loopback listeners: the exact addresses travel to the
	// manager over the bootstrap pipe, so no port pre-allocation race and no
	// foreign-process adoption is possible. A development run may pin
	// VCS_FS_ADDR instead (production rejects it).
	fsAddr := cfg.fsAddr
	if fsAddr == "" {
		fsAddr = "127.0.0.1:0"
	}
	if err := secure.RequireSecureExposure(fsAddr); err != nil {
		return fmt.Errorf("fsproto: %w", err)
	}
	fsLn, err := net.Listen("tcp", fsAddr)
	if err != nil {
		return fmt.Errorf("fsproto listen %s: %w", fsAddr, err)
	}
	defer fsLn.Close()
	var metricsLn net.Listener
	if cfg.managed() {
		metricsLn, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("metrics listen: %w", err)
		}
		defer metricsLn.Close()
	}

	// Readiness identity: the exact facts the manager validates against the
	// process answering /readyz, including the ACTUAL bound listener
	// addresses. Published before readiness flips.
	readyIdentity.Store(&readinessIdentity{
		AuthorityInstanceID: cfg.authorityInstanceID,
		VolumeID:            cfg.volumeID,
		Branch:              cfg.branch,
		Journal:             "remote",
		ManagerEpoch:        cfg.managerEpoch,
		AuthorityRuntimeSeq: cfg.authorityRuntimeSeq,
		AuthorityRuntimeID:  cfg.authorityRuntimeID,
		JournalGenerationID: rlog.GenerationID(),
		ProtocolVersion:     managedProtocolVersion,
		HAPolicyHash:        policyHash,
		FSAddr:              fsLn.Addr().String(),
		MetricsAddr:         metricsAddrString(metricsLn, cfg),
	})
	defer readyIdentity.Store(nil)

	fsServeDone := make(chan struct{})
	go func() {
		defer close(fsServeDone)
		serveFSProtoOn(dataCtx, fsLn, wfs)
	}()
	if metricsLn != nil {
		// Admin/metrics outlive the data plane (serveCtx, not dataCtx): a
		// fenced or evicted child still answers idempotent lifecycle retries
		// until the manager terminates it.
		go serveMetricsOn(serveCtx, metricsLn)
	}

	// One bounded bootstrap frame, then the descriptor closes: the manager
	// only ever adopts addresses this exact process reported.
	if cfg.bootstrapFD >= 3 {
		bootstrapPipe := os.NewFile(uintptr(cfg.bootstrapFD), "portablefs-bootstrap-pipe")
		if bootstrapPipe == nil {
			return fmt.Errorf("VCS_BOOTSTRAP_FD=%d does not name an inherited descriptor", cfg.bootstrapFD)
		}
		frame := managerlease.Bootstrap{
			AuthorityInstanceID: cfg.authorityInstanceID,
			VolumeID:            cfg.volumeID,
			Branch:              cfg.branch,
			ManagerEpoch:        cfg.managerEpoch,
			AuthorityRuntimeSeq: cfg.authorityRuntimeSeq,
			AuthorityRuntimeID:  cfg.authorityRuntimeID,
			FSAddr:              fsLn.Addr().String(),
			MetricsAddr:         metricsAddrString(metricsLn, cfg),
			JournalGenerationID: rlog.GenerationID(),
			ProtocolVersion:     managedProtocolVersion,
			HAPolicyHash:        policyHash,
		}
		if err := managerlease.EmitBootstrap(bootstrapPipe, frame); err != nil {
			_ = bootstrapPipe.Close()
			return err
		}
		if err := bootstrapPipe.Close(); err != nil {
			return fmt.Errorf("close bootstrap pipe: %w", err)
		}
	}

	// A cancellation that raced the listener bind/bootstrap (SIGTERM, lease
	// loss, guard fence) must never roll into readiness: nothing may become
	// ready after its authority to serve was already revoked.
	if err := ctx.Err(); err != nil {
		return nil
	}
	if leaseLostNow(leaseLost) {
		return fmt.Errorf("writer lease lost before readiness; refusing to serve")
	}

	// READY: HA verified, journal claimed, replay done, first lease frame
	// seen, listeners bound, bootstrap emitted.
	setReady(true)
	defer setReady(false)

	defer func() {
		// Ordinary graceful eviction (SIGTERM / manager evict / fence): close
		// the ONE admission gate, drain already-admitted operations through
		// their existing durable acknowledgement boundary, then execute the
		// exact receipted journal suspension. NO checkpoint, NO history
		// materialization, NO fabricated receipt — a failed drain or suspension
		// exits non-zero and the manager retries or force-terminates with an
		// explicit non-clean record. The teardown is BOUNDED (seal/drain has
		// its own bound; the suspension has cfg.suspendDeadline through the
		// controller): an unresolved suspension exits non-zero with the
		// writer lease UNRELEASED — database-time expiry fences it, and the
		// immutable suspend operation replays its receipt on the next start.
		res, err := controller.Evict(context.WithoutCancel(ctx))
		switch {
		case err != nil:
			log.Printf("eviction did NOT complete (admission stays sealed; every ACKNOWLEDGED write is already journal-durable): %v", err)
			shutdownErr = err
		case res.Journal != nil:
			log.Printf("evicted: admission sealed, acknowledged writes drained, journal generation %s suspended exactly at nextSeq %d tip %s (replayed=%v)",
				rlog.GenerationID(), res.Journal.NextSeq, res.Journal.TipDigest, res.Journal.Replayed)
		default:
			log.Printf("evicted: admission sealed and drained (journal step-down not executed: %s)", res.State)
		}
		if err == nil && res.State == lifecycle.StateEvicted {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if releaseErr := controller.ReleaseAfterEvict(releaseCtx); releaseErr != nil {
				log.Printf("evicted cleanly but could not release the writer claim early (database-time expiry will fence it): %v", releaseErr)
			}
			cancel()
		}
	}()

	<-dataCtx.Done()
	<-fsServeDone
	return shutdownErr
}

// waitForInitialManagerLease observes every pre-readiness fence directly.
// In particular, writer-lease loss must not wait out the manager-frame
// timeout while a replacement authority is trying to take over.
func waitForInitialManagerLease(
	ctx context.Context,
	guard *managerlease.Guard,
	leaseLost <-chan struct{},
) error {
	if guard == nil {
		return nil
	}
	timer := time.NewTimer(firstLeaseFrameTimeout)
	defer timer.Stop()
	select {
	case <-guard.FirstFrame():
		return nil
	case <-guard.Fenced():
		return fmt.Errorf("manager lease pipe fenced before the first valid frame: %w", guard.Cause())
	case <-leaseLost:
		return fmt.Errorf("writer lease lost before the first manager lease frame; refusing to serve")
	case <-ctx.Done():
		return nil
	case <-timer.C:
		return fmt.Errorf("no valid manager lease frame within %s; refusing to serve", firstLeaseFrameTimeout)
	}
}

// metricsAddrString reports the metrics address for the bootstrap frame: the
// self-bound listener in managed mode, or the operator's VCS_METRICS_ADDR in
// a development run (possibly empty — no metrics listener).
func metricsAddrString(metricsLn net.Listener, cfg config) string {
	if metricsLn != nil {
		return metricsLn.Addr().String()
	}
	return cfg.metricsAddr
}

// renewLeaseBeforeReady is the pre-readiness fresh DB-time lease validation:
// one renew whose granted window is projected from the PRE-CALL monotonic
// instant. If the round trip itself consumed the window (minus one renewal
// interval of guard, so the keeper still gets a chance to renew again before
// expiry), the proof is already stale and readiness is refused.
func renewLeaseBeforeReady(ctx context.Context, auth leaseRenewer, ttl, guard time.Duration) error {
	timeout := ttl / 2
	if timeout < time.Second {
		timeout = time.Second
	}
	start := time.Now()
	renewCtx, cancel := context.WithTimeout(ctx, timeout)
	err := auth.Renew(renewCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("pre-ready writer lease validation failed; refusing to serve: %w", err)
	}
	if remaining := ttl - guard - time.Since(start); remaining <= 0 {
		return fmt.Errorf("pre-ready writer lease renewal round trip consumed the %s window (guard %s); refusing to become ready on an already-stale lease proof", ttl, guard)
	}
	return nil
}

// journalStepDown adapts remotejournal.Log to lifecycle.JournalStepDown: it
// observes the EXACT durable head after the drain and executes (or replays)
// the receipted suspension under one deterministic per-runtime operation id.
type journalStepDown struct {
	log         *remotejournal.Log
	operationID string
}

// journalLeaseFactsProber adapts remotejournal.Log.AuthorityLeaseFacts (the
// pfj.authority_lease_facts capability/runtime-bound read on the already-
// open fenced pool) to the guard's LeaseFactsProber. The database verifies
// the exact manager epoch + live runtime row + raw authority capability and
// answers the LIVE claim's dbTimeMs/expiresAtDbMs; a proven superseded or
// fenced binding arrives as Current=false (definitive, extends nothing).
type journalLeaseFactsProber struct {
	log *remotejournal.Log
	// Probe failures never extend and never fence by themselves, which also
	// means they are INVISIBLE unless reported: a guard that later fences
	// with "deadline passed without a fresh grounded frame" must leave
	// operators the actual probe errors. Log the first few, then go quiet.
	probeErrLogs atomic.Int32
}

func (p *journalLeaseFactsProber) ProbeLeaseFacts(ctx context.Context) (managerlease.LeaseFacts, error) {
	facts, err := p.log.AuthorityLeaseFacts(ctx)
	if err != nil {
		if p.probeErrLogs.Add(1) <= 5 {
			log.Printf("manager lease-facts probe failed (never extends the fencing deadline): %v", err)
		}
		return managerlease.LeaseFacts{}, err
	}
	if !facts.Current && p.probeErrLogs.Add(1) <= 5 {
		log.Printf("manager lease-facts probe answered current=false (the database proved this binding is not the live one)")
	}
	return managerlease.LeaseFacts{
		Current:             facts.Current,
		DBTimeMs:            facts.DBTimeMs,
		ExpiresAtDbMs:       facts.ExpiresAtDbMs,
		ManagerEpoch:        facts.ManagerEpoch,
		AuthorityRuntimeSeq: facts.AuthorityRuntimeSeq,
		AuthorityRuntimeID:  facts.AuthorityRuntimeID,
	}, nil
}

func (j *journalStepDown) StepDown(ctx context.Context) (lifecycle.JournalSuspendProof, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lifecycle.JournalSuspendProof{}, fmt.Errorf("%v (caller deadline: %w)", lastErr, err)
			}
			return lifecycle.JournalSuspendProof{}, err
		}
		nextSeq, tipDigest := j.log.DurableHead()
		// The caller's bounded context governs the wait; the operation id is
		// immutable across every retry and restart, so stopping the wait can
		// never fabricate a failure — the exact receipt replays.
		receipt, err := j.log.SuspendExact(ctx, j.operationID, nextSeq, tipDigest)
		if err == nil {
			return lifecycle.JournalSuspendProof{
				NextSeq:   receipt.NextSeq,
				TipDigest: receipt.TipDigest,
				Replayed:  receipt.Replayed,
			}, nil
		}
		lastErr = err
		// Only a local revision conflict is re-observable (the durable head
		// moved between the drain and the observation, or a replayed receipt
		// names a different revision). Everything else is final here; the
		// lifecycle layer keeps the eviction retryable.
		if !errors.Is(err, remotejournal.ErrConflict) {
			break
		}
	}
	return lifecycle.JournalSuspendProof{}, lastErr
}
