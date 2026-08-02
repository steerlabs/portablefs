package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/remotejournal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// The dirty-block fold driver: the thing that notices a history cut was
// adopted underneath this child and hands the adopted base to WorkFS so the
// blocks it now contains stop occupying RAM.
//
// WHY A POLL AND NOT A CALLBACK. Nothing in remotejournal notifies on a base
// advance. The generation's base tuple is refreshed by the DATABASE's answer
// to the child's own traffic: applyAppendResultLocked and refreshCapacityLocked
// install `currentBaseSeq` / `currentBaseCommitId` from every append and every
// admission preflight, each verified against an exact cut proof before it is
// believed (ErrProofMissing otherwise). So a WRITING child learns of an
// adoption within one append, and an idle one does not need to — an idle child
// is not growing its dirty pool. Polling that already-verified mirror is
// therefore both timely and free: no extra database round trip, and no new
// trust in anything the child was not already fencing on.
//
// The driver re-proves the new base through the SAME tenant-scoped serving
// proof cold start uses (GET /v1/history/base-provenance). It is an idempotent
// read, and re-proving is not optional: the journal mirror tells us WHICH
// commit was adopted, and only pfh.serving_base_prove tells us that commit is
// this tenant's, at this generation, at this exact base tuple. Folding against
// an unproved root would rebind live inodes to unauthenticated content.

// foldPollInterval is the relaxed cadence: a base advance is picked up within
// one tick once the writing traffic has refreshed the journal mirror.
const foldPollInterval = 15 * time.Second

// foldPollIntervalUnderPressure is the cadence once resident dirty blocks pass
// foldPressureThreshold of the bound. A volume in that band is the one that
// actually needs the fold promptly.
const foldPollIntervalUnderPressure = 3 * time.Second

// foldPressureThreshold is the fraction of VCS_DIRTY_RSS_MAX_MB at which the
// driver switches to the fast cadence and starts recording pressure.
const foldPressureThreshold = 0.5

// foldMaxInodesPerPass bounds one pass's base resolves so a pathological
// namespace cannot turn a fold into an unbounded stall. Candidates are taken
// biggest-resident-first, so a bounded pass still releases the most memory
// available, and the next tick takes the rest.
const foldMaxInodesPerPass = 4096

// foldDriver folds this child's resident dirty blocks into each newly adopted
// history-cut base.
type foldDriver struct {
	client remoteBaseBackend
	fs     *workfs.FS
	rlog   *remotejournal.Log
	// identity carries the generation-stable half of the proof request; the
	// commit id, base seq and base digest are re-read from the journal mirror
	// on every pass.
	identity remoteBaseIdentity

	// cache is the generation-lifetime verified object cache every base view
	// reads through. It is created once, deliberately: a folded inode retains
	// the view it was bound to, so a cache per pass would pin one per adopted
	// base (see workfs.Pft2FoldCache).
	cache *workfs.Pft2FoldCache

	// unsupportedLogged suppresses repeating the one-time "this base family
	// cannot be folded" record every tick.
	unsupportedLogged bool
}

// run polls until ctx ends. It never returns an error: a fold failure leaves
// the blocks resident and is retried, which is exactly the pre-existing
// behaviour and never a reason to stop serving.
func (d *foldDriver) run(ctx context.Context) {
	timer := time.NewTimer(d.interval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		d.once(ctx)
		timer.Reset(d.interval())
	}
}

func (d *foldDriver) interval() time.Duration {
	if d.pressure() >= foldPressureThreshold {
		return foldPollIntervalUnderPressure
	}
	return foldPollInterval
}

// pressure is resident dirty bytes as a fraction of the bound (0 when the
// bound is disabled).
func (d *foldDriver) pressure() float64 {
	max := d.fs.DirtyRSSMax()
	if max <= 0 {
		return 0
	}
	return float64(d.fs.DirtyBlockBytes()) / float64(max)
}

// once runs at most one fold pass against the currently adopted base.
func (d *foldDriver) once(ctx context.Context) {
	baseSeq := d.rlog.CompactedThrough()
	if baseSeq == 0 || baseSeq <= d.fs.FoldedWatermark() {
		return // no adoption has landed since the last fold
	}
	commitID := d.rlog.BaseCommitID()
	if commitID == "" {
		return
	}
	id := d.identity
	id.CommitID = commitID
	id.BaseSeq = baseSeq
	id.BaseDigest = d.rlog.BaseDigest()

	resolved, err := resolveRemoteBase(ctx, d.client, id)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("dirty-block fold: prove adopted base %s at seq %d: %v (blocks stay resident; retrying)",
				commitID, baseSeq, err)
		}
		return
	}
	if resolved.proof.Kind != "pft2" {
		// Only a PFT2 base carries the numeric inode index the fold resolves
		// identities through. A manifest_v1 origin base has no adoption to
		// fold to anyway (adoption always produces PFT2), so this is a
		// startup-shape observation, not a recurring condition.
		if !d.unsupportedLogged {
			log.Printf("dirty-block fold: base family %q carries no inode index; resident dirty blocks "+
				"are released by truncate/reap only on this generation", resolved.proof.Kind)
			d.unsupportedLogged = true
		}
		return
	}
	root, err := resolved.proof.RootRef()
	if err != nil {
		log.Printf("dirty-block fold: adopted base %s root ref: %v", commitID, err)
		return
	}
	// Bind the proof to the exact watermark being folded to. The anchor's
	// as-of sequence IS the cut sequence the base was materialised at; folding
	// blocks below a watermark the proof does not restate would compare
	// provenance against the wrong boundary.
	if resolved.proof.BaseMode != "fork" {
		asOf, aerr := resolved.proof.AnchorAsOf()
		if aerr != nil {
			log.Printf("dirty-block fold: adopted base %s anchor as-of: %v", commitID, aerr)
			return
		}
		if asOf != baseSeq {
			log.Printf("dirty-block fold: adopted base %s anchor as-of %d does not restate the journal base seq %d; refusing to fold",
				commitID, asOf, baseSeq)
			return
		}
	}

	if d.cache == nil {
		d.cache = workfs.NewPft2FoldCache(backend.NewPft2Fetcher(d.client))
	}
	base, err := workfs.Pft2FoldBase(d.cache, baseSeq, commitID, root)
	if err != nil {
		log.Printf("dirty-block fold: open adopted base %s: %v", commitID, err)
		return
	}
	base.MaxInodes = foldMaxInodesPerPass

	before := d.fs.DirtyBlockBytes()
	report, ferr := d.fs.FoldToBase(ctx, base)
	if ferr != nil && errors.Is(ferr, workfs.ErrFoldStale) {
		return // a concurrent pass already folded this watermark
	}
	if report.Blocks > 0 || ferr != nil {
		log.Printf("dirty-block fold: base %s seq %d -> %d inodes / %d blocks / %d MiB released "+
			"(resident %d -> %d MiB, candidates %d absent %d raced %d failed %d)%s",
			commitID, baseSeq, report.Inodes, report.Blocks, report.BytesReleased>>20,
			before>>20, report.Resident>>20,
			report.Candidates, report.Absent, report.Raced, report.Failed, foldErrSuffix(ferr))
	}
}

func foldErrSuffix(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf(": %v", err)
}
