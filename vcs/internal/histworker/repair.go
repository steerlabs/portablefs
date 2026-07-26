package histworker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/trendup-ai/portablefs/vcs/internal/histstore"
)

// repairPass claims leased missing/failed destination copies, reads and
// re-verifies a healthy source at its recorded exact key, writes the
// destination at ITS exact per-incarnation key, proves it by readback, and
// records the fenced repair receipt. Incarnation supersession fences stale
// repairs in the database. Returns the number of claims processed.
func (w *Worker) repairPass(ctx context.Context) (int, error) {
	claims, err := w.repo.ClaimRepairs(ctx, w.cfg.WorkerID, w.cfg.RepairBatch,
		w.cfg.LeaseTTL.Milliseconds())
	if err != nil {
		return 0, err
	}
	w.setPolicyProof(err == nil)
	if len(claims) == 0 {
		return 0, nil
	}
	sem := make(chan struct{}, w.cfg.RepairConcurrency)
	var wg sync.WaitGroup
	for _, claim := range claims {
		wg.Add(1)
		go func(claim RepairClaim) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := w.repairOne(ctx, claim); err != nil {
				if ctx.Err() == nil && !errors.Is(err, ErrFenced) {
					w.metrics.Counter("pfh_worker_repair_failed_total").Inc()
					w.log.Error("repair_failed", err, map[string]any{
						"digest": claim.Digest, "missingDomain": claim.MissingDomain,
					})
				}
				return
			}
			w.metrics.Counter("pfh_worker_repairs_total").Inc()
			w.log.Info("repaired", map[string]any{
				"digest": claim.Digest, "missingDomain": claim.MissingDomain,
			})
		}(claim)
	}
	wg.Wait()
	return len(claims), nil
}

func (w *Worker) repairOne(ctx context.Context, claim RepairClaim) error {
	dest, ok := w.stores.Get(claim.MissingDomain)
	if !ok {
		return fmt.Errorf("histworker: repair destination domain %q has no store", claim.MissingDomain)
	}
	hexDigest := strings.TrimPrefix(claim.Digest, "sha256:")

	// A healthy source must re-verify AT REPAIR TIME; a stale claim row
	// grants nothing.
	var (
		data    []byte
		lastErr error
	)
	for _, source := range claim.Sources {
		srcStore, ok := w.stores.Get(source.FailureDomain)
		if !ok {
			continue
		}
		read, err := histstore.ReadVerified(ctx, srcStore, source.StorageKey, source.Size, hexDigest)
		if err != nil {
			lastErr = err
			continue
		}
		data = read
		break
	}
	if data == nil {
		if lastErr == nil {
			lastErr = errors.New("no source copy is reachable from configured domains")
		}
		return fmt.Errorf("histworker: repair %s: %w", claim.Digest, lastErr)
	}

	id := histstore.ObjectID{
		Tenant: claim.TenantID, Kind: claim.Kind,
		DigestHex: hexDigest, Incarnation: claim.Incarnation,
	}
	key, err := dest.ExactKey(id)
	if err != nil {
		return err
	}
	if err := dest.Put(ctx, key, claim.Size, hexDigest, bytes.NewReader(data)); err != nil {
		return err
	}
	if _, err := histstore.ReadVerified(ctx, dest, key, claim.Size, hexDigest); err != nil {
		return fmt.Errorf("histworker: repair readback: %w", err)
	}
	return w.repo.RecordRepairReceipt(ctx, w.cfg.WorkerID, claim, key)
}
