package histworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
)

// scrubPass claims due copies and verifies EACH against its own recorded
// exact key in its own failure domain (streamed, constant memory). Proven
// absence or content mismatch is a definite negative receipt; transport
// trouble records nothing (the pushed-out verify time is the retry lease).
// Returns the number of claims processed.
func (w *Worker) scrubPass(ctx context.Context) (int, error) {
	copies, err := w.repo.ClaimScrubCopies(ctx, w.cfg.WorkerID, w.cfg.ScrubBatch)
	if err != nil {
		return 0, err
	}
	if len(copies) == 0 {
		return 0, nil
	}
	sem := make(chan struct{}, w.cfg.ScrubConcurrency)
	var wg sync.WaitGroup
	for _, c := range copies {
		wg.Add(1)
		go func(c ScrubCopy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			w.scrubOne(ctx, c)
		}(c)
	}
	wg.Wait()
	return len(copies), nil
}

func (w *Worker) scrubOne(ctx context.Context, c ScrubCopy) {
	if c.ClaimEpoch < 1 || c.ClaimExpiresMs < 0 {
		w.metrics.Counter("pfh_worker_scrub_corrupt_total").Inc()
		w.log.Error("scrub_invalid_claim", fmt.Errorf("invalid scrub claim epoch/expiry"),
			map[string]any{"digest": c.Digest})
		return
	}
	if err := validatePFT2ObjectSize(c.Size); err != nil {
		if receiptErr := w.repo.RecordScrubReceipt(ctx, w.cfg.WorkerID, c, false); receiptErr != nil {
			w.log.Error("scrub_receipt_error", receiptErr, map[string]any{"digest": c.Digest})
			return
		}
		w.metrics.Counter("pfh_worker_scrub_corrupt_total").Inc()
		w.log.Error("scrub_invalid_size", err, map[string]any{"digest": c.Digest})
		return
	}
	store, ok := w.stores.Get(c.FailureDomain)
	if !ok {
		// Unconfigured domain: this worker cannot attest either way.
		w.metrics.Counter("pfh_worker_scrub_skipped_total").Inc()
		return
	}
	hexDigest := strings.TrimPrefix(c.Digest, "sha256:")
	err := histstore.VerifyStream(ctx, store, c.StorageKey, c.Size, hexDigest)
	switch {
	case err == nil:
		if recErr := w.repo.RecordScrubReceipt(ctx, w.cfg.WorkerID, c, true); recErr != nil {
			w.log.Error("scrub_receipt_error", recErr, map[string]any{"digest": c.Digest})
			return
		}
		w.metrics.Counter("pfh_worker_scrub_ok_total").Inc()
	case ctx.Err() != nil:
		// Shutdown/cancel: no receipt; the verify window expires on its own.
		return
	case errors.Is(err, histstore.ErrNotFound) || isVerificationFailure(err):
		// Definite negative: the exact key is absent, short, or hashes
		// wrong. Repeated negatives quarantine the object in the database.
		if recErr := w.repo.RecordScrubReceipt(ctx, w.cfg.WorkerID, c, false); recErr != nil {
			w.log.Error("scrub_receipt_error", recErr, map[string]any{"digest": c.Digest})
			return
		}
		w.metrics.Counter("pfh_worker_scrub_corrupt_total").Inc()
		w.log.Error("scrub_negative", err, map[string]any{
			"digest": c.Digest, "failureDomain": c.FailureDomain,
		})
	default:
		// Transport trouble: neither proof; retry later.
		w.metrics.Counter("pfh_worker_scrub_transport_error_total").Inc()
		w.log.Error("scrub_transport_error", err, map[string]any{
			"digest": c.Digest, "failureDomain": c.FailureDomain,
		})
	}
}

// isVerificationFailure distinguishes definite content lies (size/digest
// mismatch, short stream, non-regular file) from transport trouble. The
// histstore verify helpers phrase all definite failures locally, so any
// error NOT wrapping a network/context cause and not a store transport
// error is definite. Conservative default: treat unknown as transport.
func isVerificationFailure(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, marker := range []string{
		"content hash", "recorded size is", "streamed", "short read",
		"is not a regular file", "holds",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
