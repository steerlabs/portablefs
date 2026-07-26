package histworker

// The rehome copy loop: live pre-copy (and post-fence catch-up) of one
// volume's user-closure objects from the SOURCE tenant's recorded verified
// copies into DESTINATION-tenant-owned exact keys. Every copy is verified
// twice — the plaintext hash is proven against the digest while streaming
// from the source, and the written key is read back and re-hashed — before
// the destination copy receipt is recorded. The loop is idempotent and
// resumable: the database page excludes objects already live at the
// destination, and receipts conflict only on contradictory storage
// identity. A database that installs no rehome plane answers with
// "undefined function", which this loop treats as "no rehome work exists"
// so mixed-version deployments stay healthy.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/trendup-ai/portablefs/vcs/internal/histstore"
)

// rehomeCopyBatch bounds one copy page (objects per claim-loop iteration).
const rehomeCopyBatch = 32

// RehomeRef is one live rehome the worker may copy for.
type RehomeRef struct {
	RehomeID       string `json:"rehomeId"`
	State          string `json:"state"`
	SourceTenantID string `json:"sourceTenantId"`
	SourceVolumeID string `json:"sourceVolumeId"`
	DestTenantID   string `json:"destTenantId"`
}

// RehomeCopyItem is one object to copy with its recorded source locations.
type RehomeCopyItem struct {
	Digest       string      `json:"digest"` // "sha256:<hex>"
	Size         int64       `json:"-"`
	SourceCopies []SweepCopy `json:"sourceCopies"`
	RawSize      string      `json:"size"`
}

// DecodeRehomeLive parses pfh.rehome_live output.
func DecodeRehomeLive(raw []byte) ([]RehomeRef, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var refs []RehomeRef
	if err := json.Unmarshal(raw, &refs); err != nil {
		return nil, fmt.Errorf("histworker: rehome live decode: %w", err)
	}
	for _, ref := range refs {
		if ref.RehomeID == "" || ref.SourceTenantID == "" || ref.DestTenantID == "" {
			return nil, errors.New("histworker: rehome live row is missing identity")
		}
	}
	return refs, nil
}

// DecodeRehomeCopyPage parses pfh.rehome_copy_page output (nil when the
// rehome is not accepting copies).
func DecodeRehomeCopyPage(raw []byte) ([]RehomeCopyItem, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var env struct {
		Objects []RehomeCopyItem `json:"objects"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("histworker: rehome copy page decode: %w", err)
	}
	for i := range env.Objects {
		it := &env.Objects[i]
		size, err := strconv.ParseInt(it.RawSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("histworker: rehome object size %q", it.RawSize)
		}
		if err := validatePFT2ObjectSize(size); err != nil {
			return nil, err
		}
		it.Size = size
		if !strings.HasPrefix(it.Digest, "sha256:") || len(it.Digest) != len("sha256:")+64 {
			return nil, fmt.Errorf("histworker: rehome object digest %q", it.Digest)
		}
	}
	return env.Objects, nil
}

// rehomePass copies one bounded page for one live rehome. Returns whether
// any work was performed.
func (w *Worker) rehomePass(ctx context.Context) (bool, error) {
	refs, err := w.repo.RehomeLive(ctx, 16)
	if err != nil {
		if errors.Is(err, ErrCapabilityMissing) {
			// The database installs no rehome plane: nothing to do.
			return false, nil
		}
		return false, err
	}
	for _, ref := range refs {
		busy, err := w.rehomeCopyPage(ctx, ref)
		if err != nil || busy {
			return busy, err
		}
	}
	return false, nil
}

func (w *Worker) rehomeCopyPage(ctx context.Context, ref RehomeRef) (bool, error) {
	items, err := w.repo.RehomeCopyPage(ctx, ref.RehomeID, rehomeCopyBatch)
	if err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	copied := 0
	for _, item := range items {
		if ctx.Err() != nil {
			return copied > 0, ctx.Err()
		}
		if err := w.rehomeCopyObject(ctx, ref, item); err != nil {
			w.metrics.Counter("pfh_worker_rehome_copy_errors_total").Inc()
			w.log.Error("rehome_copy_failed", err, map[string]any{
				"rehomeId": ref.RehomeID, "digest": item.Digest,
			})
			// Other objects keep copying; this one retries on a later page.
			continue
		}
		copied++
	}
	if copied > 0 {
		w.metrics.Counter("pfh_worker_rehome_copies_total").Add(int64(copied))
		w.log.Info("rehome_copied", map[string]any{
			"rehomeId": ref.RehomeID, "objects": copied,
		})
	}
	return copied > 0, nil
}

// rehomeCopyObject copies ONE object into every required failure domain of
// this deployment and records one destination copy receipt per domain.
func (w *Worker) rehomeCopyObject(ctx context.Context, ref RehomeRef, item RehomeCopyItem) error {
	digestHex := strings.TrimPrefix(item.Digest, "sha256:")
	if len(item.SourceCopies) == 0 {
		return fmt.Errorf("object %s has no recorded source copies", item.Digest)
	}
	destID := histstore.ObjectID{
		Tenant: ref.DestTenantID, Kind: "pft2",
		DigestHex: digestHex, Incarnation: 1,
	}
	// Every configured failure domain receives a destination copy; the bind
	// transaction verifies coverage against the policy's REQUIRED set.
	for _, domain := range w.stores.Domains() {
		destStore, ok := w.stores.Get(domain)
		if !ok {
			return fmt.Errorf("failure domain %q has no store", domain)
		}
		destKey, err := destStore.ExactKey(destID)
		if err != nil {
			return err
		}
		// Prefer a same-domain source; any verified source is acceptable
		// (verification is content-addressed, not location-trusting).
		if err := w.rehomeCopyOne(ctx, item, digestHex, destStore, destKey, domain); err != nil {
			return err
		}
		if err := w.repo.RehomeCopyReceipt(ctx, w.cfg.WorkerID, ref.RehomeID,
			item.Digest, item.Size, domain, destKey); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) rehomeCopyOne(ctx context.Context, item RehomeCopyItem, digestHex string, destStore histstore.Store, destKey, destDomain string) error {
	// Already present and verified at the exact destination key? Done.
	if err := histstore.VerifyStream(ctx, destStore, destKey, item.Size, digestHex); err == nil {
		return nil
	}
	var lastErr error
	ordered := make([]SweepCopy, 0, len(item.SourceCopies))
	for _, sc := range item.SourceCopies {
		if sc.FailureDomain == destDomain {
			ordered = append(ordered, sc)
		}
	}
	for _, sc := range item.SourceCopies {
		if sc.FailureDomain != destDomain {
			ordered = append(ordered, sc)
		}
	}
	for _, source := range ordered {
		srcStore, ok := w.stores.Get(source.FailureDomain)
		if !ok {
			lastErr = fmt.Errorf("source domain %q has no store", source.FailureDomain)
			continue
		}
		body, _, err := srcStore.Get(ctx, source.StorageKey)
		if err != nil {
			lastErr = err
			continue
		}
		// Put streams and proves the plaintext hash; read-back re-proves
		// the exact destination key afterwards.
		err = destStore.Put(ctx, destKey, item.Size, digestHex, body)
		_ = body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if err := histstore.VerifyStream(ctx, destStore, destKey, item.Size, digestHex); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable source copy")
	}
	return lastErr
}
