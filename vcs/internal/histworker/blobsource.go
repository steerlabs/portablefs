package histworker

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/histstore"
)

// legacyBlobSource resolves conversion-input blobs by their DB-recorded
// exact key, size, and digest (pfh.legacy_blob_locate). It never derives a
// blob location from a digest: an unlocated blob is a typed retryable
// failure the operator resolves by backfilling the record. Legacy bucket
// objects may be transport-gzip-compressed at rest (x-amz-meta-compression)
// with the digest covering the PLAINTEXT of that transport layer; the
// source reverses exactly that layer under a hard byte bound and re-proves
// the digest before returning bytes.
type legacyBlobSource struct {
	repo     Repository
	claim    CutClaim
	maxBytes int64

	fsRoot *os.Root
	fsBase string

	s3 *histstore.S3Store
}

func newLegacyBlobSource(repo Repository, claim CutClaim, cfg Config) (*legacyBlobSource, error) {
	src := &legacyBlobSource{repo: repo, claim: claim, maxBytes: cfg.MaxLegacyBlobBytes}
	if cfg.LegacyStore == nil {
		return src, nil
	}
	switch cfg.LegacyStore.Kind {
	case "fs":
		root, err := os.OpenRoot(cfg.LegacyStore.RootDir)
		if err != nil {
			return nil, fmt.Errorf("histworker: legacy blob root: %w", err)
		}
		src.fsRoot = root
		src.fsBase = filepath.Clean(cfg.LegacyStore.RootDir)
	case "s3":
		store, err := histstore.NewS3Store(histstore.S3Config{
			Domain:   "legacy",
			Endpoint: cfg.LegacyStore.Endpoint, Region: cfg.LegacyStore.Region,
			Bucket: cfg.LegacyStore.Bucket, PathStyle: cfg.LegacyStore.PathStyle,
			AccessKeyID:      cfg.LegacyStore.AccessKeyID,
			SecretAccessKey:  cfg.LegacyStore.SecretAccessKey,
			OperationTimeout: 5 * time.Minute,
		})
		if err != nil {
			return nil, err
		}
		src.s3 = store
	default:
		return nil, fmt.Errorf("histworker: legacy store kind %q", cfg.LegacyStore.Kind)
	}
	return src, nil
}

func (s *legacyBlobSource) Close() {
	if s.fsRoot != nil {
		s.fsRoot.Close()
	}
}

// Blob implements historycut.BlobSource: recorded location only, verified
// bytes only.
func (s *legacyBlobSource) Blob(ctx context.Context, digest string, size int64) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("histworker: legacy blob %s has a negative requested size", digest)
	}
	loc, err := s.repo.LocateLegacyBlob(ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, digest)
	if err != nil {
		return nil, err
	}
	if loc == nil {
		return nil, fmt.Errorf("histworker: legacy blob %s has no database record", digest)
	}
	if loc.StorageKey == "" {
		return nil, fmt.Errorf("histworker: legacy blob %s has no recorded storage key (backfill required; keys are never derived)", digest)
	}
	if loc.Size < 0 {
		return nil, fmt.Errorf("histworker: legacy blob %s has a negative recorded size", digest)
	}
	if size > 0 && loc.Size != size {
		return nil, fmt.Errorf("histworker: legacy blob %s recorded size %d contradicts entry size %d",
			digest, loc.Size, size)
	}
	if loc.Size > s.maxBytes {
		return nil, fmt.Errorf("histworker: legacy blob %s is %d bytes, above the %d bound",
			digest, loc.Size, s.maxBytes)
	}

	var data []byte
	if strings.HasPrefix(loc.StorageKey, "file://") {
		data, err = s.readFileKey(loc.StorageKey, loc.Size)
	} else {
		data, err = s.readS3Key(ctx, loc.StorageKey, loc.Size)
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
		return nil, fmt.Errorf("histworker: legacy blob %s bytes hash to %s (recorded key %q)",
			digest, got, loc.StorageKey)
	}
	return data, nil
}

// readFileKey resolves a recorded file:// key strictly under the configured
// legacy root via openat-style traversal.
func (s *legacyBlobSource) readFileKey(storageKey string, expectSize int64) ([]byte, error) {
	if s.fsRoot == nil {
		return nil, errors.New("histworker: recorded file:// legacy key but no legacy fs store is configured")
	}
	full := filepath.Clean(strings.TrimPrefix(storageKey, "file://"))
	rel, err := filepath.Rel(s.fsBase, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("histworker: recorded legacy key %q escapes the configured root", storageKey)
	}
	f, err := s.fsRoot.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("histworker: legacy blob open: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("histworker: legacy key %q is not a regular file", storageKey)
	}
	if info.Size() != expectSize {
		return nil, fmt.Errorf("histworker: legacy key %q holds %d bytes, recorded %d",
			storageKey, info.Size(), expectSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, expectSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != expectSize {
		return nil, fmt.Errorf("histworker: legacy key %q short read", storageKey)
	}
	return data, nil
}

// readS3Key streams a recorded legacy bucket key, reversing the transport
// gzip layer when the object metadata declares it.
func (s *legacyBlobSource) readS3Key(ctx context.Context, storageKey string, expectSize int64) ([]byte, error) {
	if s.s3 == nil {
		return nil, errors.New("histworker: recorded bucket legacy key but no legacy s3 store is configured")
	}
	body, _, header, err := s.s3.GetWithMeta(ctx, storageKey)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	compression := header.Get("x-amz-meta-compression")
	switch compression {
	case "", "none":
		data, err := io.ReadAll(io.LimitReader(body, expectSize+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != expectSize {
			return nil, fmt.Errorf("histworker: legacy key %q is %d bytes, recorded %d",
				storageKey, len(data), expectSize)
		}
		return data, nil
	case "gzip":
		return gunzipBounded(io.LimitReader(body, s.maxBytes+1), expectSize)
	default:
		return nil, fmt.Errorf("histworker: legacy key %q has unsupported transport compression %q",
			storageKey, compression)
	}
}

// gunzipBounded decompresses to exactly expectSize bytes, refusing bombs.
func gunzipBounded(compressed io.Reader, expectSize int64) ([]byte, error) {
	if expectSize < 0 {
		return nil, fmt.Errorf("histworker: negative expected size")
	}
	zr, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("histworker: legacy gzip open: %w", err)
	}
	defer zr.Close()
	out := make([]byte, 0, expectSize)
	buf := make([]byte, 64<<10)
	for {
		n, readErr := zr.Read(buf)
		out = append(out, buf[:n]...)
		if int64(len(out)) > expectSize {
			return nil, fmt.Errorf("histworker: legacy gzip decompressed beyond the recorded %d bytes", expectSize)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("histworker: legacy gzip: %w", readErr)
		}
	}
	if int64(len(out)) != expectSize {
		return nil, fmt.Errorf("histworker: legacy gzip yielded %d bytes, recorded %d", len(out), expectSize)
	}
	return out, nil
}
