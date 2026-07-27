// Package checkpoint commits the working filesystem's current state to the
// durable backend: dirty files are uploaded as content-addressed blobs, a full
// manifest is built (with a tree hash the server will accept), committed via the
// volume-api, and on success the committed files are marked clean and the WAL is
// reset. This is the bridge from the live mutable tree to the immutable commit
// history.
package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/treehash"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

var (
	checkpointCommits  = metrics.Default.Counter("vcs_checkpoint_commits")
	checkpointBytes    = metrics.Default.Counter("vcs_checkpoint_bytes")
	checkpointDuration = metrics.Default.Histogram("vcs_checkpoint_duration")
)

// Committer is the held write authority the checkpointer commits through (one
// lease for the VCS's lifetime; the head advances via its own commits).
type Committer interface {
	PutBlob(ctx context.Context, digest string, data []byte) error
	Version() string
	Commit(ctx context.Context, treeHash string, entries []backend.ManifestEntry, mutationCount, byteCount int64) (string, error)
}

// chunkThreshold matches the backend: files this size or larger are stored as
// 4 MiB chunks plus a whole-file digest, rather than one blob.
const chunkThreshold = 8 << 20

// checkpointLarge streams a dirty file into CheckpointBlockSize chunks: each
// chunk is hashed + uploaded and folded into the whole-file digest, so a huge
// file is committed with bounded memory. Returns the whole-file digest, the
// chunk refs (wire + tree-hash), and the clean source to rebind the file to.
func checkpointLarge(ctx context.Context, fs *workfs.FS, c Committer, e workfs.SnapshotEntry) (string, []backend.ChunkRef, []treehash.Chunk, content.Source, error) {
	whole := sha256.New()
	var wire []backend.ChunkRef
	var hash []treehash.Chunk
	var srcChunks []backend.Chunk
	nblocks := (e.Size + workfs.CheckpointBlockSize - 1) / workfs.CheckpointBlockSize
	for bi := int64(0); bi < nblocks; bi++ {
		blk, err := fs.SnapshotBlock(e, bi)
		if err != nil {
			return "", nil, nil, content.Source{}, err
		}
		whole.Write(blk)
		sum := sha256.Sum256(blk)
		cd := "sha256:" + hex.EncodeToString(sum[:])
		if err := c.PutBlob(ctx, cd, blk); err != nil {
			return "", nil, nil, content.Source{}, err
		}
		off, sz := bi*workfs.CheckpointBlockSize, int64(len(blk))
		wire = append(wire, backend.ChunkRef{Digest: cd, Size: sz, Offset: off})
		hash = append(hash, treehash.Chunk{Digest: cd, Size: sz, Offset: off})
		srcChunks = append(srcChunks, backend.Chunk{Digest: cd, Size: sz, Offset: off})
	}
	digest := "sha256:" + hex.EncodeToString(whole.Sum(nil))
	src := content.Source{BlobDigest: digest, BlobSize: e.Size, BlobCompression: "none", Size: e.Size, Chunks: srcChunks}
	return digest, wire, hash, src, nil
}

// Run checkpoints fs through the committer. It returns the new head commit id
// (empty if there was nothing dirty to commit).
func Run(ctx context.Context, fs *workfs.FS, c Committer) (string, error) {
	// A MANAGED store (remote journal) never checkpoints in-process: its
	// durability is the fenced journal, and history materialization belongs
	// to the external HistoryCut service. The managed serving path never
	// starts the checkpoint loop; this guard keeps the invariant even if a
	// caller wires the loop against the wrong store.
	if fs.Managed() {
		return "", fmt.Errorf("checkpoint: a managed journal store never checkpoints in-process (history materialization belongs to the external HistoryCut service)")
	}
	start := time.Now()
	snap := fs.Snapshot()

	// Commit only DURABLE state: make every write the snapshot reflects fsync'd +
	// replicated before externalizing it to the backend manifest. If a write can't be
	// made durable (replica down → WAL poisoned), abort the checkpoint and commit
	// nothing, so an un-acked apply-before-durable write never becomes a phantom in
	// committed history.
	if err := fs.EnsureSnapshotDurable(snap); err != nil {
		return "", fmt.Errorf("checkpoint: snapshot not durable: %w", err)
	}

	wireEntries := make([]backend.ManifestEntry, 0, len(snap.Entries))
	hashEntries := make([]treehash.Entry, 0, len(snap.Entries))
	cleaned := map[string]content.Source{}
	var mutationCount, byteCount int64

	for _, e := range snap.Entries {
		switch e.Kind {
		case "directory":
			wireEntries = append(wireEntries, backend.ManifestEntry{
				Path: e.Path, Kind: "directory", Mode: e.Mode, Size: 0,
				MtimeMs: e.MtimeMs, CtimeMs: e.CtimeMs, AtimeMs: e.AtimeMs,
				UID: e.UID, GID: e.GID, Ino: e.Ino,
			})
			hashEntries = append(hashEntries, treehash.Entry{
				Path: e.Path, Kind: "directory", Mode: e.Mode, Size: 0, UID: e.UID, GID: e.GID,
			})

		case "symlink":
			size := int64(len(e.LinkTarget))
			wireEntries = append(wireEntries, backend.ManifestEntry{
				Path: e.Path, Kind: "symlink", Mode: e.Mode, Size: size,
				MtimeMs: e.MtimeMs, CtimeMs: e.CtimeMs, AtimeMs: e.AtimeMs,
				LinkTarget: e.LinkTarget, UID: e.UID, GID: e.GID, Ino: e.Ino,
			})
			hashEntries = append(hashEntries, treehash.Entry{
				Path: e.Path, Kind: "symlink", Mode: e.Mode, Size: size, LinkTarget: e.LinkTarget, UID: e.UID, GID: e.GID,
			})

		case "file":
			var (
				digest, compression string
				blobSize, fileSize  int64
				packed              bool
				wireChunks          []backend.ChunkRef
				hashChunks          []treehash.Chunk
			)
			if e.Dirty && e.Size >= chunkThreshold {
				d, wc, hc, src, err := checkpointLarge(ctx, fs, c, e)
				if err != nil {
					return "", err
				}
				digest, blobSize, fileSize, compression = d, e.Size, e.Size, "none"
				wireChunks, hashChunks = wc, hc
				cleaned[e.Path] = src
				mutationCount++
				byteCount += fileSize
			} else if e.Dirty {
				local, err := fs.MaterializeFull(e)
				if err != nil {
					return "", err
				}
				sum := sha256.Sum256(local)
				digest = "sha256:" + hex.EncodeToString(sum[:])
				blobSize = int64(len(local))
				fileSize = int64(len(local))
				compression = "none"
				if err := c.PutBlob(ctx, digest, local); err != nil {
					return "", err
				}
				cleaned[e.Path] = content.Source{
					BlobDigest: digest, BlobSize: blobSize, BlobCompression: compression, BlobPacked: packed, Size: fileSize,
				}
				mutationCount++
				byteCount += fileSize
			} else {
				digest = e.Source.BlobDigest
				blobSize = e.Source.BlobSize
				compression = e.Source.BlobCompression
				packed = e.Source.BlobPacked
				fileSize = e.Source.Size
				for _, c := range e.Source.Chunks {
					wireChunks = append(wireChunks, backend.ChunkRef{Digest: c.Digest, Size: c.Size, Offset: c.Offset})
					hashChunks = append(hashChunks, treehash.Chunk{Digest: c.Digest, Size: c.Size, Offset: c.Offset})
				}
			}

			executable := e.Mode&0o111 != 0
			var wireBlob *backend.BlobRef
			var hashBlob *treehash.Blob
			if digest != "" {
				wireBlob = &backend.BlobRef{Digest: digest, Size: blobSize, Compression: compression, Packed: packed}
				hashBlob = &treehash.Blob{Digest: digest, Size: blobSize, Compression: compression, Packed: packed}
			}
			wireEntries = append(wireEntries, backend.ManifestEntry{
				Path: e.Path, Kind: "file", Mode: e.Mode, Size: fileSize,
				MtimeMs: e.MtimeMs, CtimeMs: e.CtimeMs, AtimeMs: e.AtimeMs,
				Executable: executable, Blob: wireBlob, Chunks: wireChunks, UID: e.UID, GID: e.GID, Ino: e.Ino,
			})
			hashEntries = append(hashEntries, treehash.Entry{
				Path: e.Path, Kind: "file", Mode: e.Mode, Size: fileSize, Executable: executable,
				Blob: hashBlob, Chunks: hashChunks, UID: e.UID, GID: e.GID,
			})
		}
	}

	if mutationCount == 0 {
		return "", nil // nothing dirty; no checkpoint needed
	}

	treeHash := treehash.Compute(hashEntries)
	newHead, err := c.Commit(ctx, treeHash, wireEntries, mutationCount, byteCount)
	if err != nil {
		return "", err
	}
	checkpointCommits.Inc()
	checkpointBytes.Add(byteCount)
	checkpointDuration.Time(start)

	for p, src := range cleaned {
		fs.MarkClean(snap, p, src)
	}
	if err := fs.CompactWAL(snap); err != nil {
		return newHead, err
	}
	return newHead, nil
}
