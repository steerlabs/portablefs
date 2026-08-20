package archive

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

// PackSink receives pack objects as the builder produces them. Packs are opened
// in index order and each is closed before the next is opened, so a sink may be
// a multipart upload that streams: it never has to hold a whole pack, and it
// never sees two packs at once. The builder computes each pack's size, SHA-256,
// and CRC64NVME as it writes, so a sink is never asked to read a pack back.
type PackSink interface {
	OpenPack(index uint32) (io.WriteCloser, error)
}

// PackSource serves compressed byte ranges out of pack objects. It is the one
// place the format touches the object store, and it takes a single range at a
// time on purpose: the store offers no multi-range GET, so callers coalesce
// with CoalesceFrames and issue single ranges, in parallel if they want
// bandwidth.
type PackSource interface {
	ReadPackRange(index uint32, offset, length uint64) ([]byte, error)
}

// PackReader turns a validated manifest plus a pack source into content. Every
// read it returns has been verified: the frame against its recorded length and
// checksum, and the slice against its SHA-256. Nothing leaves this type
// unverified, so no caller has to remember to check.
type PackReader struct {
	manifest *Manifest
	source   PackSource
}

// NewPackReader binds a manifest to a source. The manifest must already be one
// Decode or Validate accepted; the reader relies on the frame and chunk
// references being in range rather than re-deriving that on every read.
func NewPackReader(manifest *Manifest, source PackSource) (*PackReader, error) {
	if manifest == nil || source == nil {
		return nil, fmt.Errorf("%w: pack reader needs a manifest and a source", ErrInvalid)
	}
	if err := Validate(manifest); err != nil {
		return nil, err
	}
	return &PackReader{manifest: manifest, source: source}, nil
}

// Frame fetches and decompresses one whole frame, verifying its length and
// checksum. Callers that need several slices out of one frame should hold the
// result rather than call Chunk repeatedly, which refetches.
func (r *PackReader) Frame(index uint32) ([]byte, error) {
	if index >= uint32(len(r.manifest.Frames)) {
		return nil, fmt.Errorf("%w: frame %d does not exist", ErrInvalid, index)
	}
	frame := r.manifest.Frames[index]
	compressed, err := r.source.ReadPackRange(frame.PackIndex, frame.PackOffset, frame.CompressedLength)
	if err != nil {
		return nil, fmt.Errorf("archive: read frame %d: %w", index, err)
	}
	return DecodeFrame(frame, compressed)
}

// Chunk returns exactly the bytes one chunk stores — its data extents
// concatenated, holes absent — after verifying the slice digest. A chunk that
// stores nothing returns no bytes and reads no pack.
func (r *PackReader) Chunk(chunk ChunkRef) ([]byte, error) {
	if !chunk.Stored() {
		return nil, nil
	}
	content, err := r.Frame(chunk.FrameIndex)
	if err != nil {
		return nil, err
	}
	return sliceFrame(content, chunk)
}

// sliceFrame extracts and verifies one chunk's stored bytes out of an already
// decompressed frame.
func sliceFrame(content []byte, chunk ChunkRef) ([]byte, error) {
	end := chunk.InnerOffset + chunk.Length
	if end < chunk.InnerOffset || end > uint64(len(content)) {
		return nil, fmt.Errorf("%w: chunk slice runs past its frame", ErrFrameCorrupt)
	}
	slice := content[chunk.InnerOffset:end]
	digest := sha256.Sum256(slice)
	if subtle.ConstantTimeCompare(digest[:], chunk.SliceDigest[:]) != 1 {
		return nil, fmt.Errorf("%w: chunk slice digest does not match the manifest", ErrFrameCorrupt)
	}
	return slice, nil
}

// ReadChunkLogical returns one chunk's logical span with holes materialized as
// zeros: what a reader of the restored file would see at those offsets. It is
// the hydrator's shape — fetch a chunk, expand it, write it — and it verifies
// the slice digest on the way.
func (r *PackReader) ReadChunkLogical(entryIndex uint32, chunkIndex int) ([]byte, error) {
	entry, err := r.entry(entryIndex)
	if err != nil {
		return nil, err
	}
	if chunkIndex < 0 || chunkIndex >= len(entry.Chunks) {
		return nil, fmt.Errorf("%w: entry %d has no chunk %d", ErrInvalid, entryIndex, chunkIndex)
	}
	chunk := entry.Chunks[chunkIndex]
	span := chunkSpan(entry.Size, uint64(r.manifest.Header.ChunkSizeBytes), chunkIndex)
	stored, err := r.Chunk(chunk)
	if err != nil {
		return nil, err
	}
	return expandExtents(stored, chunk.Extents, span)
}

// ReadFile reconstructs one regular file's whole logical content, holes as
// zeros. It exists for verification and for callers small enough to hold a file
// in memory; the hydrator works chunk at a time through ReadChunkLogical.
func (r *PackReader) ReadFile(entryIndex uint32) ([]byte, error) {
	entry, err := r.entry(entryIndex)
	if err != nil {
		return nil, err
	}
	if entry.Type != TypeRegular {
		return nil, fmt.Errorf("%w: entry %d is a %s, not a regular file", ErrInvalid, entryIndex, entry.Type)
	}
	if entry.Size > uint64(MaxChunkSizeBytes)*64 {
		return nil, fmt.Errorf("%w: entry %d is too large to reconstruct in memory", ErrInvalid, entryIndex)
	}
	out := make([]byte, 0, entry.Size)
	for chunkIndex := range entry.Chunks {
		span, err := r.ReadChunkLogical(entryIndex, chunkIndex)
		if err != nil {
			return nil, err
		}
		out = append(out, span...)
	}
	if uint64(len(out)) != entry.Size {
		return nil, fmt.Errorf("%w: entry %d reconstructed to %d of %d bytes",
			ErrFrameCorrupt, entryIndex, len(out), entry.Size)
	}
	return out, nil
}

func (r *PackReader) entry(index uint32) (*Entry, error) {
	if index >= uint32(len(r.manifest.Entries)) {
		return nil, fmt.Errorf("%w: entry %d does not exist", ErrInvalid, index)
	}
	return &r.manifest.Entries[index], nil
}

// chunkSpan is the logical length chunk k of a file of the given size covers:
// the chunk size everywhere but the last chunk, which is the remainder.
func chunkSpan(size, chunkSize uint64, chunkIndex int) uint64 {
	consumed := uint64(chunkIndex) * chunkSize
	if remainder := size - consumed; remainder < chunkSize {
		return remainder
	}
	return chunkSize
}

// expandExtents places stored bytes back at their logical offsets inside one
// chunk span, leaving holes as zeros.
func expandExtents(stored []byte, extents []Extent, span uint64) ([]byte, error) {
	out := make([]byte, span)
	at := uint64(0)
	for _, extent := range extents {
		end := extent.Offset + extent.Length
		if end > span || at+extent.Length > uint64(len(stored)) {
			return nil, fmt.Errorf("%w: extent map does not fit its chunk", ErrFrameCorrupt)
		}
		copy(out[extent.Offset:end], stored[at:at+extent.Length])
		at += extent.Length
	}
	if at != uint64(len(stored)) {
		return nil, fmt.Errorf("%w: extent map covers %d of %d stored bytes", ErrFrameCorrupt, at, len(stored))
	}
	return out, nil
}
