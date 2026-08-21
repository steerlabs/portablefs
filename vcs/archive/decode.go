package archive

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// Decode parses and fully validates one manifest object.
//
// Decode is bounded before it is anything else. The footer is checked first, so
// nothing is parsed out of bytes whose seal has not been verified; then every
// count is checked against the minimum bytes its records must occupy in the
// input that is actually left, so a count field can never drive an allocation
// larger than the object it arrived in. A hostile manifest claiming four
// billion entries is rejected while it is still four bytes, not after a
// four-billion-element make. Only then is the structure parsed, and only then
// is Validate run over the parsed graph.
//
// An unknown format version is refused before any other interpretation: the
// format has no field-skipping forward compatibility and never guesses.
func Decode(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: manifest of %d bytes exceeds the format bound", ErrInvalid, len(data))
	}
	if len(data) < headerFixedBytes+footerBytes {
		return nil, fmt.Errorf("%w: manifest is truncated below the minimum size", ErrInvalid)
	}
	body := data[:len(data)-footerBytes]
	footer := data[len(data)-footerBytes:]
	if string(footer[32:]) != manifestMagic {
		return nil, fmt.Errorf("%w: manifest does not end with the format magic", ErrInvalid)
	}
	seal := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(seal[:], footer[:32]) != 1 {
		return nil, fmt.Errorf("%w: manifest footer digest does not cover its contents", ErrInvalid)
	}

	cursor := &reader{buf: body}
	manifest := &Manifest{}
	entryCount, frameCount, chunkCount, err := decodeHeader(cursor, &manifest.Header)
	if err != nil {
		return nil, err
	}
	if err := cursor.budget(entryCount, entryFixedBytes, MaxEntries, "entry"); err != nil {
		return nil, err
	}
	manifest.Entries = make([]Entry, entryCount)
	chunkCounts := make([]uint32, entryCount)
	declared := uint64(0)
	for index := range manifest.Entries {
		count, err := decodeEntry(cursor, &manifest.Entries[index])
		if err != nil {
			return nil, fmt.Errorf("%w (entry %d)", err, index)
		}
		chunkCounts[index] = count
		declared += uint64(count)
		if declared > chunkCount {
			return nil, fmt.Errorf("%w: entry chunk counts exceed the declared chunk total", ErrInvalid)
		}
	}
	if declared != chunkCount {
		return nil, fmt.Errorf("%w: entry chunk counts sum to %d, header declares %d",
			ErrInvalid, declared, chunkCount)
	}
	if err := cursor.budget(frameCount, frameRecordBytes, MaxFrames, "frame"); err != nil {
		return nil, err
	}
	manifest.Frames = make([]Frame, frameCount)
	for index := range manifest.Frames {
		if err := decodeFrame(cursor, &manifest.Frames[index]); err != nil {
			return nil, fmt.Errorf("%w (frame %d)", err, index)
		}
	}
	if err := cursor.budget(chunkCount, chunkFixedBytes, MaxChunks, "chunk"); err != nil {
		return nil, err
	}
	for index := range manifest.Entries {
		count := chunkCounts[index]
		if count == 0 {
			continue
		}
		chunks := make([]ChunkRef, count)
		for chunkIndex := range chunks {
			if err := decodeChunk(cursor, &chunks[chunkIndex]); err != nil {
				return nil, fmt.Errorf("%w (entry %d chunk %d)", err, index, chunkIndex)
			}
		}
		manifest.Entries[index].Chunks = chunks
	}
	if cursor.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after the chunk-ref arrays", ErrInvalid, cursor.remaining())
	}
	if err := Validate(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func decodeHeader(cursor *reader, header *Header) (entries, frames, chunks uint64, err error) {
	fail := func(err error) (uint64, uint64, uint64, error) { return 0, 0, 0, err }
	version, err := cursor.uint32()
	if err != nil {
		return fail(err)
	}
	if version != FormatVersion {
		return fail(fmt.Errorf("%w: unsupported format version %d", ErrInvalid, version))
	}
	header.FormatVersion = version
	if header.ChunkSizeBytes, err = cursor.uint32(); err != nil {
		return fail(err)
	}
	level, err := cursor.uint32()
	if err != nil {
		return fail(err)
	}
	header.CompressionLevel = int32(level)
	if header.WindowLog, err = cursor.uint32(); err != nil {
		return fail(err)
	}
	if err = cursor.array(header.VolumeID[:]); err != nil {
		return fail(err)
	}
	if header.SealedEpoch, err = cursor.uint64(); err != nil {
		return fail(err)
	}
	if err = cursor.array(header.Attempt[:]); err != nil {
		return fail(err)
	}
	entryCount, err := cursor.uint32()
	if err != nil {
		return fail(err)
	}
	frameCount, err := cursor.uint32()
	if err != nil {
		return fail(err)
	}
	chunkCount, err := cursor.uint32()
	if err != nil {
		return fail(err)
	}
	if header.LogicalBytes, err = cursor.uint64(); err != nil {
		return fail(err)
	}
	if header.LogicalInodes, err = cursor.uint64(); err != nil {
		return fail(err)
	}
	if header.SealedAllocatedBytes, err = cursor.uint64(); err != nil {
		return fail(err)
	}
	if header.SealedInodes, err = cursor.uint64(); err != nil {
		return fail(err)
	}
	if header.Priority.PackIndex, err = cursor.uint32(); err != nil {
		return fail(err)
	}
	if header.Priority.PackOffset, err = cursor.uint64(); err != nil {
		return fail(err)
	}
	packCount, err := cursor.uint32()
	if err != nil {
		return fail(err)
	}
	if err := cursor.budget(uint64(packCount), packRecordBytes, MaxPacks, "pack"); err != nil {
		return fail(err)
	}
	header.Packs = make([]PackRef, packCount)
	for index := range header.Packs {
		pack := &header.Packs[index]
		if pack.CRC64NVME, err = cursor.uint64(); err != nil {
			return fail(err)
		}
		if err = cursor.array(pack.SHA256[:]); err != nil {
			return fail(err)
		}
		if pack.SizeBytes, err = cursor.uint64(); err != nil {
			return fail(err)
		}
	}
	return uint64(entryCount), uint64(frameCount), uint64(chunkCount), nil
}

func decodeEntry(cursor *reader, entry *Entry) (chunkCount uint32, err error) {
	if entry.ParentIndex, err = cursor.uint32(); err != nil {
		return 0, err
	}
	typeByte, err := cursor.byteValue()
	if err != nil {
		return 0, err
	}
	entry.Type = EntryType(typeByte)
	if entry.Mode, err = cursor.uint32(); err != nil {
		return 0, err
	}
	if entry.Size, err = cursor.uint64(); err != nil {
		return 0, err
	}
	mtime, err := cursor.uint64()
	if err != nil {
		return 0, err
	}
	entry.MTimeNanos = int64(mtime)
	ctime, err := cursor.uint64()
	if err != nil {
		return 0, err
	}
	entry.CTimeNanos = int64(ctime)
	if entry.Nlink, err = cursor.uint32(); err != nil {
		return 0, err
	}
	if entry.HardlinkGroup, err = cursor.uint32(); err != nil {
		return 0, err
	}
	if entry.Name, err = cursor.lengthPrefixed(MaxNameBytes); err != nil {
		return 0, err
	}
	if entry.LinkName, err = cursor.lengthPrefixed(MaxLinkNameBytes); err != nil {
		return 0, err
	}
	if err = cursor.array(entry.ContentDigest[:]); err != nil {
		return 0, err
	}
	xattrCount, err := cursor.uint32()
	if err != nil {
		return 0, err
	}
	if xattrCount > 0 {
		if err := cursor.budget(uint64(xattrCount), xattrFixedBytes, MaxXattrsPerEntry, "extended attribute"); err != nil {
			return 0, err
		}
		entry.Xattrs = make([]Xattr, xattrCount)
		for index := range entry.Xattrs {
			if entry.Xattrs[index].Name, err = cursor.lengthPrefixed(MaxXattrNameBytes); err != nil {
				return 0, err
			}
			if entry.Xattrs[index].Value, err = cursor.lengthPrefixed(MaxXattrValueSize); err != nil {
				return 0, err
			}
		}
	}
	return cursor.uint32()
}

func decodeFrame(cursor *reader, frame *Frame) (err error) {
	if frame.PackIndex, err = cursor.uint32(); err != nil {
		return err
	}
	if frame.PackOffset, err = cursor.uint64(); err != nil {
		return err
	}
	if frame.CompressedLength, err = cursor.uint64(); err != nil {
		return err
	}
	if frame.UncompressedLength, err = cursor.uint64(); err != nil {
		return err
	}
	raw, err := cursor.byteValue()
	if err != nil {
		return err
	}
	if raw > 1 {
		return fmt.Errorf("%w: raw-blocks flag is not a boolean", ErrInvalid)
	}
	frame.RawBlocks = raw == 1
	frame.XXH64Lo32, err = cursor.uint32()
	return err
}

func decodeChunk(cursor *reader, chunk *ChunkRef) (err error) {
	if chunk.FrameIndex, err = cursor.uint32(); err != nil {
		return err
	}
	if chunk.InnerOffset, err = cursor.uint64(); err != nil {
		return err
	}
	if chunk.Length, err = cursor.uint64(); err != nil {
		return err
	}
	if err = cursor.array(chunk.SliceDigest[:]); err != nil {
		return err
	}
	extentCount, err := cursor.uint32()
	if err != nil {
		return err
	}
	if extentCount == 0 {
		return nil
	}
	if err := cursor.budget(uint64(extentCount), extentBytes, MaxExtentsPerChunk, "extent"); err != nil {
		return err
	}
	chunk.Extents = make([]Extent, extentCount)
	for index := range chunk.Extents {
		if chunk.Extents[index].Offset, err = cursor.uint64(); err != nil {
			return err
		}
		if chunk.Extents[index].Length, err = cursor.uint64(); err != nil {
			return err
		}
	}
	return nil
}

// reader is a fail-closed cursor over the sealed manifest body. Every read is
// bounds-checked against what is left; nothing wraps, nothing reslices past the
// end, and the caller never sees a partially filled value.
type reader struct {
	buf []byte
	at  int
}

func (r *reader) remaining() int { return len(r.buf) - r.at }

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > r.remaining() {
		return nil, fmt.Errorf("%w: manifest is truncated, needed %d bytes with %d left", ErrInvalid, n, r.remaining())
	}
	out := r.buf[r.at : r.at+n]
	r.at += n
	return out, nil
}

func (r *reader) byteValue() (byte, error) {
	raw, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return raw[0], nil
}

func (r *reader) uint32() (uint32, error) {
	raw, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func (r *reader) uint64() (uint64, error) {
	raw, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(raw), nil
}

// array fills a fixed-size destination. The bytes are copied rather than
// aliased so that no part of a decoded manifest keeps the input buffer alive or
// mutable underneath it.
func (r *reader) array(dst []byte) error {
	raw, err := r.take(len(dst))
	if err != nil {
		return err
	}
	copy(dst, raw)
	return nil
}

// lengthPrefixed reads a u32-prefixed raw byte string. The declared length is
// checked against the field's own bound before it is checked against the input,
// so an absurd prefix is refused by name rather than as a generic truncation.
// An empty string returns nil rather than an empty slice so that a decoded
// model compares equal to the model an encoder built with an absent field.
func (r *reader) lengthPrefixed(maximum int) ([]byte, error) {
	declared, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(declared) > uint64(maximum) {
		return nil, fmt.Errorf("%w: length-prefixed field of %d bytes exceeds its %d byte bound",
			ErrInvalid, declared, maximum)
	}
	if declared == 0 {
		return nil, nil
	}
	raw, err := r.take(int(declared))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}

// budget rejects a count before it is used to allocate: the records it promises
// must fit in the bytes that are actually left, and the count must be inside
// the format's own hard bound. Both checks matter — the byte budget stops a
// count that a small object could never back, and the hard bound stops a count
// that a legitimately large object could back but the format never permits.
func (r *reader) budget(count uint64, recordBytes int, hardLimit int, what string) error {
	if count > uint64(hardLimit) {
		return fmt.Errorf("%w: %s count %d exceeds the format bound of %d", ErrInvalid, what, count, hardLimit)
	}
	if count > uint64(r.remaining()/recordBytes) {
		return fmt.Errorf("%w: %s count %d cannot be backed by the %d bytes remaining",
			ErrInvalid, what, count, r.remaining())
	}
	return nil
}
