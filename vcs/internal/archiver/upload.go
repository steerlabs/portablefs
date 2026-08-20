package archiver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// uploader is the builder's pack sink: it turns the stream of whole zstd frames
// the builder writes into multipart uploads, one upload per pack object, and
// holds at most one part in memory per pack.
//
// Part boundaries are chosen on the builder's own write boundaries, and the
// builder writes exactly one whole frame per call, so every part contains whole
// frames — the format's requirement (pack-format.md, "S3 mechanics"). A part is
// flushed once the buffer has reached the configured part size, so every
// non-final part is at least that size and at most that size plus one frame,
// which keeps it inside S3's 5 MiB..5 GiB window with room to spare.
type uploader struct {
	ctx      context.Context
	client   *archivestore.Client
	volumeID string
	epoch    uint64
	attempt  string
	partSize int

	packs []uploadedPack
	open  *packStream
}

// uploadedPack is one completed pack object: the key this process derived and
// the compressed byte count it actually uploaded, which is checked against the
// manifest's own record of the pack size before anything is sealed.
type uploadedPack struct {
	key   string
	bytes uint64
}

func newUploader(ctx context.Context, client *archivestore.Client, config LaunchConfig, partSize uint64) (*uploader, error) {
	if partSize < archive.MinPartSizeBytes || partSize > MaxPartSizeBytes {
		return nil, fmt.Errorf("%w: part size %d is outside [%d, %d]",
			ErrInvalid, partSize, archive.MinPartSizeBytes, MaxPartSizeBytes)
	}
	return &uploader{
		ctx:      ctx,
		client:   client,
		volumeID: config.VolumeID,
		epoch:    config.AuthorityEpoch,
		attempt:  config.Attempt,
		partSize: int(partSize),
	}, nil
}

// MaxPartSizeBytes is the archiver's part-size ceiling. The format admits parts
// up to 5 GiB; the archiver keeps one part in memory, so the deployable range is
// the 8..64 MiB the contract names.
const MaxPartSizeBytes uint64 = 64 << 20

func (u *uploader) key(object string) (string, error) {
	return u.client.KeyFor(u.volumeID, u.epoch, u.attempt, object)
}

// OpenPack starts one pack object's upload. The builder opens packs in index
// order and closes each before opening the next, so exactly one upload is ever
// in flight.
func (u *uploader) OpenPack(index uint32) (io.WriteCloser, error) {
	if u.open != nil {
		return nil, fmt.Errorf("%w: pack %d opened while pack %d is still open", ErrInvalid, index, u.open.index)
	}
	if int(index) != len(u.packs) {
		return nil, fmt.Errorf("%w: pack %d opened out of order after %d packs", ErrInvalid, index, len(u.packs))
	}
	key, err := u.key(packObjectName(int(index)))
	if err != nil {
		return nil, err
	}
	stream := &packStream{uploader: u, index: index, key: key}
	u.open = stream
	return stream, nil
}

// abort discards an upload that is still in flight. It runs on every failure
// path so a failed archive leaves no partial multipart upload behind for the
// store's lifecycle rules to clean up later.
func (u *uploader) abort() {
	if u.open == nil {
		return
	}
	u.open.abort()
	u.open = nil
}

type packStream struct {
	uploader *uploader
	index    uint32
	key      string
	uploadID string
	buffer   []byte
	parts    []archivestore.UploadedPart
	written  uint64
	done     bool
}

func (p *packStream) Write(payload []byte) (int, error) {
	if p.done {
		return 0, fmt.Errorf("%w: pack %d was written after it was closed", ErrInvalid, p.index)
	}
	p.buffer = append(p.buffer, payload...)
	p.written += uint64(len(payload))
	if len(p.buffer) >= p.uploader.partSize {
		if err := p.flushPart(); err != nil {
			return 0, err
		}
	}
	return len(payload), nil
}

func (p *packStream) Close() error {
	if p.done {
		return nil
	}
	p.done = true
	defer func() { p.uploader.open = nil }()
	if len(p.buffer) > 0 {
		if err := p.flushPart(); err != nil {
			return err
		}
	}
	if len(p.parts) == 0 {
		// The builder never opens a pack it does not write a frame into; an
		// empty upload would complete into a zero-byte object that no frame
		// references, so it is refused rather than sealed.
		return fmt.Errorf("%w: pack %d has no content", ErrInvalid, p.index)
	}
	if _, err := p.uploader.client.CompleteMultipartUpload(p.uploader.ctx, p.key, p.uploadID, p.parts); err != nil {
		return fmt.Errorf("archiver: complete pack %d: %w", p.index, err)
	}
	p.uploader.packs = append(p.uploader.packs, uploadedPack{key: p.key, bytes: p.written})
	p.uploadID = ""
	return nil
}

func (p *packStream) flushPart() error {
	if err := p.ensureUpload(); err != nil {
		return err
	}
	number := len(p.parts) + 1
	if number > archivestore.MaxPartNumber {
		return fmt.Errorf("%w: pack %d needs more than %d parts", ErrInvalid, p.index, archivestore.MaxPartNumber)
	}
	checksum := ""
	if p.uploader.client.ChecksumsEnabled() {
		checksum = archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(p.buffer))
	}
	part, err := p.uploader.client.UploadPart(p.uploader.ctx, p.key, p.uploadID, number,
		archivestore.PartBodyFromBytes(p.buffer), checksum)
	if err != nil {
		return fmt.Errorf("archiver: upload pack %d part %d: %w", p.index, number, err)
	}
	p.parts = append(p.parts, part)
	// The part body was fully consumed, retries included, before UploadPart
	// returned, so the buffer's storage is free to be reused.
	p.buffer = p.buffer[:0]
	return nil
}

func (p *packStream) ensureUpload() error {
	if p.uploadID != "" {
		return nil
	}
	uploadID, err := p.uploader.client.CreateMultipartUpload(p.uploader.ctx, p.key,
		archivestore.CreateMultipartOptions{FullObjectChecksum: p.uploader.client.ChecksumsEnabled()})
	if err != nil {
		return fmt.Errorf("archiver: start pack %d upload: %w", p.index, err)
	}
	p.uploadID = uploadID
	return nil
}

func (p *packStream) abort() {
	if p.uploadID == "" {
		return
	}
	// The abort runs on a failure path where the caller's context may already
	// be cancelled; a background context keeps the cleanup from being skipped
	// for that reason alone.
	_ = p.uploader.client.AbortMultipartUpload(context.WithoutCancel(p.uploader.ctx), p.key, p.uploadID)
	p.uploadID = ""
}

// putManifest writes the manifest object as a conditional create.
//
// A lost conditional create means an object already exists at this attempt's
// manifest key, which happens exactly when a previous run of this same attempt
// uploaded it and then died before writing its result record. That is treated
// as "already uploaded" only after the stored object is proved byte-identical
// to the one this run built — never assumed, because a manifest that differs is
// a different tree wearing this attempt's name.
func putManifest(ctx context.Context, client *archivestore.Client, key string, payload []byte) (string, error) {
	checksum := archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(payload))
	options := archivestore.PutOptions{IfNoneMatch: true}
	if client.ChecksumsEnabled() {
		options.ChecksumCRC64NVMEHex = checksum
	}
	_, err := client.PutObject(ctx, key, payload, options)
	if err == nil {
		return checksum, nil
	}
	if !errors.Is(err, archivestore.ErrPreconditionFailed) {
		return "", fmt.Errorf("archiver: upload manifest: %w", err)
	}
	if err := proveObjectIdentical(ctx, client, key, payload, checksum); err != nil {
		return "", fmt.Errorf("archiver: manifest key %q already holds a different object: %w", key, err)
	}
	return checksum, nil
}

// proveObjectIdentical downloads an existing object and proves it is exactly
// the bytes the caller holds: the size and, where the store carries one, the
// full-object checksum first, then the bytes themselves.
func proveObjectIdentical(ctx context.Context, client *archivestore.Client, key string, payload []byte, checksumHex string) error {
	info, err := client.HeadObject(ctx, key)
	if err != nil {
		return err
	}
	if info.Size != int64(len(payload)) {
		return fmt.Errorf("%w: stored object is %d bytes, this attempt built %d", ErrInvalid, info.Size, len(payload))
	}
	if client.ChecksumsEnabled() {
		if info.CRC64NVMEHex == "" {
			return fmt.Errorf("%w: store declared full-object checksums but returned none", ErrInvalid)
		}
		if info.CRC64NVMEHex != checksumHex {
			return fmt.Errorf("%w: stored object checksum %s does not match %s", ErrInvalid, info.CRC64NVMEHex, checksumHex)
		}
	}
	stored, err := client.GetObject(ctx, key, int64(len(payload))+1)
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, payload) {
		return fmt.Errorf("%w: stored object differs byte for byte", ErrInvalid)
	}
	return nil
}

// packSource serves compressed pack ranges out of the store for the read-back
// verification. It is the archive package's PackSource over ranged GETs, with
// every range length bounded before a byte is read.
type packSource struct {
	ctx      context.Context
	client   *archivestore.Client
	keys     []string
	maxBytes uint64
}

func (s *packSource) ReadPackRange(index uint32, offset, length uint64) ([]byte, error) {
	if int(index) >= len(s.keys) {
		return nil, fmt.Errorf("%w: pack %d does not exist", ErrInvalid, index)
	}
	if length == 0 || length > s.maxBytes {
		return nil, fmt.Errorf("%w: pack range of %d bytes is outside (0, %d]", ErrInvalid, length, s.maxBytes)
	}
	if offset > uint64(1<<62) || length > uint64(1<<62) {
		return nil, fmt.Errorf("%w: pack range does not fit a signed offset", ErrInvalid)
	}
	stream, err := s.client.GetObjectRange(s.ctx, s.keys[index], int64(offset), int64(length))
	if err != nil {
		return nil, err
	}
	defer func() { _ = stream.Close() }()
	payload := make([]byte, length)
	if _, err := io.ReadFull(stream, payload); err != nil {
		return nil, fmt.Errorf("archiver: read pack %d range [%d, %d): %w", index, offset, offset+length, err)
	}
	return payload, nil
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
