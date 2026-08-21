package archiver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sort"
	"sync"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// Read-back verification is the archiver's half of the division of labour in
// identity-lifecycle-and-capacity.md section 2 step 3: the cell's trusted
// archiver proves the *content*, and the Manager independently proves the
// manifest and the object inventory before anything may be destroyed. Nothing
// is sealed until every chunk in the archive has been fetched back out of the
// store, decompressed, and matched against its manifest digest.

// verifyPolicy sizes the read-back sweep. The defaults keep the resident set
// small: at most streams * maxRangeBytes of compressed bytes in flight plus one
// decompressed frame per stream.
type verifyPolicy struct {
	streams       int
	maxRangeBytes uint64
	maxGapBytes   uint64
}

func (p verifyPolicy) withDefaults(chunkSize uint64) verifyPolicy {
	if p.streams <= 0 {
		p.streams = 4
	}
	if p.maxRangeBytes == 0 {
		p.maxRangeBytes = 16 << 20
	}
	// A frame is never split across ranges, so the range cap must be able to
	// hold the largest frame the configured chunk size can produce.
	if minimum := chunkSize * 2; p.maxRangeBytes < minimum {
		p.maxRangeBytes = minimum
	}
	if p.maxGapBytes == 0 {
		p.maxGapBytes = 1 << 20
	}
	return p
}

// verifyPackObjects proves every pack object the store now holds is the object
// the builder produced: the recorded size, and where the store carries one, the
// full-object CRC64NVME — the checksum the Manager will later re-check with a
// HeadObject of its own.
func verifyPackObjects(ctx context.Context, client *archivestore.Client, manifest *archive.Manifest, packs []uploadedPack) error {
	if len(packs) != len(manifest.Header.Packs) {
		return fmt.Errorf("%w: uploaded %d pack objects for a manifest naming %d", ErrInvalid, len(packs), len(manifest.Header.Packs))
	}
	for index, pack := range packs {
		recorded := manifest.Header.Packs[index]
		if pack.bytes != recorded.SizeBytes {
			return fmt.Errorf("%w: pack %d uploaded %d bytes for a manifest recording %d",
				ErrInvalid, index, pack.bytes, recorded.SizeBytes)
		}
		info, err := client.HeadObject(ctx, pack.key)
		if err != nil {
			return fmt.Errorf("archiver: head pack %d: %w", index, err)
		}
		if info.Size < 0 || uint64(info.Size) != recorded.SizeBytes {
			return fmt.Errorf("%w: pack %d is %d bytes in the store, %d in the manifest",
				ErrInvalid, index, info.Size, recorded.SizeBytes)
		}
		if !client.ChecksumsEnabled() {
			continue
		}
		want := archivestore.CRC64Hex(recorded.CRC64NVME)
		if info.CRC64NVMEHex == "" {
			return fmt.Errorf("%w: store declared full-object checksums but pack %d has none", ErrInvalid, index)
		}
		if info.CRC64NVMEHex != want {
			return fmt.Errorf("%w: pack %d checksum %s does not match the manifest's %s",
				ErrInvalid, index, info.CRC64NVMEHex, want)
		}
	}
	return nil
}

// sliceKey identifies one distinct stored byte range inside one frame. Content
// dedup means several entries can reference exactly the same bytes; verifying
// the range once is verifying every reference to it, and the key includes the
// digest so two references that disagree about what the bytes should be are
// never collapsed into one check.
type sliceKey struct {
	frame       uint32
	innerOffset uint64
	length      uint64
	digest      [32]byte
}

// verifyChunks re-fetches every stored byte of the archive and verifies every
// slice digest against the manifest.
func verifyChunks(ctx context.Context, source archive.PackSource, manifest *archive.Manifest, policy verifyPolicy) error {
	slices := make(map[uint32][]sliceKey, len(manifest.Frames))
	seen := make(map[sliceKey]struct{})
	for index := range manifest.Entries {
		for _, chunk := range manifest.Entries[index].Chunks {
			if !chunk.Stored() {
				continue
			}
			key := sliceKey{frame: chunk.FrameIndex, innerOffset: chunk.InnerOffset, length: chunk.Length, digest: chunk.SliceDigest}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			slices[key.frame] = append(slices[key.frame], key)
		}
	}
	if len(manifest.Frames) == 0 {
		if len(seen) != 0 {
			return fmt.Errorf("%w: chunks reference frames in a manifest with none", ErrInvalid)
		}
		return nil
	}

	wanted := make([]uint32, 0, len(manifest.Frames))
	for index := range manifest.Frames {
		wanted = append(wanted, uint32(index))
	}
	ranges, err := manifest.CoalesceFrames(wanted, archive.RangePolicy{
		MaxGapBytes:   policy.maxGapBytes,
		MaxRangeBytes: policy.maxRangeBytes,
	})
	if err != nil {
		return err
	}
	assignment, err := framesByRange(manifest, wanted, ranges)
	if err != nil {
		return err
	}

	verified, err := runRanges(ctx, source, manifest, ranges, assignment, slices, policy.streams)
	if err != nil {
		return err
	}
	if verified != len(seen) {
		return fmt.Errorf("%w: read-back verified %d of %d distinct stored slices", ErrInvalid, verified, len(seen))
	}
	return nil
}

// framesByRange assigns every frame to the coalesced range that contains it.
// Both lists are in pack-and-offset order, so one merge pass is enough, and a
// frame that lands in no range is a bug in the coalescer rather than something
// to fetch separately.
func framesByRange(manifest *archive.Manifest, frames []uint32, ranges []archive.ByteRange) ([][]uint32, error) {
	order := append([]uint32(nil), frames...)
	sort.Slice(order, func(i, j int) bool {
		left, right := manifest.Frames[order[i]], manifest.Frames[order[j]]
		if left.PackIndex != right.PackIndex {
			return left.PackIndex < right.PackIndex
		}
		return left.PackOffset < right.PackOffset
	})
	assignment := make([][]uint32, len(ranges))
	at := 0
	for _, index := range order {
		frame := manifest.Frames[index]
		for at < len(ranges) && !rangeContains(ranges[at], frame) {
			at++
		}
		if at >= len(ranges) {
			return nil, fmt.Errorf("%w: frame %d is covered by no read-back range", ErrInvalid, index)
		}
		assignment[at] = append(assignment[at], index)
	}
	return assignment, nil
}

func rangeContains(byteRange archive.ByteRange, frame archive.Frame) bool {
	return byteRange.PackIndex == frame.PackIndex &&
		frame.PackOffset >= byteRange.Offset &&
		frame.PackOffset+frame.CompressedLength <= byteRange.End()
}

// runRanges fetches the coalesced ranges with bounded concurrency and verifies
// every frame and slice inside each one. The first failure cancels the rest:
// one bad digest fails the archive, so there is nothing to learn from finishing.
func runRanges(ctx context.Context, source archive.PackSource, manifest *archive.Manifest,
	ranges []archive.ByteRange, assignment [][]uint32, slices map[uint32][]sliceKey, streams int) (int, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	work := make(chan int)
	var (
		group    sync.WaitGroup
		mutex    sync.Mutex
		verified int
		failure  error
	)
	fail := func(err error) {
		mutex.Lock()
		defer mutex.Unlock()
		if failure == nil {
			failure = err
			cancel()
		}
	}
	if streams > len(ranges) {
		streams = len(ranges)
	}
	for worker := 0; worker < streams; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range work {
				count, err := verifyRange(ctx, source, manifest, ranges[index], assignment[index], slices)
				if err != nil {
					fail(err)
					return
				}
				mutex.Lock()
				verified += count
				mutex.Unlock()
			}
		}()
	}
	for index := range ranges {
		select {
		case work <- index:
		case <-ctx.Done():
		}
	}
	close(work)
	group.Wait()
	if failure != nil {
		return 0, failure
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return verified, nil
}

func verifyRange(ctx context.Context, source archive.PackSource, manifest *archive.Manifest,
	byteRange archive.ByteRange, frames []uint32, slices map[uint32][]sliceKey) (int, error) {

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	payload, err := source.ReadPackRange(byteRange.PackIndex, byteRange.Offset, byteRange.Length)
	if err != nil {
		return 0, err
	}
	if uint64(len(payload)) != byteRange.Length {
		return 0, fmt.Errorf("%w: read-back returned %d of %d bytes", ErrInvalid, len(payload), byteRange.Length)
	}
	verified := 0
	for _, index := range frames {
		frame := manifest.Frames[index]
		start := frame.PackOffset - byteRange.Offset
		content, err := archive.DecodeFrame(frame, payload[start:start+frame.CompressedLength])
		if err != nil {
			return 0, fmt.Errorf("archiver: read-back of frame %d: %w", index, err)
		}
		for _, slice := range slices[index] {
			end := slice.innerOffset + slice.length
			if end < slice.innerOffset || end > uint64(len(content)) {
				return 0, fmt.Errorf("%w: read-back slice of frame %d runs past the frame", ErrInvalid, index)
			}
			digest := sha256.Sum256(content[slice.innerOffset:end])
			if subtle.ConstantTimeCompare(digest[:], slice.digest[:]) != 1 {
				return 0, fmt.Errorf("%w: read-back slice at frame %d offset %d does not match its manifest digest",
					ErrInvalid, index, slice.innerOffset)
			}
			verified++
		}
	}
	return verified, nil
}
