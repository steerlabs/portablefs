package archive

import (
	"errors"
	"testing"
)

// TestCoalesceCoversEveryWantedFrame is the property the hydrator depends on:
// however the ranges are merged or split, every frame it asked for is fully
// inside exactly one returned range, no range spans two pack objects, and the
// ranges do not overlap. A frame that fell into a gap would be a read that
// silently returned the wrong bytes.
func TestCoalesceCoversEveryWantedFrame(t *testing.T) {
	policies := []RangePolicy{
		{},
		{MaxGapBytes: 64},
		{MaxGapBytes: 1 << 20},
		{MaxGapBytes: 1 << 20, MaxRangeBytes: 256},
		{MaxRangeBytes: 1},
	}
	for seed := uint64(1); seed <= 16; seed++ {
		manifest, _ := buildTree(t, seed)
		if len(manifest.Frames) == 0 {
			continue
		}
		rng := newRNG(seed * 31)
		wanted := make([]uint32, 0, len(manifest.Frames))
		for index := range manifest.Frames {
			if rng.intn(2) == 0 {
				wanted = append(wanted, uint32(index))
			}
		}
		if len(wanted) == 0 {
			wanted = append(wanted, 0)
		}
		// Duplicates and reverse order must be tolerated.
		wanted = append(wanted, wanted[0], wanted[len(wanted)-1])
		for _, policy := range policies {
			ranges, err := manifest.CoalesceFrames(wanted, policy)
			if err != nil {
				t.Fatalf("seed %d: coalesce: %v", seed, err)
			}
			for index := 1; index < len(ranges); index++ {
				previous, current := ranges[index-1], ranges[index]
				if current.PackIndex < previous.PackIndex {
					t.Fatalf("seed %d: ranges are out of pack order", seed)
				}
				if current.PackIndex == previous.PackIndex && current.Offset < previous.End() {
					t.Fatalf("seed %d: ranges overlap", seed)
				}
			}
			for _, frameIndex := range wanted {
				frame := manifest.Frames[frameIndex]
				covered := false
				for _, byteRange := range ranges {
					if byteRange.PackIndex == frame.PackIndex &&
						byteRange.Offset <= frame.PackOffset &&
						byteRange.End() >= frame.PackOffset+frame.CompressedLength {
						covered = true
					}
				}
				if !covered {
					t.Fatalf("seed %d policy %+v: frame %d is not covered by any range",
						seed, policy, frameIndex)
				}
			}
		}
	}
}

// TestCoalesceMergesOnlyWithinThePolicy proves the two knobs do what they say:
// adjacent frames always merge, a gap merges only when it is worth swallowing,
// and a merge never produces a range past the cap.
func TestCoalesceMergesOnlyWithinThePolicy(t *testing.T) {
	manifest := &Manifest{
		Header: Header{
			FormatVersion:  FormatVersion,
			ChunkSizeBytes: DefaultChunkSizeBytes,
			Packs:          []PackRef{{SizeBytes: 1000}, {SizeBytes: 500}},
		},
		Frames: []Frame{
			{PackIndex: 0, PackOffset: 0, CompressedLength: 100},
			{PackIndex: 0, PackOffset: 100, CompressedLength: 100},
			{PackIndex: 0, PackOffset: 400, CompressedLength: 100},
			{PackIndex: 1, PackOffset: 0, CompressedLength: 100},
		},
	}
	all := []uint32{0, 1, 2, 3}

	adjacent, err := manifest.CoalesceFrames(all, RangePolicy{})
	if err != nil {
		t.Fatalf("coalesce: %v", err)
	}
	if len(adjacent) != 3 {
		t.Fatalf("with no gap allowance the result is %v, want three ranges", adjacent)
	}
	if adjacent[0] != (ByteRange{PackIndex: 0, Offset: 0, Length: 200}) {
		t.Fatalf("adjacent frames did not merge: %+v", adjacent[0])
	}
	if adjacent[2].PackIndex != 1 {
		t.Fatalf("a range spanned two pack objects")
	}

	merged, err := manifest.CoalesceFrames(all, RangePolicy{MaxGapBytes: 200})
	if err != nil {
		t.Fatalf("coalesce: %v", err)
	}
	if len(merged) != 2 || merged[0].Length != 500 {
		t.Fatalf("a 200 byte gap was not swallowed: %+v", merged)
	}

	capped, err := manifest.CoalesceFrames(all, RangePolicy{MaxGapBytes: 200, MaxRangeBytes: 300})
	if err != nil {
		t.Fatalf("coalesce: %v", err)
	}
	for _, byteRange := range capped {
		if byteRange.Length > 300 {
			t.Fatalf("a range of %d bytes exceeds the cap", byteRange.Length)
		}
	}

	if _, err := manifest.CoalesceFrames([]uint32{9}, RangePolicy{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a frame that does not exist was coalesced")
	}
	if ranges, err := manifest.CoalesceFrames(nil, RangePolicy{}); err != nil || ranges != nil {
		t.Fatalf("coalescing nothing produced %v (%v)", ranges, err)
	}
}

// TestPrefetchRangesHonorSingleRangeGets proves the wake read is expressible as
// one contiguous request per pack object, which is the whole reason the pack
// ordering exists, and that a cap splits it without ever producing a gap.
func TestPrefetchRangesHonorSingleRangeGets(t *testing.T) {
	manifest := &Manifest{
		Header: Header{
			FormatVersion:  FormatVersion,
			ChunkSizeBytes: DefaultChunkSizeBytes,
			Packs:          []PackRef{{SizeBytes: 1000}, {SizeBytes: 800}, {SizeBytes: 600}},
			Priority:       PriorityBoundary{PackIndex: 1, PackOffset: 300},
		},
	}
	ranges := manifest.PrefetchRanges(RangePolicy{})
	if len(ranges) != 2 {
		t.Fatalf("prefetch produced %d ranges, want one per covered pack: %+v", len(ranges), ranges)
	}
	if ranges[0] != (ByteRange{PackIndex: 0, Offset: 0, Length: 1000}) {
		t.Fatalf("first prefetch range is %+v", ranges[0])
	}
	if ranges[1] != (ByteRange{PackIndex: 1, Offset: 0, Length: 300}) {
		t.Fatalf("second prefetch range is %+v", ranges[1])
	}

	split := manifest.PrefetchRanges(RangePolicy{MaxRangeBytes: 256})
	total := uint64(0)
	position := map[uint32]uint64{}
	for _, byteRange := range split {
		if byteRange.Length > 256 {
			t.Fatalf("a split range of %d bytes exceeds the cap", byteRange.Length)
		}
		if byteRange.Offset != position[byteRange.PackIndex] {
			t.Fatalf("split ranges leave a gap in pack %d", byteRange.PackIndex)
		}
		position[byteRange.PackIndex] = byteRange.End()
		total += byteRange.Length
	}
	if total != 1300 {
		t.Fatalf("split prefetch covers %d bytes, want 1300", total)
	}

	manifest.Header.Priority = PriorityBoundary{}
	if ranges := manifest.PrefetchRanges(RangePolicy{}); len(ranges) != 0 {
		t.Fatalf("an origin boundary produced %d ranges", len(ranges))
	}

	manifest.Header.Priority = PriorityBoundary{PackIndex: 3}
	ranges = manifest.PrefetchRanges(RangePolicy{})
	if len(ranges) != 3 {
		t.Fatalf("a whole-archive boundary produced %d ranges", len(ranges))
	}
}

// TestFramesForEntry proves the hydrator's per-file frame set is deduplicated,
// ordered, and skips the chunks that live nowhere.
func TestFramesForEntry(t *testing.T) {
	manifest, _ := sampleManifest(t)
	frames, err := manifest.FramesForEntry(3)
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	// The sparse file is larger than one chunk, so it gets one frame per stored
	// chunk; its middle chunk lies wholly inside a hole and contributes none.
	if len(manifest.Entries[3].Chunks) != 3 {
		t.Fatalf("the sparse file has %d chunks, want 3", len(manifest.Entries[3].Chunks))
	}
	if len(frames) != 2 {
		t.Fatalf("the sparse file spans %d frames, want 2 of its 3 chunks", len(frames))
	}
	for index := 1; index < len(frames); index++ {
		if frames[index] <= frames[index-1] {
			t.Fatalf("frames are not in ascending order")
		}
	}
	if _, err := manifest.FramesForEntry(uint32(len(manifest.Entries))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("frames resolved for an entry that does not exist")
	}
}
