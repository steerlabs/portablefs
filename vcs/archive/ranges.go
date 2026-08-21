package archive

import (
	"fmt"
	"sort"
)

// ByteRange is one single-range GET against one pack object. The archive store
// offers no multi-range GET, so a set of needed frames becomes a list of these
// and the caller issues them one at a time or in parallel — roughly one stream
// per 85 to 90 MB/s of provisioned bandwidth. A range never spans two objects,
// because objects are the unit a GET names.
type ByteRange struct {
	PackIndex uint32
	Offset    uint64
	Length    uint64
}

// End is the exclusive end of the range within its pack.
func (r ByteRange) End() uint64 { return r.Offset + r.Length }

// RangePolicy is the arithmetic that turns wanted frames into requests. Both
// knobs trade transferred bytes against request count, and both have a right
// answer that depends on the deployment's bandwidth and request pricing, so
// neither is hardcoded.
type RangePolicy struct {
	// MaxGapBytes is how many unwanted bytes are worth swallowing to avoid an
	// extra request. Zero coalesces only frames that are exactly adjacent.
	MaxGapBytes uint64

	// MaxRangeBytes caps one request so that a large fetch can be spread over
	// parallel streams. Zero means no cap. A single frame is never split: a
	// frame is the unit that decompresses, so half of one is useless.
	MaxRangeBytes uint64
}

// CoalesceFrames turns a set of frame indices into the minimal list of
// single-range GETs that covers them under the policy. Frames are sorted into
// pack and offset order first, so a caller may pass them in any order and pass
// duplicates.
//
// The result is ordered, non-overlapping, and never spans packs. Every wanted
// frame is fully inside exactly one returned range.
func (m *Manifest) CoalesceFrames(frames []uint32, policy RangePolicy) ([]ByteRange, error) {
	if len(frames) == 0 {
		return nil, nil
	}
	wanted := make([]uint32, 0, len(frames))
	seen := make(map[uint32]struct{}, len(frames))
	for _, index := range frames {
		if index >= uint32(len(m.Frames)) {
			return nil, fmt.Errorf("%w: frame %d does not exist", ErrInvalid, index)
		}
		if _, duplicate := seen[index]; duplicate {
			continue
		}
		seen[index] = struct{}{}
		wanted = append(wanted, index)
	}
	sort.Slice(wanted, func(i, j int) bool {
		left, right := &m.Frames[wanted[i]], &m.Frames[wanted[j]]
		if left.PackIndex != right.PackIndex {
			return left.PackIndex < right.PackIndex
		}
		return left.PackOffset < right.PackOffset
	})

	out := make([]ByteRange, 0, len(wanted))
	for _, index := range wanted {
		frame := &m.Frames[index]
		next := ByteRange{
			PackIndex: frame.PackIndex,
			Offset:    frame.PackOffset,
			Length:    frame.CompressedLength,
		}
		if len(out) == 0 {
			out = append(out, next)
			continue
		}
		current := &out[len(out)-1]
		if current.PackIndex != next.PackIndex || next.Offset < current.End() {
			out = append(out, next)
			continue
		}
		gap := next.Offset - current.End()
		merged := next.End() - current.Offset
		if gap > policy.MaxGapBytes || (policy.MaxRangeBytes != 0 && merged > policy.MaxRangeBytes) {
			out = append(out, next)
			continue
		}
		current.Length = merged
	}
	return out, nil
}

// PrefetchRanges is the wake-prefetch read: every byte before the priority
// boundary, as one range per pack object. It is the whole point of the
// mtime-descending ordering — the most recently touched small files are the
// first bytes of the first pack, so a wake reads them in one sequential sweep
// with no seeking and no per-file request.
//
// MaxRangeBytes splits the sweep for parallel streams; MaxGapBytes is not
// consulted, because the prefetch region is contiguous by construction.
func (m *Manifest) PrefetchRanges(policy RangePolicy) []ByteRange {
	boundary := m.Header.Priority
	out := make([]ByteRange, 0, len(m.Header.Packs))
	for index := uint32(0); index < uint32(len(m.Header.Packs)); index++ {
		if index > boundary.PackIndex {
			break
		}
		length := m.Header.Packs[index].SizeBytes
		if index == boundary.PackIndex {
			length = boundary.PackOffset
		}
		if length == 0 {
			continue
		}
		out = appendSplit(out, index, length, policy.MaxRangeBytes)
	}
	return out
}

// appendSplit adds [0, length) of one pack as one range, or as several if a cap
// is set. Splitting the prefetch sweep is safe where splitting an arbitrary
// fetch is not: the caller decompresses the region as one concatenated stream,
// so a split that lands mid-frame is rejoined before anything decodes it.
func appendSplit(out []ByteRange, packIndex uint32, length, maxRange uint64) []ByteRange {
	if maxRange == 0 || length <= maxRange {
		return append(out, ByteRange{PackIndex: packIndex, Length: length})
	}
	for offset := uint64(0); offset < length; offset += maxRange {
		step := maxRange
		if remaining := length - offset; remaining < step {
			step = remaining
		}
		out = append(out, ByteRange{PackIndex: packIndex, Offset: offset, Length: step})
	}
	return out
}
