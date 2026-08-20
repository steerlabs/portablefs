package archive

import (
	"errors"
	"fmt"
	"os"
)

// The extent scanner is the one place the format touches a real filesystem, and
// it lives only on the export side. The interface is portable so that the
// builder, the tests, and every consumer compile and run everywhere; the
// implementation that asks a kernel where the holes are is Linux-only, because
// SEEK_DATA and SEEK_HOLE are what the archiver's host offers and no honest
// portable equivalent exists.

// ErrExtentScanUnsupported reports that this platform cannot report where a
// file's holes are. A caller that gets it must decide deliberately: treat the
// file as fully allocated with WholeFileExtents, which is always correct but
// stores holes as zeros, or refuse. The scanner never silently chooses for it,
// because silently storing a sparse file as an allocated one turns a cheap
// archive into an expensive one and changes what a restore allocates.
var ErrExtentScanUnsupported = errors.New("archive: extent scanning is not supported on this platform")

// ExtentScanner reports a file's allocated regions over logical offsets. The
// result is strictly increasing, non-empty, non-adjacent, and inside
// [0, size) — the same canonical shape a manifest carries.
type ExtentScanner func(file *os.File, size int64) ([]Extent, error)

// WholeFileExtents is the extent map of a file with no holes: one extent
// covering everything, or none at all for an empty file. It is the portable
// fallback and the correct answer for any filesystem that does not implement
// sparseness.
func WholeFileExtents(_ *os.File, size int64) ([]Extent, error) {
	if size < 0 {
		return nil, fmt.Errorf("%w: negative file size %d", ErrInvalid, size)
	}
	if size == 0 {
		return nil, nil
	}
	return []Extent{{Offset: 0, Length: uint64(size)}}, nil
}

// normalizeExtents merges adjacent runs and enforces the canonical shape on
// whatever a scanner produced. A kernel is free to report two data regions that
// touch; the format is not, because one byte range must have one
// representation.
func normalizeExtents(extents []Extent, size uint64) ([]Extent, error) {
	out := make([]Extent, 0, len(extents))
	for index, extent := range extents {
		if extent.Length == 0 {
			continue
		}
		end, ok := checkedRange(extent.Offset, extent.Length, size)
		if !ok {
			return nil, fmt.Errorf("%w: scanned extent %d runs past the file size %d", ErrInvalid, index, size)
		}
		if len(out) > 0 {
			previous := &out[len(out)-1]
			previousEnd := previous.Offset + previous.Length
			if extent.Offset < previousEnd {
				return nil, fmt.Errorf("%w: scanned extent %d overlaps its predecessor", ErrInvalid, index)
			}
			if extent.Offset == previousEnd {
				previous.Length = end - previous.Offset
				continue
			}
		}
		out = append(out, extent)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
