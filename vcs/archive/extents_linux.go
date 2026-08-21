package archive

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ScanFileExtents reports a file's allocated regions by alternating SEEK_DATA
// and SEEK_HOLE from the front of the file. It is the export-side scanner whose
// output becomes the manifest's extent maps, and through them the sparseness a
// restore reproduces by punching holes.
//
// The walk is deliberately literal. SEEK_DATA returns the next offset at or
// after its argument that holds data, or ENXIO once there is none left;
// SEEK_HOLE returns the next hole, and at end of file returns the size, which
// terminates every loop naturally. A filesystem is permitted to under-report
// holes — returning "all data" is always a legal answer — so a file this
// scanner calls fully allocated may still be sparse underneath. That direction
// is safe: it costs storage, never correctness. The opposite direction, a
// filesystem claiming a hole where data lives, would be a kernel bug, and the
// slice digests would catch it at the first read-back.
//
// The size is taken from the caller rather than re-stated inside the loop so
// that the scan describes exactly the file the caller measured; a concurrent
// extension cannot make the extent map exceed the size the manifest records.
// The archiver runs against a read-only bind of a quiesced volume, so there is
// no writer to race, but the scan is written not to depend on that.
func ScanFileExtents(file *os.File, size int64) ([]Extent, error) {
	if file == nil {
		return nil, fmt.Errorf("%w: extent scan needs an open file", ErrInvalid)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: negative file size %d", ErrInvalid, size)
	}
	if size == 0 {
		return nil, nil
	}
	var extents []Extent
	for offset := int64(0); offset < size; {
		dataStart, err := unix.Seek(int(file.Fd()), offset, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		if err != nil {
			// A filesystem without hole awareness reports EINVAL for these
			// whences. Saying so by name lets the caller fall back to
			// WholeFileExtents deliberately instead of guessing.
			if errors.Is(err, unix.EINVAL) {
				return nil, ErrExtentScanUnsupported
			}
			return nil, fmt.Errorf("archive: seek to data at %d: %w", offset, err)
		}
		if dataStart >= size {
			break
		}
		dataEnd, err := unix.Seek(int(file.Fd()), dataStart, unix.SEEK_HOLE)
		if err != nil {
			return nil, fmt.Errorf("archive: seek to hole at %d: %w", dataStart, err)
		}
		if dataEnd > size {
			dataEnd = size
		}
		if dataEnd <= dataStart {
			return nil, fmt.Errorf("%w: extent scan made no progress at %d", ErrInvalid, dataStart)
		}
		if len(extents) >= MaxExtentsPerChunk*MaxChunks {
			return nil, fmt.Errorf("%w: file has more extents than the format can carry", ErrInvalid)
		}
		extents = append(extents, Extent{Offset: uint64(dataStart), Length: uint64(dataEnd - dataStart)})
		offset = dataEnd
	}
	return normalizeExtents(extents, uint64(size))
}
