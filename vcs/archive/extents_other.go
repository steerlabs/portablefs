//go:build !linux

package archive

import "os"

// ScanFileExtents is unavailable off Linux. The archiver runs only on the
// storage cell's Linux host; this exists so that every consumer of the format
// library compiles and its tests run on a developer's machine, and it fails
// closed rather than pretending a file is fully allocated. A caller that wants
// that answer asks for it by name with WholeFileExtents.
func ScanFileExtents(_ *os.File, _ int64) ([]Extent, error) {
	return nil, ErrExtentScanUnsupported
}
