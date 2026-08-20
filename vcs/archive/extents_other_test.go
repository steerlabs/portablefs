//go:build !linux

package archive

import (
	"errors"
	"testing"
)

// TestScanFileExtentsIsUnsupported pins the off-Linux behaviour: the scanner
// fails closed by name rather than quietly claiming a file is fully allocated,
// so a caller that wants that answer has to ask for it with WholeFileExtents.
func TestScanFileExtentsIsUnsupported(t *testing.T) {
	if _, err := ScanFileExtents(nil, 4096); !errors.Is(err, ErrExtentScanUnsupported) {
		t.Fatalf("off-Linux scan returned %v", err)
	}
}
