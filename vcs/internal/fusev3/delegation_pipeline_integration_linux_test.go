//go:build linux

package fusev3

import (
	"bytes"
	"os"
	"testing"
)

// Overlapping retained records must reach XFS in acceptance order even when
// their transport requests are in flight together. The peer read breaks the
// delegation and observes the fully applied cut.
func TestDelegationPipelinePreservesOverlappingMountedWrites(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	file := mustOpenFile(t, f.join(0, "pipeline-overlap"), os.O_CREATE|os.O_RDWR, 0600)
	defer file.Close()
	const size = 5 << 20
	want := make([]byte, size)
	for _, w := range []struct {
		off, n int
		value  byte
	}{{0, size, 0x31}, {12345, 2 << 20, 0x52}, {(1 << 20) + 37, 3 << 20, 0x73}, {size - 997, 997, 0x94}} {
		data := bytes.Repeat([]byte{w.value}, w.n)
		if n, err := file.WriteAt(data, int64(w.off)); err != nil || n != len(data) {
			t.Fatalf("buffered write=%d %v", n, err)
		}
		copy(want[w.off:], data)
	}
	requireContent(t, f.join(1, "pipeline-overlap"), want, "peer observes ordered buffered chunks")
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	requireContent(t, f.join(0, "pipeline-overlap"), want, "holder after pipeline break")
}
