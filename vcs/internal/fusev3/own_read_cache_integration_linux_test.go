//go:build linux

package fusev3

import (
	"bytes"
	"os"
	"testing"
)

func TestSameMountWritesInvalidateLiveAndReopenedCachedReaders(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "live"
		if closed {
			name = "closed-before-write"
		}
		t.Run(name, func(t *testing.T) {
			f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
			old, next := bytes.Repeat([]byte("a"), 4096), bytes.Repeat([]byte("b"), 4096)
			mustWrite(t, f.join(0, "cached"), old, 0600)
			f.waitForDelegationReleases(t)
			reader := mustOpenFile(t, f.join(0, "cached"), os.O_RDONLY, 0)
			defer reader.Close()
			if got := readExactlyAt(t, reader, 0, len(old), "prime cached pages"); !bytes.Equal(got, old) {
				t.Fatal("initial data")
			}
			if closed {
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			writer := mustOpenFile(t, f.join(0, "cached"), os.O_WRONLY, 0)
			if _, err := writer.WriteAt(next, 0); err != nil {
				t.Fatal(err)
			}
			if closed {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				// Release is an implicit local stream advance. Reopening cannot rely on
				// receiving a CONTROL invalidation for the writer's own release.
				f.waitForDelegationReleases(t)
				reader = mustOpenFile(t, f.join(0, "cached"), os.O_RDONLY, 0)
				defer reader.Close()
			}
			if got := readExactlyAt(t, reader, 0, len(next), "read after successful local write"); !bytes.Equal(got, next) {
				t.Fatal("stale cached folio after write")
			}
			if !closed {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if f.mounts[0].delegations.LossSequence() != 0 {
				t.Fatal("write escaped invalidation by losing delegation")
			}
		})
	}
}
