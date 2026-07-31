package clientcore

import (
	"context"
	"fmt"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestWriteAdmissionSurfacesNoSpaceAsENOSPC pins the write-admission errno
// surface for a definite bounded-resource refusal. The engine answers a full
// local store with writeback.ErrNoSpace instead of blocking on the uplink;
// every write lane must translate that into ENOSPC (a definite, POSIX-correct
// "the store is full") and never into the EIO default or an operation-timeout
// shape. Wrapping is deliberate: engine errors reach these lanes annotated.
func TestWriteAdmissionSurfacesNoSpaceAsENOSPC(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"bare", writeback.ErrNoSpace},
		{"wrapped once", fmt.Errorf("write %q: %w", "d/f", writeback.ErrNoSpace)},
		{"wrapped twice", fmt.Errorf("append: %w", fmt.Errorf("engine: %w", writeback.ErrNoSpace))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st := statusErr(tc.err); st != fsproto.ENOSPC {
				t.Fatalf("statusErr(%v) = %d, want ENOSPC (%d)", tc.err, st, fsproto.ENOSPC)
			}
		})
	}
	// Sanity: an unclassified engine failure still degrades to EIO, so this
	// mapping is a real classification and not a blanket rewrite.
	if st := statusErr(context.DeadlineExceeded); st != fsproto.EIO {
		t.Fatalf("statusErr(deadline exceeded) = %d, want EIO", st)
	}
}
