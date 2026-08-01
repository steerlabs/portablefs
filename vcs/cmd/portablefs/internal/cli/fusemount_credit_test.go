package cli

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestFuseCreditErrnoMatchesTheDaemonClassification pins the FUSE frontend's
// half of the two-frontend agreement. The same refusal must look the same to an
// application whichever frontend it came through, and the ENOSPC/EIO split is
// the part that changes what an application DOES: ENOSPC says "this store can
// never fit it", so a program frees space; EIO says "the far end stopped
// answering", so a program retries or reports I/O failure. A stalled uplink is
// the second thing, never the first.
func TestFuseCreditErrnoMatchesTheDaemonClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want syscall.Errno
	}{
		{"operation larger than the data lane", writeback.ErrNoSpace, syscall.ENOSPC},
		{"stalled uplink", writeback.ErrUplinkStalled, syscall.EIO},
		{"wrapped stalled uplink", fmt.Errorf("write d/f: %w", writeback.ErrUplinkStalled), syscall.EIO},
		{"wrapped no space", fmt.Errorf("write d/f: %w", writeback.ErrNoSpace), syscall.ENOSPC},
		{"cancelled request", context.Canceled, syscall.EINTR},
		{"expired request", context.DeadlineExceeded, syscall.EINTR},
		{"engine fenced", writeback.ErrFenced, syscall.EIO},
		{"unclassified", errors.New("something else"), syscall.EIO},
	}
	for _, tc := range cases {
		if got := creditErrno(tc.err); got != tc.want {
			t.Errorf("creditErrno(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
