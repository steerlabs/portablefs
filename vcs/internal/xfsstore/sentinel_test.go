package xfsstore

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
)

// TestSentinelsCarryTheirErrno is the regression for sentinels that reached
// clients as EIO. Each one now carries the errno it means, so the shared wire
// mapping classifies it without knowing this package exists and without
// looking at any message text.
//
// EIO specifically must never be the answer for any of these: a real storage
// EIO fences the volume and ends the process, and a client that receives the
// same errno for "this inode is a FIFO" cannot tell the two apart.
func TestSentinelsCarryTheirErrno(t *testing.T) {
	cases := []struct {
		err   error
		errno syscall.Errno
		wire  int32
	}{
		{ErrUnsupportedPlatform, syscall.ENOSYS, errnos.ENOSYS},
		{ErrNotXFS, syscall.ENOTSUP, errnos.EOPNOTSUPP},
		{ErrStaleObject, syscall.ESTALE, errnos.ESTALE},
		{ErrStaleOpen, syscall.ESTALE, errnos.ESTALE},
		{ErrClosed, syscall.ESTALE, errnos.ESTALE},
		{ErrFenced, syscall.EIO, errnos.EIO},
		// mv(1) falls back to copy+unlink only on EXDEV.
		{ErrWrongDevice, syscall.EXDEV, errnos.EXDEV},
		{ErrProjectIsolation, syscall.EPERM, errnos.EPERM},
		// stat(2) on a FIFO in the tree, and open(2) of a symlink object.
		{ErrForbiddenType, syscall.EPERM, errnos.EPERM},
		// getfattr -n trusted.x must say "Operation not supported".
		{ErrForbiddenXattr, syscall.ENOTSUP, errnos.EOPNOTSUPP},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.errno) {
			t.Errorf("%v does not carry %v", tc.err, tc.errno)
		}
		var errno syscall.Errno
		if !errors.As(tc.err, &errno) || errno != tc.errno {
			t.Errorf("errors.As(%v) = %v, want %v", tc.err, errno, tc.errno)
		}
		if got := errnos.Of(tc.err); got != tc.wire {
			t.Errorf("errnos.Of(%v) = %d, want %d", tc.err, got, tc.wire)
		}
		wrapped := fmt.Errorf("operation failed: %w", tc.err)
		if got := errnos.Of(wrapped); got != tc.wire {
			t.Errorf("errnos.Of(wrapped %v) = %d, want %d", tc.err, got, tc.wire)
		}
		if !errors.Is(wrapped, tc.err) {
			t.Errorf("wrapping lost the sentinel identity of %v", tc.err)
		}
	}
}

// TestSentinelsStayDistinct guards the cost of carrying an errno: two
// sentinels that mean different things must not become interchangeable just
// because they answer with the same errno.
func TestSentinelsStayDistinct(t *testing.T) {
	if errors.Is(ErrStaleObject, ErrStaleOpen) || errors.Is(ErrClosed, ErrStaleObject) {
		t.Fatal("ESTALE sentinels collapsed into one another")
	}
	if errors.Is(ErrForbiddenType, ErrProjectIsolation) {
		t.Fatal("EPERM sentinels collapsed into one another")
	}
	if errors.Is(ErrNotXFS, ErrForbiddenXattr) {
		t.Fatal("ENOTSUP sentinels collapsed into one another")
	}
}

// TestUncertainOutcomeCarriesItsCause keeps the marker errno-free. If it
// carried EIO, every uncertain outcome would look like the storage failure
// that fences the volume and takes the process down with it.
func TestUncertainOutcomeCarriesItsCause(t *testing.T) {
	err := outcomeUncertain(syscall.ENOSPC)
	if !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatal("uncertain marker lost")
	}
	if got := errnos.Of(err); got != errnos.ENOSPC {
		t.Fatalf("errnos.Of(uncertain ENOSPC) = %d, want ENOSPC %d", got, errnos.ENOSPC)
	}
	var errno syscall.Errno
	if errors.As(ErrOutcomeUncertain, &errno) {
		t.Fatalf("the uncertain marker carries errno %v on its own", errno)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a causeless uncertain outcome was accepted")
		}
	}()
	_ = outcomeUncertain(nil)
}
