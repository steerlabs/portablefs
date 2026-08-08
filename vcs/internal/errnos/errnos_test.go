package errnos

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

// TestErrnoIdentityBeatsPortableAliases pins the ordering that the previous
// mapping got wrong. syscall.ENOTEMPTY satisfies os.ErrExist and syscall.EACCES
// satisfies os.ErrPermission, so an alias tested first answers EEXIST for a
// non-empty rmdir and EPERM for a permission denial - and rmdir(1) then prints
// "File exists".
func TestErrnoIdentityBeatsPortableAliases(t *testing.T) {
	cases := []struct {
		err  error
		want int32
	}{
		{syscall.ENOTEMPTY, ENOTEMPTY},
		{syscall.EACCES, EACCES},
		{syscall.EEXIST, EEXIST},
		{syscall.EPERM, EPERM},
		{syscall.ENOENT, ENOENT},
		{fmt.Errorf("rmdir d: %w", syscall.ENOTEMPTY), ENOTEMPTY},
	}
	for _, tc := range cases {
		if got := Of(tc.err); got != tc.want {
			t.Errorf("Of(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

// TestMappingIsByIdentityNotByMessage is the regression that matters most: the
// mapping used to read err.Error() and match substrings. Text is not an
// interface. An error that says "not empty" while carrying no errno must not
// be classified as ENOTEMPTY, and an errno-carrying error must be classified
// even when its text says something else entirely.
func TestMappingIsByIdentityNotByMessage(t *testing.T) {
	if got := Of(errors.New("directory not empty")); got != EIO {
		t.Errorf("Of(text-only \"directory not empty\") = %d, want EIO %d", got, EIO)
	}
	if got := Of(errors.New("not a directory")); got != EIO {
		t.Errorf("Of(text-only \"not a directory\") = %d, want EIO %d", got, EIO)
	}
	if got := Of(errors.New("invalid argument")); got != EIO {
		t.Errorf("Of(text-only \"invalid argument\") = %d, want EIO %d", got, EIO)
	}
	quiet := fmt.Errorf("cross-device link is fine actually: %w", syscall.EXDEV)
	if got := Of(quiet); got != EXDEV {
		t.Errorf("Of(EXDEV with unrelated text) = %d, want EXDEV %d", got, EXDEV)
	}
}

// TestSentinelCarriesItsErrno covers the declaration side of the same rule:
// a package that needs a named failure to reach a client as a specific errno
// declares the errno with the error instead of hoping a text match finds it.
func TestSentinelCarriesItsErrno(t *testing.T) {
	err := Sentinel("example: directory not empty", syscall.ENOTEMPTY)
	if err.Error() != "example: directory not empty" {
		t.Fatalf("message = %q", err.Error())
	}
	if !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatal("sentinel does not carry its errno")
	}
	if got := Of(fmt.Errorf("rmdir: %w", err)); got != ENOTEMPTY {
		t.Fatalf("Of(wrapped sentinel) = %d, want %d", got, ENOTEMPTY)
	}
	other := Sentinel("example: directory not empty", syscall.ENOTEMPTY)
	if errors.Is(err, other) {
		t.Fatal("two sentinels with the same message and errno are interchangeable")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a sentinel without an errno was accepted")
		}
	}()
	_ = Sentinel("example: unclassified", 0)
}

func TestNonErrnoConditions(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int32
	}{
		{"nil", nil, OK},
		{"fs.ErrInvalid", fs.ErrInvalid, EINVAL},
		{"wrapped fs.ErrInvalid", fmt.Errorf("open: %w", fs.ErrInvalid), EINVAL},
		{"fs.ErrClosed", fs.ErrClosed, EBADF},
		{"os.ErrNotExist", os.ErrNotExist, ENOENT},
		{"os.ErrExist", os.ErrExist, EEXIST},
		{"os.ErrPermission", os.ErrPermission, EPERM},
		// A deadline is terminal. EINTR would ask the application to reissue
		// the identical call against a far end that just failed to answer in
		// time, which is an unbounded retry loop.
		{"deadline", context.DeadlineExceeded, ETIMEDOUT},
		{"io deadline", os.ErrDeadlineExceeded, ETIMEDOUT},
		// Cancellation is caller-initiated: the request being abandoned is the
		// caller's own, which is exactly what an interrupted call reports.
		{"cancel", context.Canceled, EINTR},
		{"unclassified", errors.New("cell verification failed"), EIO},
	}
	for _, tc := range cases {
		if got := Of(tc.err); got != tc.want {
			t.Errorf("Of(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestWireNumbersAreLinuxNumbered guards the constants themselves: the wire
// space is Linux-numbered whatever platform this package is compiled for, and
// a darwin build must not leak its local numbering.
func TestWireNumbersAreLinuxNumbered(t *testing.T) {
	linux := map[string]int32{
		"EPERM": 1, "ENOENT": 2, "EINTR": 4, "EIO": 5, "E2BIG": 7, "EBADF": 9,
		"EAGAIN": 11, "EACCES": 13, "EEXIST": 17, "EXDEV": 18, "ENOTDIR": 20,
		"EISDIR": 21, "EINVAL": 22, "ENOSPC": 28, "EROFS": 30, "ERANGE": 34,
		"ENAMETOOLONG": 36, "ENOSYS": 38, "ENOTEMPTY": 39, "ELOOP": 40,
		"ENODATA": 61, "EOPNOTSUPP": 95, "ETIMEDOUT": 110, "ESTALE": 116,
		"EDQUOT": 122,
	}
	got := map[string]int32{
		"EPERM": EPERM, "ENOENT": ENOENT, "EINTR": EINTR, "EIO": EIO, "E2BIG": E2BIG,
		"EBADF": EBADF, "EAGAIN": EAGAIN, "EACCES": EACCES, "EEXIST": EEXIST,
		"EXDEV": EXDEV, "ENOTDIR": ENOTDIR, "EISDIR": EISDIR, "EINVAL": EINVAL,
		"ENOSPC": ENOSPC, "EROFS": EROFS, "ERANGE": ERANGE, "ENAMETOOLONG": ENAMETOOLONG,
		"ENOSYS": ENOSYS, "ENOTEMPTY": ENOTEMPTY, "ELOOP": ELOOP, "ENODATA": ENODATA,
		"EOPNOTSUPP": EOPNOTSUPP, "ETIMEDOUT": ETIMEDOUT, "ESTALE": ESTALE, "EDQUOT": EDQUOT,
	}
	for name, want := range linux {
		if got[name] != want {
			t.Errorf("%s = %d, want Linux %d", name, got[name], want)
		}
	}
}

// TestEveryFilesystemErrnoIsEnumerated proves the default is not doing the
// work. Every errno this storage stack can produce must be classified by
// identity; anything reaching the default would be reported as a storage EIO,
// which is the errno that means "your filesystem is broken".
func TestEveryFilesystemErrnoIsEnumerated(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.EPERM, syscall.ENOENT, syscall.EINTR, syscall.ENXIO, syscall.E2BIG,
		syscall.EBADF, syscall.EAGAIN, syscall.ENOMEM, syscall.EACCES, syscall.EBUSY,
		syscall.EEXIST, syscall.EXDEV, syscall.ENODEV, syscall.ENOTDIR, syscall.EISDIR,
		syscall.EINVAL, syscall.ENFILE, syscall.EMFILE, syscall.ENOTTY, syscall.ETXTBSY,
		syscall.EFBIG, syscall.ENOSPC, syscall.ESPIPE, syscall.EROFS, syscall.EMLINK,
		syscall.EPIPE, syscall.ERANGE, syscall.ENAMETOOLONG, syscall.ENOSYS,
		syscall.ENOTEMPTY, syscall.ELOOP, syscall.ENODATA, syscall.EOVERFLOW,
		syscall.EOPNOTSUPP, syscall.ETIMEDOUT, syscall.ESTALE, syscall.EDQUOT,
	} {
		if errno == syscall.EIO {
			continue
		}
		if got := Of(errno); got == EIO {
			t.Errorf("Of(%v) fell through to EIO", errno)
		}
	}
	if got := Of(syscall.EIO); got != EIO {
		t.Errorf("Of(EIO) = %d, want EIO", got)
	}
}
