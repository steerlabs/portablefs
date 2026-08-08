// Package errnos is the single source of the Linux-numbered wire errno space
// shared by PortableFS protocols. Both the frozen v2 path and the current v3
// same-epoch replay path retain encoded outcomes, so a replay and its original
// reply must use one mapping.
package errnos

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// Errno values carried in protocol responses; 0 is success. The wire space is
// Linux-numbered (ESTALE 116, ENOTEMPTY 39, EOPNOTSUPP 95, EDQUOT 122);
// non-Linux frontends translate to their local numbering at the boundary. The
// mapping below therefore compares against the *local* syscall constants and
// answers with the Linux number, which is what makes it correct on a darwin
// build as well.
const (
	OK           int32 = 0
	EPERM        int32 = 1
	ENOENT       int32 = 2
	EINTR        int32 = 4
	EIO          int32 = 5
	ENXIO        int32 = 6
	E2BIG        int32 = 7
	EBADF        int32 = 9
	EAGAIN       int32 = 11
	ENOMEM       int32 = 12
	EACCES       int32 = 13
	EBUSY        int32 = 16
	EEXIST       int32 = 17
	EXDEV        int32 = 18
	ENODEV       int32 = 19
	ENOTDIR      int32 = 20
	EISDIR       int32 = 21
	EINVAL       int32 = 22
	ENFILE       int32 = 23
	EMFILE       int32 = 24
	ENOTTY       int32 = 25
	ETXTBSY      int32 = 26
	EFBIG        int32 = 27
	ENOSPC       int32 = 28
	ESPIPE       int32 = 29
	EROFS        int32 = 30
	EMLINK       int32 = 31
	EPIPE        int32 = 32
	ERANGE       int32 = 34
	ENAMETOOLONG int32 = 36
	ENOSYS       int32 = 38
	ENOTEMPTY    int32 = 39
	ELOOP        int32 = 40
	ENODATA      int32 = 61 // xattr not present (Linux ENODATA == ENOATTR)
	EOVERFLOW    int32 = 75
	EOPNOTSUPP   int32 = 95
	ETIMEDOUT    int32 = 110
	ESTALE       int32 = 116
	EDQUOT       int32 = 122
)

// sentinel is an error that carries the errno it means. Of classifies it
// through errors.Is like any other errno-carrying error, so a package can
// declare a named failure without also having to be known to this mapping.
type sentinel struct {
	message string
	errno   syscall.Errno
}

func (e *sentinel) Error() string { return e.message }
func (e *sentinel) Unwrap() error { return e.errno }

// Sentinel declares a package error whose wire errno is part of its value.
//
// Use it for every named failure that has to reach a client as a specific
// errno. An errors.New sentinel carries nothing an errno mapping can read, so
// it can only be classified by inspecting its message text - which is not an
// interface, changes with every rewording, and silently produces the wrong
// errno when it drifts. Declaring the errno with the error makes the two
// impossible to separate.
//
// It panics on a zero errno. That happens during package initialization, so
// an unclassified sentinel cannot reach a running process.
func Sentinel(message string, errno syscall.Errno) error {
	if errno == 0 {
		panic("errnos: sentinel error declared without an errno: " + message)
	}
	return &sentinel{message: message, errno: errno}
}

// Of maps a Go filesystem error to a wire errno. It is the canonical mapping
// for live replies and any retained replay outcome.
//
// Every classification below is an identity test on an error value. Nothing
// here inspects message text: text is not an interface, it changes with Go
// releases and with each fmt.Errorf that wraps an error, and a table that
// works by reading messages silently returns the wrong errno the moment one of
// them is reworded. An error that must carry an errno therefore has to carry
// it as a value that errors.Is can find - PortableFS sentinels wrap the errno
// they mean.
//
// The default is EIO, and it means one specific thing: an error that carries
// no errno at all is an internal integrity failure (a corrupt cell, a broken
// invariant), which is the EIO class. It is never a fallback classification
// for an errno-carrying error, because every errno this store can produce is
// enumerated above.
func Of(err error) int32 {
	if err == nil {
		return OK
	}
	// Exact errno identity comes first. The portable aliases below are not
	// one-to-one: syscall.ENOTEMPTY satisfies os.ErrExist and syscall.EACCES
	// satisfies os.ErrPermission, so an alias tested first would answer EEXIST
	// for a non-empty directory and EPERM for a permission denial.
	switch {
	case errors.Is(err, syscall.EPERM):
		return EPERM
	case errors.Is(err, syscall.ENOENT):
		return ENOENT
	case errors.Is(err, syscall.EINTR):
		return EINTR
	case errors.Is(err, syscall.EIO):
		return EIO
	case errors.Is(err, syscall.ENXIO):
		return ENXIO
	case errors.Is(err, syscall.E2BIG):
		return E2BIG
	case errors.Is(err, syscall.EBADF):
		return EBADF
	case errors.Is(err, syscall.EAGAIN):
		return EAGAIN
	case errors.Is(err, syscall.ENOMEM):
		return ENOMEM
	case errors.Is(err, syscall.EACCES):
		return EACCES
	case errors.Is(err, syscall.EBUSY):
		return EBUSY
	case errors.Is(err, syscall.EEXIST):
		return EEXIST
	case errors.Is(err, syscall.EXDEV):
		return EXDEV
	case errors.Is(err, syscall.ENODEV):
		return ENODEV
	case errors.Is(err, syscall.ENOTDIR):
		return ENOTDIR
	case errors.Is(err, syscall.EISDIR):
		return EISDIR
	case errors.Is(err, syscall.EINVAL):
		return EINVAL
	case errors.Is(err, syscall.ENFILE):
		return ENFILE
	case errors.Is(err, syscall.EMFILE):
		return EMFILE
	case errors.Is(err, syscall.ENOTTY):
		return ENOTTY
	case errors.Is(err, syscall.ETXTBSY):
		return ETXTBSY
	case errors.Is(err, syscall.EFBIG):
		return EFBIG
	case errors.Is(err, syscall.ENOSPC):
		return ENOSPC
	case errors.Is(err, syscall.ESPIPE):
		return ESPIPE
	case errors.Is(err, syscall.EROFS):
		return EROFS
	case errors.Is(err, syscall.EMLINK):
		return EMLINK
	case errors.Is(err, syscall.EPIPE):
		return EPIPE
	case errors.Is(err, syscall.ERANGE):
		return ERANGE
	case errors.Is(err, syscall.ENAMETOOLONG):
		return ENAMETOOLONG
	case errors.Is(err, syscall.ENOSYS):
		return ENOSYS
	case errors.Is(err, syscall.ENOTEMPTY):
		return ENOTEMPTY
	case errors.Is(err, syscall.ELOOP):
		return ELOOP
	case errors.Is(err, syscall.ENODATA):
		return ENODATA
	case errors.Is(err, syscall.EOVERFLOW):
		return EOVERFLOW
	case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
		return EOPNOTSUPP
	case errors.Is(err, syscall.ETIMEDOUT):
		return ETIMEDOUT
	case errors.Is(err, syscall.ESTALE):
		return ESTALE
	case errors.Is(err, syscall.EDQUOT):
		return EDQUOT
	}
	// Errors that name a condition without carrying an errno.
	switch {
	case errors.Is(err, fs.ErrInvalid):
		return EINVAL
	case errors.Is(err, fs.ErrClosed):
		return EBADF
	case errors.Is(err, os.ErrNotExist):
		return ENOENT
	case errors.Is(err, os.ErrExist):
		return EEXIST
	case errors.Is(err, os.ErrPermission):
		return EPERM
	// A deadline that expired is a terminal outcome, not an interruption:
	// EINTR asks the application to reissue the same call, which turns a
	// far-end timeout into an unbounded retry loop. Cancellation is different
	// - it is initiated by the caller whose request is being abandoned, and
	// EINTR is exactly what an interrupted call reports. A frontend must
	// never map its own operation deadline onto cancellation to reach EINTR.
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return ETIMEDOUT
	case errors.Is(err, context.Canceled):
		return EINTR
	default:
		return EIO
	}
}
