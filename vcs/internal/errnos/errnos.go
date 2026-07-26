// Package errnos is the single source of the wire errno space shared by the
// protocol layer (fsproto) and the authority filesystem (workfs). The exact-once
// mutation machinery stores each mutation's OUTCOME errno durably (so a
// lost-response retry returns the byte-identical status); that stored value and
// the live reply must come from one mapping, or a retry could observe a
// different status than the original execution.
package errnos

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

// Errno values carried in protocol responses; 0 is success. The wire space is
// Linux-numbered (ESTALE 116, ENOTEMPTY 39, EOPNOTSUPP 95, EDQUOT 122);
// non-Linux frontends translate to their local numbering at the boundary.
const (
	OK           int32 = 0
	EPERM        int32 = 1
	ENOENT       int32 = 2
	E2BIG        int32 = 7
	EIO          int32 = 5
	EAGAIN       int32 = 11
	EBUSY        int32 = 16
	EEXIST       int32 = 17
	ENOTDIR      int32 = 20
	EISDIR       int32 = 21
	EINVAL       int32 = 22
	ENOSPC       int32 = 28
	EROFS        int32 = 30
	ERANGE       int32 = 34
	ENAMETOOLONG int32 = 36
	ENOTEMPTY    int32 = 39
	ENODATA      int32 = 61 // xattr not present (Linux ENODATA == ENOATTR)
	EOPNOTSUPP   int32 = 95
	ESTALE       int32 = 116
	EDQUOT       int32 = 122
)

// Of maps a Go filesystem error to a wire errno. It is the canonical mapping:
// fsproto's reply path and workfs's outcome recording both use it, so a retried
// mutation's recorded status always equals the status the original reply carried.
func Of(err error) int32 {
	switch {
	case err == nil:
		return OK
	case errors.Is(err, os.ErrNotExist):
		return ENOENT
	case errors.Is(err, os.ErrExist):
		return EEXIST
	case errors.Is(err, os.ErrPermission):
		return EPERM
	case errors.Is(err, syscall.ENAMETOOLONG):
		return ENAMETOOLONG
	case errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP):
		return EOPNOTSUPP
	case errors.Is(err, syscall.ENOSPC):
		return ENOSPC
	case errors.Is(err, syscall.EDQUOT):
		return EDQUOT
	case errors.Is(err, syscall.ENODATA):
		return ENODATA
	case errors.Is(err, syscall.E2BIG):
		return E2BIG
	case errors.Is(err, syscall.ERANGE):
		return ERANGE
	}
	switch msg := err.Error(); {
	case strings.Contains(msg, "not empty"):
		return ENOTEMPTY
	case strings.Contains(msg, "not a directory"):
		return ENOTDIR
	case strings.Contains(msg, "is a directory"):
		return EISDIR
	case strings.Contains(msg, "invalid argument"):
		return EINVAL
	default:
		return EIO
	}
}
